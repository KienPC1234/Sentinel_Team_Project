"""
ShieldCall VN – Remote Model Context Protocol (MCP) Server Views
Implements standard Model Context Protocol (JSON-RPC 2.0) over:
  1. Server-Sent Events (SSE) Transport (Claude Chat / claude.ai Remote Custom Connectors, Claude Desktop)
  2. Streamable HTTP / Direct JSON-RPC Transport (ChatGPT, Open WebUI, LibreChat, FastMCP)

Complies with Anthropic Claude Custom Connectors specification:
  - GET  /api/v1/mcp/sse/?api_key=...  -> SSE connection stream, emits initial endpoint event
  - POST /api/v1/mcp/messages/?session_id=... -> Receives JSON-RPC requests, pushes responses to SSE stream
  - POST /api/v1/mcp/ -> Direct Streamable JSON-RPC execution
  - GET  /api/v1/mcp/ -> Server capability discovery metadata
"""
import os
import json
import uuid
import asyncio
import logging
import threading
from typing import Optional, Tuple

from django.conf import settings
from django.views import View
from django.http import StreamingHttpResponse, JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone

from api.core.models import APIKey
from scripts.shieldcall_mcp import create_server, ZeroDepMCPServer

logger = logging.getLogger("shieldcall_mcp.remote")

# In-memory thread-safe session queues for async SSE streaming in Daphne/ASGI
_ASYNC_SESSION_QUEUES: dict[str, Tuple[asyncio.Queue, asyncio.AbstractEventLoop]] = {}
_QUEUES_LOCK = threading.Lock()


def _register_session(session_id: str, loop: asyncio.AbstractEventLoop) -> asyncio.Queue:
    """Registers an active SSE session queue with its asyncio loop."""
    q: asyncio.Queue = asyncio.Queue()
    with _QUEUES_LOCK:
        _ASYNC_SESSION_QUEUES[session_id] = (q, loop)
    return q


def _unregister_session(session_id: str):
    """Removes an active SSE session queue on disconnect."""
    with _QUEUES_LOCK:
        _ASYNC_SESSION_QUEUES.pop(session_id, None)


def _deliver_to_session(session_id: str, message_data: dict) -> bool:
    """Delivers a JSON-RPC message directly to the target SSE session stream across threads."""
    with _QUEUES_LOCK:
        entry = _ASYNC_SESSION_QUEUES.get(session_id)
    if entry is not None:
        q, loop = entry
        try:
            loop.call_soon_threadsafe(q.put_nowait, message_data)
            return True
        except Exception as ex:
            logger.error("Failed to enqueue message for session %s: %s", session_id, ex)
    return False


def _extract_raw_token(request) -> Optional[str]:
    """Extracts raw API key string from query parameter, X-API-Key header, or Authorization header."""
    # 1. Query parameter (?api_key=sc_live_...)
    raw_query = request.GET.get('api_key') or request.POST.get('api_key')
    if raw_query and raw_query.strip().startswith('sc_live_'):
        return raw_query.strip()

    # 2. X-API-Key header
    key_header = request.META.get('HTTP_X_API_KEY')
    if key_header and key_header.strip().startswith('sc_live_'):
        return key_header.strip()

    # 3. Authorization: Bearer sc_live_...
    auth_header = request.META.get('HTTP_AUTHORIZATION')
    if auth_header:
        parts = auth_header.strip().split()
        if len(parts) == 2 and parts[0].lower() in ('bearer', 'api-key', 'token'):
            cand = parts[1].strip()
            if cand.startswith('sc_live_'):
                return cand

    return None


def _authenticate_mcp(request) -> Tuple[Optional[APIKey], Optional[str], Optional[dict]]:
    """
    Validates API key and enforces quotas.
    Returns: (api_key_obj, raw_token_str, error_dict)
    """
    raw_token = _extract_raw_token(request)
    if not raw_token:
        return (
            None,
            None,
            {
                "error": "Yêu cầu API Key để kết nối MCP Server ShieldCall.",
                "detail": "Vui lòng thêm tham số ?api_key=sc_live_... vào URL máy chủ hoặc cấu hình Header 'X-API-Key: sc_live_...'.",
                "code": "API_KEY_REQUIRED",
                "help_url": "https://shieldcall.vn/mcp/",
            }
        )

    hashed = APIKey.hash_token(raw_token)
    try:
        api_key = APIKey.objects.select_related('user').get(hashed_key=hashed, is_active=True)
    except APIKey.DoesNotExist:
        return (
            None,
            None,
            {
                "error": "API Key không hợp lệ hoặc đã bị vô hiệu hóa.",
                "detail": "Khóa API không tồn tại trên hệ thống ShieldCall VN.",
                "code": "INVALID_API_KEY",
            }
        )

    if not api_key.user.is_active:
        return (
            None,
            None,
            {
                "error": "Tài khoản liên kết với API Key này đã bị tạm khóa.",
                "code": "USER_INACTIVE",
            }
        )

    # Quota enforcement
    today = timezone.now().date()
    last_reset = api_key.last_reset_date
    if hasattr(last_reset, 'date') and callable(last_reset.date):
        last_reset = last_reset.date()

    if last_reset is None or last_reset != today:
        api_key.requests_today = 0
        if last_reset is None or (last_reset.month != today.month or last_reset.year != today.year):
            api_key.requests_this_month = 0
        api_key.last_reset_date = today

    if api_key.daily_quota > 0 and api_key.requests_today >= api_key.daily_quota:
        return (
            None,
            None,
            {
                "error": f"API Key đã đạt hạn mức trong ngày ({api_key.daily_quota} req/ngày).",
                "code": "QUOTA_EXCEEDED",
                "quota": api_key.daily_quota,
                "requests_today": api_key.requests_today,
            }
        )

    # Increment request usage atomically (avoids lost updates under concurrency).
    from django.db.models import F
    from django.utils import timezone as _tz
    APIKey.objects.filter(id=api_key.id).update(
        requests_today=F('requests_today') + 1,
        requests_this_month=F('requests_this_month') + 1,
        total_requests=F('total_requests') + 1,
        last_used_at=_tz.now(),
        last_reset_date=today,
    )
    api_key.refresh_from_db(fields=['requests_today', 'requests_this_month', 'total_requests', 'last_used_at', 'last_reset_date'])

    return (api_key, raw_token, None)


def _cors_response(response: HttpResponse) -> HttpResponse:
    """Attaches standard CORS headers to permit connections from Claude and web chatbots."""
    response['Access-Control-Allow-Origin'] = '*'
    response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-API-Key, mcp-session-id, Accept'
    return response


@method_decorator(csrf_exempt, name='dispatch')
class MCPConnectSSEView(View):
    """
    Standard Model Context Protocol Server-Sent Events (SSE) connection view.
    Compatible with Claude Custom Connectors (claude.ai), Claude Desktop, and SSE MCP clients.
    """

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        return _cors_response(response)

    def get(self, request, *args, **kwargs):
        api_key, raw_token, auth_err = _authenticate_mcp(request)
        if auth_err:
            response = JsonResponse(auth_err, status=401)
            response['WWW-Authenticate'] = 'Bearer realm="ShieldCall MCP"'
            return _cors_response(response)

        session_id = uuid.uuid4().hex

        # Construct messages endpoint absolute URI
        messages_path = f"/api/v1/mcp/messages/?session_id={session_id}"
        if raw_token:
            messages_path += f"&api_key={raw_token}"
        messages_url = request.build_absolute_uri(messages_path)

        async def event_stream():
            loop = asyncio.get_running_loop()
            q = _register_session(session_id, loop)
            logger.info("MCP SSE client connected: session=%s, user=%s", session_id, api_key.user.username)

            try:
                # 1. Send initial mandatory 'endpoint' event per Model Context Protocol SSE spec
                yield f"event: endpoint\ndata: {messages_url}\n\n"

                # 2. Main event loop: waits for JSON-RPC messages and emits keepalive comments
                while True:
                    try:
                        msg = await asyncio.wait_for(q.get(), timeout=15.0)
                        serialized = json.dumps(msg, ensure_ascii=False)
                        yield f"event: message\ndata: {serialized}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keepalive\n\n"

            except (asyncio.CancelledError, GeneratorExit, ConnectionResetError, BrokenPipeError):
                logger.info("MCP SSE client disconnected: session=%s", session_id)
            finally:
                _unregister_session(session_id)

        resp = StreamingHttpResponse(event_stream(), content_type='text/event-stream; charset=utf-8')
        resp['Cache-Control'] = 'no-cache, no-transform'
        resp['Connection'] = 'keep-alive'
        resp['X-Accel-Buffering'] = 'no'
        return _cors_response(resp)


class DjangoInternalShieldCallClient:
    """Direct in-process client executing ShieldCall endpoints without HTTP loopback."""

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or ""
        from rest_framework.test import APIRequestFactory
        self.factory = APIRequestFactory()

    def _headers(self) -> dict:
        headers = {}
        if self.api_key:
            headers['HTTP_X_API_KEY'] = self.api_key
            headers['HTTP_AUTHORIZATION'] = f"Bearer {self.api_key}"
        return headers

    def scan_phone(self, phone: str) -> dict:
        from api.core.views import ScanPhoneView
        req = self.factory.post('/api/v1/scan/phone/', {'phone': phone}, format='json', **self._headers())
        resp = ScanPhoneView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}

    def scan_bank_account(self, bank: str, account: str) -> dict:
        from api.core.views import ScanAccountView
        req = self.factory.post('/api/v1/scan/account/', {'bank': bank, 'account': account}, format='json', **self._headers())
        resp = ScanAccountView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}

    def scan_domain(self, url: str) -> dict:
        from api.core.views import ScanDomainView
        req = self.factory.post('/api/v1/scan/domain/', {'url': url, 'deep_scan': False}, format='json', **self._headers())
        resp = ScanDomainView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}

    def scan_message(self, message: str) -> dict:
        from api.core.views import ScanMessageView
        req = self.factory.post('/api/v1/scan/message/', {'message': message, 'sync': True}, format='json', **self._headers())
        resp = ScanMessageView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}

    def scan_email(self, email: str, content: str = "", subject: str = "") -> dict:
        from api.core.views import ScanEmailView
        req = self.factory.post('/api/v1/scan/email/', {'email': email, 'content': content, 'subject': subject, 'sync': True}, format='json', **self._headers())
        resp = ScanEmailView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}

    def get_supported_banks(self) -> list:
        from api.core.views import ScanBanksView
        req = self.factory.get('/api/v1/scan/banks/', **self._headers())
        resp = ScanBanksView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else []

    def lookup_scam_db(self, query: str, entity_type: str = "all") -> dict:
        from api.core.views import ScanLookupView
        req = self.factory.get('/api/v1/scan/lookup/', {'q': query, 'type': entity_type}, **self._headers())
        resp = ScanLookupView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}

    def get_scam_radar_trends(self) -> dict:
        from api.core.views import ScamRadarStatsView
        req = self.factory.get('/api/v1/trends/radar-stats/', **self._headers())
        resp = ScamRadarStatsView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}

    def report_scam(self, target_type: str, target_value: str, scam_type: str, description: str, evidence_note: str = "") -> dict:
        from api.core.views import ReportCreateView
        payload = {
            "target_type": target_type,
            "target_value": target_value,
            "scam_type": scam_type,
            "description": description,
            "evidence_note": evidence_note,
        }
        req = self.factory.post('/api/v1/report/', payload, format='json', **self._headers())
        resp = ReportCreateView.as_view()(req)
        return resp.data if hasattr(resp, 'data') else {}


@method_decorator(csrf_exempt, name='dispatch')
class MCPMessagesView(View):
    """
    Standard Model Context Protocol messages endpoint.
    Receives JSON-RPC 2.0 payloads from Claude / MCP clients and delivers responses.
    """

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        return _cors_response(response)

    def post(self, request, *args, **kwargs):
        api_key, raw_token, auth_err = _authenticate_mcp(request)
        if auth_err:
            response = JsonResponse(auth_err, status=401)
            response['WWW-Authenticate'] = 'Bearer realm="ShieldCall MCP"'
            return _cors_response(response)

        session_id = request.GET.get('session_id') or request.META.get('HTTP_MCP_SESSION_ID')

        try:
            body_text = request.body.decode('utf-8')
            req_data = json.loads(body_text)
        except Exception as e:
            return _cors_response(JsonResponse({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            }, status=400))

        # Instantiate ZeroDepMCPServer with direct in-process client
        client = DjangoInternalShieldCallClient(api_key=raw_token)
        server = create_server(client=client)

        res = server.handle_request(req_data)

        # If connected via SSE session, push message to SSE stream
        if session_id:
            if res is not None:
                _deliver_to_session(session_id, res)
            # Return HTTP 202 Accepted per MCP SSE transport specification
            response = JsonResponse({"status": "accepted", "id": req_data.get("id")}, status=202)
            return _cors_response(response)

        # Direct RPC response (no SSE session provided)
        response = JsonResponse(res if res is not None else {"status": "ok"}, status=200)
        return _cors_response(response)


@method_decorator(csrf_exempt, name='dispatch')
class MCPDiscoveryView(View):
    """
    Discovery and unified entrypoint for Remote MCP.
    - If accessed with 'Accept: text/event-stream' -> routes to MCPConnectSSEView.
    - If accessed via POST -> routes to MCPMessagesView.
    - If accessed via GET (regular browser/JSON) -> returns server capabilities metadata.
    """

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        return _cors_response(response)

    def get(self, request, *args, **kwargs):
        accept_header = request.META.get('HTTP_ACCEPT', '')
        if 'text/event-stream' in accept_header:
            return MCPConnectSSEView.as_view()(request, *args, **kwargs)

        api_url = request.build_absolute_uri('/api/v1/mcp/')
        sse_url = request.build_absolute_uri('/api/v1/mcp/sse/')
        messages_url = request.build_absolute_uri('/api/v1/mcp/messages/')
        guide_url = request.build_absolute_uri('/mcp/')

        data = {
            "name": "shieldcall-vn",
            "title": "ShieldCall VN Remote MCP Server",
            "version": "1.0.0",
            "protocol_version": ZeroDepMCPServer.PROTOCOL_VERSION,
            "transports": {
                "sse": {
                    "connect_url": sse_url,
                    "messages_url": messages_url,
                    "description": "Server-Sent Events transport for Claude Custom Connectors (claude.ai) and Claude Desktop"
                },
                "http_rpc": {
                    "url": api_url,
                    "description": "Direct JSON-RPC 2.0 execution over HTTP POST"
                }
            },
            "tools_count": 10,
            "tools": [
                "check_phone",
                "check_bank_account",
                "check_url_or_domain",
                "analyze_message",
                "check_email_sender",
                "get_supported_banks",
                "lookup_scam_db",
                "get_scam_radar_trends",
                "scan_full_incident",
                "report_scam",
            ],
            "prompts": [
                "shieldcall_sentry",
                "emergency_advisor",
                "scam_investigator",
            ],
            "documentation": guide_url,
            "authentication": {
                "type": "API Key",
                "query_parameter": "?api_key=sc_live_...",
                "headers": ["X-API-Key: sc_live_...", "Authorization: Bearer sc_live_..."]
            }
        }
        return _cors_response(JsonResponse(data, status=200))

    def post(self, request, *args, **kwargs):
        return MCPMessagesView.as_view()(request, *args, **kwargs)
