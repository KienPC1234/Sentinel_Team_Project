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
from django.core.cache import cache
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


MCP_BURST_PER_MINUTE = 120
MCP_SESSION_TTL = 3600
_SHARED_FACTORY = None


def _get_request_factory():
    global _SHARED_FACTORY
    if _SHARED_FACTORY is None:
        from rest_framework.test import APIRequestFactory
        _SHARED_FACTORY = APIRequestFactory()
    return _SHARED_FACTORY


def _mcp_burst_ok(api_key) -> bool:
    """Atomic per-key per-minute burst guard (fail-open on cache outage)."""
    try:
        slot = timezone.now().strftime('%Y%m%d%H%M')
        key = f"mcp_burst:{api_key.id}:{slot}"
        try:
            n = cache.incr(key)
        except ValueError:
            cache.set(key, 1, timeout=65)
            n = 1
        return n <= MCP_BURST_PER_MINUTE
    except Exception:
        return True


def _mcp_bind_session(session_id: str, api_key, raw_token) -> None:
    """Binds an SSE session to its API key so follow-up POSTs can omit ?api_key=."""
    try:
        cache.set(f"mcp_sess:{session_id}", {'key_id': api_key.id, 'token': raw_token}, timeout=MCP_SESSION_TTL)
    except Exception:
        pass


def _mcp_get_session(session_id: str) -> Optional[dict]:
    try:
        data = cache.get(f"mcp_sess:{session_id}")
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _mcp_consume_quota(api_key) -> Optional[dict]:
    """Daily/monthly quota check and atomic usage increment for actual tool executions."""
    today = timezone.now().date()
    last_reset = api_key.last_reset_date
    if hasattr(last_reset, 'date') and callable(last_reset.date):
        last_reset = last_reset.date()

    day_rolled = (last_reset is None or last_reset != today)
    month_rolled = (
        last_reset is None
        or last_reset.month != today.month
        or last_reset.year != today.year
    )
    effective_today = 0 if day_rolled else int(api_key.requests_today or 0)
    effective_month = 0 if month_rolled else int(api_key.requests_this_month or 0)

    if api_key.daily_quota > 0 and effective_today >= api_key.daily_quota:
        return {
            "error": f"API Key đã đạt hạn mức trong ngày ({api_key.daily_quota} req/ngày).",
            "code": "QUOTA_EXCEEDED",
            "quota": api_key.daily_quota,
            "requests_today": effective_today,
            "status": 429,
        }

    if api_key.monthly_quota > 0 and effective_month >= api_key.monthly_quota:
        return {
            "error": f"API Key đã đạt hạn mức trong tháng ({api_key.monthly_quota} req/tháng).",
            "code": "QUOTA_EXCEEDED",
            "quota": api_key.monthly_quota,
            "requests_this_month": effective_month,
            "status": 429,
        }

    from django.db.models import F
    from django.utils import timezone as _tz
    APIKey.objects.filter(id=api_key.id).update(
        requests_today=1 if day_rolled else F('requests_today') + 1,
        requests_this_month=1 if month_rolled else F('requests_this_month') + 1,
        total_requests=F('total_requests') + 1,
        last_used_at=_tz.now(),
        last_reset_date=today,
    )
    api_key.refresh_from_db(fields=['requests_today', 'requests_this_month', 'total_requests', 'last_used_at', 'last_reset_date'])
    return None


def _authenticate_mcp(request, *, consume_quota: bool = True) -> Tuple[Optional[APIKey], Optional[str], Optional[dict]]:
    """
    Validates API key, enforces burst guard, and optionally consumes daily quota.
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
                "help_url": f"{(getattr(settings, 'SITE_URL', None) or os.getenv('SITE_URL', 'https://sc.fptoj.com')).rstrip('/')}/mcp/",
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

    if not _mcp_burst_ok(api_key):
        return (
            None,
            None,
            {
                "error": "MCP request quá nhanh (giới hạn 120 req/phút/key).",
                "code": "BURST_EXCEEDED",
                "status": 429,
            },
        )

    if consume_quota:
        quota_err = _mcp_consume_quota(api_key)
        if quota_err:
            return (None, None, quota_err)

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
        # SSE handshake only verifies identity + burst (does not consume daily scan quota)
        api_key, raw_token, auth_err = _authenticate_mcp(request, consume_quota=False)
        if auth_err:
            status_code = auth_err.pop('status', 401)
            response = JsonResponse(auth_err, status=status_code)
            response['WWW-Authenticate'] = 'Bearer realm="ShieldCall MCP"'
            return _cors_response(response)

        session_id = uuid.uuid4().hex
        # Bind session -> key server-side so follow-up POSTs can omit ?api_key=
        # (keeps raw keys out of URLs, proxy logs and browser history).
        _mcp_bind_session(session_id, api_key, raw_token)

        # Construct messages endpoint absolute URI (no api_key in URL)
        messages_path = f"/api/v1/mcp/messages/?session_id={session_id}"
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
    """Direct in-process client executing ShieldCall endpoints without HTTP loopback or double quota billing."""

    def __init__(self, api_key: Optional[str] = None, api_key_obj: Optional[APIKey] = None):
        self.api_key = api_key or ""
        self.api_key_obj = api_key_obj
        self.factory = _get_request_factory()

    def _wrap_worker(self, fn):
        """Ensure worker threads close DB connections cleanly after parallel sub-scans."""
        def _runner():
            from django.db import close_old_connections
            try:
                return fn()
            finally:
                close_old_connections()
        return _runner

    def _dispatch(self, view_cls, method: str, path: str, data=None, query_params=None):
        if method == 'GET':
            req = self.factory.get(path, data=query_params or {})
        else:
            req = self.factory.post(path, data or {}, format='json')

        if self.api_key_obj is not None:
            # MCP layer already authenticated & billed this request: prevent sub-views
            # from running APIKeyAuthentication again (which would double/6x charge quota).
            from rest_framework.test import force_authenticate
            force_authenticate(req, user=self.api_key_obj.user, token=self.api_key_obj)
            req.api_key = self.api_key_obj
            req.is_api_key_auth = True
        elif self.api_key:
            req.META['HTTP_X_API_KEY'] = self.api_key
            req.META['HTTP_AUTHORIZATION'] = f"Bearer {self.api_key}"

        resp = view_cls.as_view()(req)
        payload = resp.data if hasattr(resp, 'data') else {}
        if getattr(resp, 'status_code', 200) >= 400 and isinstance(payload, dict) and 'error' not in payload:
            payload = {'error': payload.get('detail') or f'Request failed ({resp.status_code})', 'status_code': resp.status_code}
        return payload

    def scan_phone(self, phone: str) -> dict:
        from api.core.views import ScanPhoneView
        return self._dispatch(ScanPhoneView, 'POST', '/api/v1/scan/phone/', {'phone': phone})

    def scan_bank_account(self, bank: str, account: str) -> dict:
        from api.core.views import ScanAccountView
        return self._dispatch(ScanAccountView, 'POST', '/api/v1/scan/account/', {'bank': bank, 'account': account})

    def scan_domain(self, url: str) -> dict:
        from api.core.views import ScanDomainView
        return self._dispatch(ScanDomainView, 'POST', '/api/v1/scan/domain/', {'url': url, 'deep_scan': False})

    def scan_message(self, message: str) -> dict:
        from api.core.views import ScanMessageView
        return self._dispatch(ScanMessageView, 'POST', '/api/v1/scan/message/', {'message': message, 'sync': True})

    def scan_email(self, email: str, content: str = "", subject: str = "") -> dict:
        from api.core.views import ScanEmailView
        return self._dispatch(
            ScanEmailView,
            'POST',
            '/api/v1/scan/email/',
            {'email': email, 'content': content, 'subject': subject, 'sync': True},
        )

    def get_supported_banks(self) -> list:
        from api.core.views import ScanBanksView
        cached = cache.get('mcp_cache:supported_banks')
        if cached is not None:
            return cached
        data = self._dispatch(ScanBanksView, 'GET', '/api/v1/scan/banks/')
        if isinstance(data, list) and data:
            cache.set('mcp_cache:supported_banks', data, timeout=3600)
        return data if isinstance(data, list) else []

    def lookup_scam_db(self, query: str, entity_type: str = "all") -> dict:
        from api.core.views import ScanLookupView
        return self._dispatch(ScanLookupView, 'GET', '/api/v1/scan/lookup/', query_params={'q': query, 'type': entity_type})

    def get_scam_radar_trends(self) -> dict:
        from api.core.views import ScamRadarStatsView
        cached = cache.get('mcp_cache:radar_trends')
        if cached is not None:
            return cached
        data = self._dispatch(ScamRadarStatsView, 'GET', '/api/v1/trends/radar-stats/')
        if isinstance(data, dict) and data and not data.get('error'):
            cache.set('mcp_cache:radar_trends', data, timeout=300)
        return data if isinstance(data, dict) else {}

    def get_trust_sources(self) -> dict:
        from api.utils.trust_guard import source_catalog, trust_policy
        from api.utils.vn_sources import tinnhiem_dataset_stats
        p = trust_policy()
        return {
            'policy': p['principle'],
            'gray_zone': p['gray_zone'],
            'tinnhiem_dataset': tinnhiem_dataset_stats(),
            'sources': source_catalog(),
        }

    def get_trust_channels(self) -> dict:
        from api.utils.vn_sources import VN_OFFICIAL_CHANNELS, VN_BANK_HOTLINES, SOURCE_VERIFIED_DATE
        return {
            'verified_on': SOURCE_VERIFIED_DATE,
            'channels': VN_OFFICIAL_CHANNELS,
            'bank_hotlines_count': len(VN_BANK_HOTLINES),
            'bank_hotlines': VN_BANK_HOTLINES,
        }

    def get_trust_policy(self) -> dict:
        from api.utils.trust_guard import trust_policy
        from api.utils.privacy import privacy_notice
        data = trust_policy()
        data['privacy'] = privacy_notice()
        return data

    def report_scam(self, target_type: str, target_value: str, scam_type: str, description: str, evidence_note: str = "") -> dict:
        from api.core.views import ReportCreateView
        payload = {
            "target_type": target_type,
            "target_value": target_value,
            "scam_type": scam_type,
            "description": description,
            "evidence_note": evidence_note,
        }
        return self._dispatch(ReportCreateView, 'POST', '/api/v1/report/', payload)


def _payload_contains_tool_call(req_data) -> bool:
    items = req_data if isinstance(req_data, list) else [req_data]
    return any(isinstance(item, dict) and item.get('method') == 'tools/call' for item in items)


@method_decorator(csrf_exempt, name='dispatch')
class MCPMessagesView(View):
    """
    Standard Model Context Protocol messages endpoint.
    Receives JSON-RPC 2.0 payloads (single or batch) from Claude / MCP clients and delivers responses.
    """

    def options(self, request, *args, **kwargs):
        response = HttpResponse()
        return _cors_response(response)

    def post(self, request, *args, **kwargs):
        # Verify identity + burst first; only bill daily quota on actual tool execution.
        api_key, raw_token, auth_err = _authenticate_mcp(request, consume_quota=False)

        session_id = request.GET.get('session_id') or request.META.get('HTTP_MCP_SESSION_ID')
        if auth_err and session_id:
            # Fallback: session bound at SSE connect — client may omit ?api_key=
            sess = _mcp_get_session(session_id)
            if sess:
                try:
                    bound = APIKey.objects.select_related('user').get(id=sess.get('key_id'), is_active=True)
                except APIKey.DoesNotExist:
                    bound = None
                if bound is not None and bound.user.is_active:
                    if not _mcp_burst_ok(bound):
                        auth_err = {
                            "error": "MCP request quá nhanh (giới hạn 120 req/phút/key).",
                            "code": "BURST_EXCEEDED",
                            "status": 429,
                        }
                    else:
                        api_key, raw_token, auth_err = bound, sess.get('token'), None

        if auth_err:
            status_code = auth_err.pop('status', 401) if isinstance(auth_err, dict) else 401
            response = JsonResponse(auth_err, status=status_code)
            response['WWW-Authenticate'] = 'Bearer realm="ShieldCall MCP"'
            return _cors_response(response)

        try:
            body_text = request.body.decode('utf-8')
            req_data = json.loads(body_text)
        except Exception as e:
            return _cors_response(JsonResponse({
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": f"Parse error: {str(e)}"}
            }, status=400))

        if _payload_contains_tool_call(req_data) and api_key is not None:
            quota_err = _mcp_consume_quota(api_key)
            if quota_err:
                status_code = quota_err.pop('status', 429)
                return _cors_response(JsonResponse(quota_err, status=status_code))

        # Instantiate ZeroDepMCPServer with direct in-process client (no double billing)
        client = DjangoInternalShieldCallClient(api_key=raw_token, api_key_obj=api_key)
        server = create_server(client=client)

        res = server.handle_payload(req_data)

        # If connected via SSE session, push message to SSE stream
        if session_id:
            if res is not None:
                _deliver_to_session(session_id, res)
            req_id = req_data.get("id") if isinstance(req_data, dict) else None
            response = JsonResponse({"status": "accepted", "id": req_id}, status=202)
            return _cors_response(response)

        # Direct RPC response (no SSE session provided)
        response = JsonResponse(res if res is not None else {"status": "ok"}, status=200, safe=not isinstance(res, list))
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
            "version": "1.1.0",
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
            "resources": [
                "shieldcall://trust/sources",
                "shieldcall://trust/channels",
                "shieldcall://trust/policy",
            ],
            "batch_requests": True,
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


def mcp_download_script_view(request):
    """
    Direct download endpoint for the standalone ShieldCall MCP python script.
    """
    from django.http import Http404

    script_path = os.path.join(settings.BASE_DIR, 'scripts', 'shieldcall_mcp.py')
    if not os.path.isfile(script_path):
        raise Http404("MCP script not found.")

    with open(script_path, 'r', encoding='utf-8') as f:
        content = f.read()

    response = HttpResponse(content, content_type='text/x-python; charset=utf-8')
    if request.GET.get('raw') != '1':
        response['Content-Disposition'] = 'attachment; filename="shieldcall_mcp.py"'
    response['Cache-Control'] = 'no-cache, must-revalidate'
    return response

