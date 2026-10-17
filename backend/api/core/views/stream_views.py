"""ShieldCall VN – LLM Stream Views"""
import json
import logging
from django.http import StreamingHttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from api.utils.ollama_client import stream_response
from api.utils.normalization import normalize_phone, normalize_domain
from api.utils.prompts import (
    CHAT_SYSTEM_PROMPT, 
    SCAN_PHONE_PROMPT, 
    SCAN_MESSAGE_PROMPT,
    SCAN_DOMAIN_PROMPT,
    SCAN_ACCOUNT_PROMPT,
    SCAN_EMAIL_PROMPT,
    SCAN_FILE_PROMPT,
)
import base64
import io
from api.utils.media_utils import extract_ocr_text
from api.core.throttling import AIChatThrottle

logger = logging.getLogger(__name__)

class ScanAnalyzeSSEView(APIView):
    """
    SSE endpoint for detailed AI analysis of a scan result.
    """
    permission_classes = [AllowAny]
    throttle_classes = [AIChatThrottle]

    def post(self, request):
        scan_id = request.data.get('scan_id')
        scan_type = request.data.get('scan_type')
        scan_data = request.data.get('scan_data')
        raw_input = request.data.get('raw_input', '')

        # Chuẩn hoá kiểu: chống 500 khi client gửi raw_input không phải chuỗi
        # (trước đây `raw_input[:50]` raise TypeError -> 500 chưa bắt).
        if raw_input is None:
            raw_input = ''
        elif not isinstance(raw_input, str):
            raw_input = str(raw_input)
        if scan_type is not None and not isinstance(scan_type, str):
            scan_type = str(scan_type)

        # Chỉ dùng target gốc (allow_pii=True) cho người dùng đã xác thực / API key
        # hoặc khi được phép xem scan; ẩn danh chưa rõ chủ sở hữu -> redact PII.
        allow_pii = bool(
            getattr(request.user, 'is_authenticated', False)
            or getattr(request, 'is_api_key_auth', False)
        )

        if scan_id:
            from api.core.models import ScanEvent
            try:
                ev = ScanEvent.objects.get(id=scan_id)
                active_scans = request.session.get('active_scan_ids', []) if hasattr(request, 'session') else []
                try:
                    sid = int(scan_id)
                except (TypeError, ValueError):
                    sid = scan_id
                is_in_session = sid in (active_scans or []) or str(sid) in [str(x) for x in (active_scans or [])]
                can_view = bool(
                    getattr(request.user, 'is_staff', False)
                    or (getattr(request.user, 'is_authenticated', False) and ev.user_id == request.user.id)
                    or ev.is_public_referable
                    or is_in_session
                )
                if not can_view:
                    return Response({'error': 'Bạn không có quyền truy cập kết quả quét này.'}, status=403)
                scan_type = scan_type or ev.scan_type
                scan_data = scan_data or ev.result_json or {}
                raw_input = raw_input or ev.raw_input or ''
            except Exception:
                pass

        try:
            from api.utils.privacy import redact_pii as _redact
            _safe_preview = _redact(raw_input[:50])
        except Exception:
            _safe_preview = ''
        logger.info(f"SSE Request: type={scan_type}, raw_input={_safe_preview}...")

        if not scan_type:
            logger.error("SSE Error: Missing scan_type")
            return Response({'error': 'Missing scan_type'}, status=400)
        
        # We allow empty scan_data but log it
        if scan_data is None:
            logger.warning("SSE Warning: scan_data is None")
            scan_data = {}

        def event_stream():
            try:
                if scan_type == 'file':
                    proofs = scan_data.get('forensic_evidence', [])
                    proofs_str = '\n'.join([
                        f"- [{p.get('severity', 'INFO')}] {p.get('description', '')} | Evidence: {p.get('evidence', '')}"
                        for p in proofs
                    ]) if proofs else 'No malicious signatures detected.'

                    file_meta = scan_data.get('file_metadata', {})
                    meta_str = (
                        f"Size: {file_meta.get('size_bytes', 'N/A')} bytes | "
                        f"Entropy: {file_meta.get('entropy', 'N/A')}/8.0 | "
                        f"MD5: {file_meta.get('md5', 'N/A')} | "
                        f"SHA256: {file_meta.get('sha256', 'N/A')}"
                    )

                    engines = scan_data.get('engines', {})
                    engines_str = (
                        f"YARA: {engines.get('yara', {}).get('matches', 0)} rules matched | "
                        f"OLETools macros: {engines.get('oletools', {}).get('has_macros', False)} | "
                        f"PEFile: {'PE executable' if engines.get('pefile', {}).get('is_pe') else 'Non-PE'} | "
                        f"ClamAV: {'INFECTED' if engines.get('clamav', {}).get('infected') else 'CLEAN'}"
                    )

                    raw_snippet = scan_data.get('script_snippet', '')
                    snippet_section = (
                        f"\n\n## NOI DUNG FILE (150 dong dau)\n```\n{raw_snippet[:3500]}\n```"
                        if raw_snippet else ''
                    )

                    prompt = SCAN_FILE_PROMPT.format(
                        file_name=scan_data.get('file_name', raw_input or 'Uploaded file'),
                        file_size=f"{round(scan_data.get('file_size', file_meta.get('size_bytes', 0)) / 1024, 1)} KB",
                        risk_level=scan_data.get('risk_level', scan_data.get('verdict', 'SAFE')),
                        risk_score=scan_data.get('risk_score', 0),
                        verdict=scan_data.get('verdict', 'SAFE'),
                        threat_family=scan_data.get('threat_family') or 'Unclassified',
                        forensic_evidence=proofs_str,
                        file_metadata=meta_str,
                        engines=engines_str,
                        script_snippet=snippet_section,
                    )
                elif scan_type == 'phone':
                    prompt = SCAN_PHONE_PROMPT.format(
                        phone=raw_input,
                        scan_data=json.dumps(scan_data, ensure_ascii=False)
                    )
                elif scan_type == 'message':
                    prompt = SCAN_MESSAGE_PROMPT.format(message=raw_input)
                elif scan_type == 'email':
                    extracted = scan_data.get('extracted_info', {})
                    security_checks = scan_data.get('security_checks', [])
                    prompt = SCAN_EMAIL_PROMPT.format(
                        email=raw_input,
                        subject=extracted.get('subject', '(không có tiêu đề)'),
                        url_count=extracted.get('url_count', 0),
                        attachment_count=extracted.get('attachment_count', 0),
                        preliminary_score=scan_data.get('preliminary_score', scan_data.get('risk_score', 0)),
                        security_checks=', '.join(security_checks) if security_checks else 'Không có dữ liệu',
                        content=scan_data.get('content_snippet', scan_data.get('content', '(không có nội dung)'))
                    )
                elif scan_type == 'domain':
                    prompt = SCAN_DOMAIN_PROMPT.format(
                        url=raw_input,
                        scan_data=json.dumps(scan_data, ensure_ascii=False)
                    )
                elif scan_type == 'account':
                    # input might be "Bank - Account"
                    try:
                        bank, acc = raw_input.split(' - ')
                    except:
                        bank, acc = 'N/A', raw_input
                    prompt = SCAN_ACCOUNT_PROMPT.format(
                        bank=bank,
                        account=acc,
                        scan_data=json.dumps(scan_data, ensure_ascii=False)
                    )
                else:
                    prompt = f"Hãy phân tích rủi ro an ninh mạng cho {scan_type} sau bằng tiếng Việt: {raw_input}. Dữ liệu kèm theo: {json.dumps(scan_data, ensure_ascii=False)}"

                # Giải thích kết quả quét: chỉ dùng target gốc khi caller đã xác
                # thực; người dùng ẩn danh được redact PII trước khi gửi LLM cloud.
                for chunk in stream_response(prompt, system_prompt=CHAT_SYSTEM_PROMPT, allow_pii=allow_pii):
                    if not chunk or chunk.startswith('__'):
                        continue
                    yield f"data: {json.dumps({'type': 'delta', 'text': chunk}, ensure_ascii=False)}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
            except Exception as e:
                logger.error(f"SSE Error: {str(e)}")
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"

        resp = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        resp['Cache-Control'] = 'no-cache'
        resp['X-Accel-Buffering'] = 'no'
        return resp


