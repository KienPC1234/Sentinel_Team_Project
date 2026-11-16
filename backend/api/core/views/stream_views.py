"""ShieldCall VN – LLM Stream Views"""
import json
import logging
from django.http import StreamingHttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from api.utils.ollama_client import stream_response
from api.utils.security import verify_turnstile_token
from api.utils.scan_token import read_scan_token
from api.utils.prompts import (
    CHAT_SYSTEM_PROMPT, 
    SCAN_PHONE_PROMPT, 
    SCAN_MESSAGE_PROMPT,
    SCAN_DOMAIN_PROMPT,
    SCAN_ACCOUNT_PROMPT,
    SCAN_EMAIL_PROMPT,
    SCAN_FILE_PROMPT,
)
from api.core.throttling import AIChatThrottle, client_ip

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

        # An anonymous caller without a scan_id is basically asking for a free
        # LLM completion. Require Turnstile for that path; authenticated users
        # and API-key clients keep the existing behaviour. When scan_id is
        # present the DB record is authoritative (see the ownership check below).
        is_authenticated = bool(
            getattr(request.user, 'is_authenticated', False)
            or getattr(request, 'is_api_key_auth', False)
        )
        if not scan_id and not is_authenticated:
            cf_token = request.data.get('cf-turnstile-response')
            if not verify_turnstile_token(cf_token, remote_ip=client_ip(request)):
                return Response(
                    {
                        'error': 'Xác minh anti-spam không hợp lệ. Vui lòng thử lại.',
                        'code': 'TURNSTILE_REQUIRED',
                    },
                    status=400,
                )

        # Đăng nhập không đồng nghĩa với đồng ý gửi PII ra mô hình LLM ngoài.
        # Yêu cầu đồng thuận tường minh (consent_external_llm / allow_pii)
        # kết hợp quyền xác thực của người dùng.
        from api.utils.privacy import (
            apply_scan_privacy,
            is_scan_privacy_masked,
            parse_mask_pii_flag,
            parse_strict_bool,
            redact_pii as _redact,
        )

        mask_pii = parse_mask_pii_flag(request.data, default=True)
        user_consent = parse_strict_bool(request.data.get('consent_external_llm')) or parse_strict_bool(request.data.get('allow_pii'))
        allow_pii = bool(
            (not mask_pii)
            and user_consent
            and (
                getattr(request.user, 'is_authenticated', False)
                or getattr(request, 'is_api_key_auth', False)
            )
        )

        if scan_id:
            from api.core.models import ScanEvent
            try:
                ev = ScanEvent.objects.get(id=scan_id)
            except ScanEvent.DoesNotExist:
                return Response({'error': f'Không tìm thấy bản ghi quét #{scan_id}.'}, status=404)
            except Exception as e:
                logger.error(f"Error fetching ScanEvent #{scan_id}: {e}")
                return Response({'error': 'Lỗi truy xuất bản ghi quét.'}, status=500)

            active_scans = request.session.get('active_scan_ids', []) if hasattr(request, 'session') else []
            try:
                sid = int(scan_id)
            except (TypeError, ValueError):
                sid = scan_id
            is_in_session = sid in (active_scans or []) or str(sid) in [str(x) for x in (active_scans or [])]
            token_scan_id = read_scan_token(
                request.data.get('scan_token')
                or request.query_params.get('scan_token')
                or request.headers.get('X-Scan-Token')
            )
            is_token_owner = token_scan_id == ev.id
            can_view = bool(
                getattr(request.user, 'is_staff', False)
                or (getattr(request.user, 'is_authenticated', False) and ev.user_id == request.user.id)
                or ev.is_public_referable
                or is_in_session
                or is_token_owner
            )
            if not can_view:
                return Response({'error': 'Bạn không có quyền truy cập kết quả quét này.'}, status=403)
            # Ràng buộc sự thật phía server: khi scan_id hợp lệ, bản ghi cơ sở dữ liệu
            # có quyền tối thượng, client không được ghi đè scan_data/scan_type/raw_input.
            scan_type = ev.scan_type
            scan_data = ev.result_json or {}
            raw_input = ev.raw_input or ''
            ev_has_privacy_flag = isinstance(scan_data, dict) and 'privacy_masked' in scan_data
            if ev_has_privacy_flag:
                mask_pii = is_scan_privacy_masked(ev, default=True)
            else:
                # Legacy records or fixtures without privacy_masked metadata only mask locally when caller requests mask_pii;
                # external LLM PII forwarding still remains disabled unless explicitly consented with mask_pii=False.
                has_explicit_mask = hasattr(request.data, '__contains__') and ('mask_pii' in request.data)
                mask_pii = parse_mask_pii_flag(request.data, default=False) if has_explicit_mask else False
            if mask_pii:
                allow_pii = False

        try:
            _safe_preview = _redact(raw_input[:50])
        except Exception:
            _safe_preview = ''
        logger.info(f"SSE Request: type={scan_type}, mask_pii={mask_pii}, raw_input={_safe_preview}...")

        if not scan_type:
            logger.error("SSE Error: Missing scan_type")
            return Response({'error': 'Missing scan_type'}, status=400)

        if scan_data is None:
            logger.warning("SSE Warning: scan_data is None")
            scan_data = {}

        if mask_pii and isinstance(scan_data, dict):
            raw_input, _, scan_data = apply_scan_privacy(
                scan_type,
                scan_data,
                mask_pii=True,
                raw_input=raw_input,
            )

        def event_stream():
            try:
                # Flush headers early so proxies do not hold the response while
                # the LLM prompt is being prepared.
                yield ": ping\n\n"
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

                    guardrail_info = scan_data.get('guardrail') or {}
                    guardrail_tier = guardrail_info.get('tier') or 'INSUFFICIENT'
                    from api.utils.prompts import sanitize_delimiter_text
                    prompt = SCAN_FILE_PROMPT.format(
                        file_name=scan_data.get('file_name', raw_input or 'Uploaded file'),
                        file_size=f"{round(scan_data.get('file_size', file_meta.get('size_bytes', 0)) / 1024, 1)} KB",
                        risk_level=scan_data.get('risk_level') or guardrail_tier,
                        risk_score=scan_data.get('risk_score', 0),
                        verdict=scan_data.get('verdict') or guardrail_tier,
                        threat_family=scan_data.get('threat_family') or 'Unclassified',
                        forensic_evidence=sanitize_delimiter_text(proofs_str, limit=4000),
                        file_metadata=meta_str,
                        engines=engines_str,
                        script_snippet=sanitize_delimiter_text(snippet_section, limit=4000),
                    )
                elif scan_type == 'phone':
                    prompt = SCAN_PHONE_PROMPT.format(
                        phone=raw_input,
                        scan_data=json.dumps(scan_data, ensure_ascii=False)
                    )
                elif scan_type == 'message':
                    from api.utils.prompts import sanitize_delimiter_text
                    prompt = SCAN_MESSAGE_PROMPT.format(message=sanitize_delimiter_text(raw_input))
                elif scan_type == 'email':
                    from api.utils.prompts import sanitize_delimiter_text
                    extracted = scan_data.get('extracted_info', {})
                    security_checks = scan_data.get('security_checks', [])
                    raw_email_content = scan_data.get('content_snippet', scan_data.get('content', '(không có nội dung)'))
                    prompt = SCAN_EMAIL_PROMPT.format(
                        email=raw_input,
                        subject=extracted.get('subject', '(không có tiêu đề)'),
                        url_count=extracted.get('url_count', 0),
                        attachment_count=extracted.get('attachment_count', 0),
                        preliminary_score=scan_data.get('preliminary_score', scan_data.get('risk_score', 0)),
                        security_checks=', '.join(security_checks) if security_checks else 'Không có dữ liệu',
                        content=sanitize_delimiter_text(raw_email_content)
                    )
                elif scan_type == 'domain':
                    prompt = SCAN_DOMAIN_PROMPT.format(
                        url=raw_input,
                        scan_data=json.dumps(scan_data, ensure_ascii=False)
                    )
                elif scan_type == 'account':
                    if ' - ' in raw_input:
                        bank, acc = raw_input.split(' - ', 1)
                    elif ':' in raw_input:
                        bank, acc = raw_input.split(':', 1)
                    else:
                        bank, acc = 'N/A', raw_input
                    prompt = SCAN_ACCOUNT_PROMPT.format(
                        bank=bank.strip() or 'N/A',
                        account=acc.strip(),
                        scan_data=json.dumps(scan_data, ensure_ascii=False)
                    )
                else:
                    prompt = f"Hãy phân tích rủi ro an ninh mạng cho {scan_type} sau bằng tiếng Việt: {raw_input}. Dữ liệu kèm theo: {json.dumps(scan_data, ensure_ascii=False)}"

                _guard = (scan_data.get('guardrail') or {}) if isinstance(scan_data, dict) else {}
                _tier = _guard.get('tier')
                if _tier in ('INSUFFICIENT', 'SUSPICIOUS'):
                    prompt += (
                        f"\n\n[LƯU Ý GUARDRAIL: Trạng thái đánh giá hiện tại là {_tier} "
                        f"({_guard.get('label', _tier)}). Không khẳng định chắc chắn an toàn hay quy kết lừa đảo tuyệt đối; "
                        f"hãy nêu rõ giới hạn dữ liệu và khuyến nghị xác minh qua kênh chính thức.]"
                    )

                # Giải thích kết quả quét: chỉ dùng target gốc khi caller đã xác
                # thực; người dùng ẩn danh được redact PII trước khi gửi LLM cloud.
                for chunk in stream_response(prompt, system_prompt=CHAT_SYSTEM_PROMPT, allow_pii=allow_pii):
                    if not chunk:
                        continue
                    if isinstance(chunk, bytes):
                        try:
                            chunk = chunk.decode('utf-8', errors='replace')
                        except Exception:
                            continue
                    if chunk.startswith('__'):
                        continue
                    yield f"data: {json.dumps({'type': 'delta', 'text': chunk}, ensure_ascii=False)}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
            except Exception as e:
                logger.error(f"SSE Error: {str(e)}")
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"

        resp = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        resp['Cache-Control'] = 'no-cache, no-store'
        resp['X-Accel-Buffering'] = 'no'
        return resp


