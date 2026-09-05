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

logger = logging.getLogger(__name__)

class ScanAnalyzeSSEView(APIView):
    """
    SSE endpoint for detailed AI analysis of a scan result.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        scan_id = request.data.get('scan_id')
        scan_type = request.data.get('scan_type')
        scan_data = request.data.get('scan_data')
        raw_input = request.data.get('raw_input', '')

        if scan_id:
            from api.core.models import ScanEvent
            try:
                ev = ScanEvent.objects.get(id=scan_id)
                scan_type = scan_type or ev.scan_type
                scan_data = scan_data or ev.result_json or {}
                raw_input = raw_input or ev.raw_input or ''
            except Exception:
                pass

        logger.info(f"SSE Request: type={scan_type}, raw_input={raw_input[:50]}...")
        logger.debug(f"SSE scan_data: {scan_data}")

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

                for chunk in stream_response(prompt, system_prompt=CHAT_SYSTEM_PROMPT):
                    if not chunk or '__STATUS__:' in chunk or '__THINK__:' in chunk:
                        continue
                    yield f"data: {json.dumps({'chunk': chunk})}\n\n"
                yield f"data: {json.dumps({'done': True})}\n\n"
            except Exception as e:
                logger.error(f"SSE Error: {str(e)}")
                yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"

        resp = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        resp['Cache-Control'] = 'no-cache'
        resp['X-Accel-Buffering'] = 'no'
        return resp


class ChatStreamView(APIView):
    """
    General AI chatbot stream.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        user_message = request.data.get('user_message', '')
        images = request.data.get('images', [])  # List of base64 strings
        session_id = request.data.get('session_id', 'unknown')
        
        if not user_message and not images:
            return Response({'error': 'Empty message'}, status=400)

        def event_stream():
            try:
                # 1. OCR Processing
                ocr_text = ""
                if images:
                    msg_ocr = json.dumps({'chunk': '🔄 *Đang xử lý hình ảnh...*\n\n'})
                    yield f"data: {msg_ocr}\n\n"
                    ocr_accumulation = []
                    for img_b64 in images:
                        try:
                            if ',' in img_b64:
                                img_b64 = img_b64.split(',')[1]
                            img_bytes = base64.b64decode(img_b64)
                            img_file = io.BytesIO(img_bytes)
                            text = extract_ocr_text(img_file)
                            if text:
                                ocr_accumulation.append(text)
                        except Exception as ocr_err:
                            logger.error(f"OCR Error in Stream: {ocr_err}")
                    
                    if ocr_accumulation:
                        ocr_text = "\n---\n".join(ocr_accumulation)
                        msg_extracted = json.dumps({'chunk': '✅ *Đã trích xuất nội dung từ ảnh. Bắt đầu phân tích...*\n\n'})
                        yield f"data: {msg_extracted}\n\n"
                    else:
                        msg_none = json.dumps({'chunk': 'ℹ️ *Không tìm thấy văn bản trong ảnh. Tiến hành phân tích tổng quát...*\n\n'})
                        yield f"data: {msg_none}\n\n"

                # 2. Final Prompt Construction
                final_message = user_message
                if ocr_text:
                    final_message = f"[Nội dung từ ảnh]:\n{ocr_text}\n\n[Câu hỏi của người dùng]: {user_message}"

                # 3. LLM Streaming
                full_reply = ""
                for chunk in stream_response(final_message, system_prompt=CHAT_SYSTEM_PROMPT):
                    full_reply += chunk
                    yield f"data: {json.dumps({'chunk': chunk})}\n\n"
                
                # 4. Cleanup & Done
                yield f"data: {json.dumps({'done': True})}\n\n"
                
                # Async logging/save could happen here (not blocking stream)
                from api.ai_chat.models import ChatMessage
                ChatMessage.objects.create(
                    session_id=session_id,
                    role='user',
                    message=user_message,
                    context='chat'
                )
                ChatMessage.objects.create(
                    session_id=session_id,
                    role='assistant',
                    message=full_reply,
                    context='chat'
                )

            except Exception as e:
                logger.error(f"Chat Stream Error: {str(e)}")
                yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"

        resp = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        resp['Cache-Control'] = 'no-cache'
        resp['X-Accel-Buffering'] = 'no'
        return resp
