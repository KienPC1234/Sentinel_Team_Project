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
    SCAN_EMAIL_PROMPT
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
        scan_type = request.data.get('scan_type')
        scan_data = request.data.get('scan_data')
        raw_input = request.data.get('raw_input', '')

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
                if scan_type == 'phone':
                    prompt = SCAN_PHONE_PROMPT.format(
                        phone=raw_input,
                        scan_data=json.dumps(scan_data, ensure_ascii=False)
                    )
                elif scan_type == 'message':
                    prompt = SCAN_MESSAGE_PROMPT.format(message=raw_input)
                elif scan_type == 'email':
                    prompt = SCAN_EMAIL_PROMPT.format(
                        email=raw_input,
                        content=scan_data.get('content', '')
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
                    yield f"data: {json.dumps({'chunk': '🔄 *Đang xử lý hình ảnh...*\\n\\n'})}\n\n"
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
                        yield f"data: {json.dumps({'chunk': '✅ *Đã trích xuất nội dung từ ảnh. Bắt đầu phân tích...*\\n\\n'})}\n\n"
                    else:
                        yield f"data: {json.dumps({'chunk': 'ℹ️ *Không tìm thấy văn bản trong ảnh. Tiến hành phân tích tổng quát...*\\n\\n'})}\n\n"

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
