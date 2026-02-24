from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.http import StreamingHttpResponse
from django.core.cache import cache
from drf_spectacular.utils import extend_schema
import json
import uuid
from .models import ChatMessage, ChatAction
from .serializers import ChatAIRequestSerializer, ChatAIResponseSerializer
from api.utils.ollama_client import (
    generate_response, 
    stream_chat,
    classify_message,
    is_ollama_available
)
from api.utils.media_utils import extract_ocr_text
import base64
import io

def get_llm_response(user_message, session_id, context='general'):
    """
    Get response from Ollama LLM service for standard (non-streaming) chat.
    """
    if context == 'scam':
        prompt = f"""Bạn là chuyên gia an ninh mạng của ShieldCall VN. Nhiệm vụ của bạn là phân tích và cảnh báo người dùng về các dấu hiệu lừa đảo.
Hãy phân tích nội dung sau: "{user_message}"
Nếu có dấu hiệu lừa đảo (giả danh, yêu cầu tiền, OTP, link lạ), hãy nêu rõ lý do và đưa ra lời khuyên bảo mật cụ thể."""
    else:
        prompt = f"""Bạn là trợ lý AI thông minh của ShieldCall VN. Giúp người dùng giải đáp các thắc mắc về an toàn thông tin và cách sử dụng ứng dụng.
Câu hỏi: "{user_message}" """
    
    if is_ollama_available():
        try:
            ai_response = generate_response(prompt)
            if ai_response:
                classification = classify_message(user_message)
                return {
                    'ai_response': ai_response,
                    'action_suggested': classification.get('suggested_action', 'NONE')
                }
        except Exception as e:
            print(f"Error calling Ollama: {e}")
    
    return {
        'ai_response': f"Xin lỗi, tôi gặp khó khăn khi kết nối với hệ thống phân tích. Dựa trên nội dung '{user_message}', hãy cực kỳ cẩn trọng nếu đây là yêu cầu chuyển tiền hoặc cung cấp thông tin cá nhân.",
        'action_suggested': 'REPORT'
    }

class ChatAIView(APIView):
    """
    Standard chat endpoint - returns complete AI response.
    """
    @extend_schema(
        request=ChatAIRequestSerializer,
        responses={200: ChatAIResponseSerializer}
    )
    def post(self, request):
        serializer = ChatAIRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user_message = serializer.validated_data['user_message']
        session_uuid = serializer.validated_data['session_id']
        context = serializer.validated_data['context']
        
        ChatMessage.objects.create(
            session_id=session_uuid,
            role='user',
            message=user_message,
            context=context
        )
        
        llm_data = get_llm_response(user_message, session_uuid, context)
        
        ai_msg_record = ChatMessage.objects.create(
            session_id=session_uuid,
            role='assistant',
            message=llm_data['ai_response'],
            context=context
        )
        
        if llm_data.get('action_suggested') and llm_data['action_suggested'] != 'NONE':
            ChatAction.objects.create(
                chat_message=ai_msg_record,
                action=llm_data['action_suggested'],
                confidence=0.9
            )
        
        return Response({
            'ai_response': llm_data['ai_response'],
            'action_suggested': llm_data.get('action_suggested')
        })

class ChatAIStreamView(APIView):
    """
    Streaming chat endpoint - returns real-time SSE response.
    """
    @extend_schema(
        request=ChatAIRequestSerializer,
        responses={200: str}
    )
    def post(self, request):
        serializer = ChatAIRequestSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        user_message = serializer.validated_data['user_message']
        session_uuid = serializer.validated_data['session_id']
        context = serializer.validated_data['context']
        images_data = serializer.validated_data.get('images', [])
        
        # Process OCR from images
        ocr_accumulation = []
        for img_b64 in images_data:
            try:
                if ',' in img_b64:
                    img_b64 = img_b64.split(',')[1]
                img_bytes = base64.b64decode(img_b64)
                img_file = io.BytesIO(img_bytes)
                text = extract_ocr_text(img_file)
                if text:
                    ocr_accumulation.append(text)
            except Exception as e:
                print(f"OCR Error in Chat: {e}")

        final_user_message = user_message
        if ocr_accumulation:
            ocr_text_combined = "\n---\n".join(ocr_accumulation)
            final_user_message = f"[Nội dung trích xuất từ ảnh bạn gửi]:\n{ocr_text_combined}\n\n[Câu hỏi của người dùng]: {user_message}"

        ChatMessage.objects.create(
            session_id=session_uuid,
            role='user',
            message=user_message,
            context=context
        )
        
        def event_stream():
            full_response = ""
            try:
                messages = [{"role": "user", "content": final_user_message}]
                
                # Start streaming from Ollama
                for chunk in stream_chat(messages):
                    full_response += chunk
                    yield f"data: {json.dumps({'chunk': chunk})}\n\n"
                
                # After stream finishes, classify and save
                classification = classify_message(user_message)
                action = classification.get('suggested_action', 'NONE')
                
                yield f"data: {json.dumps({'action_suggested': action, 'done': True})}\n\n"
                
                ai_msg_record = ChatMessage.objects.create(
                    session_id=session_uuid,
                    role='assistant',
                    message=full_response,
                    context=context
                )
                
                if action != 'NONE':
                    ChatAction.objects.create(
                        chat_message=ai_msg_record,
                        action=action,
                        confidence=0.85
                    )
            except Exception as e:
                print(f"Stream error: {e}")
                error_msg = "Lỗi khi xử lý yêu cầu. Vui lòng thử lại."
                yield f"data: {json.dumps({'error': error_msg, 'done': True})}\n\n"
                # Save partial response if any
                if full_response:
                    ChatMessage.objects.create(
                        session_id=session_uuid,
                        role='assistant',
                        message=full_response + f"\n[Error: {str(e)}]",
                        context=context
                    )
        
        response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        response['Cache-Control'] = 'no-cache'
        response['X-Accel-Buffering'] = 'no'
        return response
