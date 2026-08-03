from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404, render
from drf_spectacular.utils import extend_schema
import json
import uuid
import base64
import io
import logging
import os

from .models import ChatSession, ChatMessage, ChatAction
from .serializers import ChatAIRequestSerializer, ChatAIResponseSerializer
from api.utils.ai_agent import get_agent
from api.utils.ollama_client import classify_message
from api.utils.media_utils import extract_ocr_text, extract_ocr_with_boxes
import concurrent.futures
from api.utils.vector_db import vector_db

class ChatSessionListView(APIView):
    """
    GET: List all chat sessions for the current user.
    POST: Create a new chat session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        sessions = ChatSession.objects.filter(user=request.user)
        data = [{
            'id': str(s.id),
            'title': s.title,
            'created_at': s.created_at,
            'updated_at': s.updated_at
        } for s in sessions]
        return Response(data)

    def post(self, request):
        session = ChatSession.objects.create(user=request.user)
        return Response({
            'id': str(session.id),
            'title': session.title
        }, status=status.HTTP_201_CREATED)

class ChatSessionDetailView(APIView):
    """
    GET: Retrieve message history for a session.
    DELETE: Remove a chat session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, session_id):
        session = get_object_or_404(ChatSession, id=session_id, user=request.user)
        messages = session.messages.all().order_by('created_at')
        data = [{
            'role': msg.role,
            'message': msg.message,
            'created_at': msg.created_at
        } for msg in messages]
        return Response({
            'session_id': str(session.id),
            'title': session.title,
            'messages': data
        })

    def delete(self, request, session_id):
        session = get_object_or_404(ChatSession, id=session_id, user=request.user)
        session.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ChatSessionClearAllView(APIView):
    """
    DELETE: Remove all chat sessions for the current user.
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request):
        ChatSession.objects.filter(user=request.user).delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ChatAIStreamView(APIView):
    """
    Streaming chat endpoint using AIAgent with RAG and history.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        user_message = request.data.get('user_message')
        session_id = request.data.get('session_id')
        images_data = request.data.get('images', [])
        preview_ocr = request.data.get('preview_ocr', False)

        user = request.user if request.user.is_authenticated else None
        agent = get_agent(session_id=session_id, user=user)

        async def event_stream():
            from asgiref.sync import sync_to_async
            # Start classification early
            executor = concurrent.futures.ThreadPoolExecutor(max_workers=2)
            
            try:
                # Force immediate headers flush with a larger preamble for proxies
                yield ": preamble " + (" " * 4096) + "\n\n"
                yield ": ping\n\n"
                
                import time
                def log_debug(msg):
                    print(f"DEBUG [{time.strftime('%H:%M:%S')}]: {msg}", flush=True)

                log_debug("Stream started")

                # Handle OCR inside the stream to avoid initial blocking
                ocr_text = ""
                annotated_image = None
                if images_data:
                    yield f"data: {json.dumps({'status': 'processing_images'})}\n\n"
                    log_debug("Processing OCR")
                    for i, img_b64 in enumerate(images_data):
                        try:
                            if ',' in img_b64: img_b64 = img_b64.split(',')[1]
                            img_bytes = base64.b64decode(img_b64)
                            
                            if preview_ocr and i == 0:
                                ocr_res = extract_ocr_with_boxes(io.BytesIO(img_bytes))
                                text = ocr_res.get('text', '')
                                annotated_image = ocr_res.get('annotated_image_b64')
                                if annotated_image:
                                    yield f"data: {json.dumps({'annotated_image': annotated_image})}\n\n"
                            else:
                                text = extract_ocr_text(io.BytesIO(img_bytes))
                            
                            if text: ocr_text += f"\n{text}"
                        except Exception as e:
                            logging.getLogger(__name__).error(f"OCR Error: {e}")
                    log_debug("OCR Done")

                final_query = user_message
                if ocr_text:
                    final_query = f"[Nội dung từ ảnh]:{ocr_text}\n\n[Câu hỏi]: {user_message or 'Hãy phân tích ảnh này'}"

                if not final_query:
                    yield f"data: {json.dumps({'error': 'No message provided', 'done': True})}\n\n"
                    return

                # Start agents chat stream
                log_debug(f"Calling agent.chat_stream for query: {final_query[:50]}...")
                
                # Model should already be loaded via apps.py
                if vector_db._model is None:
                    log_debug("VectorDB model missing, loading now...")
                    vector_db._load_model()
                
                # Start classification in parallel
                class_future = executor.submit(classify_message, user_message or ocr_text)

                # Use sync_to_async for the blocking generator
                agent_stream = await sync_to_async(agent.chat_stream)(final_query)
                
                chunk_count = 0
                # We need to handle the agent_stream correctly if it's a generator
                def get_next_chunk(gen):
                    try:
                        return next(gen)
                    except StopIteration:
                        return None

                while True:
                    chunk = await sync_to_async(get_next_chunk)(agent_stream)
                    if chunk is None:
                        break
                        
                    if chunk.startswith("__TITLE__:"):
                        title = chunk.replace("__TITLE__:", "")
                        yield f"data: {json.dumps({'title': title})}\n\n"
                    elif chunk.startswith("__STATUS__:"):
                        status_val = chunk.replace("__STATUS__:", "")
                        yield f"data: {json.dumps({'status': status_val})}\n\n"
                    else:
                        yield f"data: {json.dumps({'chunk': chunk})}\n\n"
                        chunk_count += 1
                        if chunk_count % 20 == 0:
                            log_debug(f"Sent {chunk_count} chunks")
                
                log_debug("Agent stream finished")
                
                # Retrieve classification result
                try:
                    classification = class_future.result(timeout=5)
                except Exception:
                    classification = {}
                
                action = classification.get('suggested_action', 'NONE')
                
                yield f"data: {json.dumps({
                    'action_suggested': action, 
                    'session_id': str(agent.session.id) if agent.session else None,
                    'title': agent.session.title if agent.session else 'Guest Session',
                    'done': True
                })}\n\n"
            except Exception as e:
                logging.getLogger(__name__).error(f"Stream Error: {e}")
                yield f"data: {json.dumps({'error': str(e), 'done': True})}\n\n"
            finally:
                executor.shutdown(wait=False)

        response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
        response['Cache-Control'] = 'no-cache, no-transform'
        response['X-Accel-Buffering'] = 'no'
        response['X-Content-Type-Options'] = 'nosniff'
        response['Connection'] = 'keep-alive'
        response['Content-Encoding'] = 'identity'
        response.streaming = True
        return response

from django.views import View

class AssistantPageView(View):
    """
    Renders the dedicated AI Assistant page.
    """
    def get(self, request):
        if not request.user.is_authenticated:
            from django.shortcuts import redirect
            return redirect('login')
        return render(request, 'AI/assistant.html')
