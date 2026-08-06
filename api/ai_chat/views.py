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

from .models import ChatFolder, ChatSession, ChatMessage, ChatAction, ChatMessageImage
from django.core.files.base import ContentFile
from .serializers import ChatAIRequestSerializer, ChatAIResponseSerializer, ChatFolderSerializer, ChatSessionSerializer
from api.utils.ai_agent import get_agent
from api.utils.ollama_client import classify_message
from api.utils.media_utils import extract_ocr_text, extract_ocr_with_boxes
import concurrent.futures
from api.utils.vector_db import vector_db

class ChatFolderListView(APIView):
    """
    GET: List all chat folders for the current user.
    POST: Create a new chat folder.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        folders = ChatFolder.objects.filter(user=request.user)
        serializer = ChatFolderSerializer(folders, many=True)
        return Response(serializer.data)

    def post(self, request):
        serializer = ChatFolderSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChatFolderDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def patch(self, request, folder_id):
        folder = get_object_or_404(ChatFolder, id=folder_id, user=request.user)
        serializer = ChatFolderSerializer(folder, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, folder_id):
        folder = get_object_or_404(ChatFolder, id=folder_id, user=request.user)
        folder.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ChatSessionListView(APIView):
    """
    GET: List all chat sessions for the current user.
    POST: Create a new chat session.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        sessions = ChatSession.objects.filter(user=request.user)
        serializer = ChatSessionSerializer(sessions, many=True)
        return Response(serializer.data)

    def post(self, request):
        folder_id = request.data.get('folder_id')
        folder = None
        if folder_id:
            folder = get_object_or_404(ChatFolder, id=folder_id, user=request.user)
        
        session = ChatSession.objects.create(user=request.user, folder=folder)
        return Response({
            'id': str(session.id),
            'title': session.title,
            'folder': session.folder_id
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
            'id': msg.id,
            'role': msg.role,
            'message': msg.message,
            'metadata': msg.metadata,
            'created_at': msg.created_at,
            'images': [request.build_absolute_uri(img.image.url) if not img.image.url.startswith('http') else img.image.url for img in msg.images.all()]
        } for msg in messages]
        return Response({
            'session_id': str(session.id),
            'title': session.title,
            'messages': data
        })

    def patch(self, request, session_id):
        session = get_object_or_404(ChatSession, id=session_id, user=request.user)
        title = request.data.get('title')
        folder_id = request.data.get('folder_id')
        
        if title:
            session.title = title
        if folder_id is not None:
            if folder_id == "": # Move out of folder
                session.folder = None
            else:
                folder = get_object_or_404(ChatFolder, id=folder_id, user=request.user)
                session.folder = folder
        
        session.save()
        return Response({
            'status': 'updated', 
            'title': session.title,
            'folder': session.folder_id
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

class ChatMessageDeleteAfterView(APIView):
    """
    DELETE: Remove all messages in a session AFTER a specific message ID.
    Used for history branching when editing an old message.
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, message_id):
        target_message = get_object_or_404(ChatMessage, id=message_id, session__user=request.user)
        session = target_message.session
        # Delete all messages in this session created AFTER this message
        ChatMessage.objects.filter(
            session=session,
            created_at__gt=target_message.created_at
        ).delete()
        
        # Also delete the target message itself (it will be replaced by the edited version)
        target_message.delete()
        
        return Response({'status': 'truncated'}, status=status.HTTP_200_OK)

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

                # Handle OCR inside the stream to avoid initial blocking

                # Handle OCR inside the stream to avoid initial blocking
                ocr_text = ""
                annotated_image = None
                if images_data:
                    yield f"data: {json.dumps({'status': 'processing_images'})}\n\n"
                    logging.getLogger(__name__).debug("Processing OCR")
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

                final_query = user_message
                if ocr_text:
                    final_query = f"[Nội dung từ ảnh]:{ocr_text}\n\n[Câu hỏi]: {user_message or 'Hãy phân tích ảnh này'}"

                if not final_query:
                    yield f"data: {json.dumps({'error': 'No message provided', 'done': True})}\n\n"
                    return

                # Start classification in parallel
                class_future = executor.submit(classify_message, user_message or ocr_text)

                # Use sync_to_async for the blocking generator
                agent_stream = await sync_to_async(agent.chat_stream)(final_query, images_data=images_data)
                
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
                
                # Retrieve classification result
                try:
                    classification = class_future.result(timeout=5)
                except Exception:
                    classification = {}
                
                action = classification.get('suggested_action', 'NONE')
                
                # Ensure session is refreshed for the final title
                if agent.session:
                    await sync_to_async(agent.session.refresh_from_db)()

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
    def get(self, request, session_id=None):
        if not request.user.is_authenticated:
            from django.shortcuts import redirect
            return redirect('login')
        
        context = {
            'initial_session_id': str(session_id) if session_id else ''
        }
        return render(request, 'AI/assistant.html', context)
