from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions, serializers
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404, render
from drf_spectacular.utils import extend_schema
import json
import uuid
import base64
import io
import logging
import os

from .models import ChatFolder, ChatSession, ChatMessage, ChatAction, ChatMessageImage, ChatbotConfig, SavedMessage
from django.core.files.base import ContentFile
from .serializers import (
    ChatAIRequestSerializer, ChatAIResponseSerializer, ChatFolderSerializer, 
    ChatSessionSerializer, ChatbotConfigSerializer, SavedMessageSerializer
)
from api.utils.ai_agent import get_agent
from api.core.throttling import AIChatThrottle
from api.utils.ollama_client import classify_message
from api.utils.media_utils import extract_ocr_text, extract_ocr_with_boxes
import concurrent.futures

class ChatFolderListView(APIView):
    """
    GET: List all chat folders for the current user.
    POST: Create a new chat folder.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: ChatFolderSerializer(many=True)})
    def get(self, request):
        folders = ChatFolder.objects.filter(user=request.user)
        serializer = ChatFolderSerializer(folders, many=True)
        return Response(serializer.data)

    @extend_schema(request=ChatFolderSerializer, responses={201: ChatFolderSerializer})
    def post(self, request):
        serializer = ChatFolderSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class ChatFolderDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=ChatFolderSerializer, responses={200: ChatFolderSerializer})
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
    GET: List all chat sessions for the current user or guest.
    POST: Create a new chat session (supports authenticated and guest users).
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(responses={200: ChatSessionSerializer(many=True)})
    def get(self, request):
        if request.user.is_authenticated:
            guest_ids = request.session.get('guest_chat_sessions', [])
            if guest_ids:
                ChatSession.objects.filter(id__in=guest_ids, user__isnull=True).update(user=request.user)
                request.session['guest_chat_sessions'] = []
                request.session.modified = True
            sessions = ChatSession.objects.filter(user=request.user).order_by('-updated_at')
            serializer = ChatSessionSerializer(sessions, many=True)
            return Response(serializer.data)

        guest_ids = request.session.get('guest_chat_sessions', [])
        if guest_ids:
            sessions = ChatSession.objects.filter(id__in=guest_ids, user__isnull=True).order_by('-updated_at')
            serializer = ChatSessionSerializer(sessions, many=True)
            return Response(serializer.data)
        return Response([])

    @extend_schema(request={'application/json': {'type': 'object', 'properties': {'folder_id': {'type': 'string'}}}}, responses={201: serializers.DictField()})
    def post(self, request):
        folder_id = request.data.get('folder_id')
        folder = None
        user = request.user if request.user.is_authenticated else None
        if folder_id and user:
            folder = get_object_or_404(ChatFolder, id=folder_id, user=user)
        
        session = ChatSession.objects.create(user=user, folder=folder)
        if not user:
            guest_sessions = request.session.get('guest_chat_sessions', [])
            sess_id_str = str(session.id)
            if sess_id_str not in guest_sessions:
                guest_sessions.insert(0, sess_id_str)
                request.session['guest_chat_sessions'] = guest_sessions
                request.session.modified = True

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
    permission_classes = [permissions.AllowAny]

    @extend_schema(responses={200: serializers.DictField()})
    def get(self, request, session_id):
        session = ChatSession.objects.filter(id=session_id).first()
        if not session:
            return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)
            
        if session.user:
            if not request.user.is_authenticated:
                return Response({'error': 'Authentication required'}, status=status.HTTP_401_UNAUTHORIZED)
            if session.user != request.user:
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        else:
            # Guest session: chỉ chủ sở hữu (theo session cookie) mới được xem.
            # Không tự gán cho user lạ chỉ vì họ biết UUID (chống chiếm đoạt hội thoại).
            if request.user.is_authenticated:
                guest_sessions = request.session.get('guest_chat_sessions', [])
                if str(session.id) not in [str(x) for x in guest_sessions]:
                    return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
                session.user = request.user
                session.save(update_fields=['user'])
            else:
                # Only the browser session that created this guest chat may read it.
                guest_sessions = request.session.get('guest_chat_sessions', [])
                if str(session.id) not in [str(x) for x in guest_sessions]:
                    return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            
        messages = session.messages.all().order_by('created_at').prefetch_related('images')

        def _img_url(img):
            try:
                url = getattr(getattr(img, 'image', None), 'url', None)
            except Exception:
                return None
            if not url:
                return None
            try:
                return url if str(url).startswith('http') else request.build_absolute_uri(url)
            except Exception:
                return str(url)

        data = [{
            'id': msg.id,
            'role': msg.role,
            'message': msg.message,
            'metadata': msg.metadata,
            'rating': getattr(msg, 'rating', 0) or 0,
            'created_at': msg.created_at,
            'images': [u for u in (_img_url(img) for img in msg.images.all()) if u]
        } for msg in messages]
        return Response({
            'session_id': str(session.id),
            'title': session.title,
            'messages': data
        })

    def patch(self, request, session_id):
        session = ChatSession.objects.filter(id=session_id).first()
        if not session:
            return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)
        if session.user:
            if not request.user.is_authenticated or session.user != request.user:
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        else:
            # Check ownership for both logged-in and anonymous browsers.
            guest_sessions = request.session.get('guest_chat_sessions', [])
            if str(session.id) not in [str(x) for x in guest_sessions]:
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            if request.user.is_authenticated:
                session.user = request.user

        title = request.data.get('title')
        folder_id = request.data.get('folder_id')
        
        if title:
            session.title = title
        if folder_id is not None and request.user.is_authenticated:
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
        session = ChatSession.objects.filter(id=session_id).first()
        if not session:
            return Response(status=status.HTTP_204_NO_CONTENT)
        if session.user:
            if not request.user.is_authenticated or session.user != request.user:
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
        else:
            # Guest session: chỉ chủ sở hữu theo session cookie mới được xóa.
            guest_sessions = request.session.get('guest_chat_sessions', [])
            sess_id_str = str(session.id)
            if sess_id_str not in [str(x) for x in guest_sessions]:
                return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            request.session['guest_chat_sessions'] = [x for x in guest_sessions if str(x) != sess_id_str]
            request.session.modified = True
        session.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

class ChatSessionClearAllView(APIView):
    """
    DELETE: Remove all chat sessions for the current user or guest.
    """
    permission_classes = [permissions.AllowAny]

    @extend_schema(responses={204: None})
    def delete(self, request):
        if request.user.is_authenticated:
            ChatSession.objects.filter(user=request.user).delete()
        else:
            guest_ids = request.session.get('guest_chat_sessions', [])
            if guest_ids:
                ChatSession.objects.filter(id__in=guest_ids, user__isnull=True).delete()
                request.session['guest_chat_sessions'] = []
                request.session.modified = True
        return Response(status=status.HTTP_204_NO_CONTENT)

class ChatMessageDeleteAfterView(APIView):
    """
    DELETE: Remove all messages in a session AFTER a specific message ID.
    Used for history branching when editing an old message.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: serializers.DictField()})
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


class ChatMessageRatingView(APIView):
    """
    PATCH /messages/<id>/rating/ {rating: 1 | -1 | 0} — thích/không thích câu trả lời AI.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(request=serializers.DictField(), responses={200: serializers.DictField()})
    def patch(self, request, message_id):
        msg = get_object_or_404(ChatMessage, id=message_id, session__user=request.user)
        try:
            rating = int(request.data.get('rating', 0))
        except (TypeError, ValueError):
            return Response({'error': 'rating không hợp lệ.'}, status=status.HTTP_400_BAD_REQUEST)
        if rating not in (-1, 0, 1):
            return Response({'error': 'rating phải là -1, 0 hoặc 1.'}, status=status.HTTP_400_BAD_REQUEST)
        msg.rating = rating
        msg.save(update_fields=['rating'])
        return Response({'status': 'ok', 'rating': msg.rating})

class ChatAIStreamView(APIView):
    """
    Streaming chat endpoint using AIAgent with RAG and history.
    """
    permission_classes = [permissions.AllowAny]
    throttle_classes = [AIChatThrottle]

    @extend_schema(request=ChatAIRequestSerializer, responses={200: serializers.DictField()})
    def post(self, request):
        user_message = request.data.get('user_message')
        session_id = request.data.get('session_id')
        images_data = request.data.get('images', [])
        preview_ocr = request.data.get('preview_ocr', False)
        scan_context = request.data.get('scan_context', '')
        safe_mode = request.data.get('safe_mode', False)
        debug = request.data.get('debug', False)

        user = request.user if request.user.is_authenticated else None
        
        # Dynamic Branding Detection
        host = request.get_host().lower()
        branding = "ShieldCall"
        branding_full = "ShieldCall VN"
        
        if "fairspace" in host:
            branding = "FairSpace"
            branding_full = "FairSpace"
            # Auto-enable safe_mode if on fairspace domain
            safe_mode = True 
            
        # Authorize before handing session_id to the agent:
        if session_id:
            try:
                parsed_session_id = uuid.UUID(str(session_id))
            except (ValueError, TypeError, AttributeError):
                return Response({'error': 'Invalid session ID format'}, status=status.HTTP_400_BAD_REQUEST)

            existing_session = ChatSession.objects.filter(id=parsed_session_id).first()
            if existing_session is None:
                return Response({'error': 'Session not found'}, status=status.HTTP_404_NOT_FOUND)

            if existing_session.user_id is not None:
                if user is None or existing_session.user_id != user.pk:
                    return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)
            else:
                session_obj = getattr(request, 'session', None)
                guest_sessions = session_obj.get('guest_chat_sessions', []) if session_obj is not None else []
                if str(existing_session.id) not in [str(x) for x in guest_sessions]:
                    return Response({'error': 'Forbidden'}, status=status.HTTP_403_FORBIDDEN)

            session_id = str(existing_session.id)

        agent = get_agent(session_id=session_id, user=user, safe_mode=safe_mode, branding=branding, branding_full=branding_full)
        if scan_context:
            agent._scan_context = scan_context

        if not user and agent.session:
            session_obj = getattr(request, 'session', None)
            if session_obj is not None:
                guest_sessions = session_obj.get('guest_chat_sessions', [])
                sess_id_str = str(agent.session.id)
                if sess_id_str not in guest_sessions:
                    guest_sessions.insert(0, sess_id_str)
                    session_obj['guest_chat_sessions'] = guest_sessions
                    session_obj.modified = True

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
                    yield f"data: {json.dumps({'type': 'status', 'value': 'processing_images'})}\n\n"
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
                                    yield f"data: {json.dumps({'type': 'image', 'annotated_image': annotated_image})}\n\n"
                            else:
                                text = extract_ocr_text(io.BytesIO(img_bytes))
                            
                            if text: ocr_text += f"\n{text}"
                        except Exception as e:
                            logging.getLogger(__name__).error(f"OCR Error: {e}")

                final_query = user_message
                if ocr_text:
                    final_query = f"[Nội dung từ ảnh]:{ocr_text}\n\n[Câu hỏi]: {user_message or 'Hãy phân tích ảnh này'}"

                if not final_query:
                    yield f"data: {json.dumps({'type': 'error', 'message': 'No message provided'})}\n\n"
                    yield f"data: {json.dumps({'type': 'done'})}\n\n"
                    return

                # Start classification in parallel
                class_future = executor.submit(classify_message, user_message or ocr_text)

                # Use sync_to_async for the blocking generator
                agent_stream = await sync_to_async(agent.chat_stream)(final_query, images_data=images_data, debug=debug, safe_mode=safe_mode)

                # AIAgent phát ra event dạng dict {'type': ...} -> serialize thẳng ra SSE.
                def get_next_event(gen):
                    try:
                        return next(gen)
                    except StopIteration:
                        return None

                while True:
                    event = await sync_to_async(get_next_event)(agent_stream)
                    if event is None:
                        break
                    if isinstance(event, dict):
                        yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
                    elif isinstance(event, str) and event and not event.startswith('__'):
                        # Tương thích: nếu agent trả text thô thì coi là delta.
                        yield f"data: {json.dumps({'type': 'delta', 'text': event}, ensure_ascii=False)}\n\n"
                
                # Retrieve classification result without blocking stream completion
                try:
                    classification = class_future.result(timeout=0.05) if class_future.done() else {}
                except Exception:
                    classification = {}
                
                action = classification.get('suggested_action', 'NONE')
                
                # Ensure session is refreshed for the final title
                if agent.session:
                    await sync_to_async(agent.session.refresh_from_db)()

                final_payload = {
                    'type': 'done',
                    'action_suggested': action,
                    'session_id': str(agent.session.id) if agent.session else None,
                    'title': agent.session.title if agent.session else 'Guest Session',
                }
                yield f"data: {json.dumps(final_payload, ensure_ascii=False)}\n\n"
            except Exception as e:
                logging.getLogger(__name__).error(f"Stream Error: {e}")
                yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
                yield f"data: {json.dumps({'type': 'done'})}\n\n"
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

class ChatSearchView(APIView):
    """
    GET: Search chat sessions and messages by query string.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: serializers.DictField()})
    def get(self, request):
        q = request.query_params.get('q', '').strip()
        if not q or len(q) < 2:
            return Response({'sessions': [], 'messages': []})
        
        from django.db.models import Q
        
        # Search sessions by title
        sessions = ChatSession.objects.filter(
            user=request.user
        ).filter(
            Q(title__icontains=q)
        ).order_by('-updated_at')[:10]
        
        session_results = [{
            'id': str(s.id),
            'title': s.title,
            'updated_at': s.updated_at,
            'folder': s.folder_id,
        } for s in sessions]
        
        # Search messages by content
        messages = ChatMessage.objects.filter(
            session__user=request.user
        ).filter(
            Q(message__icontains=q)
        ).select_related('session').order_by('-created_at')[:20]
        
        message_results = [{
            'id': m.id,
            'role': m.role,
            'message': m.message[:200],
            'session_id': str(m.session_id),
            'session_title': m.session.title,
            'created_at': m.created_at,
        } for m in messages]
        
        return Response({
            'sessions': session_results,
            'messages': message_results,
        })


class ChatbotConfigView(APIView):
    """
    GET: Get current user's chatbot personalization config.
    PUT: Update chatbot config.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: ChatbotConfigSerializer})
    def get(self, request):
        config, _ = ChatbotConfig.objects.get_or_create(user=request.user)
        serializer = ChatbotConfigSerializer(config)
        data = serializer.data
        # Include available choices
        data['tone_choices'] = [{'value': c[0], 'label': c[1]} for c in ChatbotConfig.TONE_CHOICES]
        data['language_style_choices'] = [{'value': c[0], 'label': c[1]} for c in ChatbotConfig.LANGUAGE_STYLE_CHOICES]
        return Response(data)

    @extend_schema(request=ChatbotConfigSerializer, responses={200: ChatbotConfigSerializer})
    def put(self, request):
        config, _ = ChatbotConfig.objects.get_or_create(user=request.user)
        serializer = ChatbotConfigSerializer(config, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class SavedMessageListView(APIView):
    """
    GET: List saved/bookmarked messages.
    POST: Bookmark a message.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={200: SavedMessageSerializer(many=True)})
    def get(self, request):
        saved = SavedMessage.objects.filter(user=request.user).select_related('message', 'message__session')
        serializer = SavedMessageSerializer(saved, many=True)
        return Response(serializer.data)

    @extend_schema(request={'application/json': {'type': 'object', 'properties': {'message_id': {'type': 'integer'}, 'note': {'type': 'string'}}, 'required': ['message_id']}}, responses={201: SavedMessageSerializer, 200: serializers.DictField()})
    def post(self, request):
        message_id = request.data.get('message_id')
        note = request.data.get('note', '')
        
        if not message_id:
            return Response({'error': 'message_id required'}, status=status.HTTP_400_BAD_REQUEST)
        
        message = get_object_or_404(ChatMessage, id=message_id, session__user=request.user)
        saved, created = SavedMessage.objects.get_or_create(
            user=request.user, message=message,
            defaults={'note': note}
        )
        if not created:
            # Toggle: unsave if already saved
            saved.delete()
            return Response({'status': 'unsaved', 'message_id': message_id})
        
        serializer = SavedMessageSerializer(saved)
        return Response(serializer.data, status=status.HTTP_201_CREATED)


class SavedMessageDetailView(APIView):
    """
    DELETE: Remove a bookmarked message.
    """
    permission_classes = [permissions.IsAuthenticated]

    @extend_schema(responses={204: None})
    def delete(self, request, saved_id):
        saved = get_object_or_404(SavedMessage, id=saved_id, user=request.user)
        saved.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
