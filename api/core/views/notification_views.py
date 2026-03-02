import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from api.utils.push_service import push_service
import os
from django.conf import settings
from api.maintenance.tasks import rebuild_vector_index

logger = logging.getLogger(__name__)


# ═══ Notification APIs ═══════════════════════════════════════════════════════

class NotificationListView(APIView):
    """GET — user's notifications with pagination."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from api.core.models import Notification
        page = int(request.query_params.get('page', 1))
        per_page = int(request.query_params.get('per_page', 20))
        
        qs = Notification.objects.filter(user=request.user).order_by('-created_at')
        total = qs.count()
        items = qs[(page - 1) * per_page:page * per_page]
        
        data = [{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'notification_type': n.notification_type,
            'url': n.url,
            'is_read': n.is_read,
            'created_at': n.created_at.isoformat(),
        } for n in items]
        
        return Response({
            'results': data,
            'count': total,
            'page': page,
            'pages': (total + per_page - 1) // per_page,
            'unread_count': Notification.objects.filter(user=request.user, is_read=False).count(),
        })


class NotificationUnreadCountView(APIView):
    """GET — unread notification count for the bell badge."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from api.core.models import Notification
        count = Notification.objects.filter(user=request.user, is_read=False).count()
        return Response({'unread_count': count})


class NotificationMarkReadView(APIView):
    """POST — mark a single notification as read."""
    permission_classes = [IsAuthenticated]

    def post(self, request, notification_id):
        from api.core.models import Notification
        try:
            n = Notification.objects.get(id=notification_id, user=request.user)
            n.is_read = True
            n.save()
            return Response({'status': 'ok'})
        except Notification.DoesNotExist:
            return Response({'error': 'Không tìm thấy thông báo.'}, status=404)


class NotificationMarkAllReadView(APIView):
    """POST — mark all user notifications as read."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from api.core.models import Notification
        updated = Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
        return Response({'status': 'ok', 'marked': updated})


class AdminNotificationBroadcastView(APIView):
    """POST — Admin sends a notification to all users (or specific users)."""
    permission_classes = [IsAdminUser]

    def post(self, request):
        title = request.data.get('title', '').strip()
        message = request.data.get('message', '').strip()
        notification_type = request.data.get('notification_type', 'info')
        url = request.data.get('url', '')
        
        if not title or not message:
            return Response({'error': 'Tiêu đề và nội dung là bắt buộc.'}, status=400)
        
        count = push_service.broadcast_all(title, message, url=url, notification_type=notification_type)
        return Response({
            'status': 'success',
            'message': f'Đã gửi thông báo đến {count} người dùng.',
            'count': count,
        }, status=201)


# ═══ Existing Push / RAG / OneSignal views ════════════════════════════════════

class TestPushView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        message = request.data.get('message', 'Đây là tin nhắn thử nghiệm từ ShieldCall!')
        title = request.data.get('title', 'Thông báo thử nghiệm')
        
        success = push_service.send_push(
            user_id=request.user.id,
            title=title,
            message=message,
            notification_type='success'
        )
        
        if success:
            return Response({'status': 'success', 'message': 'Đã gửi yêu cầu push tới websocket.'})
        return Response({'status': 'error', 'message': 'Không thể gửi push.'}, status=500)

class ResetRAGView(APIView):
    permission_classes = [IsAdminUser]

    def post(self, request):
        """
        Deletes the vector index files and triggers a fresh rebuild.
        """
        index_dir = os.path.join(settings.BASE_DIR, 'media', 'vector_index')
        try:
            if os.path.exists(index_dir):
                for f in os.listdir(index_dir):
                    os.remove(os.path.join(index_dir, f))
            
            # Trigger task
            rebuild_vector_index.delay(trigger='FORCE_RESET')
            
            return Response({
                'status': 'success', 
                'message': 'Đã xóa dữ liệu cũ và bắt đầu rebuild index từ đầu (chế độ nền).'
            })
        except Exception as e:
            return Response({'status': 'error', 'message': str(e)}, status=500)

class OneSignalRegistrationView(APIView):
    """
    Registers or updates the OneSignal Player ID for the authenticated user.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        player_id = request.data.get('player_id')
        if not player_id:
            return Response({'status': 'error', 'message': 'player_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            profile = request.user.profile
            profile.onesignal_player_id = player_id
            profile.save()
            logger.info(f"Registered OneSignal Player ID for user {request.user.username}: {player_id}")
            return Response({'status': 'success', 'message': 'OneSignal ID registered'})
        except Exception as e:
            logger.error(f"Error saving OneSignal ID for {request.user.username}: {e}")
            return Response({'status': 'error', 'message': str(e)}, status=500)
