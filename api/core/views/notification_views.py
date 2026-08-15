import logging
import json
from urllib.parse import urlparse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from api.utils.push_service import push_service
import os
from django.conf import settings
from django.core.cache import cache
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
            if not n.is_read:
                n.is_read = True
                n.save(update_fields=['is_read'])
            push_service.push_unread_count(request.user.id)
            return Response({'status': 'ok'})
        except Notification.DoesNotExist:
            return Response({'error': 'Không tìm thấy thông báo.'}, status=404)


class NotificationMarkAllReadView(APIView):
    """POST — mark all user notifications as read."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from api.core.models import Notification
        updated = Notification.objects.filter(user=request.user, is_read=False).update(is_read=True)
        push_service.push_unread_count(request.user.id)
        return Response({'status': 'ok', 'marked': updated})


class AdminNotificationBroadcastView(APIView):
    """POST — Admin sends a notification to all users (or specific users)."""
    permission_classes = [IsAuthenticated]

    def _has_admin_access(self, user):
        return bool(
            user
            and user.is_authenticated
            and (user.is_staff or getattr(getattr(user, 'profile', None), 'is_super_admin', False))
        )

    def post(self, request):
        if not self._has_admin_access(request.user):
            return Response({'error': 'Bạn không có quyền gửi broadcast.'}, status=403)

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


# ═══ Existing Push / RAG views ════════════════════════════════════

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

class PushPublicKeyView(APIView):
    """GET public VAPID key for frontend bootstrap."""
    permission_classes = [AllowAny]

    def get(self, request):
        key = getattr(settings, 'WEBPUSH_VAPID_PUBLIC_KEY', '')
        if not key:
            return Response({'status': 'error', 'message': 'WEBPUSH_VAPID_PUBLIC_KEY is not configured'}, status=503)
        return Response({'public_key': key})


def _push_rate_limit_ok(request, action: str, limit: int = 20, ttl: int = 60) -> bool:
    user_part = str(request.user.id) if getattr(request.user, 'is_authenticated', False) else 'anon'
    ip = request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip() or request.META.get('REMOTE_ADDR', '') or 'noip'
    key = f"push_rl:{action}:{user_part}:{ip}"
    current = cache.get(key, 0)
    if current >= limit:
        return False
    cache.set(key, current + 1, timeout=ttl)
    return True


def _is_origin_allowed(request) -> bool:
    origin = request.META.get('HTTP_ORIGIN', '').strip()
    if not origin:
        return True

    parsed = urlparse(origin)
    if parsed.scheme not in {'http', 'https'} or not parsed.netloc:
        return False

    allowed_hosts = {request.get_host()}
    for trusted in getattr(settings, 'CSRF_TRUSTED_ORIGINS', []) or []:
        t = urlparse(trusted)
        if t.netloc:
            allowed_hosts.add(t.netloc)

    return parsed.netloc in allowed_hosts


class WebPushSubscribeView(APIView):
    """Registers/updates a browser Web Push subscription for current user."""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            if not _is_origin_allowed(request):
                return Response({'status': 'error', 'message': 'Origin not allowed'}, status=403)

            if not _push_rate_limit_ok(request, 'subscribe'):
                return Response({'status': 'error', 'message': 'Too many requests'}, status=429)

            payload = request.data if isinstance(request.data, dict) else json.loads(request.body or '{}')
            endpoint = (payload.get('endpoint') or '').strip()
            keys = payload.get('keys') or {}
            p256dh = (keys.get('p256dh') or '').strip()
            auth = (keys.get('auth') or '').strip()

            if not endpoint or not p256dh or not auth:
                return Response({'status': 'error', 'message': 'Invalid subscription payload'}, status=400)
            if not endpoint.startswith('https://'):
                return Response({'status': 'error', 'message': 'Invalid endpoint format'}, status=400)
            if len(endpoint) > 700 or len(p256dh) > 255 or len(auth) > 255:
                return Response({'status': 'error', 'message': 'Payload exceeds allowed length'}, status=400)

            from api.core.models import WebPushSubscription
            sub, _created = WebPushSubscription.objects.update_or_create(
                endpoint=endpoint,
                defaults={
                    'user': request.user if request.user.is_authenticated else None,
                    'p256dh': p256dh,
                    'auth': auth,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                    'is_active': True,
                    'fail_count': 0,
                    'last_error': '',
                },
            )
            if request.user.is_authenticated and sub.user_id != request.user.id:
                sub.user = request.user
                sub.save(update_fields=['user'])

            return Response({'status': 'success'})
        except Exception as e:
            logger.error(f"WebPush subscribe error: {e}")
            return Response({'status': 'error', 'message': str(e)}, status=500)


class WebPushUnsubscribeView(APIView):
    """Marks a browser Web Push subscription inactive."""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            if not _is_origin_allowed(request):
                return Response({'status': 'error', 'message': 'Origin not allowed'}, status=403)

            if not _push_rate_limit_ok(request, 'unsubscribe'):
                return Response({'status': 'error', 'message': 'Too many requests'}, status=429)

            payload = request.data if isinstance(request.data, dict) else json.loads(request.body or '{}')
            endpoint = (payload.get('endpoint') or '').strip()
            from api.core.models import WebPushSubscription

            if not endpoint and not request.user.is_authenticated:
                return Response({'status': 'error', 'message': 'endpoint is required'}, status=400)

            qs = WebPushSubscription.objects.all()
            if request.user.is_authenticated:
                qs = qs.filter(user=request.user)
            if endpoint:
                qs = qs.filter(endpoint=endpoint)
            updated = qs.update(is_active=False)
            return Response({'status': 'success', 'updated': updated})
        except Exception as e:
            logger.error(f"WebPush unsubscribe error: {e}")
            return Response({'status': 'error', 'message': str(e)}, status=500)
