import logging
import json
from urllib.parse import urlparse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, serializers
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from drf_spectacular.utils import extend_schema
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
    
    @extend_schema(responses={200: serializers.DictField()}) # Using DictField as a placeholder for now
    def get(self, request):
        from api.core.models import Notification
        try:
            page = int(request.query_params.get('page', 1))
        except (TypeError, ValueError):
            page = 1
        try:
            per_page = int(request.query_params.get('per_page', 20))
        except (TypeError, ValueError):
            per_page = 20
        page = max(1, page)
        per_page = min(100, max(1, per_page))
        
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

    def _has_admin_access(self, user) -> bool:
        if not user or not user.is_authenticated:
            return False
        if user.is_staff or user.is_superuser:
            return True
        try:
            return bool(user.profile.is_super_admin)
        except Exception:
            return False
    
    @extend_schema(
        request={'application/json': {
            'type': 'object',
            'properties': {
                'title': {'type': 'string'},
                'message': {'type': 'string'},
                'notification_type': {'type': 'string'},
                'url': {'type': 'string'}
            },
            'required': ['title', 'message']
        }},
        responses={201: serializers.DictField()}
    )
    def post(self, request):
        if not self._has_admin_access(request.user):
            return Response({'error': 'Bạn không có quyền gửi broadcast.'}, status=403)

        title = str(request.data.get('title', '') or '').strip()
        message = str(request.data.get('message', '') or '').strip()
        notification_type = str(request.data.get('notification_type', 'info') or 'info').strip()
        url = str(request.data.get('url', '') or '').strip()

        if not title or not message:
            return Response({'error': 'Tiêu đề và nội dung là bắt buộc.'}, status=400)
        # Chan noi dung qua dai lam phinh DB + vuot gioi han webpush payload.
        if len(title) > 200:
            return Response({'error': 'Tiêu đề tối đa 200 ký tự.'}, status=400)
        if len(message) > 2000:
            return Response({'error': 'Nội dung tối đa 2000 ký tự.'}, status=400)
        if notification_type not in ('info', 'warning', 'success', 'error'):
            return Response({'error': 'Loại thông báo không hợp lệ.'}, status=400)
        # URL noi bo hoac https (chan javascript:/data: vi frontend render link).
        if url and not (url.startswith('/') or url.startswith('https://') or url.startswith('http://')):
            return Response({'error': 'URL chỉ chấp nhận đường dẫn nội bộ hoặc http(s).'}, status=400)
        if len(url) > 500:
            return Response({'error': 'URL tối đa 500 ký tự.'}, status=400)

        # Chuyen sang task nen (truoc day broadcast dong bo trong request: lap 2
        # vong toan bo user + N query dem unread + webpush tung nguoi).
        send_webpush = bool(request.data.get('send_webpush', True))
        send_inapp = bool(request.data.get('send_inapp', True))
        try:
            from api.core.tasks import admin_broadcast_task
            admin_broadcast_task.delay(
                title,
                message,
                url,
                notification_type,
                send_webpush=send_webpush,
                send_inapp=send_inapp,
            )
        except Exception:
            logger.exception('Failed to enqueue admin broadcast')
            return Response({'error': 'Không thể xếp hàng gửi thông báo lúc này.'}, status=500)
        return Response({
            'status': 'queued',
            'message': 'Đã xếp hàng gửi thông báo đến toàn bộ người dùng (WebPush + In-App).',
        }, status=202)


# ═══ Existing Push / RAG views ════════════════════════════════════

class TestPushView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        message = str(request.data.get('message', 'Đây là thông báo thử nghiệm từ ShieldCall VN!') or '').strip()
        title = str(request.data.get('title', 'Thông báo thử nghiệm ShieldCall') or '').strip()
        url = str(request.data.get('url', '/admin-cp/') or '/admin-cp/').strip()

        # 1. Ban WebSocket den cac tab dang mo
        ws_sent = push_service._send_ws(
            user_id=request.user.id,
            title=title,
            message=message,
            url=url,
            notification_type='success',
        )

        # 2. Ban native WebPush truc tiep den tat ca subscription active cua user
        from api.core.models import WebPushSubscription
        subs = list(WebPushSubscription.objects.filter(user=request.user, is_active=True))
        webpush_sent = 0
        webpush_errors = []
        for sub in subs:
            ok, err, status = push_service.send_webpush(
                sub,
                {
                    'title': title,
                    'body': message,
                    'message': message,
                    'url': url,
                    'notification_type': 'success',
                    'tag': f'sc-test-push-{request.user.id}',
                    'icon': '/web-app-manifest-192x192.png',
                    'badge': '/favicon-96x96.png',
                },
                ttl=3600,
            )
            if ok:
                webpush_sent += 1
                sub.last_used_at = timezone.now()
                sub.last_success_at = timezone.now()
                sub.fail_count = 0
                sub.last_error = ''
                sub.save(update_fields=['last_used_at', 'last_success_at', 'fail_count', 'last_error', 'updated_at'])
            else:
                webpush_errors.append(err)
                sub.last_error = err
                if status in (404, 410):
                    sub.is_active = False
                sub.save(update_fields=['is_active', 'last_error', 'updated_at'])

        if webpush_sent > 0:
            return Response({
                'status': 'success',
                'message': f'Đã gửi WebPush thành công tới {webpush_sent} thiết bị (WebSocket: {"OK" if ws_sent else "Chưa mở"}).',
                'webpush_sent': webpush_sent,
                'subscriptions_count': len(subs),
                'ws_sent': ws_sent,
            })
        elif subs:
            return Response({
                'status': 'warning',
                'message': f'Tìm thấy {len(subs)} thiết bị nhưng WebPush không phản hồi: {"; ".join(webpush_errors[:2])}. Đã gửi WebSocket.',
                'webpush_sent': 0,
                'subscriptions_count': len(subs),
                'ws_sent': ws_sent,
            })
        else:
            return Response({
                'status': 'info',
                'message': 'Đã gửi WebSocket. Thiết bị hiện tại chưa đăng ký WebPush trên hệ thống. Hãy nhấn nút "Bật thông báo" để trình duyệt nhận WebPush.',
                'webpush_sent': 0,
                'subscriptions_count': 0,
                'ws_sent': ws_sent,
            })

class ResetRAGView(APIView):
    permission_classes = [IsAdminUser]

    @extend_schema(responses={200: serializers.DictField()})
    def post(self, request):
        """
        Deletes the vector index files and triggers a fresh rebuild.
        """
        index_dir = os.path.join(settings.BASE_DIR, 'vector_store')
        try:
            if os.path.exists(index_dir):
                for f in os.listdir(index_dir):
                    fp = os.path.join(index_dir, f)
                    try:
                        if os.path.isfile(fp) or os.path.islink(fp):
                            os.remove(fp)
                    except FileNotFoundError:
                        pass
            
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
    dev_origins = {'localhost:3000', '127.0.0.1:3000', 'localhost:8001', '127.0.0.1:8001', 'localhost', '127.0.0.1'}
    allowed_hosts.update(dev_origins)
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
            caller_uid = request.user.id if request.user.is_authenticated else None
            existing = WebPushSubscription.objects.filter(endpoint=endpoint).first()
            target_uid = caller_uid if caller_uid else (existing.user_id if existing else None)

            sub, _created = WebPushSubscription.objects.update_or_create(
                endpoint=endpoint,
                defaults={
                    'user_id': target_uid,
                    'p256dh': p256dh,
                    'auth': auth,
                    'user_agent': request.META.get('HTTP_USER_AGENT', '')[:500],
                    'is_active': True,
                    'fail_count': 0,
                    'last_error': '',
                },
            )
            if caller_uid and sub.user_id != caller_uid:
                sub.user_id = caller_uid
                sub.is_active = True
                sub.fail_count = 0
                sub.last_error = ''
                sub.save(update_fields=['user_id', 'is_active', 'fail_count', 'last_error', 'updated_at'])

            return Response({'status': 'success', 'subscription_id': sub.id})
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
