import json
import logging

from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

try:
    from pywebpush import webpush, WebPushException
except Exception:
    webpush = None
    WebPushException = Exception


class PushNotificationService:
    """Push service: WebSocket for online users, native WebPush for offline users."""

    @staticmethod
    def _is_user_online(user_id):
        from django.core.cache import cache
        return cache.get(f"ws_online_{user_id}", False)

    @staticmethod
    def _send_ws(user_id, title, message, url=None, notification_type='info', unread_count=None):
        channel_layer = get_channel_layer()
        if not channel_layer:
            return False
        async_to_sync(channel_layer.group_send)(f"user_{user_id}", {
            'type': 'user_notification',
            'title': title,
            'message': message,
            'url': url,
            'notification_type': notification_type,
            'unread_count': unread_count,
        })
        return True

    @staticmethod
    def send_webpush(subscription, payload, ttl=3600):
        """Send one webpush message to one subscription record."""
        if not webpush:
            return False, 'pywebpush_not_installed', None

        vapid_private = getattr(settings, 'WEBPUSH_VAPID_PRIVATE_KEY', '')
        vapid_public = getattr(settings, 'WEBPUSH_VAPID_PUBLIC_KEY', '')
        vapid_subject = getattr(settings, 'WEBPUSH_VAPID_SUBJECT', '')
        if not vapid_private or not vapid_subject or not vapid_public:
            return False, 'vapid_not_configured', None

        subscription_info = {
            'endpoint': subscription.endpoint,
            'keys': {
                'p256dh': subscription.p256dh,
                'auth': subscription.auth,
            }
        }
        try:
            webpush(
                subscription_info=subscription_info,
                data=json.dumps(payload),
                vapid_private_key=vapid_private,
                vapid_claims={'sub': vapid_subject},
                ttl=max(3600, min(int(ttl or 3600), 86400)),
            )
            return True, '', None
        except WebPushException as exc:
            status_code = getattr(getattr(exc, 'response', None), 'status_code', None)
            return False, str(exc)[:500], status_code
        except Exception as exc:
            return False, str(exc)[:500], None

    @staticmethod
    def _send_webpush_notification(user_id, title, message, url=None, notification_type='info'):
        if not webpush:
            return 0

        vapid_private = getattr(settings, 'WEBPUSH_VAPID_PRIVATE_KEY', '')
        vapid_public = getattr(settings, 'WEBPUSH_VAPID_PUBLIC_KEY', '')
        vapid_subject = getattr(settings, 'WEBPUSH_VAPID_SUBJECT', '')
        if not vapid_private or not vapid_subject or not vapid_public:
            return 0

        from api.core.models import WebPushSubscription
        subs = list(WebPushSubscription.objects.filter(user_id=user_id, is_active=True))
        if not subs:
            return 0

        payload = json.dumps({
            'title': title,
            'message': message,
            'url': url,
            'notification_type': notification_type,
            'tag': f'sc-{notification_type}-{user_id}',
            'icon': '/static/logo.png',
        })

        sent = 0
        fail_threshold = 5
        for sub in subs:
            ok, error_text, status_code = PushNotificationService.send_webpush(sub, json.loads(payload), ttl=3600)
            if ok:
                sent += 1
                sub.last_used_at = timezone.now()
                sub.last_success_at = timezone.now()
                sub.fail_count = 0
                sub.last_error = ''
                sub.is_active = True
                sub.save(update_fields=['last_used_at', 'last_success_at', 'fail_count', 'is_active', 'last_error', 'updated_at'])
            else:
                sub.last_error = error_text
                if status_code in (404, 410):
                    sub.is_active = False
                    sub.save(update_fields=['is_active', 'last_error', 'updated_at'])
                else:
                    sub.fail_count = (sub.fail_count or 0) + 1
                    if sub.fail_count >= fail_threshold:
                        sub.is_active = False
                    sub.save(update_fields=['fail_count', 'is_active', 'last_error', 'updated_at'])

        return sent

    @staticmethod
    def send_push(user_id, title, message, url=None, notification_type='info'):
        from api.core.models import Notification
        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
            Notification.objects.create(
                user=user,
                title=title,
                message=message,
                url=url,
                notification_type=notification_type,
            )
            unread_count = Notification.objects.filter(user=user, is_read=False).count()

            if PushNotificationService._is_user_online(user_id):
                PushNotificationService._send_ws(user_id, title, message, url, notification_type, unread_count)
            else:
                PushNotificationService._send_webpush_notification(
                    user_id=user_id,
                    title=title,
                    message=message,
                    url=url,
                    notification_type=notification_type,
                )
            return True
        except Exception as e:
            logger.error(f"Failed to send push for user {user_id}: {e}")
            return False

    @staticmethod
    def broadcast_admin(title, message, url=None, notification_type='info'):
        from api.core.models import Notification
        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            admins = User.objects.filter(is_staff=True, is_active=True)
            Notification.objects.bulk_create([
                Notification(user=admin, title=title, message=message, url=url, notification_type=notification_type)
                for admin in admins
            ])

            for admin in admins:
                unread_count = Notification.objects.filter(user=admin, is_read=False).count()
                if PushNotificationService._is_user_online(admin.id):
                    PushNotificationService._send_ws(admin.id, title, message, url, notification_type, unread_count)
                else:
                    PushNotificationService._send_webpush_notification(admin.id, title, message, url, notification_type)
            return True
        except Exception as e:
            logger.error(f"Failed to broadcast admin push: {e}")
            return False

    @staticmethod
    def broadcast_all(title, message, url=None, notification_type='info'):
        from api.core.models import Notification
        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            users = User.objects.filter(is_active=True)
            Notification.objects.bulk_create([
                Notification(user=u, title=title, message=message, url=url, notification_type=notification_type)
                for u in users
            ])

            for u in users:
                unread_count = Notification.objects.filter(user=u, is_read=False).count()
                if PushNotificationService._is_user_online(u.id):
                    PushNotificationService._send_ws(u.id, title, message, url, notification_type, unread_count)
                else:
                    PushNotificationService._send_webpush_notification(u.id, title, message, url, notification_type)
            return users.count()
        except Exception as e:
            logger.error(f"Failed to broadcast to all: {e}")
            return 0

    @staticmethod
    def send_rag_status_update(status, message, count=None, error=None):
        channel_layer = get_channel_layer()
        if channel_layer:
            async_to_sync(channel_layer.group_send)("rag_updates", {
                'type': 'rag_status_update',
                'status': status,
                'message': message,
                'count': count,
                'error': error,
            })
            return True
        return False

    @staticmethod
    def push_unread_count(user_id):
        from api.core.models import Notification

        unread_count = Notification.objects.filter(user_id=user_id, is_read=False).count()
        channel_layer = get_channel_layer()
        if channel_layer:
            async_to_sync(channel_layer.group_send)(f"user_{user_id}", {
                'type': 'user_unread_count',
                'unread_count': unread_count,
            })
            return True
        return False


push_service = PushNotificationService()
