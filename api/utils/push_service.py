import logging
import json
import requests
from django.conf import settings
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer

logger = logging.getLogger(__name__)

class PushNotificationService:
    """
    Utility service to send push notifications.
    Supports OneSignal (External Push) and Django Channels (Internal WebSocket).
    """
    
    @staticmethod
    def send_push(user_id, title, message, url=None, notification_type='info'):
        """
        Sends a notification via OneSignal and saves it to the local DB.
        """
        from api.core.models import Notification, UserProfile
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            user = User.objects.get(id=user_id)
            # 1. Save to DB for internal history
            Notification.objects.create(
                user=user,
                title=title,
                message=message,
                url=url,
                notification_type=notification_type
            )
            
            # 2. Try OneSignal if Player ID exists
            try:
                profile = user.profile
                if profile.onesignal_player_id:
                    PushNotificationService._send_onesignal_notification(
                        [profile.onesignal_player_id], title, message, url
                    )
            except Exception as e:
                logger.error(f"OneSignal delivery failed for user {user_id}: {e}")

            # 3. Real-time delivery via WebSocket (Fallback/Secondary)
            channel_layer = get_channel_layer()
            if channel_layer:
                group_name = f"user_{user_id}"
                async_to_sync(channel_layer.group_send)(group_name, {
                    'type': 'user_notification',
                    'title': title,
                    'message': message,
                    'url': url,
                    'notification_type': notification_type,
                })
                
            return True
        except Exception as e:
            logger.error(f"Failed to send push for user {user_id}: {e}")
            return False

    @staticmethod
    def broadcast_admin(title, message, url=None, notification_type='info'):
        """
        Broadcasts to admins via OneSignal and WebSockets.
        """
        from api.core.models import Notification
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            # 1. Save to DB for each admin
            admins = User.objects.filter(is_staff=True)
            notifications = [
                Notification(
                    user=admin, title=title, message=message, url=url, notification_type=notification_type
                ) for admin in admins
            ]
            Notification.objects.bulk_create(notifications)
            
            # 2. OneSignal Broadcast to Admin segments (if configured) or specific IDs
            admin_ids = list(admins.exclude(profile__onesignal_player_id__isnull=True).values_list('profile__onesignal_player_id', flat=True))
            if admin_ids:
                PushNotificationService._send_onesignal_notification(admin_ids, title, message, url)

            # 3. WebSocket Broadcast
            channel_layer = get_channel_layer()
            if channel_layer:
                async_to_sync(channel_layer.group_send)("admin_notifications", {
                    'type': 'user_notification',
                    'title': title,
                    'message': message,
                    'url': url,
                    'notification_type': notification_type,
                })
            
            return True
        except Exception as e:
            logger.error(f"Failed to broadcast admin push: {e}")
            return False

    @staticmethod
    def _send_onesignal_notification(player_ids, title, message, url=None):
        """
        Internal helper to call OneSignal REST API.
        """
        app_id = getattr(settings, 'ONESIGNAL_APP_ID', None)
        api_key = getattr(settings, 'ONESIGNAL_REST_API_KEY', None)
        
        if not app_id or not api_key or api_key == "YOUR_REST_API_KEY_HERE":
            logger.warning("OneSignal not configured properly. Skipping REST API call.")
            return

        header = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Basic {api_key}"
        }

        payload = {
            "app_id": app_id,
            "include_player_ids": player_ids,
            "headings": {"en": title},
            "contents": {"en": message},
        }
        if url:
            payload["url"] = url

        req = requests.post("https://onesignal.com/api/v1/notifications", headers=header, data=json.dumps(payload))
        logger.info(f"OneSignal API response: {req.status_code} - {req.text}")

    @staticmethod
    def send_rag_status_update(status, message, count=None, error=None):
        channel_layer = get_channel_layer()
        if channel_layer:
            async_to_sync(channel_layer.group_send)("rag_updates", {
                'type': 'rag_status_update',
                'status': status,
                'message': message,
                'count': count,
                'error': error
            })
            return True
        return False

push_service = PushNotificationService()
