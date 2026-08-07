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
            admin_ids = list(
                admins.exclude(profile__onesignal_player_id__isnull=True)
                      .exclude(profile__onesignal_player_id='')
                      .values_list('profile__onesignal_player_id', flat=True)
            )
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
    def _send_onesignal_notification(subscription_ids, title, message, url=None):
        """
        Internal helper to call OneSignal REST API.
        Uses include_subscription_ids (v16 SDK) with target_channel=push.
        Docs: https://documentation.onesignal.com/reference/create-notification
        """
        app_id = getattr(settings, 'ONESIGNAL_APP_ID', None)
        api_key = getattr(settings, 'ONESIGNAL_REST_API_KEY', None)
        
        if not app_id or not api_key or api_key == "YOUR_REST_API_KEY_HERE":
            logger.warning("OneSignal not configured properly. Skipping REST API call.")
            return

        # Filter out empty/None IDs
        valid_ids = [sid for sid in subscription_ids if sid]
        if not valid_ids:
            logger.warning("OneSignal: No valid subscription IDs to send to.")
            return

        header = {
            "Content-Type": "application/json; charset=utf-8",
            "Authorization": f"Key {api_key}"
        }

        payload = {
            "app_id": app_id,
            "include_subscription_ids": valid_ids,
            "target_channel": "push",
            "headings": {"en": title},
            "contents": {"en": message},
        }
        if url:
            # OneSignal requires absolute URLs
            if url.startswith('/'):
                site_url = getattr(settings, 'SITE_URL', '').rstrip('/')
                if not site_url:
                    # Derive from CSRF_TRUSTED_ORIGINS if SITE_URL not set
                    origins = getattr(settings, 'CSRF_TRUSTED_ORIGINS', [])
                    site_url = origins[0].rstrip('/') if origins else 'https://cs.fptoj.com'
                url = site_url + url
            payload["web_url"] = url

        try:
            resp = requests.post(
                "https://api.onesignal.com/notifications?c=push",
                headers=header,
                data=json.dumps(payload),
                timeout=10
            )
            resp_data = resp.json() if resp.status_code < 500 else resp.text
            
            if resp.status_code == 200:
                logger.info(f"OneSignal push sent OK: {resp_data}")
            else:
                logger.error(f"OneSignal API error {resp.status_code}: {resp_data}")
                
            # Log any invalid IDs returned by OneSignal for cleanup
            if isinstance(resp_data, dict):
                errors = resp_data.get('errors', {})
                if isinstance(errors, dict):
                    invalid_ids = errors.get('invalid_player_ids', []) or errors.get('invalid_aliases', {})
                    if invalid_ids:
                        logger.warning(f"OneSignal invalid IDs detected: {invalid_ids}")
                elif isinstance(errors, list) and errors:
                    logger.warning(f"OneSignal errors: {errors}")
        except requests.exceptions.Timeout:
            logger.error("OneSignal API request timed out")
        except Exception as e:
            logger.error(f"OneSignal API request failed: {e}")

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
