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
    def _is_user_online(user_id):
        """Check if a user has an active WebSocket connection via cache flag."""
        from django.core.cache import cache
        return cache.get(f"ws_online_{user_id}", False)

    @staticmethod
    def send_push(user_id, title, message, url=None, notification_type='info'):
        """
        Sends a notification with hybrid delivery:
        - Online users (WebSocket connected) → deliver via WebSocket only
        - Offline users → deliver via OneSignal only
        DB record is always created for history.
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

            online = PushNotificationService._is_user_online(user_id)

            if online:
                # User is on the site — deliver via WebSocket only
                channel_layer = get_channel_layer()
                if channel_layer:
                    async_to_sync(channel_layer.group_send)(f"user_{user_id}", {
                        'type': 'user_notification',
                        'title': title,
                        'message': message,
                        'url': url,
                        'notification_type': notification_type,
                    })
                logger.debug(f"Push to user {user_id} via WebSocket (online)")
            else:
                # User is offline — deliver via OneSignal
                try:
                    profile = user.profile
                    if profile.onesignal_player_id:
                        PushNotificationService._send_onesignal_notification(
                            [profile.onesignal_player_id], title, message, url
                        )
                except Exception as e:
                    logger.error(f"OneSignal delivery failed for user {user_id}: {e}")
                logger.debug(f"Push to user {user_id} via OneSignal (offline)")
                
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
            
            # 2. Hybrid delivery: WS for online admins, OneSignal for offline
            from django.core.cache import cache
            channel_layer = get_channel_layer()
            offline_player_ids = []

            for admin in admins:
                if cache.get(f"ws_online_{admin.id}", False):
                    # Online — deliver via WebSocket
                    if channel_layer:
                        try:
                            async_to_sync(channel_layer.group_send)(f"user_{admin.id}", {
                                'type': 'user_notification',
                                'title': title,
                                'message': message,
                                'url': url,
                                'notification_type': notification_type,
                            })
                        except Exception:
                            pass
                else:
                    # Offline — collect for OneSignal
                    try:
                        pid = admin.profile.onesignal_player_id
                        if pid:
                            offline_player_ids.append(pid)
                    except Exception:
                        pass

            if offline_player_ids:
                PushNotificationService._send_onesignal_notification(offline_player_ids, title, message, url)
            
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
    def broadcast_all(title, message, url=None, notification_type='info'):
        """
        Broadcasts a notification to ALL users.
        Creates Notification records and sends via OneSignal + WebSocket.
        Returns the number of users notified.
        """
        from api.core.models import Notification
        from django.contrib.auth import get_user_model
        User = get_user_model()
        
        try:
            users = User.objects.filter(is_active=True)
            notifications = [
                Notification(
                    user=u, title=title, message=message, url=url, notification_type=notification_type
                ) for u in users
            ]
            Notification.objects.bulk_create(notifications)
            
            # Hybrid delivery: WebSocket for online users, OneSignal for offline
            from django.core.cache import cache
            channel_layer = get_channel_layer()

            online_ids = set()
            offline_users_with_player = []

            for u in users:
                if cache.get(f"ws_online_{u.id}", False):
                    online_ids.add(u.id)
                    # Send via WebSocket
                    if channel_layer:
                        try:
                            async_to_sync(channel_layer.group_send)(f"user_{u.id}", {
                                'type': 'user_notification',
                                'title': title,
                                'message': message,
                                'url': url,
                                'notification_type': notification_type,
                            })
                        except Exception:
                            pass
                else:
                    # Collect for OneSignal batch
                    try:
                        pid = u.profile.onesignal_player_id
                        if pid:
                            offline_users_with_player.append(pid)
                    except Exception:
                        pass

            # OneSignal batch for offline users only
            if offline_users_with_player:
                for i in range(0, len(offline_users_with_player), 2000):
                    batch = offline_users_with_player[i:i+2000]
                    PushNotificationService._send_onesignal_notification(batch, title, message, url)

            logger.info(f"Broadcast: {len(online_ids)} via WS, {len(offline_users_with_player)} via OneSignal")
            
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
                'error': error
            })
            return True
        return False

push_service = PushNotificationService()
