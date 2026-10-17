import json
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async

# Server-side ping interval in seconds — must be shorter than Cloudflare Tunnel's
# proxy-connection-timeout (default 90s) AND the CF edge idle detection (~30s).
# 15s gives a comfortable margin even if a ping is occasionally delayed.
WS_PING_INTERVAL = 15


class ScanProgressConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.group_name = f'scan_{self.scan_id}'
        self._ping_task = None
        self._intentional_close = False

        # Chống IDOR: chỉ chủ sở hữu (user/phiên ẩn danh), staff, hoặc scan
        # được đánh dấu công khai mới được xem tiến trình/kết quả. Trước đây
        # consumer nhận MỌI scan_id -> rò rỉ kết quả quét của người khác.
        if not await self._authorized():
            await self.close()
            return

        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        self._ping_task = asyncio.ensure_future(self._heartbeat())

    @database_sync_to_async
    def _authorized(self):
        from api.core.models import ScanEvent
        try:
            event = ScanEvent.objects.get(id=self.scan_id)
        except (ScanEvent.DoesNotExist, ValueError, TypeError):
            return False
        user = self.scope.get('user')
        session = self.scope.get('session')
        if getattr(user, 'is_staff', False):
            return True
        if getattr(user, 'is_authenticated', False) and event.user_id == user.id:
            return True
        if event.is_public_referable:
            return True
        active = session.get('active_scan_ids', []) if session is not None else []
        return self.scan_id in active or str(self.scan_id) in [str(x) for x in (active or [])]

    async def disconnect(self, close_code):
        self._intentional_close = True
        if self._ping_task:
            self._ping_task.cancel()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def _heartbeat(self):
        """Send a server-side ping every WS_PING_INTERVAL seconds to prevent
        proxy timeouts. Client-side handler filters these out via step != 'ping'."""
        try:
            while True:
                await asyncio.sleep(WS_PING_INTERVAL)
                await self.send(text_data=json.dumps({'type': 'ping', 'step': 'ping'}))
        except asyncio.CancelledError:
            pass
        except Exception:
            pass

    async def receive(self, text_data=None, bytes_data=None):
        """Handle client messages — ping keepalive and status requests."""
        if not text_data:
            return
        try:
            msg = json.loads(text_data)
            if msg.get('type') == 'ping':
                await self.send(text_data=json.dumps({'type': 'pong'}))
            elif msg.get('type') == 'get_status':
                status_data = await self._get_scan_status()
                await self.send(text_data=json.dumps(status_data))
        except json.JSONDecodeError:
            pass

    @database_sync_to_async
    def _get_scan_status(self):
        """Query DB for current scan status and return a scan_progress-compatible payload."""
        try:
            from api.core.models import ScanEvent, ScanStatus
            event = ScanEvent.objects.get(id=self.scan_id)
            if event.status == ScanStatus.COMPLETED:
                return {
                    'message': 'Hoàn tất: kết quả khôi phục từ máy chủ.',
                    'status': 'completed',
                    'step': 'completed',
                    'data': event.result_json,
                }
            elif event.status == ScanStatus.FAILED:
                return {
                    'message': (
                        event.result_json.get('error', 'Phiên quét thất bại.')
                        if isinstance(event.result_json, dict)
                        else 'Phiên quét thất bại.'
                    ),
                    'status': 'failed',
                    'step': 'error',
                    'data': None,
                }
            else:
                return {
                    'message': f'Đang xử lý (trạng thái: {event.status})...',
                    'status': event.status,
                    'step': 'processing',
                    'data': None,
                }
        except Exception:
            return {
                'message': 'Không tìm thấy phiên quét.',
                'status': 'unknown',
                'step': 'error',
                'data': None,
            }

    async def scan_progress(self, event):
        await self.send(text_data=json.dumps({
            'message': event['message'],
            'status': event.get('status'),
            'step': event.get('step'),
            'data': event.get('data'),
        }))


class RagStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        user = self.scope.get('user')
        if not user or not user.is_authenticated or not user.is_staff:
            await self.close()
            return

        self.group_name = 'rag_updates'
        self._ping_task = None
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        self._ping_task = asyncio.ensure_future(self._heartbeat())

    async def disconnect(self, close_code):
        if self._ping_task:
            self._ping_task.cancel()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def _heartbeat(self):
        try:
            while True:
                await asyncio.sleep(WS_PING_INTERVAL)
                await self.send(text_data=json.dumps({'type': 'ping'}))
        except (asyncio.CancelledError, Exception):
            pass

    async def rag_status_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'rag_status',
            'status': event['status'],
            'message': event['message'],
            'count': event.get('count'),
            'error': event.get('error'),
        }))


class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        self._ping_task = None
        if not self.user.is_authenticated:
            await self.close()
            return

        self.user_group = f'user_{self.user.id}'
        await self.channel_layer.group_add(self.user_group, self.channel_name)

        if self.user.is_staff:
            await self.channel_layer.group_add('admin_notifications', self.channel_name)

        await self._set_online(True)
        await self.accept()
        self._ping_task = asyncio.ensure_future(self._heartbeat())

        unread_count = await self._get_unread_count()
        await self.send(text_data=json.dumps({
            'type': 'notification_count',
            'unread_count': unread_count,
        }))

    async def disconnect(self, close_code):
        if self._ping_task:
            self._ping_task.cancel()
        if self.user.is_authenticated:
            await self.channel_layer.group_discard(self.user_group, self.channel_name)
            if self.user.is_staff:
                await self.channel_layer.group_discard('admin_notifications', self.channel_name)
            await self._set_online(False)

    async def _heartbeat(self):
        try:
            while True:
                await asyncio.sleep(WS_PING_INTERVAL)
                await self.send(text_data=json.dumps({'type': 'ping'}))
        except (asyncio.CancelledError, Exception):
            pass

    @database_sync_to_async
    def _set_online(self, online):
        from django.core.cache import cache
        key = f'ws_online_{self.user.id}'
        if online:
            cache.set(key, True, timeout=None)
        else:
            cache.delete(key)

    @database_sync_to_async
    def _get_unread_count(self):
        from api.core.models import Notification
        return Notification.objects.filter(user=self.user, is_read=False).count()

    async def user_notification(self, event):
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'title': event['title'],
            'message': event['message'],
            'url': event.get('url'),
            'notification_type': event.get('notification_type', 'info'),
            'unread_count': event.get('unread_count'),
        }))

    async def user_unread_count(self, event):
        await self.send(text_data=json.dumps({
            'type': 'notification_count',
            'unread_count': event.get('unread_count', 0),
        }))


class TaskProgressConsumer(AsyncWebsocketConsumer):
    """Generic task progress consumer for Celery tasks (e.g. Magic Create)."""

    async def connect(self):
        self.task_id = self.scope['url_route']['kwargs']['task_id']
        self.group_name = f'task_{self.task_id}'
        self._ping_task = None
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        self._ping_task = asyncio.ensure_future(self._heartbeat())

    async def disconnect(self, close_code):
        if self._ping_task:
            self._ping_task.cancel()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def _heartbeat(self):
        try:
            while True:
                await asyncio.sleep(WS_PING_INTERVAL)
                await self.send(text_data=json.dumps({'type': 'ping', 'step': 'ping'}))
        except (asyncio.CancelledError, Exception):
            pass

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            msg = json.loads(text_data)
            if msg.get('type') == 'ping':
                await self.send(text_data=json.dumps({'type': 'pong'}))
        except json.JSONDecodeError:
            pass

    async def task_progress(self, event):
        await self.send(text_data=json.dumps({
            'type': event.get('type', 'task_progress'),
            'status': event.get('status'),
            'message': event.get('message', ''),
            'step': event.get('step'),
            'data': event.get('data'),
        }))


class ForumLiveConsumer(AsyncWebsocketConsumer):
    """Realtime forum broadcast channel for new posts/comments."""

    async def connect(self):
        self.group_name = 'forum_live'
        self._ping_task = None
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()
        self._ping_task = asyncio.ensure_future(self._heartbeat())

    async def disconnect(self, close_code):
        if self._ping_task:
            self._ping_task.cancel()
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def _heartbeat(self):
        try:
            while True:
                await asyncio.sleep(WS_PING_INTERVAL)
                await self.send(text_data=json.dumps({'type': 'ping'}))
        except (asyncio.CancelledError, Exception):
            pass

    async def receive(self, text_data=None, bytes_data=None):
        if not text_data:
            return
        try:
            msg = json.loads(text_data)
            if msg.get('type') == 'ping':
                await self.send(text_data=json.dumps({'type': 'pong'}))
        except json.JSONDecodeError:
            pass

    async def forum_live_event(self, event):
        await self.send(text_data=json.dumps({
            'type': 'forum_live_event',
            'event': event.get('event'),
            'payload': event.get('payload', {}),
            'timestamp': event.get('timestamp'),
        }))
