import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async


class ScanProgressConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.group_name = f'scan_{self.scan_id}'

        # Join group
        await self.channel_layer.group_add(
            self.group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave group
        await self.channel_layer.group_discard(
            self.group_name,
            self.channel_name
        )

    async def receive(self, text_data=None, bytes_data=None):
        """Handle client messages — ping keepalive and status requests."""
        if text_data:
            try:
                msg = json.loads(text_data)
                if msg.get('type') == 'ping':
                    await self.send(text_data=json.dumps({'type': 'pong'}))
                elif msg.get('type') == 'get_status':
                    # Client is asking for current scan state (e.g. after reconnect)
                    status_data = await self._get_scan_status()
                    await self.send(text_data=json.dumps(status_data))
            except json.JSONDecodeError:
                pass

    @database_sync_to_async
    def _get_scan_status(self):
        """Query DB for current scan status and return it in the same
        format as a scan_progress WS message so the client can handle
        it with the same onmessage logic."""
        try:
            from api.core.models import ScanEvent, ScanStatus
            event = ScanEvent.objects.get(id=self.scan_id)
            if event.status == ScanStatus.COMPLETED:
                return {
                    'message': 'Hoàn tất — kết quả khôi phục từ máy chủ.',
                    'status': 'completed',
                    'step': 'completed',
                    'data': event.result_json,
                }
            elif event.status == ScanStatus.FAILED:
                return {
                    'message': event.result_json.get('error', 'Phiên quét thất bại.') if isinstance(event.result_json, dict) else 'Phiên quét thất bại.',
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

    # Receive message from room group
    async def scan_progress(self, event):
        # ... (reuse existing logic)
        await self.send(text_data=json.dumps({
            'message': event['message'],
            'status': event.get('status'),
            'step': event.get('step'),
            'data': event.get('data')
        }))

class RagStatusConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Check if user is authenticated and is staff
        user = self.scope.get('user')
        if not user or not user.is_authenticated or not user.is_staff:
            await self.close()
            return

        self.group_name = 'rag_updates'
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def rag_status_update(self, event):
        await self.send(text_data=json.dumps({
            'type': 'rag_status',
            'status': event['status'],
            'message': event['message'],
            'count': event.get('count'),
            'error': event.get('error')
        }))

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope["user"]
        if self.user.is_authenticated:
            self.user_group = f"user_{self.user.id}"
            await self.channel_layer.group_add(self.user_group, self.channel_name)
            
            # Admins also join a shared admin group
            if self.user.is_staff:
                await self.channel_layer.group_add("admin_notifications", self.channel_name)
                
            await self.accept()
        else:
            await self.close()

    async def disconnect(self, close_code):
        if self.user.is_authenticated:
            await self.channel_layer.group_discard(self.user_group, self.channel_name)
            if self.user.is_staff:
                await self.channel_layer.group_discard("admin_notifications", self.channel_name)

    async def user_notification(self, event):
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'title': event['title'],
            'message': event['message'],
            'url': event.get('url'),
            'notification_type': event.get('notification_type', 'info')
        }))


class TaskProgressConsumer(AsyncWebsocketConsumer):
    """Generic task progress consumer for Celery tasks (e.g. Magic Create)."""
    async def connect(self):
        self.task_id = self.scope['url_route']['kwargs']['task_id']
        self.group_name = f'task_{self.task_id}'
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)

    async def receive(self, text_data=None, bytes_data=None):
        """Handle client messages — ping keepalive."""
        if text_data:
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
