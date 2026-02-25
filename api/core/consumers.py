import json
from channels.generic.websocket import AsyncWebsocketConsumer

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
