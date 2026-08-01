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
        message = event['message']
        status = event.get('status')
        step = event.get('step')
        data = event.get('data')

        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'message': message,
            'status': status,
            'step': step,
            'data': data
        }))
