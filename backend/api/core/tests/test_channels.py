import json
from django.test import TransactionTestCase
from django.contrib.auth import get_user_model
from rest_framework.authtoken.models import Token
from channels.testing import WebsocketCommunicator
from PKV.asgi import application

User = get_user_model()


class ChannelsAuthTests(TransactionTestCase):
    async def test_anonymous_websocket_closes_cleanly(self):
        comm = WebsocketCommunicator(application, "/ws/notifications/")
        connected, _ = await comm.connect()
        self.assertTrue(connected)
        output = await comm.receive_output()
        self.assertEqual(output.get("type"), "websocket.close")
        self.assertEqual(output.get("code"), 4401)
        await comm.disconnect()

    async def test_token_websocket_authenticates_and_receives_unread(self):
        user = await User.objects.acreate(username="ws_user", email="ws@example.com")
        token = await Token.objects.acreate(user=user)

        comm = WebsocketCommunicator(application, f"/ws/notifications/?token={token.key}")
        connected, _ = await comm.connect()
        self.assertTrue(connected)

        msg = await comm.receive_json_from()
        self.assertEqual(msg.get("type"), "notification_count")
        self.assertIn("unread_count", msg)
        await comm.disconnect()
