from django.urls import reverse
from unittest.mock import patch, MagicMock
from django.test import TestCase
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model
from api.ai_chat.models import ChatFolder, ChatSession

User = get_user_model()

class ChatAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='password123')
        self.folder = ChatFolder.objects.create(user=self.user, name='Chủ đề bảo mật')

    def test_unauthenticated_folders_access(self):
        """Ensure unauthenticated users cannot list folders."""
        url = reverse('chat-folders')
        response = self.client.get(url)
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN])

    def test_authenticated_create_folder(self):
        """Ensure authenticated users can create a chat folder."""
        self.client.force_authenticate(user=self.user)
        url = reverse('chat-folders')
        response = self.client.post(url, {'name': 'Phân tích mã độc'})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(ChatFolder.objects.filter(user=self.user).count(), 2)

    def test_create_and_list_sessions(self):
        """Test creating and retrieving chat sessions."""
        self.client.force_authenticate(user=self.user)
        url = reverse('chat-sessions')
        response = self.client.post(url, {'folder_id': self.folder.id})
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        session_id = response.data.get('id')
        self.assertTrue(session_id)

        get_resp = self.client.get(url)
        self.assertEqual(get_resp.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(get_resp.data), 1)

    def test_clear_all_sessions(self):
        """Test clearing all chat sessions for the user."""
        self.client.force_authenticate(user=self.user)
        ChatSession.objects.create(user=self.user, title='Session 1')
        ChatSession.objects.create(user=self.user, title='Session 2')
        url = reverse('chat-sessions-clear-all')
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(ChatSession.objects.filter(user=self.user).count(), 0)


class ChatStreamConsentTests(TestCase):
    """Hồi quy: opt-in PII (checkbox) cho khách vãng lai → agent nhận allow_pii=True.

    Không đồng ý → allow_pii=False (PII vẫn bị ẩn trước khi gửi ra ngoài).
    """

    async def _post_stream(self, payload, mock_agent):
        from django.test import AsyncClient
        mock_agent.chat_stream.return_value = iter([{'type': 'done'}])
        mock_agent.session = None
        resp = await AsyncClient().post(
            reverse('chat-stream'), data=payload, content_type='application/json')
        self.assertEqual(resp.status_code, 200)
        body = b''
        try:
            async for chunk in resp.streaming_content:
                body += chunk if isinstance(chunk, bytes) else str(chunk).encode()
        except Exception:
            pass
        self.assertIn(b'done', body)
        return mock_agent

    @patch('api.ai_chat.views.get_agent')
    @patch('api.ai_chat.views.classify_message', return_value={})
    async def test_guest_consent_enables_pii(self, _mock_classify, mock_get_agent):
        mock_agent = MagicMock()
        mock_get_agent.return_value = mock_agent
        await self._post_stream(
            {'user_message': 'Kiểm tra SĐT 0912345678 giúp tôi', 'consent_external_llm': True},
            mock_agent,
        )
        _, kwargs = mock_agent.chat_stream.call_args
        self.assertTrue(kwargs.get('allow_pii'), 'khách đã đồng ý phải được allow_pii=True')

    @patch('api.ai_chat.views.get_agent')
    @patch('api.ai_chat.views.classify_message', return_value={})
    async def test_guest_no_consent_stays_redacted(self, _mock_classify, mock_get_agent):
        mock_agent = MagicMock()
        mock_get_agent.return_value = mock_agent
        await self._post_stream({'user_message': 'Kiểm tra SĐT 0912345678 giúp tôi'}, mock_agent)
        _, kwargs = mock_agent.chat_stream.call_args
        self.assertFalse(kwargs.get('allow_pii'), 'mặc định phải ẩn PII (allow_pii=False)')

