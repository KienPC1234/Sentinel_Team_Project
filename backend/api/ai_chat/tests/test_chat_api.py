from django.urls import reverse
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

