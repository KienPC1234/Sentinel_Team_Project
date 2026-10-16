"""Regression coverage for cross-session access in the AI streaming endpoint."""
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

User = get_user_model()

class GuestStreamAuthorizationTests(APITestCase):
    def setUp(self):
        self.owner = APIClient()
        self.stranger = APIClient()
        r = self.owner.post(reverse("chat-sessions"), {}, format="json")
        self.assertEqual(r.status_code, status.HTTP_201_CREATED)
        self.session_id = r.data["id"]
        self.url = reverse("chat-stream")

    def test_anonymous_stranger_cannot_stream_other_guest_session(self):
        r = self.stranger.post(self.url, {
            "session_id": self.session_id,
            "user_message": "test",
        }, format="json")
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_logged_in_stranger_cannot_stream_other_guest_session(self):
        account = User.objects.create_user(username="stranger_stream_test", password="test_only_password")
        self.stranger.force_authenticate(user=account)
        r = self.stranger.post(self.url, {
            "session_id": self.session_id,
            "user_message": "test",
        }, format="json")
        self.assertEqual(r.status_code, status.HTTP_403_FORBIDDEN)

    def test_invalid_session_id_is_bad_request(self):
        r = self.stranger.post(self.url, {
            "session_id": "invalid-not-uuid",
            "user_message": "test",
        }, format="json")
        self.assertEqual(r.status_code, status.HTTP_400_BAD_REQUEST)

    def test_missing_session_is_not_found(self):
        r = self.stranger.post(self.url, {
            "session_id": "00000000-0000-4000-8000-000000000001",
            "user_message": "test",
        }, format="json")
        self.assertEqual(r.status_code, status.HTTP_404_NOT_FOUND)
