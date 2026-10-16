"""Regression tests: no chat transcript disclosure by guessing a guest UUID."""
from django.contrib.auth import get_user_model
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient, APITestCase

from api.ai_chat.models import ChatSession

User = get_user_model()


class GuestSessionOwnershipTests(APITestCase):
    def setUp(self):
        self.owner = APIClient()
        self.stranger = APIClient()
        created = self.owner.post(reverse("chat-sessions"), {}, format="json")
        self.assertEqual(created.status_code, status.HTTP_201_CREATED)
        self.session_id = created.data["id"]
        self.url = reverse("chat-session-detail", args=[self.session_id])

    def test_owner_can_read_guest_session(self):
        response = self.owner.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_stranger_cannot_read_guest_session_or_adopt_cookie(self):
        response = self.stranger.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertNotIn(
            self.session_id, self.stranger.session.get("guest_chat_sessions", [])
        )

    def test_guest_owner_can_update_title(self):
        response = self.owner.patch(
            self.url, {"title": "Updated by owner"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(
            ChatSession.objects.get(pk=self.session_id).title,
            "Updated by owner",
        )

    def test_stranger_cannot_patch_guest_session(self):
        response = self.stranger.patch(
            self.url, {"title": "Hijacked"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertNotEqual(ChatSession.objects.get(pk=self.session_id).title, "Hijacked")

    def test_logged_in_stranger_cannot_claim_other_guest_session(self):
        logged_in = APIClient()
        account = User.objects.create_user(
            username="stranger_guest_test", password="test_password_not_production"
        )
        logged_in.force_authenticate(user=account)
        response = logged_in.get(self.url)
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        response = logged_in.patch(
            self.url, {"title": "Claim attempt"}, format="json"
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertIsNone(ChatSession.objects.get(pk=self.session_id).user_id)
