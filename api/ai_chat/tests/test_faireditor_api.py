import json
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase
from django.contrib.auth import get_user_model

User = get_user_model()

class FairEditorAPITests(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='password123')
        self.url = reverse('faireditor-analyze')

    def test_unauthenticated_access(self):
        """Ensure unauthenticated users cannot access the API."""
        response = self.client.post(self.url, {'text': 'Hello'})
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_authenticated_analyze_bias(self):
        """Test analysis with mock authenticated user."""
        self.client.force_authenticate(user=self.user)
        # Mocking generate_response would be better, but we test the view logic
        data = {'text': 'Nam lập trình viên là người giỏi nhất.'}
        response = self.client.post(self.url, data)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        res_data = response.json()
        self.assertIn('inclusiveScore', res_data)
        self.assertIn('biasDetected', res_data)
        self.assertIn('suggestedText', res_data)

    def test_empty_text(self):
        """Test with empty text."""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.url, {'text': ''})
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_recruitment_context_detection(self):
        """Test if recruitment context is detected."""
        self.client.force_authenticate(user=self.user)
        response = self.client.post(self.url, {'text': 'Tuyển dụng nhân sự chuyên nghiệp.'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.json().get('context'), 'recruitment')
