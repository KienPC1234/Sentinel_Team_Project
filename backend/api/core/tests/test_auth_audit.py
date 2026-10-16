"""Tests cho audit auth/2FA: logout GET, xoay token, OTP rate limit, TOTP guard."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from django.test import TestCase

User = get_user_model()


class LogoutMethodTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='auth_logout', password='x'*10)
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_logout_get_rejected(self):
        resp = self.client.get('/api/v1/auth/logout/')
        self.assertEqual(resp.status_code, 405)

    def test_logout_post_ok(self):
        resp = self.client.post('/api/v1/auth/logout/')
        self.assertEqual(resp.status_code, 200)


class PasswordChangeRotationTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username='auth_pwd', password='Oldpass123')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        from django_otp.plugins.otp_email.models import EmailDevice
        self.device = EmailDevice.objects.create(
            user=self.user, name='default', email=self.user.email, confirmed=True)

    def test_password_change_rotates_token(self):
        old_token, _ = Token.objects.get_or_create(user=self.user)
        old_key = old_token.key
        # Luong that: GET setup/email de nhan OTP nhu frontend ChangePassword
        sent = self.client.get('/api/v1/auth/mfa/setup/email/')
        self.assertEqual(sent.status_code, 200)
        from django_otp.plugins.otp_email.models import EmailDevice as ED
        dev = ED.objects.get(user=self.user, name='default')
        real_token = dev.token
        self.assertTrue(real_token)
        resp = self.client.post('/api/v1/auth/password/change/', {
            'old_password': 'Oldpass123',
            'new_password': 'Newpass456',
            'token': real_token,
        }, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('token', resp.data)
        self.assertNotEqual(resp.data['token'], old_key)
        self.assertFalse(Token.objects.filter(key=old_key).exists())


class EmailChangeRateLimitTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username='auth_email', password='Oldpass123', email='a@x.vn')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_otp_send_capped_per_hour(self):
        ok_count = 0
        for i in range(7):
            resp = self.client.post('/api/v1/auth/email-change/request/', {
                'password': 'Oldpass123',
                'new_email': f'new{i}@x.vn',
            }, format='json')
            if resp.status_code == 200:
                ok_count += 1
        # Moi email khac nhau nhung cung user -> bi chan sau 5 lan
        self.assertLessEqual(ok_count, 5)
        last = self.client.post('/api/v1/auth/email-change/request/', {
            'password': 'Oldpass123',
            'new_email': 'blocked@x.vn',
        }, format='json')
        self.assertEqual(last.status_code, 429)
