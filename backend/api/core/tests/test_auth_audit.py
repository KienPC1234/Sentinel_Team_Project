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


class MFAEmailAndOtpHardeningTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username='mfa_hard', password='Oldpass123', email='mfa@x.vn')
        self.client = APIClient()

    def test_setup_email_get_does_not_confirm_device(self):
        self.client.force_authenticate(user=self.user)
        resp = self.client.get('/api/v1/auth/mfa/setup/email/')
        self.assertEqual(resp.status_code, 200)
        from django_otp.plugins.otp_email.models import EmailDevice
        from django_otp import user_has_device
        dev = EmailDevice.objects.get(user=self.user, name='default')
        self.assertFalse(dev.confirmed)
        self.assertFalse(user_has_device(self.user, confirmed=True))

        # Verify POST confirms device (test valid confirmation cleanly; wrong OTP tested in lockout test)
        dev.refresh_from_db()
        ok_post = self.client.post('/api/v1/auth/mfa/setup/email/', {'token': dev.token}, format='json')
        self.assertEqual(ok_post.status_code, 200)
        self.assertTrue(user_has_device(self.user, confirmed=True))

    def test_setup_email_blocks_unconfirmed_session_hijack_and_unauth_post(self):
        sess = self.client.session
        sess['mfa_user_id'] = self.user.id
        sess.save()
        get_resp = self.client.get('/api/v1/auth/mfa/setup/email/')
        self.assertEqual(get_resp.status_code, 403)
        post_resp = self.client.post('/api/v1/auth/mfa/setup/email/', {'token': '123456'}, format='json')
        self.assertIn(post_resp.status_code, (401, 403))

    def test_password_change_and_deactivate_otp_lockout(self):
        from api.core.otp_guard import OTP_MAX_VERIFY_FAILS
        from django_otp.plugins.otp_email.models import EmailDevice
        EmailDevice.objects.create(
            user=self.user, name='default', email=self.user.email, confirmed=True)
        self.client.force_authenticate(user=self.user)
        self.client.get('/api/v1/auth/mfa/setup/email/')

        for _ in range(OTP_MAX_VERIFY_FAILS):
            r = self.client.post('/api/v1/auth/password/change/', {
                'old_password': 'Oldpass123',
                'new_password': 'Newpass456',
                'token': '999999',
            }, format='json')
            self.assertEqual(r.status_code, 400)
        locked = self.client.post('/api/v1/auth/password/change/', {
            'old_password': 'Oldpass123',
            'new_password': 'Newpass456',
            'token': '999999',
        }, format='json')
        self.assertEqual(locked.status_code, 429)

        cache.clear()
        for _ in range(OTP_MAX_VERIFY_FAILS):
            r = self.client.post('/api/v1/auth/mfa/deactivate/', {
                'password': 'Oldpass123',
                'token': '999999',
                'method': 'email',
            }, format='json')
            self.assertEqual(r.status_code, 400)
        deact_locked = self.client.post('/api/v1/auth/mfa/deactivate/', {
            'password': 'Oldpass123',
            'token': '999999',
            'method': 'email',
        }, format='json')
        self.assertEqual(deact_locked.status_code, 429)


class AccountControlsAndUserDataTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(
            username='data_owner', password='Oldpass123', email='owner@x.vn')
        self.other = User.objects.create_user(
            username='other_user', password='Oldpass123', email='other@x.vn')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_me_includes_has_usable_password_and_total_posts(self):
        from api.core.models import ForumPost
        ForumPost.objects.create(author=self.user, title='Canh bao', content='Noi dung test')
        resp = self.client.get('/api/v1/auth/me/')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['user']['has_usable_password'])
        self.assertEqual(resp.data['stats']['total_posts'], 1)

        self.user.set_unusable_password()
        self.user.save(update_fields=['password'])
        oauth_me = self.client.get('/api/v1/auth/me/')
        self.assertFalse(oauth_me.data['user']['has_usable_password'])

    def test_delete_account_vietnamese_confirmation_and_oauth_user(self):
        oauth_user = User.objects.create_user(username='oauth_del', email='oauth@x.vn')
        oauth_user.set_unusable_password()
        oauth_user.save(update_fields=['password'])
        c = APIClient()
        c.force_authenticate(user=oauth_user)
        resp = c.post('/api/v1/auth/account/delete/', {
            'confirmation_text': 'XÓA TÀI KHOẢN',
        }, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(User.objects.filter(id=oauth_user.id).exists())

    def test_password_reset_confirm_revokes_existing_tokens(self):
        from allauth.account.forms import EmailAwarePasswordResetTokenGenerator
        from allauth.account.utils import user_pk_to_url_str
        old_token, _ = Token.objects.get_or_create(user=self.user)
        uid = user_pk_to_url_str(self.user)
        key = EmailAwarePasswordResetTokenGenerator().make_token(self.user)
        anon = APIClient()
        resp = anon.post('/api/v1/auth/password/reset/confirm/', {
            'uid': uid,
            'token': key,
            'password1': 'ResetPass789!',
            'password2': 'ResetPass789!',
        }, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Token.objects.filter(key=old_token.key).exists())
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password('ResetPass789!'))

    def test_user_scan_patch_export_and_alert_delete(self):
        import json
        from api.core.models import ScanEvent, UserAlert
        scan = ScanEvent.objects.create(
            user=self.user, scan_type='phone', raw_input='0901234567',
            normalized_input='0901234567', risk_score=80, risk_level='RED',
            is_public_referable=False,
        )
        alert = UserAlert.objects.create(
            user=self.user, target_type='phone', target_value='0901234567', risk_level='RED',
        )

        # Owner can toggle is_public_referable; other user cannot
        patch_ok = self.client.patch(
            f'/api/v1/user/scans/{scan.id}/', {'is_public_referable': True}, format='json')
        self.assertEqual(patch_ok.status_code, 200)
        self.assertTrue(patch_ok.data['is_public_referable'])
        scan.refresh_from_db()
        self.assertTrue(scan.is_public_referable)

        other_client = APIClient()
        other_client.force_authenticate(user=self.other)
        patch_forbidden = other_client.patch(
            f'/api/v1/user/scans/{scan.id}/', {'is_public_referable': False}, format='json')
        self.assertEqual(patch_forbidden.status_code, 403)

        # Export personal data JSON
        export_resp = self.client.get('/api/v1/user/privacy/export-data/')
        self.assertEqual(export_resp.status_code, 200)
        self.assertIn('attachment;', export_resp.get('Content-Disposition', ''))
        payload = json.loads(export_resp.content.decode('utf-8'))
        self.assertEqual(payload['account']['username'], 'data_owner')
        self.assertEqual(len(payload['scans']), 1)
        self.assertEqual(len(payload['alerts']), 1)

        # Delete alert via query param
        del_resp = self.client.delete(f'/api/v1/user/alerts/?id={alert.id}')
        self.assertEqual(del_resp.status_code, 200)
        self.assertEqual(del_resp.data['deleted_id'], alert.id)
        self.assertFalse(UserAlert.objects.filter(id=alert.id).exists())
