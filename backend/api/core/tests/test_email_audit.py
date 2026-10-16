"""Tests cho audit email/SMTP: bulk rieng tung nguoi, that bai gui OTP."""
from unittest.mock import patch

from django.core import mail
from django.test import TestCase, override_settings

from api.utils import email_utils

LOC = override_settings(EMAIL_BACKEND='django.core.mail.backends.locmem.EmailBackend')


@LOC
class BulkEmailPrivacyTest(TestCase):
    def test_recipients_do_not_see_each_other(self):
        sent = email_utils.send_new_lesson_email(
            ['a@x.vn', 'b@x.vn', 'c@x.vn'], 'Bai hoc test', 'https://x/lesson/')
        self.assertEqual(sent, 3)
        self.assertEqual(len(mail.outbox), 3)
        for msg in mail.outbox:
            self.assertEqual(len(msg.to), 1)
        seen = sorted(m.to[0] for m in mail.outbox)
        self.assertEqual(seen, ['a@x.vn', 'b@x.vn', 'c@x.vn'])

    def test_invalid_addresses_skipped(self):
        sent = email_utils.send_new_lesson_email(['ok@x.vn', 'khong-phai-mail', ''], 'T', 'U')
        self.assertEqual(sent, 1)


@LOC
class OtpSendResultTest(TestCase):
    def test_returns_true_on_success(self):
        self.assertTrue(email_utils.send_html_otp_email('u@x.vn', '123456'))
        self.assertEqual(len(mail.outbox), 1)

    def test_returns_false_on_smtp_failure(self):
        with patch('api.utils.email_utils.send_mail', side_effect=Exception('smtp down')):
            self.assertFalse(email_utils.send_html_otp_email('u@x.vn', '123456'))
