"""Tests cho audit cum scan: phan trang lich su, validate domain, status 403."""
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from django.test import TestCase

from api.core.models import ScanEvent

User = get_user_model()


class UserScansPaginationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='scan_auditor', password='x')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        for i in range(3):
            ScanEvent.objects.create(
                user=self.user, scan_type='phone', raw_input=f'0911000{i}',
                status='completed', risk_score=10 if i < 2 else 80,
                risk_level='GREEN' if i < 2 else 'RED', result_json={},
            )

    def test_pagination_envelope_and_stats(self):
        resp = self.client.get('/api/v1/user/scans/?page=1&page_size=2')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['count'], 3)
        self.assertEqual(len(resp.data['results']), 2)
        self.assertEqual(resp.data['pages'], 2)
        self.assertEqual(resp.data['stats']['total'], 3)
        self.assertEqual(resp.data['stats']['red'], 1)
        self.assertEqual(len(resp.data['stats']['last_7_days']), 7)

    def test_scan_status_forbidden_for_stranger(self):
        other = User.objects.create_user(username='scan_stranger', password='x')
        scan = ScanEvent.objects.create(
            user=other, scan_type='phone', raw_input='0987000111',
            status='completed', risk_score=10, risk_level='GREEN', result_json={},
        )
        anon = APIClient()
        resp = anon.get(f'/api/v1/scan/status/{scan.id}/')
        self.assertEqual(resp.status_code, 403)


class ScanDomainValidationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='scan_domain', password='x')
        self.client = APIClient()
        # Authenticated -> bypass turnstile, isolate domain validation
        self.client.force_authenticate(user=self.user)

    def test_garbage_domain_rejected_before_network(self):
        resp = self.client.post('/api/v1/scan/domain/', {'url': '!!!'}, format='json')
        self.assertEqual(resp.status_code, 400)
        self.assertIn('khong hop le', resp.data.get('error', ''))


class ScanAccountAuditTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='account_auditor', password='x')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_account_scan_excludes_rejected_reports(self):
        from api.core.models import Report
        # Create a rejected report for account 123456789
        Report.objects.create(
            target_type='account',
            target_value='123456789',
            scammer_bank_account='123456789',
            scammer_bank_name='MBBank',
            status='rejected',
            description='Spam fake report'
        )
        resp = self.client.post('/api/v1/scan/account/', {'bank': 'MBBank', 'account': '123456789'}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['risk_score'], 0)
        self.assertEqual(resp.data['risk_level'], 'SAFE')
        self.assertIn('scan_id', resp.data)

        # Now create an approved report
        Report.objects.create(
            target_type='account',
            target_value='123456789',
            scammer_bank_account='123456789',
            scammer_bank_name='MBBank',
            status='approved',
            description='Real fraud'
        )
        resp2 = self.client.post('/api/v1/scan/account/', {'bank': 'MBBank', 'account': '123456789'}, format='json')
        self.assertEqual(resp2.status_code, 200)
        self.assertGreaterEqual(resp2.data['risk_score'], 25)

    def test_account_scan_registers_session_and_status_accessible(self):
        from unittest.mock import patch
        anon_client = APIClient()
        with patch('api.core.views.scan_views._verify_turnstile_or_api_key', return_value=None):
            resp = anon_client.post('/api/v1/scan/account/', {'bank': 'Vietcombank', 'account': '9876543210'}, format='json')
            self.assertEqual(resp.status_code, 200)
            scan_id = resp.data.get('scan_id')
            self.assertIsNotNone(scan_id)

            # Anon client can access status of their own scan via registered session
            status_resp = anon_client.get(f'/api/v1/scan/status/{scan_id}/')
            self.assertEqual(status_resp.status_code, 200)
            self.assertEqual(status_resp.data['scan_type'], 'account')
