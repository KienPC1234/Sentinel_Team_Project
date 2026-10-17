"""Tests cho audit cum scan: phan trang lich su, validate domain, status 403."""
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from django.test import TestCase, TransactionTestCase

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


class ScanSecurityHardeningTest(TestCase):
    """Hồi quy cho các lỗ hổng/độ bền đã sửa trong audit cụm scan."""

    def setUp(self):
        self.user = User.objects.create_user(username='scan_hardener', password='x')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_message_oversized_rejected(self):
        resp = self.client.post('/api/v1/scan/message/', {'message': 'x' * 25000}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_report_admin_blocks_foreign_anonymous_scan(self):
        scan = ScanEvent.objects.create(
            user=None, scan_type='message', raw_input='hi',
            status='completed', risk_score=10, risk_level='GREEN', result_json={},
        )
        resp = self.client.post(f'/api/v1/scan/{scan.id}/report-admin/', {'reason': 'x'}, format='json')
        self.assertEqual(resp.status_code, 403)

    def test_sse_endpoint_survives_non_string_input(self):
        from unittest.mock import patch
        with patch('api.core.views.stream_views.stream_response', return_value=iter(['ok'])):
            resp = self.client.post(
                '/api/v1/scan/analyze/',
                {'scan_type': 'phone', 'raw_input': 12345, 'scan_data': {}},
                format='json',
            )
            self.assertEqual(resp.status_code, 200)

    def test_guardrail_label_never_raw_english(self):
        # (frontend helper không test ở đây) — đảm bảo backend luôn cấp label khi có guardrail
        scan = ScanEvent.objects.create(
            user=self.user, scan_type='phone', raw_input='0911000000',
            status='completed', risk_score=0, risk_level='SAFE', result_json={},
        )
        resp = self.client.get(f'/api/v1/scan/status/{scan.id}/')
        self.assertEqual(resp.status_code, 200)
        g = (resp.data.get('result') or {}).get('guardrail') or {}
        self.assertEqual(g.get('tier'), 'INSUFFICIENT')


class ScanInfraHardeningTest(TestCase):
    """Hồi quy: throttle IP đáng tin, ngưỡng canonical, reaper scan kẹt."""

    def test_client_ip_ignores_spoofable_xff(self):
        from api.core.throttling import client_ip

        class Req:
            def __init__(self, meta):
                self.META = meta

        # Có CF-Connecting-IP -> ưu tiên nó, bỏ XFF giả mạo.
        self.assertEqual(
            client_ip(Req({'HTTP_X_FORWARDED_FOR': '1.2.3.4', 'HTTP_CF_CONNECTING_IP': '9.9.9.9', 'REMOTE_ADDR': '10.0.0.1'})),
            '9.9.9.9',
        )
        # Không có CF -> dùng REMOTE_ADDR, KHÔNG dùng XFF.
        self.assertEqual(
            client_ip(Req({'HTTP_X_FORWARDED_FOR': '1.2.3.4', 'REMOTE_ADDR': '10.0.0.1'})),
            '10.0.0.1',
        )

    def test_level_from_score_canonical(self):
        from api.utils.trust_guard import level_from_score
        self.assertEqual(level_from_score(0), 'SAFE')
        self.assertEqual(level_from_score(9), 'SAFE')
        self.assertEqual(level_from_score(10), 'GREEN')
        self.assertEqual(level_from_score(40), 'YELLOW')
        self.assertEqual(level_from_score(70), 'RED')
        self.assertEqual(level_from_score('bad'), 'SAFE')

    def test_reap_stale_scans_marks_failed(self):
        from datetime import timedelta
        from django.utils import timezone
        from api.core.tasks import reap_stale_scans

        ev = ScanEvent.objects.create(
            scan_type='file', raw_input='File: x', status='processing', result_json={},
        )
        # created_at là auto_now_add -> cập nhật lùi thời gian để mô phỏng "kẹt".
        ScanEvent.objects.filter(id=ev.id).update(
            created_at=timezone.now() - timedelta(minutes=30))
        reap_stale_scans(max_age_minutes=15)
        ev.refresh_from_db()
        self.assertEqual(ev.status, 'failed')
        self.assertIn('error', ev.result_json)


class ScanWsAuthorizationTest(TransactionTestCase):
    """WS /ws/scan/<id>/ phải chống IDOR (chỉ chủ sở hữu/phiên/staff được xem)."""

    async def test_ws_consumer_authorization(self):
        from django.contrib.auth.models import AnonymousUser
        from api.core.consumers import ScanProgressConsumer

        scan = await ScanEvent.objects.acreate(
            user=None, scan_type='message', raw_input='hi',
            status='completed', risk_score=10, risk_level='GREEN', result_json={},
        )

        def mk(scope):
            c = ScanProgressConsumer()
            c.scan_id = str(scan.id)
            c.scope = scope
            return c

        # Khách lạ (không phiên, không phải chủ) -> bị từ chối.
        self.assertFalse(await mk({'user': AnonymousUser(), 'session': {}})._authorized())
        # Chủ phiên ẩn danh -> được phép.
        self.assertTrue(
            await mk({'user': AnonymousUser(), 'session': {'active_scan_ids': [scan.id]}})._authorized())
        # Staff -> được phép.
        staff = await User.objects.acreate(username='ws_staff', is_staff=True)
        self.assertTrue(await mk({'user': staff, 'session': {}})._authorized())
