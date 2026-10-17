"""Tests cho audit report: chong trung, validate mo ta, stats cache, privacy lookup."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.utils import timezone
from rest_framework.test import APIClient

from django.test import TestCase

from api.core.models import Report

User = get_user_model()

BASE = {
    'target_type': 'phone',
    'target_value': '0912345678',
    'scam_type': 'otp_steal',
    'severity': 'high',
    'description': 'Mo ta vu viec day du hon muoi ky tu.',
}


class ReportDuplicateTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username='report_auditor', password='x')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_duplicate_pending_rejected(self):
        r1 = self.client.post('/api/v1/report/', dict(BASE), format='multipart')
        self.assertEqual(r1.status_code, 201)
        r2 = self.client.post('/api/v1/report/', dict(BASE), format='multipart')
        self.assertEqual(r2.status_code, 400)
        self.assertIn('24h', r2.data.get('error', ''))

    def test_description_too_short_rejected(self):
        payload = dict(BASE, target_value='0987654321', description='ngan')
        resp = self.client.post('/api/v1/report/', payload, format='multipart')
        self.assertEqual(resp.status_code, 400)

    def test_stats_cached_and_invalidated(self):
        Report.objects.create(
            reporter=self.user, status='approved', **BASE)
        first = self.client.get('/api/v1/reports/stats/')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(first.data['total_approved'], 1)
        # Them bao cao nua nhung cache giu so cu
        Report.objects.create(
            reporter=self.user, status='approved',
            **dict(BASE, target_value='0987654321'))
        second = self.client.get('/api/v1/reports/stats/')
        self.assertEqual(second.data['total_approved'], 1)
        cache.delete('report_stats_v1')
        third = self.client.get('/api/v1/reports/stats/')
        self.assertEqual(third.data['total_approved'], 2)

    def test_user_reports_pagination_and_status_filter(self):
        for i in range(3):
            Report.objects.create(
                reporter=self.user, status='approved',
                **dict(BASE, target_value=f'09110000{i:02d}'))
        page1 = self.client.get('/api/v1/user/reports/?page=1&page_size=2')
        self.assertEqual(page1.status_code, 200)
        self.assertEqual(page1.data['count'], 3)
        self.assertEqual(len(page1.data['results']), 2)
        self.assertEqual(page1.data['pages'], 2)
        self.assertEqual(page1.data['status_counts']['approved'], 3)
        filt = self.client.get('/api/v1/user/reports/?status=pending')
        self.assertEqual(filt.data['count'], 0)

    def test_lookup_hides_reporter_username(self):
        Report.objects.create(
            reporter=self.user, status='approved', **BASE)
        resp = self.client.get('/api/v1/scan/lookup/?q=0912345678')
        self.assertEqual(resp.status_code, 200)
        blob = str(resp.data)
        self.assertNotIn('report_auditor', blob)

    def test_lookup_excludes_private_scans_and_masks_sensitive(self):
        from api.core.models import ScanEvent, ScanStatus
        stranger = User.objects.create_user(username='secret_scanner', password='x')
        ScanEvent.objects.create(
            user=stranger,
            scan_type='message',
            raw_input='Mat khau bi mat cua toi la supersecret123',
            status=ScanStatus.COMPLETED,
            risk_score=90,
            risk_level='RED',
            is_public_referable=False,
        )
        ScanEvent.objects.create(
            user=stranger,
            scan_type='message',
            raw_input='Tin nhan lua dao trung thuong 500 trieu',
            status=ScanStatus.COMPLETED,
            risk_score=95,
            risk_level='RED',
            is_public_referable=True,
        )
        anon = APIClient()
        resp = anon.get('/api/v1/scan/lookup/?type=message')
        self.assertEqual(resp.status_code, 200)
        blob = str(resp.data)
        self.assertNotIn('supersecret123', blob)
        self.assertIn('******', blob)
