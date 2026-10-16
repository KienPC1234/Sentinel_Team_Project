"""Tests cho audit Radar: privacy username, approved-only, cache, risk cap."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIClient

from django.test import TestCase

from api.core.models import Report

User = get_user_model()

BASE = {
    'target_type': 'phone',
    'target_value': '0912999888',
    'scam_type': 'otp_steal',
    'severity': 'high',
    'description': 'Mo ta day du hon muoi ky tu.',
}


class RadarPrivacyTest(TestCase):
    def setUp(self):
        cache.clear()
        self.user = User.objects.create_user(username='radar_reporter', password='x')
        self.client = APIClient()
        Report.objects.create(reporter=self.user, status='approved', **BASE)

    def test_hot_hides_reporter_username(self):
        resp = self.client.get('/api/v1/trends/hot/?type=phone')
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn('radar_reporter', str(resp.data))

    def test_hot_only_approved(self):
        Report.objects.create(
            reporter=self.user, status='pending',
            **dict(BASE, target_value='0912000100'))
        resp = self.client.get('/api/v1/trends/hot/?type=phone')
        targets = [h['target_value'] for h in resp.data['hot']]
        self.assertIn('0912999888', targets)
        self.assertNotIn('0912000100', targets)

    def test_hot_risk_change_capped(self):
        for h in self.client.get('/api/v1/trends/hot/?type=phone').data['hot']:
            self.assertLessEqual(h['risk_change'], 100)

    def test_radar_stats_cached_and_private(self):
        first = self.client.get('/api/v1/trends/radar-stats/?filter=all&timeRange=7d')
        self.assertEqual(first.status_code, 200)
        self.assertNotIn('radar_reporter', str(first.data))
        Report.objects.create(
            reporter=self.user, status='approved',
            **dict(BASE, target_value='0912000200'))
        second = self.client.get('/api/v1/trends/radar-stats/?filter=all&timeRange=7d')
        # Cache 120s giu ket qua cu
        self.assertEqual(
            second.data['reports_this_week'], first.data['reports_this_week'])
