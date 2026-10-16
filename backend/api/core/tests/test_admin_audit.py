"""Tests cho audit admin panel: stats cache, broadcast validate, users/tickets paging."""
from django.contrib.auth import get_user_model
from django.core.cache import cache
from rest_framework.test import APIClient

from django.test import TestCase

from api.core.models import SupportTicket

User = get_user_model()


class AdminStatsCacheTest(TestCase):
    def setUp(self):
        cache.clear()
        self.staff = User.objects.create_user(username='admin_audit', password='x', is_staff=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)

    def test_stats_cached(self):
        first = self.client.get('/api/v1/admin/stats/')
        self.assertEqual(first.status_code, 200)
        self.assertIn('total_users', first.data)
        User.objects.create_user(username='admin_audit_new', password='x')
        second = self.client.get('/api/v1/admin/stats/')
        # Cache 60s giu so cu
        self.assertEqual(second.data['total_users'], first.data['total_users'])

    def test_stats_forbidden_for_member(self):
        member = User.objects.create_user(username='admin_audit_member', password='x')
        self.client.force_authenticate(user=member)
        resp = self.client.get('/api/v1/admin/stats/')
        self.assertEqual(resp.status_code, 403)


class AdminBroadcastValidationTest(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(username='admin_bc', password='x', is_staff=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)

    def test_broadcast_validation(self):
        resp = self.client.post('/api/v1/admin/notifications/broadcast/', {}, format='json')
        self.assertEqual(resp.status_code, 400)
        resp = self.client.post('/api/v1/admin/notifications/broadcast/', {
            'title': 't', 'message': 'm', 'notification_type': 'nope',
        }, format='json')
        self.assertEqual(resp.status_code, 400)
        resp = self.client.post('/api/v1/admin/notifications/broadcast/', {
            'title': 't', 'message': 'm', 'url': 'javascript:alert(1)',
        }, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_broadcast_queued(self):
        resp = self.client.post('/api/v1/admin/notifications/broadcast/', {
            'title': 'Bao tri', 'message': 'He thong bao tri luc 2h.',
        }, format='json')
        self.assertEqual(resp.status_code, 202)
        self.assertEqual(resp.data['status'], 'queued')


class AdminUsersPagingTest(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(username='admin_users', password='x', is_staff=True)
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)
        for i in range(3):
            User.objects.create_user(username=f'target_user_{i}', password='x')

    def test_search_finds_old_users(self):
        resp = self.client.get('/api/v1/admin/users/?q=target_user_2')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['count'], 1)

    def test_status_filter(self):
        resp = self.client.get('/api/v1/admin/users/?status=active')
        self.assertEqual(resp.status_code, 200)
        self.assertGreaterEqual(resp.data['count'], 4)


class AdminTicketsPagingTest(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(username='admin_tk', password='x', is_staff=True)
        self.author = User.objects.create_user(username='ticket_author', password='x')
        self.client = APIClient()
        self.client.force_authenticate(user=self.staff)
        for i in range(3):
            SupportTicket.objects.create(
                author=self.author, title=f'Ticket {i}', description='mo ta',
                category='other', priority='low', status='open',
            )

    def test_envelope_and_paging(self):
        resp = self.client.get('/api/v1/admin/tickets/?page=1&page_size=2')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data['count'], 3)
        self.assertEqual(len(resp.data['results']), 2)
        self.assertEqual(resp.data['status_counts']['open'], 3)
