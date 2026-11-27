"""RED/GREEN subscriber ownership tests on isolated SQLite test DB only.

Cache rate limiter mocked so no production Redis keys are touched.
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.test import APIClient

from api.core.models import WebPushSubscription

User = get_user_model()


@override_settings(
    CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    }
)
class WebPushOwnershipTests(TestCase):
    def setUp(self):
        self.u1 = User.objects.create_user(username='r80_owner', password='disabled')
        self.u2 = User.objects.create_user(username='r80_other', password='disabled')
        self.endpoint = 'https://push.synthetic.test/endpoint/opaque-r80-token'
        self.sub = WebPushSubscription.objects.create(
            user=self.u1,
            endpoint=self.endpoint,
            p256dh='original-p256dh',
            auth='original-auth',
            is_active=True,
        )
        self.payload = {
            'endpoint': self.endpoint,
            'keys': {
                'p256dh': 'attacker-p256dh',
                'auth': 'attacker-auth',
            },
        }

    def request(self, path, who=None, body=None):
        client = APIClient()
        if who:
            client.force_authenticate(user=who)
        with patch('api.core.views.notification_views._push_rate_limit_ok', return_value=True):
            return client.post(
                path,
                body if body is not None else self.payload,
                format='json',
            )

    def refresh(self):
        self.sub.refresh_from_db()

    def test_anonymous_cannot_replace_authenticated_subscription(self):
        response = self.request('/api/v1/push/subscribe/')
        self.assertEqual(response.status_code, 403)
        self.refresh()
        self.assertEqual(self.sub.user_id, self.u1.id)
        self.assertEqual(self.sub.p256dh, 'original-p256dh')
        self.assertEqual(self.sub.auth, 'original-auth')

    def test_other_user_cannot_steal_endpoint(self):
        response = self.request('/api/v1/push/subscribe/', self.u2)
        self.assertEqual(response.status_code, 403)
        self.refresh()
        self.assertEqual(self.sub.user_id, self.u1.id)
        self.assertEqual(self.sub.p256dh, 'original-p256dh')

    def test_anonymous_cannot_unsubscribe_user_device(self):
        response = self.request('/api/v1/push/unsubscribe/', body={'endpoint': self.endpoint})
        self.assertEqual(response.status_code, 200)
        self.refresh()
        self.assertTrue(self.sub.is_active)
        self.assertEqual(response.data.get('updated'), 0)

    def test_other_user_cannot_unsubscribe_user_device(self):
        response = self.request(
            '/api/v1/push/unsubscribe/',
            self.u2,
            body={'endpoint': self.endpoint},
        )
        self.assertEqual(response.status_code, 200)
        self.refresh()
        self.assertTrue(self.sub.is_active)
        self.assertEqual(response.data.get('updated'), 0)

    def test_owner_can_refresh(self):
        response = self.request('/api/v1/push/subscribe/', self.u1)
        self.assertEqual(response.status_code, 200)
        self.refresh()
        self.assertEqual(self.sub.p256dh, 'attacker-p256dh')
        self.assertEqual(self.sub.user_id, self.u1.id)

    def test_owner_can_unsubscribe(self):
        response = self.request(
            '/api/v1/push/unsubscribe/',
            self.u1,
            body={'endpoint': self.endpoint},
        )
        self.assertEqual(response.status_code, 200)
        self.refresh()
        self.assertFalse(self.sub.is_active)

    def test_anonymous_guest_can_create_and_unsubscribe_unbound_device(self):
        endpoint = 'https://push.synthetic.test/guest-new'
        response = self.request(
            '/api/v1/push/subscribe/',
            body={
                'endpoint': endpoint,
                'keys': {'p256dh': 'guest-p256dh', 'auth': 'guest-auth'},
            },
        )
        self.assertEqual(response.status_code, 200)
        guest = WebPushSubscription.objects.get(endpoint=endpoint)
        self.assertIsNone(guest.user_id)
        response = self.request('/api/v1/push/unsubscribe/', body={'endpoint': endpoint})
        self.assertEqual(response.status_code, 200)
        guest.refresh_from_db()
        self.assertFalse(guest.is_active)

    def test_origin_rejected_before_database_change(self):
        client = APIClient()
        response = client.post(
            '/api/v1/push/subscribe/',
            self.payload,
            format='json',
            HTTP_ORIGIN='https://other.invalid',
        )
        self.assertEqual(response.status_code, 403)
        self.refresh()
        self.assertEqual(self.sub.p256dh, 'original-p256dh')
