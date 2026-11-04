from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from api.utils.security import is_safe_url, safe_get
from api.utils.scan_utils import _analyze_network

User = get_user_model()


class SSRFAndUrlSecurityTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testsec', email='testsec@example.com', password='password123')
        self.client.force_authenticate(user=self.user)

    def test_is_safe_url_blocks_private_destinations(self):
        unsafe_urls = [
            'http://127.0.0.1:8000/api/',
            'http://localhost:5000/',
            'http://169.254.169.254/latest/meta-data/',
            'http://10.0.0.5/admin',
            'http://192.168.1.1/router',
            'http://172.16.0.1/',
            'file:///etc/passwd',
            'gopher://127.0.0.1:6379/_flushall',
        ]
        for u in unsafe_urls:
            self.assertFalse(is_safe_url(u), f"Expected {u} to be marked unsafe")

    def test_safe_get_blocks_direct_private_target(self):
        with self.assertRaises(ValueError):
            safe_get('http://127.0.0.1:8000/secret')

    def test_safe_get_blocks_redirect_to_private_target(self):
        mock_302 = MagicMock()
        mock_302.is_redirect = True
        mock_302.headers = {'Location': 'http://169.254.169.254/latest/meta-data/'}

        with patch('requests.get', return_value=mock_302):
            with self.assertRaises(ValueError) as ctx:
                safe_get('https://example.com/redirect')
            self.assertIn('Unsafe URL blocked', str(ctx.exception))

    def test_editor_fetch_url_view_blocks_unsafe_url(self):
        resp = self.client.get('/api/v1/utils/fetch-url/?url=http://127.0.0.1:8000')
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(resp.data.get('success'), 0)

    def test_analyze_network_blocks_private_ip(self):
        res = _analyze_network('http://127.0.0.1:8000', '127.0.0.1')
        self.assertEqual(res.get('error'), 'Blocked internal destination')

    def test_web_fetch_url_blocks_redirect_ssrf(self):
        from api.utils.ollama_client import web_fetch_url

        # Direct loopback
        self.assertIsNone(web_fetch_url('http://127.0.0.1:8001/secret'))
        self.assertIsNone(web_fetch_url('http://169.254.169.254/latest/meta-data/'))

        # Redirect to loopback: mock safe_get throwing ValueError for unsafe redirect
        with patch('api.utils.security.safe_get', side_effect=ValueError('Unsafe URL blocked: http://127.0.0.1')):
            res = web_fetch_url('https://malicious-redirector.com/hop')
            self.assertIsNone(res)

