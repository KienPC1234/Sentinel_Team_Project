"""
Test suite for ShieldCall VN – MCP Server & API Key Management System
Verifies:
1. APIKey model generation, hashing, and regeneration.
2. APIKeyAuthentication: valid key, invalid key, rate limiting, and quota enforcement.
3. Turnstile bypass for authenticated API clients.
4. User API Key management views (CRUD, toggle, regenerate).
5. MCP Server tools (check_phone, check_bank_account, check_url_or_domain, etc.).
6. /mcp/ documentation page rendering.
"""
import json
import asyncio
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework import status

from api.core.models import APIKey
from api.core.authentication import APIKeyAuthentication
from mcp_server.server import create_server

User = get_user_model()


class APIKeyModelAndAuthTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='test_mcp_user',
            email='mcp_user@test.com',
            password='Password123!'
        )
        self.client = APIClient()

    def test_api_key_generation_and_hashing(self):
        key_obj, raw_token = APIKey.generate(
            user=self.user,
            name="Test Claude Desktop",
            tier=APIKey.Tier.FREE
        )
        self.assertTrue(raw_token.startswith("sc_live_"))
        self.assertEqual(key_obj.prefix, raw_token[:16])
        self.assertEqual(key_obj.hashed_key, APIKey.hash_token(raw_token))
        self.assertEqual(key_obj.daily_quota, 500)
        self.assertEqual(key_obj.rate_limit_per_minute, 60)
        self.assertEqual(key_obj.requests_today, 0)

        # Test regeneration
        old_hash = key_obj.hashed_key
        new_token = key_obj.regenerate()
        self.assertNotEqual(old_hash, key_obj.hashed_key)
        self.assertEqual(key_obj.hashed_key, APIKey.hash_token(new_token))

    def test_api_key_authentication_success_and_usage_tracking(self):
        key_obj, raw_token = APIKey.generate(
            user=self.user,
            name="Test Key",
            tier=APIKey.Tier.FREE
        )

        self.client.credentials(HTTP_X_API_KEY=raw_token)
        # Calling scan phone endpoint without Turnstile captcha
        resp = self.client.post('/api/v1/scan/phone/', {'phone': '0912345678'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn('risk_score', resp.data)

        # Verify usage was tracked
        key_obj.refresh_from_db()
        self.assertEqual(key_obj.requests_today, 1)
        self.assertEqual(key_obj.total_requests, 1)
        self.assertIsNotNone(key_obj.last_used_at)

    def test_daily_quota_exhaustion(self):
        key_obj, raw_token = APIKey.generate(
            user=self.user,
            name="Quota Test Key",
            tier=APIKey.Tier.FREE
        )
        # Simulate that user has already hit their daily quota
        key_obj.daily_quota = 2
        key_obj.requests_today = 2
        key_obj.save()

        self.client.credentials(HTTP_X_API_KEY=raw_token)
        resp = self.client.post('/api/v1/scan/phone/', {'phone': '0912345678'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_429_TOO_MANY_REQUESTS)
        self.assertIn('hạn mức', str(resp.data).lower())

    def test_invalid_api_key(self):
        self.client.credentials(HTTP_X_API_KEY='sc_live_invalid_token_123456')
        resp = self.client.post('/api/v1/scan/phone/', {'phone': '0912345678'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_401_UNAUTHORIZED)


class APIKeyManagementViewsTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='api_manager',
            email='api_mgr@test.com',
            password='Password123!'
        )
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def test_crud_api_keys(self):
        # 1. Create key
        resp = self.client.post('/api/v1/user/api-keys/', {'name': 'Cursor Workspace'}, format='json')
        self.assertEqual(resp.status_code, status.HTTP_201_CREATED)
        self.assertIn('raw_key', resp.data)
        key_id = resp.data['id']
        raw_key = resp.data['raw_key']
        self.assertTrue(raw_key.startswith('sc_live_'))

        # 2. List keys
        resp = self.client.get('/api/v1/user/api-keys/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(len(resp.data['api_keys']), 1)
        self.assertEqual(resp.data['api_keys'][0]['name'], 'Cursor Workspace')

        # 3. Toggle key
        resp = self.client.post(f'/api/v1/user/api-keys/{key_id}/toggle/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertFalse(resp.data['is_active'])

        # 4. Regenerate key
        resp = self.client.post(f'/api/v1/user/api-keys/{key_id}/regenerate/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertIn('raw_key', resp.data)

        # 5. Delete key
        resp = self.client.delete(f'/api/v1/user/api-keys/{key_id}/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(APIKey.objects.filter(id=key_id).count(), 0)


class MCPIntegrationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='mcp_bot_owner',
            email='mcp_bot@test.com',
            password='Password123!'
        )
        self.key_obj, self.raw_token = APIKey.generate(
            user=self.user,
            name="MCP Test Key",
            tier=APIKey.Tier.FREE
        )

    def test_mcp_server_tools_registration_and_prompts(self):
        server = create_server(api_key=self.raw_token)

        async def run_checks():
            tools = await server.list_tools()
            tool_names = [t.name for t in tools]
            self.assertIn('check_phone', tool_names)
            self.assertIn('check_bank_account', tool_names)
            self.assertIn('check_url_or_domain', tool_names)
            self.assertIn('analyze_message', tool_names)
            self.assertIn('check_email_sender', tool_names)
            self.assertIn('get_supported_banks', tool_names)
            self.assertIn('scan_full_incident', tool_names)
            self.assertIn('lookup_scam_db', tool_names)
            self.assertIn('get_scam_radar_trends', tool_names)
            self.assertIn('report_scam', tool_names)
            self.assertEqual(len(tool_names), 10)

            prompts = await server.list_prompts()
            prompt_names = [p.name for p in prompts]
            self.assertIn('shieldcall_sentry', prompt_names)
            self.assertIn('emergency_advisor', prompt_names)
            self.assertIn('scam_investigator', prompt_names)

            # Test prompt content retrieval
            p = await server.get_prompt('shieldcall_sentry', {})
            self.assertTrue(len(p.messages) > 0)
            self.assertIn('ShieldCall Sentry', p.messages[0].content.text)

        asyncio.run(run_checks())

    def test_mcp_guide_page_renders(self):
        client = Client()
        client.force_login(self.user)
        resp = client.get('/mcp/')
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Model Context Protocol")
        self.assertContains(resp, "Claude Desktop")
        self.assertContains(resp, "Cursor IDE")
        self.assertContains(resp, self.key_obj.prefix)


class AnalysisFeaturesVerificationTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='feature_verifier',
            email='verifier@test.com',
            password='Password123!'
        )
        self.key_obj, self.raw_token = APIKey.generate(
            user=self.user,
            name="Verification Key",
            tier=APIKey.Tier.FREE
        )
        self.client = APIClient()
        self.client.credentials(HTTP_X_API_KEY=self.raw_token)

    def test_synchronous_message_scan_via_api_key(self):
        """Verify message scan executes synchronously and returns risk assessment immediately."""
        resp = self.client.post('/api/v1/scan/message/', {
            'message': 'Chuc mung ban da trung thuong 500 trieu dong. Hay gui ma OTP de xac nhan.'
        }, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data.get('status'), 'completed')
        self.assertIn('risk_score', resp.data)
        self.assertGreater(resp.data.get('risk_score', 0), 0)
        self.assertIn('risk_level', resp.data)
        self.assertIn('actions', resp.data)

    def test_bank_account_scan_and_normalization(self):
        """Verify bank name normalization for abbreviations (MB, MB Bank, VCB)."""
        # Scan with 'MB Bank'
        resp1 = self.client.post('/api/v1/scan/account/', {
            'bank': 'MB Bank',
            'account': '0987654321'
        }, format='json')
        self.assertEqual(resp1.status_code, status.HTTP_200_OK)
        self.assertEqual(resp1.data.get('bank'), 'MBBank')
        self.assertIn('risk_score', resp1.data)

        # Scan with 'VCB'
        resp2 = self.client.post('/api/v1/scan/account/', {
            'bank': 'VCB',
            'account': '1234567890'
        }, format='json')
        self.assertEqual(resp2.status_code, status.HTTP_200_OK)
        self.assertEqual(resp2.data.get('bank'), 'Vietcombank')

    def test_synchronous_email_scan_via_api_key(self):
        """Verify email sender and content scan via API Key."""
        resp = self.client.post('/api/v1/scan/email/', {
            'email': 'support@bank-security-alert.xyz',
            'content': 'Tai khoan cua ban bi khoa, vui long xac thuc ngay lap tuc.'
        }, format='json')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertEqual(resp.data.get('status'), 'completed')
        self.assertIn('risk_score', resp.data)
        self.assertIn('security_checks', resp.data)

    def test_banks_list_endpoint(self):
        """Verify /api/v1/scan/banks/ returns bank list without crashing."""
        resp = self.client.get('/api/v1/scan/banks/')
        self.assertEqual(resp.status_code, status.HTTP_200_OK)
        self.assertTrue(len(resp.data) > 0)
        bank_names = [b.get('shortName') or b.get('code') for b in resp.data]
        self.assertTrue(any('MB' in str(b) for b in bank_names))

