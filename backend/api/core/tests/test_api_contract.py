"""Regression tests for the JSON/API contract used by the Next.js client."""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from api.core.models import LearnLesson, ScanEvent
from api.core.tasks import send_bulk_lesson_email
from api.utils.scan_token import issue_scan_token, read_scan_token

User = get_user_model()


@override_settings(ALLOWED_HOSTS=['*'])
class ApiContractTests(TestCase):
    def setUp(self):
        self.client = APIClient()

    def test_unknown_api_path_returns_json_404(self):
        response = self.client.get('/api/v1/definitely-not-a-real-endpoint/')
        self.assertEqual(response.status_code, 404)
        self.assertIn('application/json', response['Content-Type'])
        self.assertEqual(response.json().get('code'), 'NOT_FOUND')

    def test_admin_api_requires_auth_without_html_redirect(self):
        response = self.client.post(
            '/api/v1/admin/learn/ai-generate/',
            {},
            format='json',
        )
        self.assertIn(response.status_code, (401, 403))
        self.assertIn('application/json', response['Content-Type'])
        self.assertIsNone(response.get('Location'))
        body = response.json()
        self.assertTrue(body.get('error'))
        self.assertEqual(body.get('code'), 'AUTH_REQUIRED' if response.status_code == 401 else 'PERMISSION_DENIED')

    def test_admin_cp_action_returns_json_401_without_session(self):
        response = self.client.post(
            '/admin-cp/reports/1/note/',
            {'note': 'x'},
            format='json',
            HTTP_ACCEPT='application/json',
        )
        self.assertEqual(response.status_code, 401)
        self.assertIn('application/json', response['Content-Type'])
        self.assertIsNone(response.get('Location'))
        self.assertEqual(response.json().get('code'), 'AUTH_REQUIRED')

    def test_admin_api_accepts_drf_token(self):
        admin = User.objects.create_user(
            username='contract-admin',
            email='contract-admin@example.com',
            password='a-strong-password-123',
            is_staff=True,
        )
        token = Token.objects.create(user=admin)
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')

        response = self.client.post(
            '/api/v1/admin/learn/ai-generate/',
            {'text': ''},
            format='json',
        )
        # Auth passed; the empty payload is rejected by the view (400), not 401/403.
        self.assertEqual(response.status_code, 400)

    def test_scan_analyze_requires_turnstile_without_scan_id(self):
        with patch('api.core.views.stream_views.verify_turnstile_token', return_value=False) as verify:
            response = self.client.post(
                '/api/v1/scan/analyze-sse/',
                {'scan_type': 'phone', 'scan_data': {}, 'raw_input': '0912345678'},
                format='json',
            )
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json().get('code'), 'TURNSTILE_REQUIRED')
        verify.assert_called_once()

    def test_scan_analyze_skips_turnstile_when_scan_id_provided(self):
        with patch('api.core.views.stream_views.verify_turnstile_token', return_value=False) as verify:
            response = self.client.post(
                '/api/v1/scan/analyze-sse/',
                {'scan_id': 999999, 'scan_type': 'phone'},
                format='json',
            )
        self.assertEqual(response.status_code, 404)
        verify.assert_not_called()

    def test_lesson_notify_is_queued_to_celery(self):
        admin = User.objects.create_user(
            username='notify-admin',
            email='notify-admin@example.com',
            password='a-strong-password-123',
            is_staff=True,
        )
        token = Token.objects.create(user=admin)
        with patch('api.maintenance.tasks.rebuild_vector_index.delay'):
            lesson = LearnLesson.objects.create(
                title='Bài học kiểm thử',
                slug='bai-hoc-kiem-thu',
                summary='Tóm tắt',
                content='Nội dung',
            )
        self.client.credentials(HTTP_AUTHORIZATION=f'Token {token.key}')

        with patch('api.core.tasks.send_bulk_lesson_email.delay') as delay:
            response = self.client.post(f'/api/v1/admin/learn/{lesson.pk}/notify/', {}, format='json')

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.json().get('status'), 'queued')
        delay.assert_called_once_with(lesson.pk)

    @patch('api.core.tasks.admin_broadcast_task.delay')
    @patch('api.utils.email_utils.send_new_lesson_email', return_value=2)
    def test_bulk_lesson_task_sends_email_and_queues_push(self, email_mock, push_mock):
        User.objects.create_user(
            username='lesson-reader',
            email='lesson-reader@example.com',
            password='a-strong-password-123',
        )
        with patch('api.maintenance.tasks.rebuild_vector_index.delay'):
            lesson = LearnLesson.objects.create(
                title='Bài học chạy nền',
                slug='bai-hoc-chay-nen',
                summary='Tóm tắt',
                content='Nội dung',
            )

        result = send_bulk_lesson_email.run(lesson.pk)

        self.assertEqual(result.get('status'), 'ok')
        self.assertEqual(result.get('sent_emails'), 2)
        self.assertTrue(email_mock.called)
        push_mock.assert_called_once()

    def test_scan_token_roundtrip_and_status_access(self):
        event = ScanEvent.objects.create(
            scan_type='phone',
            raw_input='0912345678',
            normalized_input='+84912345678',
            risk_score=0,
            risk_level='SAFE',
            status='completed',
            result_json={},
        )
        token = issue_scan_token(event.id)
        self.assertEqual(read_scan_token(token), event.id)
        self.assertIsNone(read_scan_token('not-a-token'))

        denied = self.client.get(f'/api/v1/scan/status/{event.id}/')
        self.assertEqual(denied.status_code, 403)

        allowed = self.client.get(f'/api/v1/scan/status/{event.id}/?scan_token={token}')
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(allowed.json().get('id'), event.id)

        wrong = self.client.get(f'/api/v1/scan/status/{event.id}/?scan_token=bad')
        self.assertEqual(wrong.status_code, 403)

    def test_frontend_proxy_avoids_double_gzip_encoding(self):
        import asyncio
        import gzip
        import httpx
        from django.test import RequestFactory
        from PKV.views.proxy_views import frontend_proxy_view

        captured = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured['accept_encoding'] = req.headers.get('accept-encoding')
            body = gzip.compress(b'<!DOCTYPE html><html><body>ok</body></html>')
            return httpx.Response(
                200,
                headers={'content-type': 'text/html; charset=utf-8', 'content-encoding': 'gzip'},
                content=body,
            )

        orig_async_client = httpx.AsyncClient
        transport = httpx.MockTransport(handler)

        def patched_client(*args, **kwargs):
            kwargs['transport'] = transport
            return orig_async_client(*args, **kwargs)

        async def _call():
            rf = RequestFactory()
            req = rf.get('/', HTTP_ACCEPT_ENCODING='gzip, deflate, br, zstd')
            with patch('PKV.views.proxy_views.httpx.AsyncClient', side_effect=patched_client):
                resp = await frontend_proxy_view(req, '')
                chunks = []
                async for part in resp.streaming_content:
                    chunks.append(part)
                return resp, b''.join(chunks)

        resp, payload = asyncio.run(_call())
        self.assertEqual(captured.get('accept_encoding'), 'identity')
        self.assertNotIn('Content-Encoding', resp)
        self.assertTrue(payload.startswith(b'<!DOCTYPE html>'))
