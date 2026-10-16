"""Tests cho yeu cau hoi dong: guardrail, nguon VN, evidence, PII."""
from django.test import TestCase
from rest_framework.test import APIClient

from api.utils.privacy import redact_pii, redact_for_external_llm
from api.utils.trust_guard import apply_guardrail, source_catalog
from api.utils.vn_sources import tinnhiem_dataset_stats


class PrivacyRedactionTest(TestCase):
    def test_phone_email_account_masked(self):
        text = 'Lien he 0912345678 hoac mail scam@xac.vn, stk 97042212345678'
        out = redact_pii(text)
        self.assertNotIn('0912345678', out)
        self.assertNotIn('scam@xac.vn', out)
        self.assertNotIn('97042212345678', out)

    def test_safe_text_untouched(self):
        text = 'Canh bao lua dao chuyen tien'
        self.assertEqual(redact_pii(text), text)

    def test_external_llm_redaction(self):
        out = redact_for_external_llm('SĐT +84912345678 can kiem tra')
        self.assertNotIn('+84912345678', out)

    def test_redact_endpoint(self):
        client = APIClient()
        resp = client.post('/api/v1/trust/redact/', {'text': 'goi 0901112223'}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn('0901112223', resp.data['redacted'])


class ExternalLLMRedactionTest(TestCase):
    def test_generate_response_redacts_by_default(self):
        from unittest.mock import patch
        from api.utils import ollama_client as oc
        seen = {}

        class FakeMsg:
            content = 'ok'
            tool_calls = None

        class FakeResp:
            message = FakeMsg()
            done_reason = 'stop'

        def fake_chat(**kwargs):
            seen['messages'] = kwargs.get('messages')
            return FakeResp()

        with patch.object(oc, '_chat_with_retry', side_effect=fake_chat):
            oc.generate_response('Kiem tra SDT 0912345678 dum', tools=[],
                                 max_loop_iterations=1)
        user_text = ' '.join(
            m.get('content', '') for m in seen['messages'] if m.get('role') == 'user')
        self.assertNotIn('0912345678', user_text)

    def test_generate_response_keeps_pii_when_allowed(self):
        from unittest.mock import patch
        from api.utils import ollama_client as oc
        seen = {}

        class FakeMsg:
            content = 'ok'
            tool_calls = None

        class FakeResp:
            message = FakeMsg()
            done_reason = 'stop'

        def fake_chat(**kwargs):
            seen['messages'] = kwargs.get('messages')
            return FakeResp()

        with patch.object(oc, '_chat_with_retry', side_effect=fake_chat):
            oc.generate_response('Kiem tra SDT 0912345678 dum', tools=[],
                                 max_loop_iterations=1, allow_pii=True)
        user_text = ' '.join(
            m.get('content', '') for m in seen['messages'] if m.get('role') == 'user')
        self.assertIn('0912345678', user_text)


class GuardrailTest(TestCase):
    def test_insufficient_when_no_evidence(self):
        r = apply_guardrail({'risk_score': 0, 'risk_level': 'SAFE'}, kind='message')
        self.assertEqual(r['guardrail']['tier'], 'INSUFFICIENT')
        self.assertFalse(r['guardrail']['is_conclusive'])
        self.assertTrue(r['guardrail']['requires_verification'])
        self.assertTrue(len(r['guardrail']['cautions']) > 0)

    def test_confirmed_with_high_reliability_evidence(self):
        r = apply_guardrail({
            'risk_score': 85, 'risk_level': 'RED',
            'tinnhiem': {'status': 'scam', 'record': {'impersonated': 'VCB', 'url': 'https://x'}},
        }, kind='domain')
        self.assertEqual(r['guardrail']['tier'], 'CONFIRMED_RISK')
        self.assertTrue(r['guardrail']['is_conclusive'])
        srcs = [e['source'] for e in r['evidence']]
        self.assertIn('tinnhiemmang', srcs)

    def test_source_catalog_has_limits(self):
        for s in source_catalog():
            self.assertIn('reliability', s)
            self.assertIn('limits', s)
        keys = {s['key'] for s in source_catalog()}
        self.assertTrue({'tinnhiemmang', 'ai_model', 'community'} <= keys)


class VNSourcesTest(TestCase):
    def test_dataset_stats_real(self):
        stats = tinnhiem_dataset_stats()
        self.assertGreater(stats['scam'], 1000)
        self.assertGreater(stats['trusted'], 100)

    def test_sources_endpoint_has_dataset(self):
        client = APIClient()
        resp = client.get('/api/v1/trust/sources/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('vn_dataset', resp.data)
        self.assertGreater(resp.data['vn_dataset']['scam'], 1000)

    def test_channels_endpoint(self):
        client = APIClient()
        resp = client.get('/api/v1/trust/channels/')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(len(resp.data['channels']) >= 5)
        self.assertTrue(len(resp.data['bank_hotlines']) >= 5)
