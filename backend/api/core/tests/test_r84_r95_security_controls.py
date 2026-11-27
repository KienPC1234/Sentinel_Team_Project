"""Regression tests for R84 holdout gate, R89 moderation abstention, and R95 URL agent."""
from pathlib import Path

from django.test import SimpleTestCase

from api.core.tasks import _parse_moderation_ai_result_or_abstain
from api.utils import r84_holdout_gate as gate
from api.utils import url_agent_v3


class ModerationAbstentionTests(SimpleTestCase):
    def test_rejects_invalid_or_non_finite_payloads(self):
        self.assertIsNone(_parse_moderation_ai_result_or_abstain(None))
        self.assertIsNone(_parse_moderation_ai_result_or_abstain('not-json'))
        self.assertIsNone(_parse_moderation_ai_result_or_abstain('{}'))
        self.assertIsNone(
            _parse_moderation_ai_result_or_abstain(
                '{"violation": "yes", "confidence": 0.8, "reason": "bad type"}'
            )
        )
        self.assertIsNone(
            _parse_moderation_ai_result_or_abstain(
                '{"violation": true, "confidence": true, "reason": "bool confidence"}'
            )
        )
        self.assertIsNone(
            _parse_moderation_ai_result_or_abstain(
                '{"violation": false, "confidence": NaN, "reason": "nan"}'
            )
        )
        self.assertIsNone(
            _parse_moderation_ai_result_or_abstain(
                '{"violation": false, "confidence": Infinity, "reason": "inf"}'
            )
        )

    def test_clamps_valid_moderation_payload(self):
        parsed = _parse_moderation_ai_result_or_abstain(
            '{"violation": true, "confidence": 1.4, "reason": "Vi pham noi quy"}'
        )
        self.assertEqual(
            parsed,
            {'violation': True, 'confidence': 1.0, 'reason': 'Vi pham noi quy'},
        )


class UrlAgentSecurityTests(SimpleTestCase):
    def test_safe_display_url_blocks_ssrf_and_redacts_sensitive_paths(self):
        for unsafe in (
            'http://127.0.0.1/admin',
            'http://169.254.169.254/latest/meta-data/',
            'https://localhost/test',
            'https://user:pass@example.com/',
            'https://example.com:8443/custom',
        ):
            with self.subTest(unsafe=unsafe):
                with self.assertRaises(ValueError):
                    url_agent_v3.safe_display_url(unsafe)

        cleaned, host = url_agent_v3.safe_display_url(
            'https://Example.COM/token/secret123/profile?otp=999999'
        )
        self.assertEqual(host, 'example.com')
        self.assertEqual(cleaned, 'https://example.com/[REDACTED]/profile')

    def test_investigate_enforces_scope_and_citation_integrity(self):
        calls = []

        def fake_chat(*, model, messages, tools, **kwargs):
            calls.append(len(tools))
            if len(calls) == 1:
                return {
                    'message': {
                        'content': '',
                        'tool_calls': [
                            {
                                'function': {
                                    'name': '_tool_search_public_sources',
                                    'arguments': {'query': 'unrelateddomain login'},
                                }
                            },
                            {
                                'function': {
                                    'name': '_tool_search_public_sources',
                                    'arguments': {'query': 'vietcombank token=mysecretvalue'},
                                }
                            },
                        ],
                    }
                }
            if len(calls) == 2:
                return {'message': {'content': '', 'tool_calls': []}}
            return {
                'message': {
                    'content': (
                        '{"recommended_class": "phishing", '
                        '"evidence_ids": ["ev_999"], '
                        '"hypotheses": [], "uncertainties": [], "explanation": "bad citation"}'
                    )
                }
            }

        outcome = url_agent_v3.investigate(
            'https://vietcombank-alert.example.org/login',
            'Snapshot text phone 0912345678',
            chat=fake_chat,
            search=lambda q, n: [],
            seed_search=False,
        )
        self.assertFalse(outcome['score_authority'])
        self.assertEqual(outcome['denied_tools'], 2)
        self.assertEqual(outcome['denial_reasons'].get('out_of_scope'), 1)
        self.assertEqual(outcome['denial_reasons'].get('sensitive_value'), 1)
        self.assertEqual(outcome['invalid_citations'], 1)
        self.assertEqual(outcome['recommended_class'], 'insufficient_evidence')


class HoldoutGateBaselineTests(SimpleTestCase):
    def test_pinned_synthetic_baseline_matches_tracked_corpus(self):
        baseline = (
            Path(__file__).resolve().parents[1] / 'data' / 'r84_known_synthetic_sha256.txt'
        )
        loaded = gate.load_pinned_prior(baseline)
        self.assertEqual(len(loaded), gate.KNOWN_PRIOR_COUNT)
