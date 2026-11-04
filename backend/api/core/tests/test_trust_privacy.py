"""Tests cho yeu cau hoi dong: guardrail, nguon VN, evidence, PII."""
from django.test import TestCase
from rest_framework.test import APIClient

from api.utils.privacy import redact_pii, redact_for_external_llm
from api.utils.trust_guard import apply_guardrail, chat_guardrail, source_catalog
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

    def test_external_llm_redaction_cannot_be_disabled_by_env_var(self):
        import os
        old_val = os.environ.get("LLM_PII_REDACTION")
        try:
            os.environ["LLM_PII_REDACTION"] = "false"
            out = redact_for_external_llm('SĐT 0912345678 và CCCD 001234567890')
            self.assertNotIn('0912345678', out)
            self.assertIn('[SĐT đã ẩn]', out)
        finally:
            if old_val is not None:
                os.environ["LLM_PII_REDACTION"] = old_val
            else:
                os.environ.pop("LLM_PII_REDACTION", None)

    def test_severe_extortion_negation_psa(self):
        from api.utils.trust_guard import _detect_severe_extortion, compute_evidence_aware_ensemble
        psa = 'Viện kiểm sát không yêu cầu người dân chuyển tiền vào tài khoản tạm giữ. Nếu nhận được yêu cầu như vậy, hãy cảnh giác với lừa đảo.'
        self.assertFalse(_detect_severe_extortion(psa))
        res = compute_evidence_aware_ensemble(
            text=psa,
            ai_result={'is_scam': False, 'risk_score': 5},
            rule_score=60,
        )
        self.assertLessEqual(res['final_score'], 35)
        self.assertIn(res['risk_level'], ('SAFE', 'GREEN'))

    def test_over_masking_prevention(self):
        """Kiểm tra chống ngộ nhận: mã đơn hàng/vận đơn không được gán nhãn thành số tài khoản."""
        order_text = 'Don hang cua ban co ma van don 2026110488 dang giao, ma khach hang KH12345678'
        out = redact_pii(order_text)
        self.assertNotIn('2026110488', out)
        self.assertNotIn('KH12345678', out)
        self.assertIn('[mã tra cứu đã ẩn]', out)
        self.assertNotIn('[số tài khoản đã ẩn]', out)

        # Ngược lại: khi có tiền tố STK rõ ràng thì mới gán nhãn số tài khoản
        bank_text = 'Chuyen tien vao STK 1902847562 Techcombank'
        out_bank = redact_pii(bank_text)
        self.assertNotIn('1902847562', out_bank)
        self.assertIn('[số tài khoản đã ẩn]', out_bank)

    def test_severe_extortion_floor_enforced_on_true_threat(self):
        from api.utils.trust_guard import _detect_severe_extortion, compute_evidence_aware_ensemble
        threat = 'Cơ quan cảnh sát điều tra: Bạn dính líu đến đường dây rửa tiền, lệnh bắt tạm giam đã ký. Yêu cầu chuyển ngay 100 triệu vào tài khoản tạm giữ của viện kiểm sát để bảo lãnh.'
        self.assertTrue(_detect_severe_extortion(threat))
        res = compute_evidence_aware_ensemble(
            text=threat,
            ai_result={'is_scam': False, 'risk_score': 5},
            rule_score=60,
        )
        self.assertGreaterEqual(res['final_score'], 70)
        self.assertEqual(res['risk_level'], 'RED')

    def test_mixed_context_attack_severe_extortion(self):
        """Kiểm tra chống tấn công Mixed-context: kẻ lừa đảo mượn danh văn bản khuyến cáo để tống tiền."""
        from api.utils.trust_guard import _detect_severe_extortion, compute_evidence_aware_ensemble
        mixed_attack = (
            'Khuyến cáo từ Bộ Công an: Hãy cảnh giác với các chiêu trò lừa đảo qua mạng xã hội. '
            'Tuy nhiên hồ sơ của bạn đang có lệnh bắt tạm giam từ Viện kiểm sát nhân dân về tội rửa tiền. '
            'Yêu cầu chuyển ngay 50 triệu vào số tài khoản tạm giữ 0912837461 để niêm phong.'
        )
        # Vì câu đòi tiền không có phủ định nên vẫn BẮT BUỘC nhận diện đe dọa nghiêm trọng
        self.assertTrue(_detect_severe_extortion(mixed_attack))
        res = compute_evidence_aware_ensemble(
            text=mixed_attack,
            ai_result={'is_scam': False, 'risk_score': 10},  # Giả lập LLM bị đánh lừa bởi đoạn mở đầu
            rule_score=60,
        )
        # Bắt buộc khóa sàn ĐỎ (>= 70)
        self.assertGreaterEqual(res['final_score'], 70)
        self.assertEqual(res['risk_level'], 'RED')

    def test_same_sentence_mixed_context_anti_veto(self):
        """
        Kiểm tra P0.6 dứt điểm: Tín hiệu khuyến cáo KHÔNG ĐƯỢC PHÉP phủ quyết chỉ thị nguy hiểm
        đang có hiệu lực trong cùng một câu (Same-sentence mixed-context attack).
        """
        from api.utils.trust_guard import _detect_severe_extortion, compute_evidence_aware_ensemble

        # Tấn công pha trộn trong đúng 1 câu duy nhất (ngăn cách bằng dấu phẩy và liên từ)
        same_sentence_attack = (
            'Khuyến cáo cảnh giác chiêu trò lừa đảo, tuy nhiên lệnh bắt tạm giam từ Viện kiểm sát '
            'đã ban hành và bạn phải chuyển ngay 50 triệu vào số tài khoản 0912837461 trước 17h.'
        )
        self.assertTrue(_detect_severe_extortion(same_sentence_attack))

        # Khi LLM bị jailbreak/đánh lừa trả về an toàn (is_scam=False, risk_score=5)
        res = compute_evidence_aware_ensemble(
            text=same_sentence_attack,
            ai_result={'is_scam': False, 'risk_score': 5},
            rule_score=60,
        )
        # Sàn ĐỎ (>= 70) BẮT BUỘC được bảo vệ nguyên vẹn
        self.assertGreaterEqual(res['final_score'], 70)
        self.assertEqual(res['risk_level'], 'RED')
        self.assertEqual(res['decision_reason'], 'severe_extortion_floor')

    def test_same_sentence_otp_coercion_anti_veto(self):
        """Kiểm tra chỉ thị đòi OTP có hiệu lực trong cùng câu không bị từ ngữ khuyến cáo vô hiệu hoá."""
        from api.utils.trust_guard import has_active_threat_directive, compute_evidence_aware_ensemble

        otp_mixed = 'Cảnh báo lừa đảo qua mạng nhưng yêu cầu cung cấp lại mã OTP 6 số để xác minh giao dịch.'
        self.assertTrue(has_active_threat_directive(otp_mixed))

        res = compute_evidence_aware_ensemble(
            text=otp_mixed,
            ai_result={'is_scam': False, 'risk_score': 10},
            rule_score=50,
        )
        # Không được phép hạ điểm về mức an toàn (<= 35)
        self.assertGreater(res['final_score'], 35)
        self.assertIn(res['decision_reason'], ('critical_threat_preserved', 'severe_extortion_floor'))

    def test_ambiguous_negation_scope_cannot_auto_discount(self):
        """Khi không xác định được phạm vi phủ định thì tuyệt đối không tự động giảm xuống mức an toàn."""
        from api.utils.trust_guard import compute_evidence_aware_ensemble

        ambiguous_text = 'Thông báo phòng chống tội phạm công an yêu cầu nộp tiền vào tài khoản thanh tra.'
        res = compute_evidence_aware_ensemble(
            text=ambiguous_text,
            ai_result={'is_scam': False, 'risk_score': 10},
            rule_score=50,
        )
        # Safe context discount bị chặn khi phạm vi phủ định mơ hồ
        self.assertNotEqual(res['decision_reason'], 'safe_context_discounted')
        self.assertGreater(res['final_score'], 35)

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
            role = 'assistant'
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
            role = 'assistant'
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

    def test_single_virustotal_engine_is_high_risk_not_confirmed(self):
        """1 engine đơn lẻ trên VirusTotal chỉ coi là HIGH_RISK (tránh false positive), không đưa ra CONFIRMED_RISK."""
        r = apply_guardrail({
            'risk_score': 65,
            'virustotal': {
                'available': True,
                'stats': {'malicious': 1, 'suspicious': 0},
                'total_engines': 70,
                'permalink': 'https://www.virustotal.com/x',
            },
        }, kind='url')
        self.assertEqual(r['guardrail']['tier'], 'HIGH_RISK')
        self.assertNotEqual(r['guardrail']['tier'], 'CONFIRMED_RISK')
        self.assertEqual(r['guardrail']['confidence_type'], 'rule_heuristic')

    def test_multiple_virustotal_engines_yields_confirmed_risk(self):
        """Từ 3 engine trở lên trên VirusTotal được công nhận là bằng chứng xác thực độc lập -> CONFIRMED_RISK."""
        r = apply_guardrail({
            'risk_score': 85,
            'virustotal': {
                'available': True,
                'stats': {'malicious': 4, 'suspicious': 2},
                'total_engines': 70,
                'permalink': 'https://www.virustotal.com/x',
            },
        }, kind='url')
        self.assertEqual(r['guardrail']['tier'], 'CONFIRMED_RISK')
        self.assertGreaterEqual(r['guardrail']['confidence'], 0.90)

    def test_heuristic_alone_never_yields_confirmed_risk(self):
        """Dấu hiệu heuristic nội bộ dù có điểm cao vẫn chỉ là HIGH_RISK, không thể là CONFIRMED_RISK."""
        r = apply_guardrail({
            'risk_score': 85,
            'reasons': ['Phát hiện từ khóa lừa đảo mạo danh ngân hàng và yêu cầu chuyển tiền gấp'],
            'patterns_found': ['Dấu hiệu rủi ro cao từ phân tích từ vựng'],
        }, kind='message')
        self.assertEqual(r['guardrail']['tier'], 'HIGH_RISK')
        self.assertNotEqual(r['guardrail']['tier'], 'CONFIRMED_RISK')

    def test_source_catalog_has_limits(self):
        for s in source_catalog():
            self.assertIn('reliability', s)
            self.assertIn('limits', s)
        keys = {s['key'] for s in source_catalog()}
        self.assertTrue({'tinnhiemmang', 'ai_model', 'community'} <= keys)


class ChatGuardrailTest(TestCase):
    def test_chat_guardrail_never_asserts_safe_by_default(self):
        g = chat_guardrail('Toi nghi so nay co dau hieu lua dao.')
        self.assertEqual(g['tier'], 'INSUFFICIENT')
        self.assertFalse(g['is_conclusive'])
        self.assertTrue(g['requires_verification'])
        self.assertTrue(any('AI' in c for c in g['cautions']))
        self.assertTrue(len(g['official_channels']) >= 1)
        self.assertEqual(g['kind'], 'chat')

    def test_chat_guardrail_flags_absolute_safety_claim(self):
        g = chat_guardrail('Yen tam, so nay 100% an toan, khong co van de gi.')
        self.assertTrue(g['answer_asserts_absolute_safety'])
        self.assertEqual(g['tier'], 'INSUFFICIENT')
        self.assertFalse(g['is_conclusive'])

    def test_chat_guardrail_confirmed_from_tool_evidence(self):
        g = chat_guardrail(
            'So nay co dau hieu lua dao.',
            tool_results=[{
                'risk_score': 90,
                'tinnhiem': {'status': 'scam', 'record': {'impersonated': 'VCB', 'url': 'https://x'}},
            }],
        )
        self.assertEqual(g['tier'], 'CONFIRMED_RISK')
        self.assertTrue(g['is_conclusive'])
        self.assertTrue(any(e['source'] == 'tinnhiemmang' for e in g.get('evidence', [])))

    def test_chat_guardrail_decisive_when_evidence_is_clean(self):
        """Có bằng chứng sạch độ tin cậy cao -> KẾT LUẬN quyết đoán (LIKELY_SAFE), không hạ xuống INSUFFICIENT."""
        g = chat_guardrail(
            'Da doi chieu, URL nay sach tren nhieu engine.',
            tool_results=[{
                'virustotal': {
                    'available': True,
                    'stats': {'malicious': 0, 'suspicious': 0},
                    'total_engines': 90,
                    'permalink': 'https://www.virustotal.com/x',
                },
            }],
        )
        self.assertEqual(g['tier'], 'LIKELY_SAFE')
        self.assertTrue(any(e['supports'] == 'benign' for e in g['evidence']))

    def test_chat_guardrail_skips_general_chit_chat(self):
        """Chat kiến thức/hướng dẫn thông thường không bị gắn nhãn (giữ quyết đoán, tránh nhiễu)."""
        self.assertIsNone(chat_guardrail('OTP la ma dung mot lan, ban nen giu kin no.'))


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
