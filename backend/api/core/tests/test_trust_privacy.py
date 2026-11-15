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
        for ch in resp.data['channels']:
            self.assertTrue(ch.get('verified_on'))


class FinalRequirementsGuardrailAndPrivacyTest(TestCase):
    def test_source_catalog_and_evidence_have_updated_at_and_citation(self):
        for s in source_catalog():
            self.assertTrue(s.get('updated_at'), f"Missing updated_at for {s['key']}")
            self.assertTrue(s.get('citation'), f"Missing citation for {s['key']}")

        r = apply_guardrail({
            'risk_score': 85,
            'tinnhiem': {'status': 'scam', 'record': {'impersonated': 'VCB', 'url': 'https://tinnhiemmang.vn'}},
        }, kind='domain')
        self.assertTrue(len(r['evidence']) >= 1)
        for ev in r['evidence']:
            self.assertTrue(ev.get('updated_at'))
            self.assertTrue(ev.get('citation'))

    def test_contradictory_evidence_forces_insufficient_and_refuses_overconclusion(self):
        # High-reliability VT clean vs heuristic flag -> contradiction -> INSUFFICIENT
        r = apply_guardrail({
            'risk_score': 45,
            'virustotal': {
                'available': True,
                'stats': {'malicious': 0, 'suspicious': 0},
                'total_engines': 72,
                'permalink': 'https://www.virustotal.com/clean',
            },
            'reasons': ['Phát hiện từ khóa rủi ro cao trong nội dung trang'],
        }, kind='url')
        g = r['guardrail']
        self.assertEqual(g['tier'], 'INSUFFICIENT')
        self.assertFalse(g['is_conclusive'])
        self.assertTrue(g['requires_verification'])
        self.assertTrue(g['has_contradiction'])
        self.assertTrue(len(g['contradiction_details']) >= 1)

        # Trusted NCSC tinnhiemmang vs external VT >=3 -> contradiction -> INSUFFICIENT
        r2 = apply_guardrail({
            'risk_score': 75,
            'tinnhiem': {'status': 'trusted', 'record': {'owner': 'Ngân hàng A', 'url': 'https://tinnhiemmang.vn'}},
            'virustotal': {
                'available': True,
                'stats': {'malicious': 3, 'suspicious': 1},
                'total_engines': 70,
                'permalink': 'https://www.virustotal.com/conflict',
            },
        }, kind='domain')
        self.assertEqual(r2['guardrail']['tier'], 'INSUFFICIENT')
        self.assertFalse(r2['guardrail']['is_conclusive'])
        self.assertTrue(r2['guardrail']['has_contradiction'])

    def test_account_and_phone_never_conclusive_and_pending_reports_capped(self):
        from django.contrib.auth import get_user_model
        from api.core.models import Report

        user = get_user_model().objects.create_user(username='acc_tester', password='pw')
        Report.objects.create(
            reporter=user,
            target_type='account',
            target_value='999888777666',
            scam_type='other',
            description='Bao cao cho duyet',
            status='pending',
            scammer_bank_account='999888777666',
            scammer_bank_name='Vietcombank',
        )
        client = APIClient()
        client.force_authenticate(user=user)
        resp = client.post('/api/v1/scan/account/', {
            'bank': 'Vietcombank',
            'account': '999888777666',
        }, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertLessEqual(resp.data['risk_score'], 35)
        self.assertEqual(resp.data['reports_pending'], 1)
        self.assertEqual(resp.data['reports_verified'], 0)
        self.assertEqual(resp.data['guardrail']['tier'], 'INSUFFICIENT')
        self.assertFalse(resp.data['guardrail']['is_conclusive'])
        self.assertTrue(resp.data['guardrail']['requires_verification'])

        # Even high-risk phone scan is never marked conclusive
        phone_g = apply_guardrail({
            'risk_score': 88,
            'reasons': ['3 báo cáo cộng đồng đã duyệt - dấu hiệu rủi ro cao'],
        }, kind='phone')['guardrail']
        self.assertEqual(phone_g['tier'], 'HIGH_RISK')
        self.assertFalse(phone_g['is_conclusive'])
        self.assertTrue(phone_g['requires_verification'])

    def test_user_data_deletion_endpoints_and_idor(self):
        from django.contrib.auth import get_user_model
        from api.core.models import ScanEvent, UserAlert
        from api.ai_chat.models import ChatSession

        User = get_user_model()
        owner = User.objects.create_user(username='del_owner', password='pw')
        other = User.objects.create_user(username='del_other', password='pw')

        s1 = ScanEvent.objects.create(user=owner, scan_type='message', raw_input='sample 1')
        s2 = ScanEvent.objects.create(user=owner, scan_type='url', raw_input='https://a.test')
        ChatSession.objects.create(user=owner, title='Chat 1')
        UserAlert.objects.create(user=owner, target_type='phone', target_value='0900000001')

        # Other user cannot delete owner's scan
        other_client = APIClient()
        other_client.force_authenticate(user=other)
        r_forbid = other_client.delete(f'/api/v1/user/scans/{s1.id}/')
        self.assertEqual(r_forbid.status_code, 403)
        self.assertTrue(ScanEvent.objects.filter(id=s1.id).exists())

        # Owner deletes single scan
        owner_client = APIClient()
        owner_client.force_authenticate(user=owner)
        r_del1 = owner_client.delete(f'/api/v1/user/scans/{s1.id}/')
        self.assertEqual(r_del1.status_code, 200)
        self.assertFalse(ScanEvent.objects.filter(id=s1.id).exists())
        self.assertTrue(ScanEvent.objects.filter(id=s2.id).exists())

        # Owner deletes selective privacy scopes
        r_priv = owner_client.post('/api/v1/user/privacy/delete-data/', {
            'scopes': ['scans', 'chat_sessions', 'alerts'],
        }, format='json')
        self.assertEqual(r_priv.status_code, 200)
        self.assertEqual(r_priv.data['deleted'], {'scans': 1, 'chat_sessions': 1, 'alerts': 1})
        self.assertEqual(ScanEvent.objects.filter(user=owner).count(), 0)
        self.assertEqual(ChatSession.objects.filter(user=owner).count(), 0)
        self.assertEqual(UserAlert.objects.filter(user=owner).count(), 0)

    def test_cloud_llm_retry_preserves_pii_redaction(self):
        from unittest.mock import patch
        from api.utils import ollama_client as oc

        calls = []

        def fake_gen(*args, **kwargs):
            calls.append(kwargs.get('allow_pii'))
            # Return invalid JSON first 2 times to trigger repair & retry, then valid JSON
            if len(calls) < 3:
                return 'NOT_VALID_JSON'
            return '{"is_scam": false, "risk_score": 10, "indicators": [], "explanation": "ok", "web_sources": []}'

        with patch.object(oc, 'OLLAMA_API_KEY', 'test-cloud-key'), \
             patch.object(oc, 'generate_response', side_effect=fake_gen):
            oc.analyze_text_for_scam(
                'Tin nhan thu nghiem co SDT 0912345678',
                model='qwen3.5:cloud',
                use_web_search=False,
                external_consent=False,
            )

        self.assertEqual(len(calls), 3)
        self.assertEqual(calls, [False, False, False])


class PerScanPrivacyToggleTest(TestCase):
    """Tests cho nút gạt `mask_pii` thống nhất trên mọi loại scan và SSE."""

    def test_privacy_display_helpers(self):
        from api.utils.privacy import mask_phone_display, mask_email_display, mask_url_query, redact_pii

        self.assertEqual(mask_phone_display('0987654321'), '098****321')
        self.assertEqual(mask_phone_display('+84978589220'), '+849****220')
        self.assertEqual(mask_email_display('nguyen.van.a@gmail.com'), 'ng***@gmail.com')

        masked_url = mask_url_query('https://example.com/reset?token=supersecrettoken123456&email=alice@example.com&tab=1')
        self.assertIn('https://example.com/reset?', masked_url)
        self.assertNotIn('supersecrettoken123456', masked_url)
        self.assertNotIn('alice@example.com', masked_url)
        self.assertIn('tab=1', masked_url)

        bearer_out = redact_pii('Authorization: Bearer super_secret_bearer_token_value_1234')
        self.assertNotIn('super_secret_bearer_token_value_1234', bearer_out)
        self.assertIn('[khoá/bí mật đã ẩn]', bearer_out)

    def test_scan_phone_respects_mask_pii_default_and_opt_out(self):
        from django.contrib.auth import get_user_model
        from api.core.models import ScanEvent

        User = get_user_model()
        u = User.objects.create_user(username='phone_privacy_u', password='x')
        client = APIClient()
        client.force_authenticate(user=u)

        # Default (mask_pii=True)
        r_masked = client.post('/api/v1/scan/phone/', {'phone': '+84978589220'}, format='json')
        self.assertEqual(r_masked.status_code, 200)
        self.assertTrue(r_masked.data.get('privacy_masked'))
        self.assertEqual(r_masked.data.get('phone'), '+849****220')
        ev_masked = ScanEvent.objects.get(id=r_masked.data['scan_id'])
        self.assertEqual(ev_masked.raw_input, '+849****220')
        self.assertEqual(ev_masked.normalized_input, '+849****220')

        # Opt-out (mask_pii=False)
        r_full = client.post('/api/v1/scan/phone/', {'phone': '+84978589220', 'mask_pii': False}, format='json')
        self.assertEqual(r_full.status_code, 200)
        self.assertFalse(r_full.data.get('privacy_masked'))
        self.assertEqual(r_full.data.get('phone'), '+84978589220')
        ev_full = ScanEvent.objects.get(id=r_full.data['scan_id'])
        self.assertEqual(ev_full.raw_input, '+84978589220')

    def test_scan_message_and_account_privacy_toggle(self):
        from unittest.mock import patch
        from django.contrib.auth import get_user_model
        from api.core.models import ScanEvent

        User = get_user_model()
        u = User.objects.create_user(username='msg_privacy_u', password='x')
        client = APIClient()
        client.force_authenticate(user=u)

        # Message sync with mask_pii=True keeps rule/AI detection working while masking persisted input
        with patch('api.core.views.scan_views.analyze_text_for_scam', return_value={
            'risk_score': 80,
            'explanation': 'Tin nhan yeu cau chuyen tien toi STK 1902847562 hoac goi 0912345678.',
        }):
            r_msg = client.post('/api/v1/scan/message/', {
                'message': 'Chuyen tien gap vao STK 1902847562 va goi 0912345678 nhan qua OTP',
                'sync': True,
                'mask_pii': True,
            }, format='json')
        self.assertEqual(r_msg.status_code, 200)
        self.assertGreater(r_msg.data['risk_score'], 0)
        self.assertTrue(r_msg.data.get('privacy_masked'))
        ev_msg = ScanEvent.objects.get(id=r_msg.data['scan_id'])
        self.assertNotIn('1902847562', ev_msg.raw_input)
        self.assertNotIn('0912345678', ev_msg.raw_input)
        self.assertNotIn('1902847562', r_msg.data.get('explanation', ''))

        # Bank account default masked vs opt-out display
        r_acc_masked = client.post('/api/v1/scan/account/', {
            'bank': 'MBBank',
            'account': '1902847562',
        }, format='json')
        self.assertEqual(r_acc_masked.status_code, 200)
        self.assertTrue(r_acc_masked.data.get('privacy_masked'))
        self.assertNotIn('1902847562', r_acc_masked.data.get('account_display', ''))

        r_acc_full = client.post('/api/v1/scan/account/', {
            'bank': 'MBBank',
            'account': '1902847562',
            'mask_pii': False,
        }, format='json')
        self.assertEqual(r_acc_full.status_code, 200)
        self.assertFalse(r_acc_full.data.get('privacy_masked'))
        self.assertEqual(r_acc_full.data.get('account_display'), '1902847562')
        self.assertNotEqual(r_acc_full.data.get('account_masked'), '1902847562')

    def test_scan_domain_masks_sensitive_query_and_sse_honors_mask_pii(self):
        from unittest.mock import patch
        from django.contrib.auth import get_user_model
        from api.core.models import ScanEvent

        User = get_user_model()
        u = User.objects.create_user(username='dom_privacy_u', password='x')
        client = APIClient()
        client.force_authenticate(user=u)

        with patch('api.core.views.scan_views._analyze_domain', return_value={
            'domain': 'example-verify.top',
            'url': 'https://example-verify.top/login?token=secret_tok_987654321&email=victim@gmail.com',
            'risk_score': 65,
            'risk_level': 'YELLOW',
            'details': [],
        }):
            r_dom = client.post('/api/v1/scan/domain/', {
                'url': 'https://example-verify.top/login?token=secret_tok_987654321&email=victim@gmail.com',
                'mask_pii': True,
            }, format='json')

        self.assertEqual(r_dom.status_code, 200)
        self.assertTrue(r_dom.data.get('privacy_masked'))
        self.assertEqual(r_dom.data.get('domain'), 'example-verify.top')
        self.assertNotIn('secret_tok_987654321', r_dom.data.get('url', ''))
        self.assertNotIn('victim@gmail.com', r_dom.data.get('url', ''))
        ev = ScanEvent.objects.get(id=r_dom.data['scan_id'])
        self.assertNotIn('secret_tok_987654321', ev.raw_input)

        # SSE stream honors ev.privacy_masked=True even if caller tries allow_pii=True
        captured = {}

        def fake_stream(prompt, **kwargs):
            captured['allow_pii'] = kwargs.get('allow_pii')
            captured['prompt'] = prompt
            yield 'ok'

        with patch('api.core.views.stream_views.stream_response', side_effect=fake_stream):
            r_sse = client.post('/api/v1/scan/analyze-sse/', {
                'scan_id': ev.id,
                'consent_external_llm': True,
                'allow_pii': True,
            }, format='json')
            list(r_sse.streaming_content)

        self.assertEqual(r_sse.status_code, 200)
        self.assertFalse(captured['allow_pii'])
        self.assertNotIn('secret_tok_987654321', captured['prompt'])

    def test_scan_message_forwards_user_privacy_consent_to_ai_and_keeps_masked_prompt_analyzable(self):
        import hashlib
        import uuid
        from unittest.mock import patch
        from django.contrib.auth import get_user_model
        from django.core.cache import cache
        from api.utils import ollama_client as oc

        User = get_user_model()
        u = User.objects.create_user(username='msg_consent_u', password='x')
        client = APIClient()
        client.force_authenticate(user=u)

        seen_prompts = []

        def fake_gen(prompt, *args, **kwargs):
            seen_prompts.append((kwargs.get('allow_pii'), prompt))
            return '{"is_scam": true, "risk_score": 82, "indicators": ["Chuyển tiền vào STK"], "explanation": "Yêu cầu chuyển tiền khả nghi.", "web_sources": []}'

        sample_msg = f'Anh chuyen gap 5 trieu vao STK 1902847562 hoac goi 0912345678 nhan OTP [{uuid.uuid4().hex[:8]}]'
        msg_digest = hashlib.sha256(sample_msg.encode('utf-8')).hexdigest()
        try:
            with patch.object(oc, 'OLLAMA_API_KEY', 'test-cloud-key'), \
                 patch.object(oc, 'generate_response', side_effect=fake_gen):
                r_masked = client.post('/api/v1/scan/message/', {
                    'message': sample_msg,
                    'sync': True,
                    'mask_pii': True,
                }, format='json')
                r_full = client.post('/api/v1/scan/message/', {
                    'message': sample_msg,
                    'sync': True,
                    'mask_pii': False,
                }, format='json')
        finally:
            cache.delete(f'msg_analysis:0:{msg_digest}')
            cache.delete(f'msg_analysis:1:{msg_digest}')

        self.assertEqual(r_masked.status_code, 200)
        self.assertEqual(r_full.status_code, 200)
        self.assertEqual(len(seen_prompts), 2)
        allow_masked, prompt_masked = seen_prompts[0]
        allow_full, _ = seen_prompts[1]
        self.assertFalse(allow_masked)
        self.assertTrue(allow_full)
        self.assertIn('PII REDACTION', prompt_masked)
        self.assertIn('[SĐT đã ẩn]', prompt_masked)

    def test_empty_ocr_and_ai_fallback_never_saved_as_safe_in_db(self):
        from unittest.mock import patch
        from api.core.models import ScanEvent, RiskLevel
        from api.core.tasks import perform_scan_task, _has_external_pii_consent

        ev_masked = ScanEvent.objects.create(
            scan_type='email',
            raw_input='sc***@fake-bank.top',
            result_json={'privacy_masked': True},
        )
        self.assertFalse(_has_external_pii_consent(ev_masked))

        ev_full = ScanEvent.objects.create(
            scan_type='email',
            raw_input='victim@fake-bank.top',
            result_json={'privacy_masked': False},
        )
        self.assertTrue(_has_external_pii_consent(ev_full))

        with patch('api.utils.ollama_client.analyze_text_for_scam', return_value=None):
            perform_scan_task.run(ev_masked.id)

        ev_masked.refresh_from_db()
        self.assertNotEqual(ev_masked.risk_level, RiskLevel.SAFE)
        self.assertEqual(ev_masked.result_json.get('guardrail', {}).get('tier'), 'INSUFFICIENT')


