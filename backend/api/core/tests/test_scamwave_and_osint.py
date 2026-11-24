from types import SimpleNamespace
from unittest.mock import patch

from django.test import SimpleTestCase, TestCase

from api.utils import ollama_client as oc
from api.utils import scamwave
from api.utils import trust_guard as tg


class ScamWaveIntegrationTests(SimpleTestCase):
    def test_source_catalog_includes_scamwave_with_limits_and_url(self):
        catalog = {item['key']: item for item in tg.source_catalog()}
        self.assertIn('scamwave', catalog)
        sw = catalog['scamwave']
        self.assertEqual(sw['url'], 'https://scamwave.com')
        self.assertTrue(sw.get('limits'))
        self.assertTrue(sw.get('updated_at'))

    def test_build_evidence_handles_scamwave_hit_and_miss(self):
        hit_ev = tg.build_evidence({
            'scamwave': {
                'checked': True,
                'matched': True,
                'primary_status': 'Scam',
                'query_url': 'https://scamwave.com/scammers/',
                'updated_at': '2026-11-16',
            }
        })
        sw_items = [e for e in hit_ev if e['source'] == 'scamwave']
        self.assertEqual(len(sw_items), 1)
        self.assertEqual(sw_items[0]['supports'], 'malicious')
        self.assertEqual(sw_items[0]['url'], 'https://scamwave.com/scammers/')

        miss_ev = tg.build_evidence({
            'scamwave': {
                'checked': True,
                'matched': False,
                'primary_status': None,
                'query_url': 'https://scamwave.com/scammers/',
                'updated_at': '2026-11-16',
            }
        })
        miss_items = [e for e in miss_ev if e['source'] == 'scamwave']
        self.assertEqual(len(miss_items), 1)
        self.assertEqual(miss_items[0]['supports'], 'context')

    def test_exact_domain_match_prevents_substring_false_positive(self):
        sample_rows = [
            {'name': 'downloadmanager.ir', 'normalized': 'downloadmanager.ir', 'status': 'Scam'},
        ]
        sample_map = {'downloadmanager.ir': [sample_rows[0]]}
        with patch.object(scamwave, '_load_index', return_value=(sample_map, sample_rows, {'updated_at': '2026-11-16', 'count': 1})):
            hit = scamwave.lookup_scamwave('https://www.downloadmanager.ir/Faq/faq_preorder.htm')
            self.assertTrue(hit['matched'])
            self.assertEqual(hit['primary_status'], 'Scam')

            miss = scamwave.lookup_scamwave('manager.ir')
            self.assertFalse(miss['matched'])
            self.assertIsNone(miss['primary_status'])


class OsintPipelineRegressionTests(TestCase):
    def test_sanitize_web_context_preserves_unstructured_real_findings(self):
        raw = (
            "### [Web search / Kiểm chứng chính thức]\n"
            "Trang chủ nhà phát hành Tonec xác nhận downloadmanager.ir là đại lý chính thức tại Iran.\n\n"
            "### [Tranco]\n"
            "Domain not found in top 1M list (Low Popularity)\n\n"
            "### [Kết luận chung]\n"
            "- **Đánh giá/Điểm số**: Không có dữ liệu\n"
            "- **Chi tiết quan trọng**: Không tìm thấy thông tin cụ thể."
        )
        sanitized = oc._sanitize_web_context(raw)
        self.assertIn('Tonec xác nhận downloadmanager.ir là đại lý chính thức', sanitized)
        self.assertIn('Không nằm trong Top 1M', sanitized)
        # Empty conclusion filler should be pruned when real findings exist
        self.assertNotIn('[Kết luận chung]', sanitized)
        # Substantive section should have tool jargon stripped and come before neutral section
        self.assertNotIn('Web search /', sanitized)
        self.assertLess(
            sanitized.index('Kiểm chứng chính thức'),
            sanitized.index('Tranco'),
        )

    def test_medium_score_58_with_scamwave_stays_suspicious_not_high_risk(self):
        guard = tg.assess({
            'risk_score': 58,
            'ai_available': True,
            'ai_score': 58,
            'ai_is_scam': False,
            'scamwave': {
                'checked': True,
                'matched': True,
                'primary_status': 'Scam',
                'query_url': 'https://scamwave.com/scammers/',
                'updated_at': '2026-11-16',
            },
        }, kind='url')
        self.assertEqual(guard['tier'], 'SUSPICIOUS')

    def test_sanitize_web_context_strips_tool_jargon_prefixes(self):
        raw = (
            "### [Web fetch / Trang chủ nhà phát hành]\n"
            "- **Đánh giá/Điểm số**: Có dữ liệu\n"
            "- **Chi tiết quan trọng**: Đã đối chiếu trang chính thức."
        )
        sanitized = oc._sanitize_web_context(raw)
        self.assertIn('### [Trang chủ nhà phát hành]', sanitized)
        self.assertNotIn('Web fetch', sanitized)

    def test_search_agent_runs_synthesis_fallback_when_max_iterations_reached(self):
        tool_call = SimpleNamespace(
            id='call_1',
            function=SimpleNamespace(
                name='_tool_web_fetch',
                arguments={'url': 'https://www.internetdownloadmanager.com/resellers/reseller_ir.html'},
            ),
        )
        msg_with_tool = SimpleNamespace(content='', tool_calls=[tool_call])
        msg_final = SimpleNamespace(
            content='### [Web search]\n- **Đánh giá/Điểm số**: An toàn\n- **Chi tiết quan trọng**: Đại lý được Tonec xác nhận.',
            tool_calls=None,
        )
        progress_events = []

        with patch.object(oc, '_tool_web_fetch', return_value={'content': 'Authorized reseller downloadmanager.ir'}), \
             patch.object(oc, '_chat_with_retry', side_effect=[
                 SimpleNamespace(message=msg_with_tool),
                 SimpleNamespace(message=msg_final),
             ]) as mock_chat:
            res = oc.search_agent(
                query='Kiểm tra downloadmanager.ir',
                max_iterations=1,
                progress_callback=lambda m, s: progress_events.append((m, s)),
            )

        self.assertIsNotNone(res)
        self.assertIn('Đại lý được Tonec xác nhận', res['answer'])
        self.assertIn('https://www.internetdownloadmanager.com/resellers/reseller_ir.html', res['searched_urls'])
        self.assertEqual(mock_chat.call_count, 2)
        self.assertTrue(any(step == 'osint_synthesize' for _, step in progress_events))

    def test_scam_rules_detect_ocr_wrapped_shopee_task_scam(self):
        from api.utils.scam_rules import heuristic_score, match_patterns
        import re
        raw_ocr = (
            "HR Tuyến Dụng Shopee/TikTok Shop: cộng tác viên Online xử lý đơn hàng ảo.\n"
            "Đường link đăng ký: https: I/shopee-mall-\nnhiemvu-vip.top/register.php?code=HR992\n"
            "Sau khi đăng ký, bạn nạp 150.000 phí kích hoạt, hoa hồng 20% chuyển khoản."
        )
        repaired = re.sub(r'(https?)\s*:\s*(?:/\s*/|[Il|]/)', r'\1://', raw_ocr, flags=re.IGNORECASE)
        repaired = re.sub(r'([a-zA-Z0-9-])-\s*\n\s*([a-zA-Z0-9-]+\.[a-z]{2,})', r'\1-\2', repaired)
        self.assertIn('https://shopee-mall-nhiemvu-vip.top/register.php?code=HR992', repaired)
        self.assertGreaterEqual(heuristic_score(repaired), 70)
        self.assertGreaterEqual(len(match_patterns(repaired)), 3)

    def test_perform_message_scan_task_runs_with_url_and_vn_lookup(self):
        from api.core.models import ScanEvent, ScanStatus, ScanType
        from api.core.tasks import perform_message_scan_task

        event = ScanEvent.objects.create(
            scan_type=ScanType.MESSAGE,
            raw_input='Tuyen CTV nap phi kich hoat https://shopee-mall-nhiemvu-vip.top',
            status=ScanStatus.PENDING,
        )
        fake_ai = {
            'is_scam': True,
            'risk_score': 92,
            'explanation': 'Tin nhắn có dấu hiệu tuyển cộng tác viên lừa đảo.',
            'web_sources': ['ScamWave'],
            'web_context': '',
            'searched_urls': [],
            'db_sources_consulted': ['scamwave'],
        }
        with patch('api.utils.ollama_client.analyze_text_for_scam', return_value=fake_ai), \
             patch('api.utils.vt_client.VTClient.scan_url', return_value={'risk_score': 0}):
            res = perform_message_scan_task(event.id, event.raw_input, [])

        event.refresh_from_db()
        self.assertEqual(event.status, ScanStatus.COMPLETED)
        self.assertEqual(res['risk_level'], 'RED')
        self.assertGreaterEqual(res['risk_score'], 90)
