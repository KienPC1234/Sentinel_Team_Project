"""End-to-end resilience & step-by-step recommendation quality tests (Stage 2).

Covers 4 core failure/threat families:
1. OCR errors (ca OCR sai: crash, garbled symbol noise, OCR URL punctuation misread)
2. Dangerous URLs (URL nguy hiem: NCSC/VT phishing with and without AI)
3. Stale / noisy / contradictory sources (nguon loi thoi > 90 ngay, 404/reCAPTCHA, mau thuan)
4. Unavailable tools (cong cu khong hoat dong: VT crash, Ollama timeout/offline, OCR crash)
And evaluates step-by-step recommendation quality across 4 pipeline stages.
"""
import base64
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase, TestCase, override_settings

from api.core.models import RiskLevel, ScanEvent, ScanStatus
from api.core.tasks import perform_image_scan_task, perform_message_scan_task
from api.core.views import scan_views
from api.utils import ollama_client
from api.utils.media_utils import clean_ocr_text, is_garbled_ocr_text
from api.utils.trust_guard import apply_guardrail


_TINY_PNG_B64 = base64.b64encode(
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd4\x8d\x00\x00\x00\x00IEND\xaeB`\x82"
).decode("ascii")


def measure_recommendation_quality(result: dict, *, expected_tiers: tuple[str, ...]) -> dict:
    """Measure step-by-step pipeline quality across 4 stages (S1 Input -> S2 Guardrail -> S3 Explanation -> S4 Actions)."""
    guardrail = result.get("guardrail") or {}
    tier = guardrail.get("tier", "")
    explanation = str(result.get("explanation") or result.get("ai_insight") or "")
    actions = list(result.get("actions") or [])
    cautions = list(guardrail.get("cautions") or [])

    checks = {
        "s1_input_tool_isolation": "error" not in result or bool(guardrail),
        "s2_guardrail_aligned": tier in expected_tiers,
        "s3_explanation_clean_and_honest": (
            bool(explanation.strip())
            and not any(
                marker in explanation.lower()
                for marker in ("recaptcha", "cloudflare", "whoops! the page", "_tool_", "404 not found")
            )
            and (
                True
                if result.get("ai_available", True) or result.get("patterns_found")
                else "không phát hiện dấu hiệu lừa đảo rõ ràng" not in explanation.lower()
            )
        ),
        "s4_actions_complete": len(actions) >= 2 and all(isinstance(a, str) and len(a.strip()) > 5 for a in actions),
        "s4_cautions_and_no_false_safe": (
            len(cautions) >= 1
            and (
                True
                if tier == "LIKELY_SAFE"
                else not any(
                    phrase in txt.lower()
                    for txt in [explanation, *actions]
                    for phrase in ("chắc chắn an toàn", "an toàn tuyệt đối", "an toàn 100%")
                )
            )
        ),
    }
    passed = sum(1 for v in checks.values() if v)
    return {
        "checks": checks,
        "passed": passed,
        "total": len(checks),
        "quality_score": round(passed * 100.0 / len(checks), 1),
    }


@override_settings(CELERY_TASK_ALWAYS_EAGER=True)
class E2EScanResilienceTests(TestCase):
    """End-to-end resilience tests for OCR errors, dangerous URLs, stale sources, and tool outages."""

    def test_e2e_ocr_exception_yields_insufficient_and_safe_actions(self):
        event = ScanEvent.objects.create(
            scan_type="qr",
            raw_input="image_upload.png",
            status=ScanStatus.PENDING,
        )
        with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
             patch("api.utils.media_utils.extract_ocr_with_boxes", side_effect=RuntimeError("VietOCR crashed")), \
             patch("api.core.tasks._notify_scan_complete"):
            res = perform_image_scan_task(event.id, [{"content": _TINY_PNG_B64, "name": "broken.png"}])

        event.refresh_from_db()
        self.assertEqual(event.status, ScanStatus.COMPLETED)
        self.assertTrue(res.get("insufficient_input"))
        self.assertIn("nhận dạng chữ", res.get("explanation", "").lower())
        metrics = measure_recommendation_quality(res, expected_tiers=("INSUFFICIENT",))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)

    def test_e2e_garbled_ocr_short_circuits_before_llm_hallucination(self):
        self.assertTrue(is_garbled_ocr_text("||| ### ??? 0O1l"))
        self.assertFalse(is_garbled_ocr_text("Bien lai chuyen khoan 500.000 VND"))

        event = ScanEvent.objects.create(
            scan_type="qr",
            raw_input="noisy_ocr.png",
            status=ScanStatus.PENDING,
        )
        noisy_ocr = {"text": "||| ### ??? 0O1l", "qr_contents": [], "annotated_image_b64": ""}
        mock_ai = MagicMock()
        with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
             patch("api.utils.media_utils.extract_ocr_with_boxes", return_value=noisy_ocr), \
             patch("api.utils.ollama_client.analyze_text_for_scam", mock_ai), \
             patch("api.core.tasks._notify_scan_complete"):
            res = perform_image_scan_task(event.id, [{"content": _TINY_PNG_B64, "name": "noisy.png"}])

        mock_ai.assert_not_called()
        self.assertTrue(res.get("insufficient_input"))
        metrics = measure_recommendation_quality(res, expected_tiers=("INSUFFICIENT",))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)

    def test_e2e_ocr_url_punctuation_error_repaired_and_flagged_in_message_scan(self):
        raw_ocr_url = "Cap nhat VNeID tai https ://vneid-xacthuc,top/login ngay hom nay"
        repaired = clean_ocr_text(raw_ocr_url)
        self.assertIn("https://vneid-xacthuc.top/login", repaired)

        event = ScanEvent.objects.create(
            scan_type="message",
            raw_input="",
            status=ScanStatus.PENDING,
        )
        ocr_payload = {"text": raw_ocr_url, "qr_contents": [], "annotated_image_b64": ""}
        fake_vt = MagicMock()
        fake_vt.scan_url.return_value = {"risk_score": 90, "malicious": 4, "suspicious": 1}

        with patch("api.utils.media_utils.extract_ocr_with_boxes", return_value=ocr_payload), \
             patch("api.utils.vt_client.VTClient", return_value=fake_vt), \
             patch("api.utils.vn_sources.tinnhiem_lookup_domain", return_value={"status": "scam"}), \
             patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=RuntimeError("AI offline")), \
             patch("api.core.tasks._notify_scan_complete"):
            res = perform_message_scan_task(event.id, "", [{"content": _TINY_PNG_B64, "name": "sms.png"}])

        self.assertGreaterEqual(res["risk_score"], 90)
        self.assertIn("113", " ".join(res["actions"]))
        metrics = measure_recommendation_quality(res, expected_tiers=("CONFIRMED_RISK", "HIGH_RISK"))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)

    def test_e2e_malicious_url_in_message_propagates_to_confirmed_risk_and_urgent_actions(self):
        scam_msg = (
            "Tai khoan cua ban sap bi khoa. Vui long xac thuc ngay tai "
            "https://fake-bank-verify.invalid/login trong 30 phut."
        )
        fake_vt = MagicMock()
        fake_vt.scan_url.return_value = {"risk_score": 92, "malicious": 5, "suspicious": 1}
        fake_ai = {
            "is_scam": True,
            "risk_score": 95,
            "explanation": "Tin nhắn giả mạo ngân hàng, dùng tên miền lạ để đánh cắp thông tin đăng nhập.",
            "advice": "Không bấm vào đường dẫn và liên hệ ngân hàng qua tổng đài chính thức.",
            "prevention_measures": ["Không nhập mật khẩu hay mã OTP", "Chặn người gửi"],
        }

        with patch.object(scan_views, "VTClient", return_value=fake_vt), \
             patch("api.utils.vn_sources.tinnhiem_lookup_domain", return_value={"status": "scam"}), \
             patch.object(scan_views, "analyze_text_for_scam", return_value=fake_ai):
            res = scan_views._analyze_message_text(scam_msg, external_consent=False)

        self.assertGreaterEqual(res["risk_score"], 90)
        self.assertEqual(res["risk_level"], RiskLevel.RED)
        self.assertIn("113", " ".join(res["actions"]))
        metrics = measure_recommendation_quality(res, expected_tiers=("CONFIRMED_RISK", "HIGH_RISK"))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)

    def test_e2e_message_scan_task_isolates_vt_crash_and_ai_outage_honestly(self):
        event = ScanEvent.objects.create(
            scan_type="message",
            raw_input="Alo ban oi mai hop luc 9h tai phong 302 nhe https://intranet-company.invalid/doc",
            status=ScanStatus.PENDING,
        )
        broken_vt = MagicMock()
        broken_vt.scan_url.side_effect = ConnectionError("VirusTotal API unreachable")

        with patch("api.utils.vt_client.VTClient", return_value=broken_vt), \
             patch("api.utils.vn_sources.tinnhiem_lookup_domain", side_effect=RuntimeError("SQLite busy")), \
             patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=TimeoutError("Ollama timeout")), \
             patch("api.core.tasks._notify_scan_complete"):
            res = perform_message_scan_task(
                event.id,
                "Alo ban oi mai hop luc 9h tai phong 302 nhe https://intranet-company.invalid/doc",
                [],
            )

        event.refresh_from_db()
        self.assertEqual(event.status, ScanStatus.COMPLETED)
        self.assertFalse(res["ai_available"])
        self.assertIn("gián đoạn", res["explanation"].lower())
        metrics = measure_recommendation_quality(res, expected_tiers=("INSUFFICIENT",))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)

    def test_e2e_all_ai_retries_fail_in_image_scan_gracefully_degrades(self):
        event = ScanEvent.objects.create(
            scan_type="qr",
            raw_input="receipt.png",
            status=ScanStatus.PENDING,
        )
        ocr_ok = {"text": "Bien lai chuyen khoan 500.000 VND", "qr_contents": [], "annotated_image_b64": ""}
        with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
             patch("api.utils.media_utils.extract_ocr_with_boxes", return_value=ocr_ok), \
             patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=TimeoutError("LLM timeout")), \
             patch("api.core.tasks._notify_scan_complete"):
            res = perform_image_scan_task(event.id, [{"content": _TINY_PNG_B64, "name": "receipt.png"}])

        self.assertTrue(res.get("insufficient_input"))
        self.assertIn("3 lần thử", res.get("explanation", ""))
        metrics = measure_recommendation_quality(res, expected_tiers=("INSUFFICIENT",))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)


class E2EStaleAndNoisySourceTests(SimpleTestCase):
    """Tests for stale dataset snapshots (>90d), 404/reCAPTCHA filtering, and source contradictions."""

    def test_e2e_404_and_recaptcha_pages_are_filtered_from_threat_intel(self):
        noisy_page = (
            "Categories Blog Log in For businesses Whoops! The page you're looking for could not be found. "
            "This site is protected by reCAPTCHA. We collect device and interaction signals."
        )
        mock_http_resp = MagicMock(ok=True, text=f"<html><body>{noisy_page}</body></html>")
        with patch("requests.get", return_value=mock_http_resp), \
             patch.object(ollama_client, "web_fetch_url", return_value={"content": noisy_page, "title": "404", "links": []}), \
             patch.object(ollama_client, "web_search_query", return_value=[]):
            tp = ollama_client.lookup_trustpilot("example-scam.invalid")
            sj = ollama_client.lookup_sitejabber("example-scam.invalid")
            sa = ollama_client.lookup_scamadviser("example-scam.invalid")

        for item in (tp, sj, sa):
            if not item:
                continue
            content = (item.get("content") or "").lower()
            self.assertNotIn("recaptcha", content)
            self.assertNotIn("whoops!", content)
            if content:
                self.assertTrue(
                    any(k in content for k in ("không tìm thấy", "chưa có", "không lấy được")),
                    content,
                )

    def test_e2e_stale_benign_snapshot_downgrades_from_likely_safe_to_insufficient(self):
        result = {
            "risk_score": 0,
            "risk_level": "SAFE",
            "tinnhiem": {
                "found": True,
                "status": "trusted",
                "updated_at": "2024-05-01",
                "record": {"owner": "Old Company"},
            },
            "explanation": "Đối chiếu danh bạ Tín nhiệm mạng từ bản lưu cũ.",
            "actions": [
                "Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức (156 hoặc 113)",
                "Tuyệt đối không chuyển tiền, không cung cấp OTP khi chưa xác minh",
            ],
        }
        apply_guardrail(result, kind="domain")
        self.assertIn("tinnhiemmang", result["guardrail"]["stale_sources"])
        self.assertEqual(result["guardrail"]["tier"], "INSUFFICIENT")
        self.assertFalse(result["verdict_conclusive"])
        metrics = measure_recommendation_quality(result, expected_tiers=("INSUFFICIENT",))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)

    def test_e2e_contradiction_between_benign_tinnhiem_and_malicious_vt_downgrades_to_insufficient(self):
        result = {
            "risk_score": 85,
            "risk_level": "RED",
            "tinnhiem": {"found": True, "status": "trusted", "name": "Demo"},
            "virustotal": {"available": True, "stats": {"malicious": 4, "suspicious": 1, "harmless": 60}, "total_engines": 65},
            "explanation": "Có mâu thuẫn giữa danh bạ tin cậy và cảnh báo kỹ thuật.",
            "actions": [
                "Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức",
                "Không nhập mật khẩu hay OTP khi chưa kiểm chứng",
            ],
        }
        apply_guardrail(result, kind="domain")
        self.assertTrue(result["guardrail"]["has_contradiction"])
        metrics = measure_recommendation_quality(result, expected_tiers=("INSUFFICIENT",))
        self.assertEqual(metrics["quality_score"], 100.0, metrics)
