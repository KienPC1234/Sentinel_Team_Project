#!/usr/bin/env python3
"""Stage 2 End-to-End Evaluation & Step-by-Step Recommendation Quality Benchmark.

Evaluates 20 curated end-to-end scenarios across 4 failure/threat families:
  1. OCR Errors (5 cases: engine exception, garbled noise, URL comma/space misread, blank image)
  2. Dangerous URLs (5 cases: NCSC scam, VT multi-engine phishing, ScamWave + rule, AI offline on phishing, APK lure)
  3. Stale & Noisy Sources (5 cases: stale NCSC >90d, Trustpilot 404+reCAPTCHA, ScamAdviser Cloudflare wall, SiteJabber 404, NCSC-vs-VT contradiction)
  4. Tool Outages (5 cases: VT+NCSC exception on benign text, Ollama offline on benign text, 3x AI retry failure on OCR, ScamWave+AI outage on suspicious SMS, full external outage)

Outputs structured JSON metrics (including Before vs After comparison per stage) to stdout or --out.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings_ci")

import django  # noqa: E402

django.setup()

from django.core.management import call_command  # noqa: E402

call_command("migrate", "--run-syncdb", verbosity=0)

from api.core.models import ScanEvent, ScanStatus  # noqa: E402
from api.core.tasks import perform_image_scan_task, perform_message_scan_task  # noqa: E402
from api.core.tests.test_e2e_scan_resilience import measure_recommendation_quality  # noqa: E402
from api.core.views import scan_views  # noqa: E402
from api.utils import ollama_client  # noqa: E402
from api.utils.trust_guard import apply_guardrail  # noqa: E402

_TINY_PNG = base64.b64encode(
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
    b"\x00\x01\x01\x00\x05\x18\xd4\x8d\x00\x00\x00\x00IEND\xaeB`\x82"
).decode("ascii")


def run_benchmark() -> dict:
    cases = []

    # --- GROUP 1: CA OCR SAI (5 cases) ---
    # 1.1 OCR engine crash in QR/image scan
    ev1 = ScanEvent.objects.create(scan_type="qr", raw_input="ocr_crash.png", status=ScanStatus.PENDING)
    with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
         patch("api.utils.media_utils.extract_ocr_with_boxes", side_effect=RuntimeError("VietOCR bridge crashed")), \
         patch("api.core.tasks._notify_scan_complete"):
        r1 = perform_image_scan_task(ev1.id, [{"content": _TINY_PNG, "name": "ocr_crash.png"}])
    cases.append(("OCR_01_engine_crash_image", "ocr_error", r1, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
        "s3_explanation_clean_and_honest": False, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": True,
    }))

    # 1.2 Garbled symbol noise in image scan
    ev2 = ScanEvent.objects.create(scan_type="qr", raw_input="garbled.png", status=ScanStatus.PENDING)
    with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
         patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "||| ### ~~~ ??? 0_0", "qr_contents": [], "annotated_image_b64": ""}), \
         patch("api.core.tasks._notify_scan_complete"):
        r2 = perform_image_scan_task(ev2.id, [{"content": _TINY_PNG, "name": "garbled.png"}])
    cases.append(("OCR_02_garbled_symbols_shortcircuit", "ocr_error", r2, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": False,
        "s3_explanation_clean_and_honest": False, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": False,
    }))

    # 1.3 OCR URL comma/space misread in message screenshot
    ev3 = ScanEvent.objects.create(scan_type="message", raw_input="", status=ScanStatus.PENDING)
    vt_mal = MagicMock()
    vt_mal.scan_url.return_value = {"risk_score": 90, "malicious": 4, "suspicious": 1}
    with patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "Xac thuc VNeID tai https ://vneid-capnhat,top/login", "qr_contents": [], "annotated_image_b64": ""}), \
         patch("api.utils.vt_client.VTClient", return_value=vt_mal), \
         patch("api.utils.vn_sources.tinnhiem_lookup_domain", return_value={"status": "scam"}), \
         patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=RuntimeError("AI offline")), \
         patch("api.core.tasks._notify_scan_complete"):
        r3 = perform_message_scan_task(ev3.id, "", [{"content": _TINY_PNG, "name": "url_ocr.png"}])
    cases.append(("OCR_03_misread_phishing_url_repaired", "ocr_error", r3, ("CONFIRMED_RISK", "HIGH_RISK"), {
        "s1_input_tool_isolation": False, "s2_guardrail_aligned": False,
        "s3_explanation_clean_and_honest": False, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": True,
    }))

    # 1.4 OCR failure on screenshot-only message scan (previously ScanStatus.FAILED)
    ev4 = ScanEvent.objects.create(scan_type="message", raw_input="", status=ScanStatus.PENDING)
    with patch("api.utils.media_utils.extract_ocr_with_boxes", side_effect=RuntimeError("Tesseract missing")), \
         patch("api.core.tasks._notify_scan_complete"):
        r4 = perform_message_scan_task(ev4.id, "", [{"content": _TINY_PNG, "name": "msg_img_err.png"}])
    cases.append(("OCR_04_message_screenshot_ocr_crash", "ocr_error", r4 or {}, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": False, "s2_guardrail_aligned": False,
        "s3_explanation_clean_and_honest": False, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": False,
    }))

    # 1.5 Blank image (0 OCR chars, 0 QR)
    ev5 = ScanEvent.objects.create(scan_type="qr", raw_input="blank.png", status=ScanStatus.PENDING)
    with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
         patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "", "qr_contents": [], "annotated_image_b64": ""}), \
         patch("api.core.tasks._notify_scan_complete"):
        r5 = perform_image_scan_task(ev5.id, [{"content": _TINY_PNG, "name": "blank.png"}])
    cases.append(("OCR_05_blank_image_no_text", "ocr_error", r5, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
        "s3_explanation_clean_and_honest": True, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": True,
    }))

    # --- GROUP 2: URL NGUY HIEM (5 cases) ---
    for idx, (cid, sms, tn_st, vt_score, vt_m, ai_down) in enumerate([
        ("URL_01_ncsc_blacklisted_bank_phish", "TK VCB sap khoa, xac thuc tai https://vcb-digibank-verify.invalid/login", "scam", 95, 6, False),
        ("URL_02_vt_consensus_tax_apk", "Tai ung dung Thue dien tu https://thuedientu-gov.invalid/etax.apk", None, 92, 5, False),
        ("URL_03_phish_url_when_ai_offline", "Nhan ho tro BHXH tai https://bhxh-nhantien.invalid/claim", "scam", 88, 3, True),
        ("URL_04_delivery_fee_micro_phish", "Don hang VN882 tam giu, thanh toan 5.000d phi luu kho https://vnpost-cod.invalid/pay", None, 86, 4, False),
        ("URL_05_evn_power_cutoff_url", "EVN thong bao cat dien sau 2h neu khong thanh toan tai https://evn-hanoi-pay.invalid", "scam", 94, 5, True),
    ], 1):
        vt_mck = MagicMock()
        vt_mck.scan_url.return_value = {"risk_score": vt_score, "malicious": vt_m, "suspicious": 1}
        ai_ctx = (
            patch.object(scan_views, "analyze_text_for_scam", side_effect=RuntimeError("AI offline"))
            if ai_down
            else patch.object(scan_views, "analyze_text_for_scam", return_value={
                "is_scam": True, "risk_score": 93,
                "explanation": "Tin nhắn mạo danh tổ chức uy tín kèm đường dẫn giả mạo nhằm đánh cắp thông tin.",
                "advice": "Tuyệt đối không truy cập liên kết và không cài đặt tệp lạ.",
                "prevention_measures": ["Không nhập mật khẩu/OTP", "Báo cơ quan công an 113"],
            })
        )
        with patch.object(scan_views, "VTClient", return_value=vt_mck), \
             patch("api.utils.vn_sources.tinnhiem_lookup_domain", return_value=({"status": tn_st} if tn_st else None)), \
             ai_ctx:
            r_url = scan_views._analyze_message_text(sms, external_consent=False)
        cases.append((cid, "dangerous_url", r_url, ("CONFIRMED_RISK", "HIGH_RISK"), {
            "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
            "s3_explanation_clean_and_honest": True, "s4_actions_complete": True, "s4_cautions_and_no_false_safe": True,
        }))

    # --- GROUP 3: NGUON LOI THOI & TRANG LOI (5 cases) ---
    # 3.1 Stale NCSC trusted snapshot (>90 days)
    r_s1 = {
        "risk_score": 0, "risk_level": "SAFE",
        "tinnhiem": {"found": True, "status": "trusted", "updated_at": "2024-03-15", "record": {"owner": "Expired Org"}},
        "explanation": "Bản ghi chứng nhận cũ quá hạn cập nhật.",
        "actions": ["Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức (156 hoặc 113)", "Không chuyển tiền khi chưa xác minh"],
    }
    apply_guardrail(r_s1, kind="domain")
    cases.append(("STALE_01_ncsc_snapshot_over_90d", "stale_or_noisy_source", r_s1, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": False,
        "s3_explanation_clean_and_honest": True, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": False,
    }))

    # 3.2 - 3.4 Trustpilot / SiteJabber / ScamAdviser 404 & reCAPTCHA & Cloudflare walls
    noisy_html = "Whoops! The page you're looking for could not be found. This site is protected by reCAPTCHA and Cloudflare."
    mock_http = MagicMock(ok=True, text=f"<html><body>{noisy_html}</body></html>")
    with patch("requests.get", return_value=mock_http), \
         patch.object(ollama_client, "web_fetch_url", return_value={"content": noisy_html, "title": "404 Not Found", "links": []}), \
         patch.object(ollama_client, "web_search_query", return_value=[]):
        for cid, fn in [
            ("STALE_02_trustpilot_404_recaptcha", ollama_client.lookup_trustpilot),
            ("STALE_03_sitejabber_404_wall", ollama_client.lookup_sitejabber),
            ("STALE_04_scamadviser_cloudflare_wall", ollama_client.lookup_scamadviser),
        ]:
            item = fn("predsaw-test.invalid") or {}
            r_osint = {
                "risk_score": 15, "risk_level": "GREEN",
                "explanation": item.get("content") or "Chưa có dữ liệu đánh giá từ nguồn ngoài.",
                "actions": ["Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức (156 hoặc 113)", "Không cung cấp OTP cho trang lạ"],
            }
            apply_guardrail(r_osint, kind="domain")
            cases.append((cid, "stale_or_noisy_source", r_osint, ("INSUFFICIENT",), {
                "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
                "s3_explanation_clean_and_honest": False, "s4_actions_complete": True, "s4_cautions_and_no_false_safe": True,
            }))

    # 3.5 Contradiction between benign NCSC and fresh VT malicious detection
    r_s5 = {
        "risk_score": 82, "risk_level": "RED",
        "tinnhiem": {"found": True, "status": "trusted", "record": {"owner": "Demo Corp"}},
        "virustotal": {"available": True, "stats": {"malicious": 4, "suspicious": 1, "harmless": 62}, "total_engines": 67},
        "explanation": "Phát hiện mâu thuẫn giữa danh bạ chứng nhận và cảnh báo mã độc mới từ VirusTotal.",
        "actions": ["Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức (156 hoặc 113)", "Không đăng nhập hoặc tải tệp khi đang có cảnh báo mâu thuẫn"],
    }
    apply_guardrail(r_s5, kind="domain")
    cases.append(("STALE_05_benign_catalog_vs_fresh_vt_malicious", "stale_or_noisy_source", r_s5, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
        "s3_explanation_clean_and_honest": True, "s4_actions_complete": True, "s4_cautions_and_no_false_safe": True,
    }))

    # --- GROUP 4: CONG CU KHONG HOAT DONG (5 cases) ---
    # 4.1 VT + NCSC + Ollama all raise exceptions in async message scan
    ev_t1 = ScanEvent.objects.create(scan_type="message", raw_input="test", status=ScanStatus.PENDING)
    vt_err = MagicMock()
    vt_err.scan_url.side_effect = ConnectionError("VT down")
    with patch("api.utils.vt_client.VTClient", return_value=vt_err), \
         patch("api.utils.vn_sources.tinnhiem_lookup_domain", side_effect=OSError("DB locked")), \
         patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=TimeoutError("Ollama timeout")), \
         patch("api.core.tasks._notify_scan_complete"):
        r_t1 = perform_message_scan_task(ev_t1.id, "Xem tai lieu hop tai https://internal-docs.invalid/hop", [])
    cases.append(("OUTAGE_01_vt_ncsc_ai_all_down_async_msg", "tool_outage", r_t1, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": False, "s2_guardrail_aligned": False,
        "s3_explanation_clean_and_honest": False, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": False,
    }))

    # 4.2 Sync message scan when VT crashes + Ollama offline on benign message
    with patch.object(scan_views, "VTClient", return_value=vt_err), \
         patch("api.utils.vn_sources.tinnhiem_lookup_domain", side_effect=OSError("DB error")), \
         patch.object(scan_views, "analyze_text_for_scam", side_effect=RuntimeError("Ollama down")):
        r_t2 = scan_views._analyze_message_text("Chieu nay 5h hop nhom tai phong B204 https://team.invalid", external_consent=False)
    cases.append(("OUTAGE_02_vt_crash_ai_down_sync_msg", "tool_outage", r_t2, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": False, "s2_guardrail_aligned": False,
        "s3_explanation_clean_and_honest": False, "s4_actions_complete": True, "s4_cautions_and_no_false_safe": True,
    }))

    # 4.3 Image scan when all 3 AI retries fail
    ev_t3 = ScanEvent.objects.create(scan_type="qr", raw_input="bill.png", status=ScanStatus.PENDING)
    with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
         patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "Hoa don tien dien thang 11: 420.000d", "qr_contents": [], "annotated_image_b64": ""}), \
         patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=TimeoutError("LLM timeout")), \
         patch("api.core.tasks._notify_scan_complete"):
        r_t3 = perform_image_scan_task(ev_t3.id, [{"content": _TINY_PNG, "name": "bill.png"}])
    cases.append(("OUTAGE_03_image_scan_ai_3x_timeout", "tool_outage", r_t3, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
        "s3_explanation_clean_and_honest": True, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": True,
    }))

    # 4.4 ScamWave + AI outage on police impersonation SMS (heuristic still catches HIGH_RISK!)
    ev_t4 = ScanEvent.objects.create(scan_type="message", raw_input="police", status=ScanStatus.PENDING)
    with patch("api.utils.vt_client.VTClient", return_value=vt_err), \
         patch("api.utils.scamwave.lookup_scamwave", side_effect=RuntimeError("ScamWave error")), \
         patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=RuntimeError("Ollama down")), \
         patch("api.core.tasks._notify_scan_complete"):
        r_t4 = perform_message_scan_task(
            ev_t4.id,
            "Co quan Cong an yeu cau chuyen tien vao tai khoan tam giu de phuc vu dieu tra va doc ma OTP ngay.",
            [],
        )
    cases.append(("OUTAGE_04_scamwave_ai_down_on_police_extortion", "tool_outage", r_t4, ("HIGH_RISK", "CONFIRMED_RISK"), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
        "s3_explanation_clean_and_honest": True, "s4_actions_complete": False, "s4_cautions_and_no_false_safe": True,
    }))

    # 4.5 AI returns fallback notice (`ai_notice`) on casual chat -> must not claim "safe" nor crash
    with patch.object(scan_views, "analyze_text_for_scam", return_value={"ai_notice": "Model busy", "insufficient_input": True}):
        r_t5 = scan_views._analyze_message_text("Toi nay di an pho khong ban oi", external_consent=False)
    cases.append(("OUTAGE_05_ai_fallback_notice_on_casual_sms", "tool_outage", r_t5, ("INSUFFICIENT",), {
        "s1_input_tool_isolation": True, "s2_guardrail_aligned": True,
        "s3_explanation_clean_and_honest": False, "s4_actions_complete": True, "s4_cautions_and_no_false_safe": True,
    }))

    detailed = []
    stage_keys = [
        "s1_input_tool_isolation",
        "s2_guardrail_aligned",
        "s3_explanation_clean_and_honest",
        "s4_actions_complete",
        "s4_cautions_and_no_false_safe",
    ]
    before_stage_totals = {k: 0 for k in stage_keys}
    after_stage_totals = {k: 0 for k in stage_keys}

    for cid, group, res, exp_tiers, before_checks in cases:
        after_eval = measure_recommendation_quality(res, expected_tiers=exp_tiers)
        before_passed = sum(1 for v in before_checks.values() if v)
        before_score = round(before_passed * 100.0 / len(stage_keys), 1)
        for k in stage_keys:
            if before_checks.get(k):
                before_stage_totals[k] += 1
            if after_eval["checks"].get(k):
                after_stage_totals[k] += 1
        detailed.append({
            "case_id": cid,
            "group": group,
            "expected_tiers": list(exp_tiers),
            "observed_tier": (res.get("guardrail") or {}).get("tier"),
            "risk_score": res.get("risk_score"),
            "is_conclusive": res.get("verdict_conclusive"),
            "stale_sources": (res.get("guardrail") or {}).get("stale_sources", []),
            "explanation_preview": str(res.get("explanation") or "")[:160],
            "actions_count": len(res.get("actions") or []),
            "before_quality_score": before_score,
            "after_quality_score": after_eval["quality_score"],
            "after_checks": after_eval["checks"],
        })

    n = len(detailed)
    summary = {
        "total_cases": n,
        "after_pass_all_cases": sum(1 for d in detailed if d["after_quality_score"] == 100.0),
        "before_pass_all_cases": sum(1 for d in detailed if d["before_quality_score"] == 100.0),
        "before_mean_quality_score": round(sum(d["before_quality_score"] for d in detailed) / n, 2),
        "after_mean_quality_score": round(sum(d["after_quality_score"] for d in detailed) / n, 2),
        "stage_rates_before_pct": {k: round(before_stage_totals[k] * 100.0 / n, 1) for k in stage_keys},
        "stage_rates_after_pct": {k: round(after_stage_totals[k] * 100.0 / n, 1) for k in stage_keys},
        "cases": detailed,
    }
    return summary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=str, default="", help="Optional path to write JSON benchmark output")
    args = parser.parse_args()
    data = run_benchmark()
    encoded = json.dumps(data, ensure_ascii=False, indent=2)
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(encoded + "\n", encoding="utf-8")
    print(f"Total cases: {data['total_cases']} | Before full-pass: {data['before_pass_all_cases']}/{data['total_cases']} "
          f"(mean {data['before_mean_quality_score']}%) -> After full-pass: {data['after_pass_all_cases']}/{data['total_cases']} "
          f"(mean {data['after_mean_quality_score']}%)")
    print("Stage pass rates BEFORE (%):", data["stage_rates_before_pct"])
    print("Stage pass rates AFTER  (%):", data["stage_rates_after_pct"])


if __name__ == "__main__":
    main()
