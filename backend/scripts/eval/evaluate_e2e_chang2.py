#!/usr/bin/env python3
"""Automated Fault-Injection Integration Benchmark for Stage 2 (20 scenarios).

Design principles for auditability:
- ZERO hardcoded before/after booleans: this script executes the live codebase
  present in BACKEND_DIR (or --backend-dir) and computes all 5 step-by-step
  criteria strictly from actual runtime outputs (or unhandled exceptions).
- Standalone (no dependency on new test modules) so the exact same script can be
  executed against a historical git worktree (e.g. commit f3af2c5) and against
  HEAD to produce a reproducible, automated Before-vs-After comparison via
  `--compare-baseline <before.json>`.
- Scope note: external faults (OCR crash/noise, VirusTotal error, Trustpilot 404,
  Ollama timeout) are injected via unittest.mock onto real task/view entrypoints
  (`perform_image_scan_task`, `perform_message_scan_task`, `_analyze_message_text`,
  `lookup_*`, `apply_guardrail`). For unmocked end-to-end API + OCR + DB + LLM
  execution, see `verify_real_pipeline_chang2.py`.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch


def evaluate_criteria(result: dict | None, *, expected_tiers: tuple[str, ...], crashed: bool = False) -> dict:
    """Evaluate 5 automated criteria across pipeline outputs (20 pts each = 100%)."""
    if crashed or not isinstance(result, dict) or not result:
        checks = {
            "s1_input_tool_isolation": False,
            "s2_guardrail_aligned": False,
            "s3_explanation_clean_and_honest": False,
            "s4_actions_complete": False,
            "s4_cautions_and_no_false_safe": False,
        }
        return {"checks": checks, "passed": 0, "total": 5, "quality_score": 0.0}

    guardrail = result.get("guardrail") or {}
    tier = str(guardrail.get("tier") or "")
    explanation = str(result.get("explanation") or result.get("ai_insight") or "")
    actions = list(result.get("actions") or [])
    cautions = list(guardrail.get("cautions") or [])

    has_unhandled_error = "error" in result and not guardrail
    noise_markers = ("recaptcha", "cloudflare", "whoops! the page", "_tool_", "404 not found")
    false_clear_when_ai_down = (
        not result.get("ai_available", True)
        and not result.get("patterns_found")
        and "không phát hiện dấu hiệu lừa đảo rõ ràng" in explanation.lower()
    )

    checks = {
        "s1_input_tool_isolation": not has_unhandled_error,
        "s2_guardrail_aligned": tier in expected_tiers,
        "s3_explanation_clean_and_honest": (
            bool(explanation.strip())
            and not any(m in explanation.lower() for m in noise_markers)
            and not false_clear_when_ai_down
        ),
        "s4_actions_complete": (
            len(actions) >= 2 and all(isinstance(a, str) and len(a.strip()) > 5 for a in actions)
        ),
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


def run_suite(backend_dir: Path) -> dict:
    sys.path.insert(0, str(backend_dir))
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings_ci")

    import django

    django.setup()
    from django.core.management import call_command

    call_command("migrate", "--run-syncdb", verbosity=0)

    from api.core.models import ScanEvent, ScanStatus
    from api.core.tasks import perform_image_scan_task, perform_message_scan_task
    from api.core.views import scan_views
    from api.utils import ollama_client
    from api.utils.trust_guard import apply_guardrail

    tiny_png = base64.b64encode(
        b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
        b"\x08\x02\x00\x00\x00\x90wS\xde\x00\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00"
        b"\x00\x01\x01\x00\x05\x18\xd4\x8d\x00\x00\x00\x00IEND\xaeB`\x82"
    ).decode("ascii")

    raw_cases: list[tuple[str, str, str, tuple[str, ...], callable]] = []

    # --- GROUP 1: OCR ERRORS (5 cases) ---
    def _c_ocr_01():
        ev = ScanEvent.objects.create(scan_type="qr", raw_input="ocr_crash.png", status=ScanStatus.PENDING)
        with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
             patch("api.utils.media_utils.extract_ocr_with_boxes", side_effect=RuntimeError("VietOCR bridge crashed")), \
             patch("api.core.tasks._notify_scan_complete"):
            return perform_image_scan_task(ev.id, [{"content": tiny_png, "name": "ocr_crash.png"}])

    def _c_ocr_02():
        ev = ScanEvent.objects.create(scan_type="qr", raw_input="garbled.png", status=ScanStatus.PENDING)
        fake_llm_guess = {
            "is_scam": False,
            "risk_score": 5,
            "explanation": "Không phát hiện dấu hiệu lừa đảo rõ ràng.",
        }
        with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
             patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "||| ### ~~~ ??? 0_0", "qr_contents": [], "annotated_image_b64": ""}), \
             patch("api.utils.ollama_client.analyze_text_for_scam", return_value=fake_llm_guess), \
             patch("api.core.tasks._notify_scan_complete"):
            return perform_image_scan_task(ev.id, [{"content": tiny_png, "name": "garbled.png"}])

    def _c_ocr_03():
        ev = ScanEvent.objects.create(scan_type="message", raw_input="", status=ScanStatus.PENDING)
        vt_mal = MagicMock()
        vt_mal.scan_url.side_effect = lambda u: (
            {"risk_score": 90, "malicious": 4, "suspicious": 1}
            if "ho-so-capnhat.top" in str(u)
            else {"risk_score": 0, "malicious": 0, "suspicious": 0}
        )
        tn_fn = lambda d: {"status": "scam"} if d == "ho-so-capnhat.top" else None
        with patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "Cap nhat ho so tai https ://ho-so-capnhat,top/login", "qr_contents": [], "annotated_image_b64": ""}), \
             patch("api.utils.vt_client.VTClient", return_value=vt_mal), \
             patch("api.utils.vn_sources.tinnhiem_lookup_domain", side_effect=tn_fn), \
             patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=RuntimeError("AI offline")), \
             patch("api.core.tasks._notify_scan_complete"):
            return perform_message_scan_task(ev.id, "", [{"content": tiny_png, "name": "url_ocr.png"}])

    def _c_ocr_04():
        ev = ScanEvent.objects.create(scan_type="message", raw_input="", status=ScanStatus.PENDING)
        with patch("api.utils.media_utils.extract_ocr_with_boxes", side_effect=RuntimeError("Tesseract missing")), \
             patch("api.core.tasks._notify_scan_complete"):
            res = perform_message_scan_task(ev.id, "", [{"content": tiny_png, "name": "msg_img_err.png"}])
            ev.refresh_from_db()
            if res is None and ev.status == ScanStatus.FAILED:
                return ev.result_json or {"error": "ScanStatus.FAILED"}
            return res

    def _c_ocr_05():
        ev = ScanEvent.objects.create(scan_type="qr", raw_input="blank.png", status=ScanStatus.PENDING)
        with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
             patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "", "qr_contents": [], "annotated_image_b64": ""}), \
             patch("api.core.tasks._notify_scan_complete"):
            return perform_image_scan_task(ev.id, [{"content": tiny_png, "name": "blank.png"}])

    raw_cases.extend([
        ("OCR-01", "ocr_error", "perform_image_scan_task", ("INSUFFICIENT",), _c_ocr_01),
        ("OCR-02", "ocr_error", "perform_image_scan_task", ("INSUFFICIENT",), _c_ocr_02),
        ("OCR-03", "ocr_error", "perform_message_scan_task", ("CONFIRMED_RISK", "HIGH_RISK"), _c_ocr_03),
        ("OCR-04", "ocr_error", "perform_message_scan_task", ("INSUFFICIENT",), _c_ocr_04),
        ("OCR-05", "ocr_error", "perform_image_scan_task", ("INSUFFICIENT",), _c_ocr_05),
    ])

    # --- GROUP 2: DANGEROUS URLS (5 cases: 2 sync REST helper + 3 async Celery task) ---
    def _make_sync_url_case(sms: str, tn_st: str | None, vt_score: int, vt_m: int):
        def _fn():
            vt_mck = MagicMock()
            vt_mck.scan_url.return_value = {"risk_score": vt_score, "malicious": vt_m, "suspicious": 1}
            ai_ok = {
                "is_scam": True,
                "risk_score": 93,
                "explanation": "Tin nhắn mạo danh tổ chức uy tín kèm đường dẫn giả mạo nhằm đánh cắp thông tin.",
                "advice": "Không truy cập đường dẫn lạ và không cài đặt tệp ngoài kho ứng dụng.",
                "prevention_measures": ["Không nhập mật khẩu/OTP", "Báo cơ quan công an 113"],
            }
            with patch.object(scan_views, "VTClient", return_value=vt_mck), \
                 patch("api.utils.vn_sources.tinnhiem_lookup_domain", return_value=({"status": tn_st} if tn_st else None)), \
                 patch.object(scan_views, "analyze_text_for_scam", return_value=ai_ok):
                return scan_views._analyze_message_text(sms, external_consent=False)
        return _fn

    def _make_async_url_case(sms: str, tn_st: str | None, vt_score: int, vt_m: int, ai_down: bool):
        def _fn():
            ev = ScanEvent.objects.create(scan_type="message", raw_input=sms, status=ScanStatus.PENDING)
            vt_mck = MagicMock()
            vt_mck.scan_url.return_value = {"risk_score": vt_score, "malicious": vt_m, "suspicious": 1}
            ai_patch = (
                patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=RuntimeError("AI offline"))
                if ai_down
                else patch("api.utils.ollama_client.analyze_text_for_scam", return_value={
                    "is_scam": True,
                    "risk_score": 94,
                    "explanation": "Phát hiện kịch bản thúc ép thanh toán phí nhỏ qua tên miền giả mạo.",
                    "advice": "Không thanh toán qua liên kết trong tin nhắn.",
                    "prevention_measures": ["Kiểm tra đơn hàng trên ứng dụng chính thức", "Chặn số gửi"],
                })
            )
            with patch("api.utils.vt_client.VTClient", return_value=vt_mck), \
                 patch("api.utils.vn_sources.tinnhiem_lookup_domain", return_value=({"status": tn_st} if tn_st else None)), \
                 ai_patch, \
                 patch("api.core.tasks._notify_scan_complete"):
                return perform_message_scan_task(ev.id, sms, [])
        return _fn

    raw_cases.extend([
        ("URL-01", "dangerous_url", "_analyze_message_text", ("CONFIRMED_RISK", "HIGH_RISK"),
         _make_sync_url_case("TK VCB sap khoa, xac thuc tai https://vcb-digibank-verify.invalid/login", "scam", 95, 6)),
        ("URL-02", "dangerous_url", "_analyze_message_text", ("CONFIRMED_RISK", "HIGH_RISK"),
         _make_sync_url_case("Tai ung dung Thue dien tu https://thuedientu-gov.invalid/etax.apk", None, 92, 5)),
        ("URL-03", "dangerous_url", "perform_message_scan_task", ("CONFIRMED_RISK", "HIGH_RISK"),
         _make_async_url_case("Nhan ho tro BHXH tai https://bhxh-nhantien.invalid/claim", "scam", 90, 3, True)),
        ("URL-04", "dangerous_url", "perform_message_scan_task", ("CONFIRMED_RISK", "HIGH_RISK"),
         _make_async_url_case("Don hang VN882 tam giu, thanh toan 5.000d phi luu kho https://vnpost-cod.invalid/pay", None, 88, 4, False)),
        ("URL-05", "dangerous_url", "perform_message_scan_task", ("CONFIRMED_RISK", "HIGH_RISK"),
         _make_async_url_case("EVN thong bao cat dien sau 2h neu khong thanh toan tai https://evn-hanoi-pay.invalid", "scam", 94, 5, True)),
    ])

    # --- GROUP 3: STALE & NOISY SOURCES (5 cases) ---
    def _c_stale_01():
        r = {
            "risk_score": 0,
            "risk_level": "SAFE",
            "tinnhiem": {"found": True, "status": "trusted", "updated_at": "2024-03-15", "record": {"updated_at": "2024-03-15", "owner": "Expired Org"}},
            "explanation": "Đối chiếu bản ghi chứng nhận từ kỳ cập nhật cũ.",
            "actions": [
                "Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức (156 hoặc 113)",
                "Không chuyển tiền khi chưa xác minh",
            ],
        }
        apply_guardrail(r, kind="domain")
        return r

    noisy_html = (
        "Categories Blog Log in For businesses Whoops! The page you're looking for could not be found. "
        "This site is protected by reCAPTCHA and Cloudflare. Verify you are human. " * 2
    )

    def _make_osint_noise_case(fn_name: str):
        def _fn():
            mock_http = MagicMock(ok=True, text=f"<html><body>{noisy_html}</body></html>")
            lookup_fn = getattr(ollama_client, fn_name)
            with patch("requests.get", return_value=mock_http), \
                 patch.object(ollama_client, "web_fetch_url", return_value={"content": noisy_html, "title": "404 Not Found", "links": []}), \
                 patch.object(ollama_client, "web_search_query", return_value=[]):
                item = lookup_fn("predsaw-test.invalid") or {}
            r = {
                "risk_score": 15,
                "risk_level": "GREEN",
                "explanation": item.get("content") or "Chưa có dữ liệu đánh giá từ nguồn ngoài.",
                "actions": [
                    "Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức (156 hoặc 113)",
                    "Không cung cấp OTP cho trang lạ",
                ],
            }
            apply_guardrail(r, kind="domain")
            return r
        return _fn

    def _c_stale_05():
        r = {
            "risk_score": 82,
            "risk_level": "RED",
            "tinnhiem": {"found": True, "status": "trusted", "record": {"owner": "Demo Corp"}},
            "virustotal": {"available": True, "stats": {"malicious": 4, "suspicious": 1, "harmless": 62}, "total_engines": 67},
            "explanation": "Phát hiện mâu thuẫn giữa danh bạ chứng nhận cũ và cảnh báo độc hại mới từ VirusTotal.",
            "actions": [
                "Chưa đủ cơ sở để kết luận: hãy xác minh qua kênh chính thức (156 hoặc 113)",
                "Không đăng nhập hoặc tải tệp khi đang có cảnh báo mâu thuẫn",
            ],
        }
        apply_guardrail(r, kind="domain")
        return r

    raw_cases.extend([
        ("STALE-01", "stale_or_noisy_source", "apply_guardrail", ("INSUFFICIENT",), _c_stale_01),
        ("STALE-02", "stale_or_noisy_source", "lookup_trustpilot", ("INSUFFICIENT",), _make_osint_noise_case("lookup_trustpilot")),
        ("STALE-03", "stale_or_noisy_source", "lookup_sitejabber", ("INSUFFICIENT",), _make_osint_noise_case("lookup_sitejabber")),
        ("STALE-04", "stale_or_noisy_source", "lookup_scamadviser", ("INSUFFICIENT",), _make_osint_noise_case("lookup_scamadviser")),
        ("STALE-05", "stale_or_noisy_source", "apply_guardrail", ("INSUFFICIENT",), _c_stale_05),
    ])

    # --- GROUP 4: TOOL OUTAGES (5 cases) ---
    def _c_down_01():
        ev = ScanEvent.objects.create(scan_type="message", raw_input="test", status=ScanStatus.PENDING)
        vt_err = MagicMock()
        vt_err.scan_url.side_effect = ConnectionError("VT down")
        with patch("api.utils.vt_client.VTClient", return_value=vt_err), \
             patch("api.utils.vn_sources.tinnhiem_lookup_domain", side_effect=OSError("DB locked")), \
             patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=RuntimeError("Ollama down")), \
             patch("api.core.tasks._notify_scan_complete"):
            res = perform_message_scan_task(ev.id, "Xem tai lieu hop tai https://internal-docs.invalid/hop", [])
            ev.refresh_from_db()
            if res is None and ev.status == ScanStatus.FAILED:
                return ev.result_json or {"error": "ScanStatus.FAILED"}
            return res

    def _c_down_02():
        vt_err = MagicMock()
        vt_err.scan_url.side_effect = ConnectionError("VT down")
        with patch.object(scan_views, "VTClient", return_value=vt_err), \
             patch("api.utils.vn_sources.tinnhiem_lookup_domain", side_effect=OSError("DB error")), \
             patch.object(scan_views, "analyze_text_for_scam", side_effect=RuntimeError("Ollama down")):
            return scan_views._analyze_message_text("Chieu nay 5h hop nhom tai phong B204 https://team.invalid", external_consent=False)

    def _c_down_03():
        ev = ScanEvent.objects.create(scan_type="qr", raw_input="bill.png", status=ScanStatus.PENDING)
        with patch("api.utils.ollama_client.LLM_VISION_ENABLED", False), \
             patch("api.utils.media_utils.extract_ocr_with_boxes", return_value={"text": "Hoa don tien dien thang 11: 420.000d", "qr_contents": [], "annotated_image_b64": ""}), \
             patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=TimeoutError("LLM timeout")), \
             patch("api.core.tasks._notify_scan_complete"):
            return perform_image_scan_task(ev.id, [{"content": tiny_png, "name": "bill.png"}])

    def _c_down_04():
        ev = ScanEvent.objects.create(scan_type="message", raw_input="police", status=ScanStatus.PENDING)
        vt_err = MagicMock()
        vt_err.scan_url.side_effect = ConnectionError("VT down")
        with patch("api.utils.vt_client.VTClient", return_value=vt_err), \
             patch("api.utils.scamwave.lookup_scamwave", side_effect=RuntimeError("ScamWave error")), \
             patch("api.utils.ollama_client.analyze_text_for_scam", side_effect=RuntimeError("Ollama down")), \
             patch("api.core.tasks._notify_scan_complete"):
            return perform_message_scan_task(
                ev.id,
                "Co quan Cong an yeu cau chuyen tien vao tai khoan tam giu de phuc vu dieu tra va doc ma OTP ngay.",
                [],
            )

    def _c_down_05():
        with patch.object(scan_views, "analyze_text_for_scam", return_value={"ai_notice": "Model busy", "insufficient_input": True}):
            return scan_views._analyze_message_text("Toi nay di an pho khong ban oi", external_consent=False)

    raw_cases.extend([
        ("DOWN-01", "tool_outage", "perform_message_scan_task", ("INSUFFICIENT",), _c_down_01),
        ("DOWN-02", "tool_outage", "_analyze_message_text", ("INSUFFICIENT",), _c_down_02),
        ("DOWN-03", "tool_outage", "perform_image_scan_task", ("INSUFFICIENT",), _c_down_03),
        ("DOWN-04", "tool_outage", "perform_message_scan_task", ("HIGH_RISK", "CONFIRMED_RISK"), _c_down_04),
        ("DOWN-05", "tool_outage", "_analyze_message_text", ("INSUFFICIENT",), _c_down_05),
    ])

    stage_keys = [
        "s1_input_tool_isolation",
        "s2_guardrail_aligned",
        "s3_explanation_clean_and_honest",
        "s4_actions_complete",
        "s4_cautions_and_no_false_safe",
    ]
    stage_totals = {k: 0 for k in stage_keys}
    detailed = []
    t_suite_start = time.perf_counter()

    for cid, group, entrypoint, exp_tiers, fn in raw_cases:
        t0 = time.perf_counter()
        crashed = False
        err_msg = ""
        res = None
        try:
            res = fn()
        except Exception as exc:
            crashed = True
            err_msg = f"{type(exc).__name__}: {exc}"
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)

        ev_metrics = evaluate_criteria(res, expected_tiers=exp_tiers, crashed=crashed)
        for k in stage_keys:
            if ev_metrics["checks"][k]:
                stage_totals[k] += 1

        guard = (res.get("guardrail") if isinstance(res, dict) else None) or {}
        detailed.append({
            "case_id": cid,
            "group": group,
            "entrypoint": entrypoint,
            "expected_tiers": list(exp_tiers),
            "crashed": crashed,
            "exception": err_msg,
            "observed_tier": guard.get("tier"),
            "risk_score": res.get("risk_score") if isinstance(res, dict) else None,
            "is_conclusive": res.get("verdict_conclusive") if isinstance(res, dict) else None,
            "stale_sources": guard.get("stale_sources", []),
            "explanation_preview": str((res or {}).get("explanation") or "")[:180] if isinstance(res, dict) else err_msg,
            "actions_count": len((res or {}).get("actions") or []) if isinstance(res, dict) else 0,
            "elapsed_ms_mocked": elapsed_ms,
            "quality_score": ev_metrics["quality_score"],
            "checks": ev_metrics["checks"],
        })

    suite_ms = round((time.perf_counter() - t_suite_start) * 1000.0, 2)
    n = len(detailed)
    return {
        "scope": "fault_injection_integration_benchmark_with_mocked_external_faults",
        "backend_dir": str(backend_dir),
        "total_cases": n,
        "full_pass_cases": sum(1 for d in detailed if d["quality_score"] == 100.0),
        "mean_quality_score": round(sum(d["quality_score"] for d in detailed) / n, 2),
        "total_elapsed_ms_mocked": suite_ms,
        "stage_rates_pct": {k: round(stage_totals[k] * 100.0 / n, 1) for k in stage_keys},
        "cases": detailed,
    }


def merge_comparison(before_data: dict, after_data: dict) -> dict:
    before_by_id = {c["case_id"]: c for c in before_data["cases"]}
    merged_cases = []
    for ac in after_data["cases"]:
        bc = before_by_id.get(ac["case_id"], {})
        merged_cases.append({
            "case_id": ac["case_id"],
            "group": ac["group"],
            "entrypoint": ac["entrypoint"],
            "expected_tiers": ac["expected_tiers"],
            "before": {
                "crashed": bc.get("crashed"),
                "exception": bc.get("exception"),
                "observed_tier": bc.get("observed_tier"),
                "risk_score": bc.get("risk_score"),
                "actions_count": bc.get("actions_count"),
                "explanation_preview": bc.get("explanation_preview"),
                "quality_score": bc.get("quality_score"),
                "checks": bc.get("checks"),
            },
            "after": {
                "crashed": ac.get("crashed"),
                "observed_tier": ac.get("observed_tier"),
                "risk_score": ac.get("risk_score"),
                "actions_count": ac.get("actions_count"),
                "stale_sources": ac.get("stale_sources"),
                "explanation_preview": ac.get("explanation_preview"),
                "quality_score": ac.get("quality_score"),
                "checks": ac.get("checks"),
            },
        })
    return {
        "scope": "automated_git_worktree_before_vs_after_comparison",
        "total_cases": after_data["total_cases"],
        "before_full_pass_cases": before_data["full_pass_cases"],
        "after_full_pass_cases": after_data["full_pass_cases"],
        "before_mean_quality_score": before_data["mean_quality_score"],
        "after_mean_quality_score": after_data["mean_quality_score"],
        "stage_rates_before_pct": before_data["stage_rates_pct"],
        "stage_rates_after_pct": after_data["stage_rates_pct"],
        "cases": merged_cases,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--backend-dir", type=str, default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--out", type=str, default="")
    parser.add_argument("--compare-baseline", type=str, default="", help="Path to JSON run from baseline commit")
    args = parser.parse_args()

    current = run_suite(Path(args.backend_dir).resolve())
    output_obj = current
    if args.compare_baseline:
        base_obj = json.loads(Path(args.compare_baseline).read_text(encoding="utf-8"))
        output_obj = merge_comparison(base_obj, current)

    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(output_obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    if args.compare_baseline:
        print(
            f"Automated Before vs After ({output_obj['total_cases']} cases): "
            f"Before {output_obj['before_full_pass_cases']}/{output_obj['total_cases']} "
            f"(mean {output_obj['before_mean_quality_score']}%) -> "
            f"After {output_obj['after_full_pass_cases']}/{output_obj['total_cases']} "
            f"(mean {output_obj['after_mean_quality_score']}%)"
        )
        print("Stage rates BEFORE (%):", output_obj["stage_rates_before_pct"])
        print("Stage rates AFTER  (%):", output_obj["stage_rates_after_pct"])
    else:
        print(
            f"Executed {current['total_cases']} cases in {current['total_elapsed_ms_mocked']} ms (mocked faults): "
            f"full-pass {current['full_pass_cases']}/{current['total_cases']} "
            f"(mean {current['mean_quality_score']}%)"
        )
        print("Stage rates (%):", current["stage_rates_pct"])


if __name__ == "__main__":
    main()
