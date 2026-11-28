#!/usr/bin/env python3
"""Unmocked Integration Verification via Django REST APIClient (3 scan cases).

Complements `evaluate_e2e_chang2.py` (which injects mocked faults) by running
3 unmocked scan cases through Django's in-process REST APIClient with eager
Celery execution (`CELERY_TASK_ALWAYS_EAGER=True`), real VietOCR/Tesseract image
extraction, real SQLite NCSC/ScamWave databases, and live LLM configuration,
recording processing time measured in this test setup. Does not exercise an
external HTTP server, Redis broker, standalone Celery worker, or browser UI.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[2]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings")

import django  # noqa: E402

django.setup()

from django.conf import settings  # noqa: E402
from django.core.files.uploadedfile import SimpleUploadedFile  # noqa: E402
from django.test.utils import override_settings  # noqa: E402
from PIL import Image, ImageDraw, ImageFilter, ImageFont  # noqa: E402
from rest_framework.test import APIClient  # noqa: E402


def _make_png_bytes(lines: list[str], *, blur: float = 0.0) -> bytes:
    img = Image.new("RGB", (880, 220), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 22)
    except Exception:
        font = ImageFont.load_default()
    y = 28
    for line in lines:
        draw.text((28, y), line, fill=(20, 20, 20), font=font)
        y += 46
    if blur > 0:
        img = img.filter(ImageFilter.GaussianBlur(radius=blur))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def run_real_e2e() -> dict:
    from django.contrib.auth import get_user_model
    allowed = list(getattr(settings, "ALLOWED_HOSTS", [])) + ["testserver", "localhost", "127.0.0.1"]
    results = []
    User = get_user_model()

    with override_settings(
        CELERY_TASK_ALWAYS_EAGER=True,
        CELERY_TASK_EAGER_PROPAGATES=True,
        ALLOWED_HOSTS=allowed,
    ):
        user, created = User.objects.get_or_create(username="_chang2_e2e_probe")
        client = APIClient()
        client.force_authenticate(user=user)

        try:
            # 1. Real blurred/noisy image via POST /api/v1/scan/image/ -> GET /api/v1/scan/status/<id>/
            t0 = time.perf_counter()
            noisy_bytes = _make_png_bytes(["||| ### ~~~ ???"], blur=4.0)
            up1 = SimpleUploadedFile("noisy_real.png", noisy_bytes, content_type="image/png")
            r1 = client.post("/api/v1/scan/image/", {"image": up1}, format="multipart")
            d1 = r1.json()
            scan_id_1 = d1.get("scan_id")
            st1 = client.get(f"/api/v1/scan/status/{scan_id_1}/").json() if scan_id_1 else d1
            res1 = st1.get("result") or st1
            results.append({
                "case_id": "REAL-API-01_noisy_image_endpoint",
                "http_status": r1.status_code,
                "elapsed_seconds": round(time.perf_counter() - t0, 3),
                "scan_status": st1.get("status"),
                "risk_score": res1.get("risk_score"),
                "guardrail_tier": (res1.get("guardrail") or {}).get("tier"),
                "actions_count": len(res1.get("actions") or []),
                "explanation_preview": str(res1.get("explanation") or "")[:180],
            })

            # 2. Real message with ScamWave-listed domain via POST /api/v1/scan/message/
            t0 = time.perf_counter()
            msg_scam = (
                "Thong bao khan: Ho so dinh danh bi tam khoa sau 24h00 hom nay. "
                "Xac thuc ngay tai https://predsaw.com/xac-thuc hoac nhan Zalo 0900000123."
            )
            r2 = client.post("/api/v1/scan/message/", {"message": msg_scam}, format="json")
            d2 = r2.json()
            scan_id_2 = d2.get("scan_id")
            st2 = client.get(f"/api/v1/scan/status/{scan_id_2}/").json() if scan_id_2 else d2
            res2 = st2.get("result") or st2
            results.append({
                "case_id": "REAL-API-02_scam_url_message_endpoint",
                "http_status": r2.status_code,
                "elapsed_seconds": round(time.perf_counter() - t0, 3),
                "scan_status": st2.get("status"),
                "risk_score": res2.get("risk_score"),
                "guardrail_tier": (res2.get("guardrail") or {}).get("tier"),
                "actions_count": len(res2.get("actions") or []),
                "explanation_preview": str(res2.get("explanation") or "")[:180],
            })

            # 3. Real screenshot containing phishing URL via POST /api/v1/scan/message/ (multipart real OCR + DB + AI)
            t0 = time.perf_counter()
            ocr_url_bytes = _make_png_bytes([
                "THONG BAO KHOA TAI KHOAN NGAN HANG",
                "Vui long xac thuc OTP ngay tai: https://predsaw.com/login",
            ])
            up3 = SimpleUploadedFile("scam_sms.png", ocr_url_bytes, content_type="image/png")
            r3 = client.post("/api/v1/scan/message/", {"message": "", "image": up3}, format="multipart")
            d3 = r3.json()
            scan_id_3 = d3.get("scan_id")
            st3 = client.get(f"/api/v1/scan/status/{scan_id_3}/").json() if scan_id_3 else d3
            res3 = st3.get("result") or st3
            results.append({
                "case_id": "REAL-API-03_screenshot_ocr_to_message_endpoint",
                "http_status": r3.status_code,
                "elapsed_seconds": round(time.perf_counter() - t0, 3),
                "scan_status": st3.get("status"),
                "ocr_extracted_preview": str(res3.get("ocr_text") or "")[:120],
                "risk_score": res3.get("risk_score"),
                "guardrail_tier": (res3.get("guardrail") or {}).get("tier"),
                "actions_count": len(res3.get("actions") or []),
                "explanation_preview": str(res3.get("explanation") or "")[:180],
            })
        finally:
            if created:
                user.delete()

    return {
        "scope": "unmocked_django_apiclient_eager_celery_ocr_db_llm",
        "execution_mode": {
            "client": "rest_framework.test.APIClient (in-process)",
            "celery_task_always_eager": True,
            "mocks_used": False,
            "not_covered": ["http_network_server", "redis_broker", "standalone_celery_worker", "browser_ui"],
        },
        "total_cases": len(results),
        "cases": results,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=str, default="")
    args = parser.parse_args()
    out_data = run_real_e2e()
    if args.out:
        p = Path(args.out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(out_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for c in out_data["cases"]:
        print(
            f"{c['case_id']}: HTTP {c['http_status']}, status={c['scan_status']}, "
            f"tier={c['guardrail_tier']}, score={c['risk_score']}, actions={c['actions_count']}, "
            f"time={c['elapsed_seconds']}s"
        )


if __name__ == "__main__":
    main()
