#!/usr/bin/env python3
"""
ShieldCall VN — So sánh OCR engine trên ảnh thật (VietOCR vs Tesseract) + tính CER.

Chạy:
  .venv/bin/python backend/scripts/ocr_compare.py --image /path/screenshot.png
  .venv/bin/python backend/scripts/ocr_compare.py --image a.png --engines vietocr,tesseract
  .venv/bin/python backend/scripts/ocr_compare.py --image a.png --truth a.txt
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings")

import django  # noqa: E402
django.setup()

from api.utils import media_utils  # noqa: E402


def _lev(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--image", required=True)
    ap.add_argument("--engines", default="vietocr,tesseract")
    ap.add_argument("--truth", default="", help="Text đúng (tính CER) — tuỳ chọn.")
    args = ap.parse_args()

    data = Path(args.image).read_bytes()
    truth = ""
    if args.truth:
        truth = Path(args.truth).read_text(encoding="utf-8") if Path(args.truth).exists() else args.truth

    funcs = {
        "vietocr": media_utils._ocr_vietocr_bytes,
        "tesseract": media_utils._ocr_tesseract_bytes,
    }
    for name in [e.strip() for e in args.engines.split(",") if e.strip()]:
        fn = funcs.get(name)
        if not fn:
            print(f"== {name}: không hỗ trợ ==")
            continue
        t0 = time.time()
        try:
            raw = fn(media_utils.preprocess_image_for_ocr(data))
        except Exception as exc:
            raw = f"[ERROR] {exc}"
        dt = time.time() - t0
        text = media_utils.clean_ocr_text(raw)
        print(f"== {name} ({dt:.2f}s, {len(text)} ký tự) ==")
        print(text[:1500])
        if truth:
            print(f"   CER = {_lev(text, truth) / max(1, len(truth)):.3f}")
        print()


if __name__ == "__main__":
    main()
