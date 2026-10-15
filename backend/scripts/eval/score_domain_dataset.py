#!/usr/bin/env python3
"""
ShieldCall VN — Chấm điểm DOMAIN cho tập nhãn (dùng engine thật, CÓ mạng).

Gọi `_analyze_domain(url)` cho từng mẫu (SSRF-safe, có VT/SSL/WHOIS) → ghi cột "score".
Sau đó đánh giá:
  evaluate_generic.py --dataset <scored.jsonl> --scorer field --text-field url

Chạy:
  .venv/bin/python backend/scripts/eval/score_domain_dataset.py \
      --in backend/scripts/eval/domain_labels.jsonl \
      --out backend/scripts/eval/domain_labels_scored.jsonl --sleep 0.3

Lưu ý:
- Cần mạng; nên chạy vào giờ thấp điểm. VirusTotal bản free giới hạn số lượt/phút.
- Có --limit để chạy thử nhỏ trước (VD --limit 40).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings")

import django  # noqa: E402
django.setup()

from api.core.views.scan_views import _analyze_domain  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--out", dest="outfile", required=True)
    ap.add_argument("--sleep", type=float, default=0.3)
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--per-class", type=int, default=0, help="Giới hạn số mẫu MỖI nhãn (để chạy cân bằng).")
    args = ap.parse_args()

    rows = [json.loads(l) for l in Path(args.infile).read_text(encoding="utf-8").splitlines() if l.strip()]
    if args.per_class:
        pos = [r for r in rows if int(r.get("label", 0)) == 1][: args.per_class]
        neg = [r for r in rows if int(r.get("label", 0)) == 0][: args.per_class]
        rows = pos + neg
    if args.limit:
        rows = rows[: args.limit]

    out_path = Path(args.outfile)
    # Resume: bỏ qua URL đã chấm (đọc từ outfile cũ nếu có).
    done = set()
    if out_path.exists():
        for line in out_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    done.add(json.loads(line).get("url"))
                except Exception:
                    pass
        print(f"resume: đã có {len(done)} mẫu trong {out_path.name}")

    remaining = [r for r in rows if r.get("url") not in done]
    print(f"cần chấm {len(remaining)}/{len(rows)} mẫu (mỗi URL có thể mất ~30-60s do fetch/VT)")

    with out_path.open("a", encoding="utf-8") as fh:
        for i, r in enumerate(remaining, 1):
            url = r.get("url", "")
            try:
                res = _analyze_domain(url)
                score = int(res.get("risk_score", 0) or 0)
                level = res.get("risk_level", "")
            except Exception as exc:  # không làm hỏng cả lô
                score, level = 0, f"ERROR:{type(exc).__name__}"
            fh.write(json.dumps({**r, "score": score, "risk_level": level}, ensure_ascii=False) + "\n")
            fh.flush()
            print(f"[{i}/{len(remaining)}] {url} -> {score} ({level})", flush=True)
            time.sleep(max(0.0, args.sleep))

    print(f"xong → {out_path}")


if __name__ == "__main__":
    main()
