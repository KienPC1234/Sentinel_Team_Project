#!/usr/bin/env python3
"""
ShieldCall VN — Thu thập tập nhãn DOMAIN từ nguồn công khai (không cần gán tay).

- Positives (label 1): OpenPhish public feed (phishing) — mirror GitHub raw.
- Negatives (label 0): Tranco top-1M (tên miền phổ biến, hợp lệ) + danh mục tin cậy VN.

Ghi ra JSONL: {"url", "label", "tactic", "source", "collected"}
Chạy:
  .venv/bin/python backend/scripts/eval/collect_domain_dataset.py --pos 100 --neg 100 \
      --out backend/scripts/eval/domain_labels.jsonl

Lưu ý: ghi RÕ nguồn + ngày trong báo cáo (liêm chính). Không dùng dữ liệu cá nhân.
"""
from __future__ import annotations

import argparse
import io
import json
import random
import sys
import urllib.request
import zipfile
from datetime import date
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "backend"

OPENPHISH_URL = "https://raw.githubusercontent.com/openphish/public_feed/refs/heads/main/feed.txt"
TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
CACHE_DIR = Path(__file__).resolve().parent / ".cache"

# Thêm vài tên miền tin cậy VN làm negative (đảm bảo có mẫu thương hiệu nội địa).
VN_LEGIT_EXTRA = [
    "vietcombank.com.vn", "techcombank.com.vn", "bidv.com.vn", "vietinbank.vn",
    "mbbank.com.vn", "agribank.com.vn", "vpbank.com.vn", "tpb.vn",
    "momo.vn", "zalopay.vn", "vnpay.vn", "shopee.vn", "lazada.vn", "tiki.vn",
    "chinhphu.vn", "bocongan.gov.vn", "gdt.gov.vn", "bhxh.gov.vn",
    "vnexpress.net", "tuoitre.vn", "thanhnien.vn", "dantri.com.vn",
]


def _fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "ShieldCall-Eval/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _domain_from_url(u: str) -> str:
    u = u.strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    try:
        host = (urlparse(u).hostname or "").lower()
    except Exception:
        return ""
    if host.startswith("www."):
        host = host[4:]
    return host


def load_openphish() -> list[str]:
    raw = _fetch(OPENPHISH_URL).decode("utf-8", "ignore")
    doms = []
    for line in raw.splitlines():
        d = _domain_from_url(line)
        if d:
            doms.append(d)
    return list(dict.fromkeys(doms))


def load_tranco(top_n: int) -> list[str]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    zp = CACHE_DIR / "tranco.zip"
    if not zp.exists():
        zp.write_bytes(_fetch(TRANCO_URL, timeout=90))
    out = []
    with zipfile.ZipFile(zp) as z:
        name = z.namelist()[0]
        with io.TextIOWrapper(z.open(name), encoding="utf-8") as fh:
            for i, line in enumerate(fh):
                if i >= top_n:
                    break
                parts = line.strip().split(",")
                if len(parts) == 2 and parts[1]:
                    out.append(parts[1].lower())
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pos", type=int, default=100)
    ap.add_argument("--neg", type=int, default=100)
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "domain_labels.jsonl"))
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    random.seed(args.seed)

    print("Đang tải OpenPhish...")
    pos_all = load_openphish()
    print(f"  OpenPhish: {len(pos_all)} tên miền phishing")

    print("Đang tải Tranco top-1M (có thể mất vài giây lần đầu)...")
    tranco_top = load_tranco(top_n=5000)
    print(f"  Tranco: {len(tranco_top)} tên miền phổ biến")

    pos = random.sample(pos_all, min(args.pos, len(pos_all)))
    pos_set = set(pos)
    neg_pool = [d for d in (tranco_top + VN_LEGIT_EXTRA) if d not in pos_set]
    neg = random.sample(neg_pool, min(args.neg, len(neg_pool)))

    today = date.today().isoformat()
    rows = []
    for d in pos:
        rows.append({"url": d, "label": 1, "tactic": "phishing", "source": "OpenPhish", "collected": today})
    for d in neg:
        rows.append({"url": d, "label": 0, "tactic": "legit", "source": "Tranco top-5k + VN trusted", "collected": today})

    out = Path(args.out)
    out.write_text("\n".join(json.dumps(r, ensure_ascii=False) for r in rows) + "\n", encoding="utf-8")
    print(f"Đã ghi {len(rows)} mẫu ({len(pos)} pos / {len(neg)} neg) → {out}")


if __name__ == "__main__":
    main()
