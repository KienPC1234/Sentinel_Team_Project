#!/usr/bin/env python3
"""
ShieldCall VN — Đánh giá ngưỡng TỔNG QUÁT (mọi vector) trên tập dữ liệu có nhãn.

Dùng chung cho phone / domain / message / AI khi đã có tập nhãn.

Ví dụ:
  # Message (đã có sẵn):
  .venv/bin/python backend/scripts/eval/evaluate_generic.py \
      --dataset backend/scripts/eval/scam_messages_vn.jsonl --scorer message

  # Domain (offline, chỉ heuristic lookalike — không cần mạng):
  .venv/bin/python backend/scripts/eval/evaluate_generic.py \
      --dataset backend/scripts/eval/domain_labels.jsonl --scorer domain_lookalike \
      --text-field url

  # Phone / AI: tự tính điểm trước rồi đưa cột 'score' trong dataset:
  .venv/bin/python backend/scripts/eval/evaluate_generic.py \
      --dataset backend/scripts/eval/phone_labels.jsonl --scorer field --score-field score

Dataset: JSONL, mỗi dòng {"text"|"url"|"phone": "...", "label": 0|1, "tactic": "..."}.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Callable, Dict, List

import numpy as np
from sklearn.metrics import roc_auc_score

REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))


def _load(path: Path) -> List[Dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            rows.append(json.loads(line))
    return rows


def scorer_message(field: str) -> Callable[[Dict], float]:
    from api.utils.scam_rules import heuristic_score
    return lambda r: float(heuristic_score(str(r.get(field, ""))))


def scorer_field(score_field: str) -> Callable[[Dict], float]:
    return lambda r: float(r.get(score_field, 0) or 0)


def scorer_domain_lookalike(field: str) -> Callable[[Dict], float]:
    """Offline: 100 nếu tên miền là 'lookalike' của thương hiệu tin cậy, ngược lại 0.

    LƯU Ý: chỉ là lớp heuristic offline (không dùng SSL/VT/WHOIS). Dùng để có
    baseline trước khi bổ sung tầng network.
    """
    import os
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings")
    import django
    django.setup()
    from api.utils.scan_utils import _is_lookalike, _levenshtein  # noqa
    from api.utils.vn_sources import VN_TRUSTED_DOMAINS
    from api.utils.normalization import normalize_domain

    trusted = set(VN_TRUSTED_DOMAINS.keys()) | {
        "google.com", "facebook.com", "shopee.vn", "lazada.vn", "tiki.vn",
        "youtube.com", "momo.vn", "zalo.me", "viettel.vn", "vnpt.vn",
    }

    def score(r: Dict) -> float:
        raw = str(r.get(field, ""))
        dom = normalize_domain(raw) or raw.lower().strip()
        dom = dom.split("/")[0].split(":")[0]
        for t in trusted:
            if dom == t:
                return 0.0  # chính danh → không nghi ngờ
        # lookalike của bất kỳ thương hiệu nào?
        return 100.0 if any(_is_lookalike(dom, t) for t in trusted) else 0.0

    return score


def metrics(y: np.ndarray, s: np.ndarray, thr: float) -> Dict[str, float]:
    pred = (s >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / len(y) if len(y) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"precision": prec, "recall": rec, "f1": f1, "accuracy": acc, "fpr": fpr,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--scorer", choices=["message", "domain_lookalike", "field"], required=True)
    ap.add_argument("--text-field", default="text")
    ap.add_argument("--score-field", default="score")
    ap.add_argument("--label-field", default="label")
    ap.add_argument("--thresholds", default="0,10,20,30,40,50,60,70,80,90,100")
    ap.add_argument("--report", default="")
    args = ap.parse_args()

    rows = _load(Path(args.dataset))
    if not rows:
        print("Dataset rỗng.")
        return
    scorer = {"message": scorer_message(args.text_field),
              "domain_lookalike": scorer_domain_lookalike(args.text_field),
              "field": scorer_field(args.score_field)}[args.scorer]

    y = np.array([int(r.get(args.label_field, 0)) for r in rows])
    s = np.array([scorer(r) for r in rows], dtype=float)
    thr_list = [float(x) for x in args.thresholds.split(",")]

    auc = roc_auc_score(y, s) if len(set(y.tolist())) > 1 else float("nan")
    table = [(t, metrics(y, s, t)) for t in thr_list]
    best = max(table, key=lambda x: (x[1]["f1"], x[1]["recall"]))

    print(f"dataset={Path(args.dataset).name} scorer={args.scorer} n={len(rows)} "
          f"pos={int(y.sum())} neg={int((y == 0).sum())}")
    print(f"AUC={auc:.3f}  best-F1@thr={best[0]:g} (P={best[1]['precision']:.2f} "
          f"R={best[1]['recall']:.2f} F1={best[1]['f1']:.2f})")
    print(f"{'thr':>5} {'prec':>5} {'rec':>5} {'f1':>5} {'acc':>5} {'fpr':>5}  TP FP TN FN")
    for t, m in table:
        print(f"{t:>5g} {m['precision']:>5.2f} {m['recall']:>5.2f} {m['f1']:>5.2f} "
              f"{m['accuracy']:>5.2f} {m['fpr']:>5.2f}  {m['tp']} {m['fp']} {m['tn']} {m['fn']}")

    fps = [r.get(args.text_field, "") for r, sc in zip(rows, s) if r.get(args.label_field, 0) == 0 and sc >= 40]
    fns = [r.get(args.text_field, "") for r, sc in zip(rows, s) if r.get(args.label_field, 0) == 1 and sc < 40]
    if fps:
        print("\nFP (hợp lệ bị gắn cờ):")
        for x in fps[:10]:
            print("  -", x)
    if fns:
        print("\nFN (lừa đảo bị bỏ sót):")
        for x in fns[:10]:
            print("  -", x)

    if args.report:
        out = Path(args.report)
        lines = [f"# Eval — scorer `{args.scorer}`", "",
                 f"- Dataset: `{Path(args.dataset).name}` · n={len(rows)} (pos={int(y.sum())}, neg={int((y == 0).sum())})",
                 f"- **AUC = {auc:.3f}**", "", "| thr | precision | recall | f1 | accuracy | fpr | tp | fp | tn | fn |",
                 "|---|---|---|---|---|---|---|---|---|---|"]
        for t, m in table:
            lines.append(f"| {t:g} | {m['precision']:.2f} | {m['recall']:.2f} | {m['f1']:.2f} | "
                         f"{m['accuracy']:.2f} | {m['fpr']:.2f} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} |")
        if fps:
            lines += ["", "**FP:**"] + [f"- {x}" for x in fps[:20]]
        if fns:
            lines += ["", "**FN:**"] + [f"- {x}" for x in fns[:20]]
        out.write_text("\n".join(lines) + "\n", encoding="utf-8")
        print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
