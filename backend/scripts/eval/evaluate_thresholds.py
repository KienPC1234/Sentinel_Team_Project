#!/usr/bin/env python3
"""
ShieldCall VN — Đánh giá & tinh chỉnh ngưỡng tầng heuristic (mục C6).

- Nạp tập dữ liệu có nhãn (tập chuẩn nhỏ, nội bộ): backend/scripts/eval/scam_messages_vn.jsonl
- Chấm điểm heuristic (api.utils.scam_rules) — TÁCH khỏi AI/network để tái lập được.
- Tính ROC/AUC + bảng precision/recall/F1 theo ngưỡng; so sánh với baseline từ khoá.
- Xuất báo cáo: docs/EVAL_THRESHOLDS.md (+ CSV điểm ngưỡng).

Chạy:  .venv/bin/python backend/scripts/eval/evaluate_thresholds.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

REPO = Path(__file__).resolve().parents[3]
BACKEND = REPO / "backend"
sys.path.insert(0, str(BACKEND))

from api.utils.scam_rules import heuristic_score, PATTERNS  # noqa: E402

DATASET = Path(__file__).resolve().parent / "scam_messages_vn.jsonl"
REPORT = REPO / "docs" / "EVAL_THRESHOLDS.md"
CSV_OUT = Path(__file__).resolve().parent / "thresholds_vn.csv"

# Baseline: bộ 6 khoá cơ sở (trước khi mở rộng từ điển VN).
BASELINE_KEYWORDS = ["otp", "chuyển khoản", "chuyển tiền", "công an", "trúng thưởng", "khóa tài khoản"]


def load_dataset() -> List[Dict]:
    rows = []
    for line in DATASET.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def baseline_score(text: str) -> int:
    t = (text or "").lower()
    return 100 if any(k in t for k in BASELINE_KEYWORDS) else 0


def metrics_at(y: np.ndarray, s: np.ndarray, thr: int) -> Tuple[float, float, float, float, float, int, int, int, int]:
    pred = (s >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / len(y) if len(y) else 0.0
    tpr = rec
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return prec, rec, f1, acc, fpr, tp, fp, tn, fn


def main() -> None:
    rows = load_dataset()
    y = np.array([int(r["label"]) for r in rows])
    scores = np.array([heuristic_score(r["text"]) for r in rows], dtype=float)
    base_scores = np.array([baseline_score(r["text"]) for r in rows], dtype=float)

    n = len(rows)
    n_pos = int(y.sum())
    n_neg = n - n_pos
    auc = roc_auc_score(y, scores) if len(set(y.tolist())) > 1 else float("nan")
    auc_base = roc_auc_score(y, base_scores) if len(set(y.tolist())) > 1 else float("nan")

    thresholds = list(range(0, 101, 10))
    table = []
    with CSV_OUT.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["threshold", "precision", "recall", "f1", "accuracy", "fpr", "tp", "fp", "tn", "fn"])
        for thr in thresholds:
            prec, rec, f1, acc, fpr, tp, fp, tn, fn = metrics_at(y, scores, thr)
            table.append((thr, prec, rec, f1, acc, fpr, tp, fp, tn, fn))
            w.writerow([thr, round(prec, 3), round(rec, 3), round(f1, 3), round(acc, 3), round(fpr, 3), tp, fp, tn, fn])

    best = max(table, key=lambda r: (r[3], r[2]))  # theo F1 rồi recall
    # Điểm vận hành hiện tại của hệ thống (ngưỡng vùng xám/đáng ngờ/cao)
    current = [(t,) + metrics_at(y, scores, t)[:5] for t in (10, 40, 70)]

    # Ngưỡng tối ưu theo Youden J (TPR - FPR)
    fpr, tpr, thr_sk = roc_curve(y, scores)
    j = tpr - fpr
    youden_idx = int(np.argmax(j))
    youden_thr = int(thr_sk[youden_idx])

    # Bảng lỗi để minh bạch
    fps = [r["text"] for r, s in zip(rows, scores) if r["label"] == 0 and s >= 40]
    fns = [r["text"] for r, s in zip(rows, scores) if r["label"] == 1 and s < 40]

    lines: List[str] = []
    lines.append("# Đánh giá & tinh chỉnh ngưỡng — Tầng heuristic phát hiện lừa đảo (VN)\n")
    lines.append("> Sinh tự động bởi `backend/scripts/eval/evaluate_thresholds.py`.\n")
    lines.append("> **Phạm vi:** chỉ tầng LUẬT heuristic (`api/utils/scam_rules.py`), tách khỏi AI/network để tái lập.")
    lines.append("> Đây là **tập chuẩn nhỏ, nội bộ** (không phải benchmark công khai).\n")
    lines.append("")
    lines.append("## 1. Tập dữ liệu")
    lines.append(f"- Tổng mẫu: **{n}** ({n_pos} lừa đảo / {n_neg} hợp lệ).")
    lines.append(f"- Nguồn nhãn: đội dự án gán thủ công theo chiến thuật; file `backend/scripts/eval/scam_messages_vn.jsonl`.")
    lines.append("- Hạn chế: mẫu nhỏ; một người gán nhãn (chưa có inter-annotator agreement).")
    lines.append("- **Cảnh báo thiên lệch (liêm chính):** cùng đội dự án vừa biên soạn từ điển dấu hiệu vừa tạo tập nhãn,")
    lines.append("  nên điểm số **có thể lạc quan hơn** thực tế. Tập nhãn cần được bổ sung bởi người độc lập và")
    lines.append("  mẫu thu thập từ dữ liệu thật trước khi coi là benchmark.")
    lines.append("")
    lines.append("## 2. Kết quả tổng hợp")
    lines.append(f"- **AUC (heuristic mở rộng): {auc:.3f}**")
    lines.append(f"- AUC (baseline khoá cơ sở — 6 từ khoá): {auc_base:.3f}")
    lines.append(f"- Ngưỡng tốt nhất theo F1: **{best[0]}** (precision {best[1]:.2f}, recall {best[2]:.2f}, F1 {best[3]:.2f})")
    lines.append(f"- Ngưỡng Youden-J: **{youden_thr}**")
    lines.append("")
    lines.append("## 3. Precision / Recall / F1 theo ngưỡng (dự đoán 'lừa đảo' nếu điểm ≥ ngưỡng)")
    lines.append("")
    lines.append("| Ngưỡng | Precision | Recall | F1 | Accuracy | FPR | TP | FP | TN | FN |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")
    for thr, prec, rec, f1, acc, fpr_, tp, fp, tn, fn in table:
        mark = " ⭐" if thr == best[0] else ""
        lines.append(f"| {thr}{mark} | {prec:.2f} | {rec:.2f} | {f1:.2f} | {acc:.2f} | {fpr_:.2f} | {tp} | {fp} | {tn} | {fn} |")
    lines.append("")
    lines.append("## 4. Điểm vận hành hiện tại của hệ thống (ngưỡng vùng xám 10 / đáng ngờ 40 / cao 70)")
    lines.append("")
    lines.append("| Ngưỡng | Precision | Recall | F1 | Accuracy | FPR |")
    lines.append("|---|---|---|---|---|---|")
    for t, prec, rec, f1, acc, fpr_ in current:
        lines.append(f"| {t} | {prec:.2f} | {rec:.2f} | {f1:.2f} | {acc:.2f} | {fpr_:.2f} |")
    lines.append("")
    lines.append("## 5. Lỗi minh bạch (ngưỡng 40)")
    lines.append(f"- **Dương tính giả (FP)** — tin hợp lệ bị gắn cờ ({len(fps)}):")
    for t in fps[:12]:
        lines.append(f"  - “{t}”")
    lines.append(f"- **Âm tính giả (FN)** — tin lừa đảo bị bỏ sót ({len(fns)}):")
    for t in fns[:12]:
        lines.append(f"  - “{t}”")
    lines.append("")
    lines.append("## 6. Khuyến nghị")
    lines.append(f"- Giữ **3 ngưỡng guardrail (10/40/70)** cho phân loại đa mức (vùng xám 10–39 vẫn cần xác minh).")
    lines.append(f"- Với **chế độ cảnh báo nhị phân**, ngưỡng {best[0]} cho F1 cao nhất trên tập này ({best[3]:.2f});")
    lines.append(f"  ngưỡng Youden-J là {youden_thr}. Không đủ cơ sở để thay đổi ngưỡng production từ tập nhỏ này.")
    lines.append("- Dương tính giả chủ yếu là **tin thật chứa từ khoá** (VD OTP thật, nhờ chuyển khoản) — hệ thống")
    lines.append("  xử lý bằng nhãn 'cần xác minh' thay vì khẳng định lừa đảo, giảm hệ quả FP.")
    lines.append(f"- Việc mở rộng từ điển VN (6 khoá → {len(PATTERNS)} mẫu) đưa AUC từ **{auc_base:.3f} → {auc:.3f}**")
    lines.append("  — đây là kết quả chính, có thể tái lập bằng script này.")
    lines.append("- Việc tiếp theo: mở rộng tập nhãn (nhiều người gán, có kiểm định), thêm trọng số theo mức độ dấu hiệu,")
    lines.append("  và đánh giá cả tầng AI (faithfulness/hallucination) — hiện **chưa** công bố vì chưa đủ dữ liệu.")
    lines.append("")

    REPORT.write_text("\n".join(lines), encoding="utf-8")

    print(f"n={n} pos={n_pos} neg={n_neg}")
    print(f"AUC(heuristic)={auc:.3f}  AUC(baseline)={auc_base:.3f}")
    print(f"best-F1 threshold={best[0]} (P={best[1]:.2f} R={best[2]:.2f} F1={best[3]:.2f})")
    print(f"Youden threshold={youden_thr}")
    print(f"wrote {REPORT}")
    print(f"wrote {CSV_OUT}")


if __name__ == "__main__":
    main()
