#!/usr/bin/env python3
"""
ShieldCall VN — Đo độ đồng thuận giữa 2 người gán nhãn (Cohen's kappa).

Dùng khi có 2 người gán nhãn ĐỘC LẬP cùng một tập (khuyến nghị ~10-20% mẫu).

Input CSV (UTF-8) với header: id,label_a,label_b  (label = 0 hoặc 1)
  id,label_a,label_b
  1,1,1
  2,0,1
  ...

Chạy:
  .venv/bin/python backend/scripts/eval/cohen_kappa.py --csv backend/scripts/eval/labels_agreement.csv

Diễn giải kappa (Landis & Koch): <0.20 kém · 0.21-0.40 tạm · 0.41-0.60 vừa ·
0.61-0.80 tốt · 0.81-1.00 rất tốt. Nếu kappa thấp → họp lại thống nhất tiêu chí gán nhãn.
"""
from __future__ import annotations

import argparse
import csv
from pathlib import Path


def cohen_kappa(a: list[int], b: list[int]) -> float:
    n = len(a)
    if n == 0:
        return float("nan")
    # ma trận nhầm lẫn cho 2 nhãn 0/1
    labels = sorted(set(a) | set(b))
    idx = {l: i for i, l in enumerate(labels)}
    k = len(labels)
    m = [[0] * k for _ in range(k)]
    for x, y in zip(a, b):
        m[idx[x]][idx[y]] += 1
    po = sum(m[i][i] for i in range(k)) / n
    row = [sum(m[i]) / n for i in range(k)]
    col = [sum(m[i][j] for i in range(k)) / n for j in range(k)]
    pe = sum(row[i] * col[i] for i in range(k))
    if pe == 1.0:
        return 1.0
    return (po - pe) / (1 - pe)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    ap.add_argument("--col-a", default="label_a")
    ap.add_argument("--col-b", default="label_b")
    args = ap.parse_args()

    a: list[int] = []
    b: list[int] = []
    with Path(args.csv).open(encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            if row.get(args.col_a, "").strip() == "" or row.get(args.col_b, "").strip() == "":
                continue
            a.append(int(float(row[args.col_a])))
            b.append(int(float(row[args.col_b])))

    n = len(a)
    if n == 0:
        print("Không có dòng nhãn hợp lệ.")
        return
    agree = sum(1 for x, y in zip(a, b) if x == y)
    kappa = cohen_kappa(a, b)
    tp = sum(1 for x, y in zip(a, b) if x == 1 and y == 1)
    tn = sum(1 for x, y in zip(a, b) if x == 0 and y == 0)
    fn = sum(1 for x, y in zip(a, b) if x == 1 and y == 0)
    fp = sum(1 for x, y in zip(a, b) if x == 0 and y == 1)
    print(f"n={n}  percent_agreement={agree / n:.3f}  cohen_kappa={kappa:.3f}")
    print(f"cùng nói LỪA ĐẢO(tp/both1)={tp}  cùng nói HỢP LỆ(tn/both0)={tn}  "
          f"bất đồng(A=1,B=0)={fn}  bất đồng(A=0,B=1)={fp}")
    if kappa < 0.61:
        print("→ Kappa < 0.61: nên họp lại để thống nhất tiêu chí gán nhãn trước khi chốt.")
    else:
        print("→ Kappa đạt mức 'tốt' trở lên: có thể dùng tập nhãn.")


if __name__ == "__main__":
    main()
