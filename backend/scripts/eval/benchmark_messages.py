#!/usr/bin/env python3
"""
ShieldCall VN — Comprehensive Benchmark Suite for Scam Message Detection.

Supports:
  1. Dev Set (80 samples) - ablation & optimization verification.
  2. Holdout Test Set B (40 unseen samples) - out-of-sample generalization.

Evaluates 4 configurations:
  1. Heuristic Only (scam_rules.py: heuristic_score)
  2. LLM Only (ollama_client.py: analyze_text_for_scam)
  3. Calibrated Ensemble (Heuristic + LLM with evidence guardrail)
  4. Full Production Pipeline (_analyze_message_text with domain checks & TrustGuard)

Computes:
  - Precision, Recall (with Wilson 95% Confidence Interval), F1, Accuracy, Specificity
  - Confusion Matrix [[TN, FP], [FN, TP]]
  - Latency: avg, min, max, p95
  - Detailed Error Mode Analysis (False Positives and False Negatives)

Usage:
  .venv/bin/python backend/scripts/eval/benchmark_messages.py --dataset dev
  .venv/bin/python backend/scripts/eval/benchmark_messages.py --dataset holdout_b
  .venv/bin/python backend/scripts/eval/benchmark_messages.py --all
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import logging
import math
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

# Configure Django environment
REPO_ROOT = Path(__file__).resolve().parents[3]
BACKEND_DIR = REPO_ROOT / "backend"
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings")

import django  # noqa: E402
django.setup()

from django.core.cache import cache  # noqa: E402
from api.utils.scam_rules import heuristic_score, match_patterns  # noqa: E402
from api.utils.ollama_client import analyze_text_for_scam  # noqa: E402
from api.core.views.scan_views import _analyze_message_text  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("benchmark")


def wilson_ci(k: int, n: int, confidence: float = 0.95) -> Tuple[float, float]:
    """Calculate Wilson score interval for binomial proportion."""
    if n == 0:
        return (0.0, 0.0)
    z = 1.95996  # 95% confidence z-score
    p = k / n
    denom = 1 + (z ** 2) / n
    center = (p + (z ** 2) / (2 * n)) / denom
    spread = (z * math.sqrt((p * (1 - p) / n) + (z ** 2) / (4 * (n ** 2)))) / denom
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (round(lower, 4), round(upper, 4))


def compute_metrics(y_true: List[int], scores: List[float], threshold: float) -> Dict[str, Any]:
    y_pred = [1 if s >= threshold else 0 for s in scores]
    tp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 1)
    fp = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 1)
    tn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 0 and yp == 0)
    fn = sum(1 for yt, yp in zip(y_true, y_pred) if yt == 1 and yp == 0)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0

    pos_total = sum(y_true)
    neg_total = len(y_true) - pos_total

    recall_ci = wilson_ci(tp, pos_total)
    precision_ci = wilson_ci(tp, tp + fp) if (tp + fp) > 0 else (0.0, 0.0)
    specificity_ci = wilson_ci(tn, neg_total)

    return {
        "threshold": threshold,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "precision_ci95": precision_ci,
        "recall": round(recall, 4),
        "recall_ci95": recall_ci,
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
        "specificity": round(specificity, 4),
        "specificity_ci95": specificity_ci,
        "confusion_matrix": {
            "matrix": [[tn, fp], [fn, tp]],
            "legend": "[[TN, FP], [FN, TP]]"
        }
    }


def evaluate_heuristic(sample: Dict[str, Any]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    text = sample["text"]
    patterns = match_patterns(text)
    score = heuristic_score(text)
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "score": score,
        "latency_ms": latency_ms,
        "patterns": patterns,
    }


def evaluate_llm(sample: Dict[str, Any]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    text = sample["text"]
    try:
        res = analyze_text_for_scam(text)
        score = res.get("risk_score", 0) or 0
        explanation = res.get("explanation") or res.get("reason") or ""
        indicators = res.get("indicators", [])
        is_scam = res.get("is_scam", False)
    except Exception as ex:
        logger.warning(f"LLM evaluation failed on sample {sample['id']}: {ex}")
        score = 0
        explanation = f"Error: {ex}"
        indicators = []
        is_scam = False
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "score": score,
        "latency_ms": latency_ms,
        "explanation": explanation,
        "indicators": indicators,
        "is_scam": is_scam,
    }


def evaluate_full_pipeline(sample: Dict[str, Any]) -> Dict[str, Any]:
    t0 = time.perf_counter()
    text = sample["text"]
    import hashlib
    clean_text = (text or "").strip()
    cache_key = f"msg_analysis:{hashlib.sha256(clean_text.encode('utf-8')).hexdigest()}"
    cache.delete(cache_key)

    try:
        res = _analyze_message_text(text)
        score = res.get("risk_score", 0) or 0
        risk_level = res.get("risk_level", "SAFE")
        explanation = res.get("explanation", "")
        guardrail = res.get("guardrail", {})
    except Exception as ex:
        logger.warning(f"Pipeline evaluation failed on sample {sample['id']}: {ex}")
        score = 0
        risk_level = "ERROR"
        explanation = f"Error: {ex}"
        guardrail = {}
    latency_ms = (time.perf_counter() - t0) * 1000.0
    return {
        "score": score,
        "latency_ms": latency_ms,
        "risk_level": risk_level,
        "explanation": explanation,
        "guardrail": guardrail,
    }


def run_benchmark_for_dataset(dataset_file: Path, report_file: Path, json_file: Path, title: str):
    items = []
    with open(dataset_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                items.append(json.loads(line))

    logger.info(f"Loaded {len(items)} samples from {dataset_file.name}")
    y_true = [s["label"] for s in items]

    # 1. Heuristic Only
    logger.info("Evaluating Heuristic Only...")
    heuristic_results = [evaluate_heuristic(s) for s in items]

    # 2. LLM Only (Workers = 3)
    logger.info("Evaluating LLM Only...")
    llm_results = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_idx = {executor.submit(evaluate_llm, s): i for i, s in enumerate(items)}
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                llm_results[idx] = future.result()
            except Exception as e:
                llm_results[idx] = {"score": 0, "latency_ms": 0.0, "explanation": str(e), "indicators": [], "is_scam": False}
            if (idx + 1) % 10 == 0 or idx == len(items) - 1:
                logger.info(f"LLM progress: {sum(1 for r in llm_results if r is not None)}/{len(items)}")

    # 3. Calibrated Ensemble
    logger.info("Evaluating Calibrated Ensemble...")
    ensemble_results = []
    for h_res, l_res in zip(heuristic_results, llm_results):
        h_score = h_res["score"]
        l_score = l_res["score"]
        is_safe = (l_score <= 20) and not l_res.get("is_scam", False)
        if is_safe:
            score = max(l_score, min(h_score, 35))
        else:
            score = max(h_score, l_score)
        lat = h_res["latency_ms"] + l_res["latency_ms"]
        ensemble_results.append({
            "score": score,
            "latency_ms": lat,
            "heuristic_score": h_score,
            "llm_score": l_score,
        })

    # 4. Full Production Pipeline
    logger.info("Evaluating Full Production Pipeline...")
    full_pipeline_results = [None] * len(items)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        future_to_idx = {executor.submit(evaluate_full_pipeline, s): i for i, s in enumerate(items)}
        for future in concurrent.futures.as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                full_pipeline_results[idx] = future.result()
            except Exception as e:
                full_pipeline_results[idx] = {"score": 0, "latency_ms": 0.0, "risk_level": "ERROR", "explanation": str(e), "guardrail": {}}
            if (idx + 1) % 10 == 0 or idx == len(items) - 1:
                logger.info(f"Pipeline progress: {sum(1 for r in full_pipeline_results if r is not None)}/{len(items)}")

    configurations = {
        "Heuristic Only": [r["score"] for r in heuristic_results],
        "LLM Only": [r["score"] for r in llm_results],
        "Calibrated Ensemble": [r["score"] for r in ensemble_results],
        "Full Pipeline": [r["score"] for r in full_pipeline_results],
    }

    latencies = {
        "Heuristic Only": [r["latency_ms"] for r in heuristic_results],
        "LLM Only": [r["latency_ms"] for r in llm_results],
        "Calibrated Ensemble": [r["latency_ms"] for r in ensemble_results],
        "Full Pipeline": [r["latency_ms"] for r in full_pipeline_results],
    }

    summary_report = {}
    for name, scores in configurations.items():
        m_70 = compute_metrics(y_true, scores, threshold=70.0)
        m_40 = compute_metrics(y_true, scores, threshold=40.0)
        lats = latencies[name]
        summary_report[name] = {
            "threshold_70": m_70,
            "threshold_40": m_40,
            "latency": {
                "avg_ms": round(float(np.mean(lats)), 2),
                "min_ms": round(float(np.min(lats)), 2),
                "max_ms": round(float(np.max(lats)), 2),
                "p95_ms": round(float(np.percentile(lats, 95)), 2),
            }
        }

    # Error analysis for Full Pipeline at threshold 70
    pipeline_scores = configurations["Full Pipeline"]
    false_positives = []
    false_negatives = []
    for i, (sample, score) in enumerate(zip(items, pipeline_scores)):
        is_pred_scam = score >= 70.0
        is_true_scam = sample["label"] == 1
        record = {
            "id": sample["id"],
            "category": sample["category"],
            "text": sample["text"],
            "true_label": sample["label"],
            "predicted_score": score,
            "heuristic_score": heuristic_results[i]["score"],
            "llm_score": llm_results[i]["score"],
            "explanation": full_pipeline_results[i]["explanation"],
        }
        if not is_true_scam and is_pred_scam:
            false_positives.append(record)
        elif is_true_scam and not is_pred_scam:
            false_negatives.append(record)

    full_output = {
        "metadata": {
            "title": title,
            "dataset": dataset_file.name,
            "total_samples": len(items),
            "positives_scam": sum(y_true),
            "negatives_legit": len(y_true) - sum(y_true),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        },
        "summary": summary_report,
        "error_analysis": {
            "false_positives_count": len(false_positives),
            "false_positives": false_positives,
            "false_negatives_count": len(false_negatives),
            "false_negatives": false_negatives,
        },
        "raw_samples": [
            {
                "id": s["id"],
                "category": s["category"],
                "label": s["label"],
                "scores": {
                    "heuristic": heuristic_results[i]["score"],
                    "llm": llm_results[i]["score"],
                    "ensemble": ensemble_results[i]["score"],
                    "full_pipeline": full_pipeline_results[i]["score"],
                }
            }
            for i, s in enumerate(items)
        ]
    }

    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(full_output, f, ensure_ascii=False, indent=2)

    # Generate Markdown Report
    generate_markdown(full_output, summary_report, false_positives, false_negatives, report_file, title)
    logger.info(f"Saved results to {report_file} and {json_file}")

    print(f"\n================== {title.upper()} (THRESHOLD 70 - RED) ==================")
    print(f"{'Configuration':<25} | {'Prec':<7} | {'Recall':<7} | {'Wilson 95% CI':<15} | {'F1':<7} | {'Spec':<7} | {'Avg Latency'}")
    print("-" * 92)
    for name, data in summary_report.items():
        m = data["threshold_70"]
        lat = data["latency"]["avg_ms"]
        ci_str = f"[{m['recall_ci95'][0]:.3f}, {m['recall_ci95'][1]:.3f}]"
        print(f"{name:<25} | {m['precision']:<7.4f} | {m['recall']:<7.4f} | {ci_str:<15} | {m['f1']:<7.4f} | {m['specificity']:<7.4f} | {lat:.1f}ms")

    m_full = summary_report["Full Pipeline"]["threshold_70"]
    cm = m_full["confusion_matrix"]["matrix"]
    print(f"\nConfusion Matrix for Full Pipeline (Threshold >= 70):")
    print(f"  TN: {cm[0][0]:<3} | FP: {cm[0][1]:<3}")
    print(f"  FN: {cm[1][0]:<3} | TP: {cm[1][1]:<3}")
    print("=========================================================================================\n")


def generate_markdown(full_output, summary_report, false_positives, false_negatives, out_path: Path, title: str):
    meta = full_output["metadata"]
    md = f"""# {title}

> **Thời điểm thực nghiệm:** {meta['timestamp']}  
> **Tệp dữ liệu:** `{meta['dataset']}`  
> **Quy mô mẫu:** **{meta['total_samples']} mẫu** ({meta['positives_scam']} mẫu lừa đảo, {meta['negatives_legit']} mẫu an toàn)  
> **Khoảng tin cậy:** Wilson Score 95% Confidence Interval

---

## 1. Kết Quả Tổng Hợp Đa Cấu Hình (Ablation Study)

### Bảng 1.1: Hiệu năng ở Ngưỡng Khẳng định Lừa đảo (Ngưỡng $\\ge 70$ - Mức ĐỎ)

| Cấu hình | Precision | Recall | Recall 95% CI (Wilson) | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
"""
    for name, data in summary_report.items():
        m = data["threshold_70"]
        lat = data["latency"]["avg_ms"]
        ci_str = f"[{m['recall_ci95'][0]:.3f}, {m['recall_ci95'][1]:.3f}]"
        md += f"| **{name}** | {m['precision']:.4f} | {m['recall']:.4f} | `{ci_str}` | **{m['f1']:.4f}** | {m['accuracy']:.4f} | {m['specificity']:.4f} | {lat:.1f} ms |\n"

    md += """
### Bảng 1.2: Hiệu năng ở Ngưỡng Cảnh báo Rủi ro (Ngưỡng $\\ge 40$ - Mức VÀNG + ĐỎ)

| Cấu hình | Precision | Recall | F1-Score | Accuracy | Specificity | Độ trễ TB |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
"""
    for name, data in summary_report.items():
        m = data["threshold_40"]
        lat = data["latency"]["avg_ms"]
        md += f"| **{name}** | {m['precision']:.4f} | {m['recall']:.4f} | **{m['f1']:.4f}** | {m['accuracy']:.4f} | {m['specificity']:.4f} | {lat:.1f} ms |\n"

    pipe_70 = summary_report["Full Pipeline"]["threshold_70"]
    cm_70 = pipe_70["confusion_matrix"]["matrix"]

    md += f"""
---

## 2. Ma Trận Nhầm Lẫn (Confusion Matrix) — Full Production Pipeline (Threshold $\\ge 70$)

| Thực tế \\ Dự đoán | Dự đoán: An toàn (Safe/Insufficient) | Dự đoán: Lừa đảo (Scam) | Tổng thực tế |
| :--- | :---: | :---: | :---: |
| **Thực tế: Tin an toàn (Legitimate)** | **TN = {cm_70[0][0]}** | **FP = {cm_70[0][1]}** | {cm_70[0][0] + cm_70[0][1]} |
| **Thực tế: Lừa đảo (Scam)** | **FN = {cm_70[1][0]}** | **TP = {cm_70[1][1]}** | {cm_70[1][0] + cm_70[1][1]} |

---

## 3. Phân Tích Lỗi (Error Mode Analysis)

### 3.1. Các Trường Hợp Dương Tính Giả (False Positives - Ngưỡng $\\ge 70$)
Số lượng: **{len(false_positives)} trường hợp**
"""
    if not false_positives:
        md += "\n> Không có trường hợp dương tính giả nào ở ngưỡng 70. Hệ thống đạt độ đặc hiệu (Specificity) 100%.\n"
    else:
        for fp in false_positives:
            md += f"""
- **Mẫu `{fp['id']}`** (Phân loại: `{fp['category']}`):
  - *Nội dung*: "{fp['text']}"
  - *Điểm*: Pipeline = `{fp['predicted_score']}`, Heuristic = `{fp['heuristic_score']}`, LLM = `{fp['llm_score']}`
  - *Giải trình*: {fp['explanation']}
"""

    md += f"""
### 3.2. Các Trường Hợp Âm Tính Giả (False Negatives - Ngưỡng $\\ge 70$)
Số lượng: **{len(false_negatives)} trường hợp**
"""
    if not false_negatives:
        md += "\n> Không có trường hợp âm tính giả nào ở ngưỡng 70.\n"
    else:
        for fn in false_negatives:
            md += f"""
- **Mẫu `{fn['id']}`** (Phân loại: `{fn['category']}`):
  - *Nội dung*: "{fn['text']}"
  - *Điểm*: Pipeline = `{fn['predicted_score']}`, Heuristic = `{fn['heuristic_score']}`, LLM = `{fn['llm_score']}`
  - *Giải trình*: {fn['explanation']}
"""

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(md)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", choices=["dev", "holdout_b", "all"], default="all")
    args = parser.parse_args()

    eval_dir = Path(__file__).resolve().parent

    if args.dataset in ["dev", "all"]:
        dev_file = eval_dir / "dev_set_80.jsonl"
        dev_report = REPO_ROOT / "docs" / "BENCHMARK_MESSAGES_DEV.md"
        dev_json = eval_dir / "benchmark_dev_results.json"
        run_benchmark_for_dataset(dev_file, dev_report, dev_json, "Báo Cáo Đánh Giá Tập Phát Triển (Dev Set - 80 mẫu)")

    if args.dataset in ["holdout_b", "all"]:
        holdout_file = eval_dir / "holdout_test_set_b.jsonl"
        holdout_report = REPO_ROOT / "docs" / "BENCHMARK_MESSAGES_HOLDOUT_B.md"
        holdout_json = eval_dir / "benchmark_holdout_b_results.json"
        run_benchmark_for_dataset(holdout_file, holdout_report, holdout_json, "Báo Cáo Đánh Giá Tập Kiểm Thử Độc Lập Thứ Hai (Holdout Set B - 40 mẫu)")


if __name__ == "__main__":
    main()
