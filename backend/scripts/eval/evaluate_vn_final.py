"""Đánh giá hệ thống trên tình huống Việt Nam & bộ ca thử Chung kết (Yêu cầu #2).

Chạy offline (không gọi mạng ngoài/API trả phí) trên hai bộ dữ liệu:
1. `independent_test_set_vn.jsonl` (80 tin nhắn thực tế Việt Nam: 40 lừa đảo + 40 hợp lệ dễ nhầm)
   qua `scam_rules.heuristic_score` + `compute_evidence_aware_ensemble`.
2. `vn_final_suite.jsonl` (20 tình huống tổng hợp: bằng chứng mâu thuẫn, thiếu dữ liệu,
   tài khoản/SĐT cộng đồng chờ duyệt, nguồn chính thống VN và ca dễ báo nhầm).

Xuất kết quả JSON thực tế ra `vn_final_eval_results.json`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

BACKEND_DIR = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_DIR))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "PKV.settings")

import django  # noqa: E402
django.setup()

from api.utils.scam_rules import heuristic_score, match_patterns  # noqa: E402
from api.utils.trust_guard import apply_guardrail, compute_evidence_aware_ensemble  # noqa: E402


EVAL_DIR = Path(__file__).resolve().parent
INDEPENDENT_PATH = EVAL_DIR / "independent_test_set_vn.jsonl"
FINAL_SUITE_PATH = EVAL_DIR / "vn_final_suite.jsonl"
OUT_PATH = EVAL_DIR / "vn_final_eval_results.json"


def _load_jsonl(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def evaluate_independent_messages(threshold: int = 40) -> Dict[str, Any]:
    rows = _load_jsonl(INDEPENDENT_PATH)
    tp = fp = tn = fn = 0
    fp_cases: List[Dict[str, Any]] = []
    fn_cases: List[Dict[str, Any]] = []

    for row in rows:
        text = row["text"]
        label = int(row["label"])
        rule_score = heuristic_score(text)
        matched = match_patterns(text)
        ens = compute_evidence_aware_ensemble(
            text=text,
            ai_result=None,
            rule_score=rule_score,
        )
        score = int(ens["final_score"])
        pred = 1 if score >= threshold else 0

        if label == 1 and pred == 1:
            tp += 1
        elif label == 0 and pred == 1:
            fp += 1
            fp_cases.append({"id": row["id"], "category": row.get("category"), "score": score, "patterns": matched})
        elif label == 0 and pred == 0:
            tn += 1
        else:
            fn += 1
            fn_cases.append({"id": row["id"], "category": row.get("category"), "score": score, "patterns": matched})

    total = len(rows)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (tp + fn) if (tp + fn) else 0.0

    return {
        "dataset": INDEPENDENT_PATH.name,
        "mode": "offline_heuristic_plus_evidence_ensemble",
        "threshold": threshold,
        "total": total,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "fp_cases": fp_cases,
        "fn_cases": fn_cases,
    }


def evaluate_final_suite() -> Dict[str, Any]:
    rows = _load_jsonl(FINAL_SUITE_PATH)
    passed = 0
    failed_cases: List[Dict[str, Any]] = []
    insufficient_expected = 0
    insufficient_actual = 0
    contradiction_expected = 0
    contradiction_actual = 0
    details_rows: List[Dict[str, Any]] = []

    for row in rows:
        cid = row["id"]
        group = row["group"]
        ok = True
        actual: Dict[str, Any] = {}

        if "text" in row:
            rule_score = heuristic_score(row["text"])
            matched = match_patterns(row["text"])
            ens = compute_evidence_aware_ensemble(
                text=row["text"],
                ai_result=None,
                rule_score=rule_score,
            )
            score = int(ens["final_score"])
            g_res = apply_guardrail({"risk_score": score, "patterns_found": matched}, kind="message")["guardrail"]
            actual = {"score": score, "tier": g_res["tier"], "is_conclusive": g_res["is_conclusive"]}
            if "expected_max_score" in row and score > int(row["expected_max_score"]):
                ok = False
        else:
            payload = dict(row["payload"])
            kind = row.get("kind", "generic")
            res = apply_guardrail(payload, kind=kind)
            g = res["guardrail"]
            actual = {
                "tier": g["tier"],
                "is_conclusive": g["is_conclusive"],
                "has_contradiction": g.get("has_contradiction", False),
                "evidence_count": len(res.get("evidence", [])),
            }
            if row.get("expected_tier") == "INSUFFICIENT":
                insufficient_expected += 1
                if g["tier"] == "INSUFFICIENT":
                    insufficient_actual += 1
            if row.get("expected_contradiction"):
                contradiction_expected += 1
                if g.get("has_contradiction") and g["tier"] == "INSUFFICIENT":
                    contradiction_actual += 1

            if "expected_tier" in row and g["tier"] != row["expected_tier"]:
                ok = False
            if "expected_conclusive" in row and bool(g["is_conclusive"]) != bool(row["expected_conclusive"]):
                ok = False
            if "expected_contradiction" in row and bool(g.get("has_contradiction")) != bool(row["expected_contradiction"]):
                ok = False

        if ok:
            passed += 1
        else:
            failed_cases.append({"id": cid, "group": group, "expected": row, "actual": actual})

        details_rows.append({"id": cid, "group": group, "passed": ok, "actual": actual})

    return {
        "dataset": FINAL_SUITE_PATH.name,
        "total": len(rows),
        "passed": passed,
        "failed": len(failed_cases),
        "insufficient_refusal_rate": (
            round(insufficient_actual / insufficient_expected, 4) if insufficient_expected else 1.0
        ),
        "contradiction_refusal_rate": (
            round(contradiction_actual / contradiction_expected, 4) if contradiction_expected else 1.0
        ),
        "failed_cases": failed_cases,
        "results": details_rows,
    }


def main() -> int:
    ind_res = evaluate_independent_messages(threshold=40)
    suite_res = evaluate_final_suite()
    report = {
        "independent_vn_messages": ind_res,
        "final_guardrail_suite": suite_res,
    }
    OUT_PATH.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if suite_res["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
