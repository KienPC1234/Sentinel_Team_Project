# ShieldCall VN — Verification & Test Suites

> **Status:** current · **Updated:** 2026-11-16 · **Audience:** engineers, CI maintainers

Execute test suites to validate database integrity, LLM reasoning, sandbox analysis, and API endpoints.

```bash
# --- Backend Validation ---
.venv/bin/python backend/manage.py check
.venv/bin/python backend/manage.py test api.ai_chat.tests # AI Chat & Session streaming tests
.venv/bin/python backend/manage.py test api.core.tests # Core scanning & trust telemetry

# --- CI / Full Backend Regression Suite (skips live token-consuming AI Red-Team by default) ---
DJANGO_SETTINGS_MODULE=PKV.settings_ci .venv/bin/python backend/manage.py test --noinput

# --- Opt-in Live AI Red-Team & Anti-Abuse Suite (consumes real LLM tokens) ---
RUN_LIVE_AI_TESTS=1 .venv/bin/python backend/manage.py test api.core.tests.test_ai_redteam_live --noinput

# --- Malware Sandbox (Requires Docker with sentinel-sandbox image) ---
.venv/bin/python backend/manage.py test api.core.tests.test_sandbox_and_puppeteer

# --- Frontend Verification ---
cd frontend && npm run lint && npx tsc --noEmit && npm run check:tours && cd ..
# check:tours: hồi quy neo data-tour của tour hướng dẫn (driver.js) — bắt lỗi
# refactor làm mất phần tử mà tour trỏ tới. Xem frontend/scripts/check-tours.mjs.

# --- Puppeteer Headless Host (26/26 Deep Test Suite) ---
cd puppeteer_host && npm test && cd ..

# --- OCR Engine (VietOCR Character Error Rate Evaluation) ---
.venv/bin/python backend/scripts/ocr_compare.py --image shot.png --truth shot.txt

# --- Final VN Benchmark & Guardrail Evaluation ---
.venv/bin/python backend/scripts/eval/evaluate_vn_final.py

# --- Decision Threshold & ROC Evaluation (Reproducible, GPU optional) ---
.venv/bin/python backend/scripts/eval/evaluate_thresholds.py # Results output to docs/EVAL_THRESHOLDS.md
.venv/bin/python backend/scripts/eval/evaluate_generic.py --dataset <file.jsonl> \
 --scorer <message|domain_lookalike|field>
.venv/bin/python backend/scripts/eval/cohen_kappa.py --csv backend/scripts/eval/labels_agreement.csv
# Step-by-step guidance available in docs/EVAL_GUIDE.md

# --- Service Readiness & Smoke Tests ---
.venv/bin/python backend/scripts/test_ollama.py
.venv/bin/python backend/scripts/test_api.py
```
