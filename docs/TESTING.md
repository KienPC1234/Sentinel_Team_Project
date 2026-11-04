# ShieldCall VN — Verification & Test Suites

Execute test suites to validate database integrity, LLM reasoning, sandbox analysis, and API endpoints.

```bash
# --- Backend Validation ---
.venv/bin/python backend/manage.py check
.venv/bin/python backend/manage.py test api.ai_chat.tests # AI Chat & Session streaming tests
.venv/bin/python backend/manage.py test api.core.tests # Core scanning & trust telemetry

# --- Malware Sandbox (Requires Docker with sentinel-sandbox image) ---
.venv/bin/python backend/manage.py test api.core.tests.test_sandbox_and_puppeteer

# --- Frontend Verification ---
cd frontend && npx tsc --noEmit && npx oxlint && cd ..

# --- Puppeteer Headless Host (26/26 Deep Test Suite) ---
cd puppeteer_host && npm test && cd ..

# --- OCR Engine (VietOCR Character Error Rate Evaluation) ---
.venv/bin/python backend/scripts/ocr_compare.py --image shot.png --truth shot.txt

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
