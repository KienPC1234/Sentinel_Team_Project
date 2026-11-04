<div align="center">
 <h1>ShieldCall VN (Sentinel Core)</h1>
 <p><b>Multi-Modal Threat Intelligence, Zero-Trust Sandbox & Anti-Fraud Architecture</b></p>
 <p><b>Live Demo:</b> <a href="https://sc.fptoj.com">https://sc.fptoj.com</a></p>

 [![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
 [![Django](https://img.shields.io/badge/Django-5.2-green.svg)](https://www.djangoproject.com/)
 [![Database](https://img.shields.io/badge/Database-MariaDB%2FMySQL-orange.svg)](https://mariadb.org/)
 [![Cache/Broker](https://img.shields.io/badge/Broker-Redis%208-red.svg)](https://redis.io/)
 [![Inference](https://img.shields.io/badge/LLM-Ollama%20(DeepSeek%20%7C%20Gemma4)-purple.svg)](https://ollama.com/)
 [![Docker](https://img.shields.io/badge/Sandbox-Docker%20Zero--Trust-2496ED.svg)](https://www.docker.com/)
 [![Hardware](https://img.shields.io/badge/GPU-NVIDIA%20CUDA-76B900.svg)](https://developer.nvidia.com/cuda-zone)
 [![Orchestration](https://img.shields.io/badge/Process-PM2-lightgrey.svg)](https://pm2.keymetrics.io/)
</div>

---

## Overview

**ShieldCall VN** detects, analyzes, and neutralizes cyber-fraud across telephony, banking, web, email, images, audio, and executable files. It combines an asynchronous Django/Channels core, Celery workers, GPU-accelerated OCR/STT, local LLM inference (Ollama), a hardened Puppeteer cluster, and an isolated Docker malware sandbox.

| Vector | Engine |
| :--- | :--- |
| Phone / MSISDN | E.164 normalization, threat telemetry, carrier and community reports |
| Bank account | VietQR beneficiary resolution + fraud intelligence databases |
| Domain / URL | DNS/MX, WHOIS age, SSL reputation, SSRF-isolated rendering |
| Email / message | `.eml` parsing, SPF/DKIM/DMARC alignment, scam-script detection |
| Image / audio | VietOCR + QR decoding, Faster-Whisper transcription + urgency analysis |
| File / APK | Zero-Trust Docker sandbox: YARA, OLETools, PEFile, PyPDF, ClamAV |

Findings are aggregated, enriched through FAISS RAG, and scored by the local LLM into a **0–100 risk score**, a threat level (SAFE / WARNING / CRITICAL), and actionable remediation guidance.

### Safety guarantees

1. **Uncertainty guardrail** — inconclusive evidence (10–39 with no independent confirmation) never yields "safe"; it returns *"INSUFFICIENT EVIDENCE FOR VERIFICATION"* with official hotlines.
2. **Evidence-backed findings** — every result carries structured `evidence[]` entries (source, reliability tier, severity, references).
3. **Source telemetry** — `/api/v1/trust/sources/` documents reliability metrics and each engine's operational limits.
4. **Vietnamese threat intelligence** — national hotlines (NCSC 156, Police 113, VNCERT), bank/e-wallet emergency lines, scam vocabularies, and the **Tín nhiệm mạng** crawler ([`docs/TINNHIEM.md`](docs/TINNHIEM.md)).
5. **PII redaction** — phones, emails, accounts, citizen IDs, cards, and secrets are sanitized before logging or cloud LLM transmission.

> Evaluation dossier: [`docs/CAI_TIEN_THEO_HOI_DONG.md`](docs/CAI_TIEN_THEO_HOI_DONG.md).
> Limitations and roadmap: [`docs/REBUTTAL_QA.md`](docs/REBUTTAL_QA.md). Benchmark numbers are preliminary internal baselines.

---

## Architecture

```
Clients / MCP agents → Reverse proxy → Daphne ASGI (:8001) → Redis / MariaDB
                                            ├→ Puppeteer cluster (:3010)
                                            └→ Celery workers → FAISS, sandbox, AI service (:5010)
                                                                  └→ Ollama (:11434)
```

Full topology, the six-vector pipeline, sandbox hardening flags, and the MCP server are documented in **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**.

---

## Repository Layout

```text
Sentinel_Team_Project/
├── backend/           # Django 5.2 core (api, PKV, vector_store, scripts, sandbox)
├── frontend/          # Next.js 16 App Router UI
├── puppeteer_host/    # Headless browser cluster (TypeScript, anti-SSRF)
├── docs/              # Architecture, setup, API, testing, evaluation papers
└── ecosystem.config.js# PM2 orchestration for the 6 microservices
```

> Run commands from the relevant subdirectory: `backend/`, `frontend/`, or `puppeteer_host/`.

---

## Quick Start

Full prerequisites, environment variables, S3 setup, and troubleshooting: **[docs/SETUP.md](docs/SETUP.md)**.

```bash
# 1) System packages
sudo apt-get update && sudo apt-get install -y \
 python3.11 python3.11-venv python3-pip mariadb-server redis-server \
 clamav clamav-daemon docker.io docker-compose-v2 \
 chromium-browser chromium-chromedriver nodejs npm ffmpeg git
sudo systemctl enable --now mariadb redis-server docker clamav-daemon
sudo usermod -aG docker $USER

# 2) Python environment (Python 3.11)
python3.11 -m venv .venv
.venv/bin/pip install -U pip && .venv/bin/pip install -r backend/requirements.txt
.venv/bin/pip install gdown && .venv/bin/pip install --no-deps vietocr==0.3.13

# 3) Configure backend/.env (see docs/SETUP.md for every variable)
#    Minimum: DEBUG, SECRET_KEY, ALLOWED_HOSTS, DB_*, REDIS_*, OLLAMA_BASE_URL

# 4) Database, knowledge base, sandbox image
cd backend && python manage.py migrate && python manage.py collectstatic --noinput
python manage.py seed_vn_knowledge   # optional: 18 Vietnamese intelligence articles
cd .. && docker build -t sentinel-sandbox:latest ./backend/sandbox

# 5) Frontend and headless browser
cd puppeteer_host && npm install && npm run build && cd ..
cd frontend && npm install && npm run build && cd ..

# 6) Run everything
pm2 start ecosystem.config.js && pm2 save && pm2 status
```

GPU is optional: set `WHISPER_DEVICE=cpu`, `VIETOCR_DEVICE=cpu`, `VECTOR_DB_USE_GPU=False` to run on CPU.

---

## Technology Stack

| Layer | Technologies |
| :--- | :--- |
| Runtime | Python 3.11, Node.js 24.x, Docker Engine 29.x |
| Web & API | Django 5.2, DRF, Daphne ASGI, Channels 4 |
| Data | MariaDB 11 / MySQL 8 (PyMySQL), Redis 8 (django-redis, channels-redis) |
| Tasks | Celery 5.6 (thread-pool worker + beat scheduler) |
| AI & neural | Ollama, PyTorch 2 CUDA, FAISS (`nomic-embed-text-v1`), Faster-Whisper, VietOCR |
| Sandbox | Docker ephemeral containers, YARA, OLETools, PEFile, PyPDF, ClamAV |
| Browser | Puppeteer Extra + Chromium headless + stealth plugin + anti-SSRF relay |
| Security | Cloudflare Turnstile, Django-OTP (TOTP/email MFA), Google OAuth2, WhiteNoise |
| Ops | PM2, object storage (S3-compatible via django-storages/boto3) |

---

## Documentation

| Document | Contents |
| :--- | :--- |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Topology, analysis pipeline, sandbox, Puppeteer, MCP |
| [docs/SETUP.md](docs/SETUP.md) | Prerequisites, `.env`, S3, builds, PM2 services |
| [docs/API_REFERENCE.md](docs/API_REFERENCE.md) | Endpoint table, auth, Swagger / ReDoc |
| [docs/TESTING.md](docs/TESTING.md) | Backend, sandbox, frontend, Puppeteer, OCR, ROC evaluation |
| [docs/TINNHIEM.md](docs/TINNHIEM.md) | Trusted-domain crawler and threat feed |
| [docs/OCR_VIETNAMESE.md](docs/OCR_VIETNAMESE.md) | OCR pipeline and CER benchmarks |
| [docs/EVAL_GUIDE.md](docs/EVAL_GUIDE.md) | Threshold and inter-annotator evaluation |
| [PROJECT_OVERVIEW.md](PROJECT_OVERVIEW.md) | Vietnamese feature and screen overview |

Interactive API docs: `/api/docs/` (Swagger UI), `/api/redoc/` (ReDoc), `/api/schema/` (OpenAPI).

---

## License

Copyright (c) 2026 **Sentinel Team**. Licensed under the
**GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — see `LICENSE`.
Running a modified version on a public server requires offering the Corresponding Source to
remote users (AGPL §13). Third-party components retain their upstream licenses; see
[`docs/LEGAL_AND_LICENSE.md`](docs/LEGAL_AND_LICENSE.md).
