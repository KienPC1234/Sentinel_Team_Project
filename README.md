<div align="center">
  <h1>ShieldCall VN (Sentinel Core)</h1>
  <p><b>Advanced Multi-Modal Threat Intelligence, Zero-Trust Sandbox & Anti-Fraud Architecture</b></p>
  <p><b>Production Endpoint:</b> <a href="https://sc.fptoj.com">https://sc.fptoj.com</a></p>

  [![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
  [![Django](https://img.shields.io/badge/Django-5.2-green.svg)](https://www.djangoproject.com/)
  [![Database](https://img.shields.io/badge/Database-MariaDB%2FMySQL-orange.svg)](https://mariadb.org/)
  [![Cache%2FBroker](https://img.shields.io/badge/Broker-Redis%208-red.svg)](https://redis.io/)
  [![Inference](https://img.shields.io/badge/LLM-Ollama%20(DeepSeek%20%7C%20Gemma4)-purple.svg)](https://ollama.com/)
  [![Docker](https://img.shields.io/badge/Sandbox-Docker%20Zero--Trust-2496ED.svg)](https://www.docker.com/)
  [![Orchestration](https://img.shields.io/badge/Process-PM2-lightgrey.svg)](https://pm2.keymetrics.io/)
</div>

---

## 1. Executive Summary & Architecture

**ShieldCall VN** is an enterprise-grade digital safety and cyber-fraud mitigation platform designed to detect, analyze, and neutralize multifaceted threats across telecommunication, financial, digital communication, and executable file vectors.

The platform employs a hybrid asynchronous architecture combining real-time ASGI WebSocket/SSE streams, background distributed task workers, GPU-accelerated neural computing, and an isolated Zero-Trust Docker Sandbox backed by industry-standard forensic toolsets.

```
                                      [ Client Layer ]
                      (Web Frontend / Mobile Client / REST API Consumer)
                                             │
                                             ▼
                            [ Reverse Proxy / TLS Termination ]
                                        (sc.fptoj.com)
                                             │
                 ┌───────────────────────────┴───────────────────────────┐
                 │                                                       │
                 ▼ (HTTP / WebSocket / SSE)                              ▼ (Headless JS Render)
        [ Daphne ASGI Server :8001 ]                                [ Puppeteer Host :3010 ]
           ├── Django REST Framework                                     ├── Anti-SSRF DNS Resolver
           ├── Channels Protocol Router                                  ├── Auto Memory Tab Recycling
           └── Anti-SSRF Web Scraping Relay ◄────────────────────────────└── Stealth Mode (Blink Masking)
                 │
                 ├───► [ MariaDB / MySQL 11.x ] (Relational Persistence & Auth)
                 │
                 ├───► [ Redis 8.x ] (Channel Layers, Cache, Celery Broker)
                 │        ▲
                 │        │ (Task Distribution)
                 │     [ Celery Workers & Celery Beat ]
                 │        ├── Deep OCR Extraction (EasyOCR - GPU CUDA)
                 │        ├── Voice Impersonation & Speech-to-Text (Faster-Whisper - GPU CUDA)
                 │        └── Vector Index Ingestion (FAISS + Nomic Embed)
                 │
                 ├───► [ Zero-Trust Docker Malware Sandbox ] (Ephemeral Container : sentinel-sandbox)
                 │        ├── YARA Multi-Vector Signature Rules
                 │        ├── OLETools (VBA Macro Forensics & IOC Extraction)
                 │        ├── PEFile (Windows PE Inspection, Section Entropy & API Imports)
                 │        ├── PyPDF Exploit & Stream Decoder (/Launch, /JS, /OpenAction)
                 │        └── ClamAV Antivirus Scanner
                 │
                 └───► [ Ollama Local / Cloud Daemon :11434 ]
                          ├── Primary LLM: deepseek-v4-flash:cloud
                          └── Fast / Classification LLM: gemma4:31b-cloud
```

---

## 2. Core Subsystems

### 2.1 Multi-Vector Threat Analysis Pipeline
- **Telecommunication & Number Scoring**: Normalizes international and domestic Vietnamese MSISDN formats, cross-referencing threat telemetry and blacklist repositories.
- **Financial Account Verification**: Detects fraudulent accounts and illicit beneficiary channels.
- **Domain & Web Intelligence**: Inspects DNS MX records, domain age (WHOIS), SSL reputation, and ScamAdviser / Trustpilot metrics with SSRF-isolated relays.
- **Multi-Modal AI Analysis**:
  - **Audio Streams**: Acoustic transcription via `Faster-Whisper` running on NVIDIA GPU CUDA followed by psychological manipulation analysis.
  - **Visual Media**: Image OCR via `EasyOCR` (GPU accelerated) combined with QR code matrix decoding and phishing banner classification.

### 2.2 Zero-Trust Local Malware Sandbox Engine
Replaces third-party external dependencies with an entirely isolated on-premise containment engine:
- **Containment Model**: Every suspicious file is mounted read-only inside an ephemeral container (`sentinel-sandbox:latest`) with `--network none`, `--cap-drop ALL`, `--read-only`, `--memory 1g`, `--cpus 2.0`, and `--pids-limit 64`.
- **Multi-Engine Static & Heuristic Dissection**:
  - **YARA Engine**: Scans binary patterns for ransomware extortion notes, process injection calls, and obfuscated droppers.
  - **OLETools (`olevba`)**: Dissects VBA macro streams in `.doc`, `.docx`, `.xls`, `.xlsx`, `.xlsm` files to detect `Auto_Open`, `Shell()`, and `WScript.Shell`.
  - **PEFile Engine**: Computes `imphash`, analyzes section Shannon entropy, and flags critical injection APIs (`VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`).
  - **PyPDF Dissection**: Flags `/Launch` system execution commands, `/EmbeddedFiles` droppers, and `/JS` JavaScript streams.
  - **ClamAV Engine**: Cross-references against updated open-source antivirus definitions.

### 2.3 Hardened Puppeteer Headless Web Cluster
- **Anti-SSRF Isolation**: Validates all target hostnames and DNS resolutions to block access to private subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.169.254`).
- **Anti-Detection Stealth**: Employs `puppeteer-extra-plugin-stealth` with automated flag masking (`navigator.webdriver` removal, custom humanized User-Agents).
- **Leak Prevention & Resource Optimization**: Utilizes `WeakMap` page tracking, blocks heavy media streams (`audio`, `video`, `fonts`), and automatically recycles browser instances after 50 renders to release accumulated V8 memory.

---

## 3. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Runtime Environment** | Python 3.11 (Virtualenv), Node.js v24.x, Docker Engine v29.x |
| **Web & API Framework** | Django 5.2.x, Django REST Framework, Daphne ASGI, Channels 4.x |
| **Database & Caching** | MariaDB 11.x / MySQL 8.x (`PyMySQL`), Redis 8.x (`django-redis`, `channels-redis`) |
| **Distributed Tasks** | Celery 5.6.x (Thread Pool Worker + Periodic Beat Scheduler) |
| **Hardware Acceleration** | NVIDIA CUDA GPU (RTX 4070 SUPER), cuDNN |
| **Malware Sandbox** | Docker Isolated Ephemeral Containers, YARA, OLETools, PEFile, PyPDF, ClamAV |
| **Browser Cluster** | Puppeteer Extra, Chromium (Headless), Stealth Plugin, Anti-SSRF Relay |
| **AI & Neural Computing** | Ollama SDK, PyTorch 2.x CUDA, Sentence-Transformers, FAISS, Faster-Whisper, EasyOCR |
| **Process Manager** | PM2 (Production Ecosystem with Dynamic Path Resolution) |
| **Security & Auth** | Cloudflare Turnstile, Django-OTP (TOTP/Email MFA), Google OAuth2, WhiteNoise |

---

## 4. API Specification Overview

Base URL: `https://sc.fptoj.com/api/v1`

| Endpoint | Method | Purpose | Authentication |
| :--- | :--- | :--- | :--- |
| `/check-session` | `GET` | Validates or provisions ephemeral mobile sessions | Public |
| `/check-phone` | `GET` | High-speed risk classification for MSISDNs | Public |
| `/scan/phone/` | `POST` | Comprehensive telephone threat assessment | Turnstile |
| `/scan/message/` | `POST` | SMS and social messaging fraud analysis | Turnstile |
| `/scan/domain/` | `POST` | URL, domain reputation, and DNS/WHOIS scan | Turnstile |
| `/scan/account/` | `POST` | Bank account fraud verification | Turnstile |
| `/scan/image/` | `POST` | OCR extraction and visual fraud detection | Turnstile |
| `/scan/audio/` | `POST` | Speech-to-text and voice phishing detection | Turnstile |
| `/scan/file/` | `POST` | Zero-Trust Docker sandbox file analysis | Turnstile |
| `/chat/stream/` | `POST` | Server-Sent Events (SSE) AI assistant stream | Session / Token |
| `/auth/register/` | `POST` | User registration with OTP validation | Public |
| `/auth/login/` | `POST` | Credential validation and MFA challenge trigger | Public |
| `/auth/mfa/verify/` | `POST` | Multi-Factor Authentication verification | Pre-auth Token |

Interactive OpenAPI / Swagger Documentation is available at:
- **Swagger UI**: `https://sc.fptoj.com/api/docs/`
- **ReDoc**: `https://sc.fptoj.com/api/redoc/`
- **OpenAPI Schema**: `https://sc.fptoj.com/api/schema/`

---

## 5. Complete Setup & Deployment Guide

### 5.1 System Prerequisites
```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y \
  python3.11 python3.11-venv python3-pip \
  mariadb-server redis-server clamav clamav-daemon \
  docker.io docker-compose-v2 \
  chromium-browser chromium-chromedriver \
  nodejs npm ffmpeg git

# Start core services
sudo systemctl enable --now mariadb redis-server docker clamav-daemon
sudo chmod 666 /var/run/docker.sock
```

### 5.2 Environment Configuration (`.env`)
Create `.env` at the project root:

```bash
# Core
DEBUG=False
SECRET_KEY='<cryptographically_secure_token>'
ALLOWED_HOSTS=sc.fptoj.com,localhost,127.0.0.1
SITE_URL=https://sc.fptoj.com

# Database (MariaDB / MySQL)
DB_ENGINE=mysql
DB_NAME=shieldcall_db
DB_USER=shieldcall_user
DB_PASSWORD=<db_password>
DB_HOST=127.0.0.1
DB_PORT=3306

# Redis & Broker
REDIS_URL=redis://127.0.0.1:6379/0
REDIS_CACHE_URL=redis://127.0.0.1:6379/1

# AI & LLM Inference
OLLAMA_BASE_URL=http://localhost:11434
LLM_MODEL=deepseek-v4-flash:cloud
SMALL_MODEL=gemma4:31b-cloud

# GPU Acceleration
EASYOCR_GPU=True
WHISPER_DEVICE=cuda
WHISPER_MODEL_SIZE=small
VECTOR_DB_USE_GPU=True

# Anti-Bot & Auth
TURNSTILE_SITEKEY=<cloudflare_turnstile_sitekey>
TURNSTILE_SECRET=<cloudflare_turnstile_secret>
SOCIAL_AUTH_GOOGLE_OAUTH2_KEY=<google_oauth2_client_id>
SOCIAL_AUTH_GOOGLE_OAUTH2_SECRET=<google_oauth2_secret>

# Mail Delivery (SMTP)
EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend
EMAIL_HOST=mail.fptoj.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=noreply@fptoj.com
EMAIL_HOST_PASSWORD=<smtp_password>
DEFAULT_FROM_EMAIL=FPTOJ Support <noreply@fptoj.com>
```

### 5.3 Build the Docker Malware Sandbox Image
```bash
docker build -t sentinel-sandbox:latest ./sandbox
```

### 5.4 Install Dependencies & Build Frontend Assets
```bash
# Python Virtual Environment
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Database Migrations & Static Files
python manage.py migrate
python manage.py collectstatic --noinput

# Build Tailwind CSS Assets
npm --prefix theme/static_src install
npm --prefix theme/static_src run build

# Install Puppeteer Node Dependencies
cd scripts/puppeteer_host && npm install && cd ../..
```

### 5.5 Process Management via PM2
The system is managed via [ecosystem.config.js](file:///data/Sentinel_Team_Project/ecosystem.config.js):

```bash
# Start all microservices
pm2 start ecosystem.config.js

# Persist process configuration across reboots
pm2 save

# Inspect cluster health
pm2 status
pm2 logs --lines 50
```

Managed cluster processes:
- `pkv-web`: ASGI server handling HTTP requests and WebSocket/SSE streams (`0.0.0.0:8001`).
- `pkv-celery`: Multi-threaded Celery worker handling CUDA OCR, speech transcription, and sandbox jobs.
- `pkv-celery-beat`: Periodic task scheduler.
- `pkv-puppeteer`: Headless Chromium render cluster with SSRF protection (`0.0.0.0:3010`).

---

## 6. Verification & Test Suites

Execute test suites to validate database integrity, LLM reasoning, sandbox analysis, and API endpoints:

```bash
# 1. Validate Ollama Integration & Model Readiness
.venv/bin/python scripts/test_ollama.py

# 2. Execute Backend API Integration Suite
.venv/bin/python scripts/test_api.py
```

---

## 7. License & Authorship

Developed by **Sentinel Team**. Proprietary and Confidential. Distributed under standard project terms.
