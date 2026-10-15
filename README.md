<div align="center">
  <h1>ShieldCall VN (Sentinel Core)</h1>
  <p><b>Advanced Multi-Modal Threat Intelligence, Zero-Trust Sandbox & Anti-Fraud Architecture</b></p>
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

## 0. Cấu trúc thư mục (Repository layout)

```
Sentinel_Team_Project/
├── backend/                 # Toàn bộ backend Django (PKV, api, manage.py, theme, scripts, sandbox, helps, static, media…)
├── frontend/                # Toàn bộ frontend Next.js (app router, src, public)
├── docs/                    # Tài liệu (phản biện, cải tiến, API…)
├── ecosystem.config.js      # Cấu hình PM2 (chạy backend từ backend/, frontend từ frontend/)
├── README.md
└── _minhchung/              # Minh chứng nộp bài (gitignored)
```

> Lệnh backend chạy từ trong `backend/` (ví dụ `cd backend && python manage.py check`).

---

## 0.1 Cập nhật gần nhất — Cải tiến theo góp ý Hội đồng (2026-10-15)

Năm cải tiến trọng tâm (chi tiết + kiểm chứng: [`docs/CAI_TIEN_THEO_HOI_DONG.md`](docs/CAI_TIEN_THEO_HOI_DONG.md)):

1. **Guardrail độ bất định** — khi chưa đủ bằng chứng, hệ thống **KHÔNG kết luận "an toàn"** mà trả nhãn *"CHƯA ĐỦ CƠ SỞ XÁC MINH"*, kèm cảnh báo và kênh xác minh chính thức.
2. **Bằng chứng cho mọi nhận định** — mỗi kết quả quét kèm `evidence[]` (nguồn, độ tin cậy, mức độ, liên kết tham chiếu).
3. **Minh bạch nguồn & giới hạn** — danh mục nguồn tại `/api/v1/trust/sources/` nêu rõ độ tin cậy và hạn chế của từng công cụ (kể cả mô hình AI).
4. **Dữ liệu nguồn Việt Nam** — kênh chính thức (NCSC 156, Công an 113, VNCERT), tổng đài ngân hàng, từ điển dấu hiệu lừa đảo tiếng Việt (`/api/v1/trust/channels/`).
5. **Bảo mật dữ liệu** — ẩn PII (SĐT/email/STK/CCCD/thẻ/khoá) trước khi ghi log hoặc gửi mô hình cloud (`/api/v1/trust/privacy/`).

> **Hạn chế & lộ trình:** xem [`docs/REBUTTAL_QA.md`](docs/REBUTTAL_QA.md). Các chỉ số định lượng
> được công bố ở mức *"kết quả nội bộ sơ bộ"*, không tuyên bố tuyệt đối.

---

## 1. Executive Summary & Architecture

**ShieldCall VN** is an enterprise-grade digital safety and cyber-fraud mitigation platform designed to detect, analyze, and neutralize multifaceted threats across telecommunication, financial, digital communication, and executable file vectors.

The platform employs a hybrid asynchronous architecture combining real-time ASGI WebSocket/SSE streams, background distributed task workers, GPU-accelerated neural computing, and an isolated Zero-Trust Docker Sandbox backed by industry-standard forensic toolsets.

### 1.1 System Architecture Topology

```mermaid
flowchart TD
    subgraph ClientTier["Client & Integration Layer"]
        WebUI["Web Frontend & PWA"]
        MobileClient["Mobile Client / Native Application"]
        MCPClient["Claude Desktop & MCP Agents"]
        APIClient["External REST API Consumers"]
    end

    subgraph IngressTier["Perimeter & Ingress Security"]
        ReverseProxy["Reverse Proxy / Cloudflare WAF / TLS (:443)"]
    end

    subgraph AppTier["Application & Routing Tier (PM2 Cluster)"]
        DaphneServer["Daphne ASGI Server (:8001)<br/>Django 5.2 | Channels 4 | DRF"]
        PuppeteerCluster["Puppeteer Headless Cluster (:3010)<br/>Anti-SSRF DNS Resolver | Stealth Engine"]
    end

    subgraph DataTier["Storage, State & Cache Broker"]
        RedisNode["Redis 8.x<br/>Cache | Channel Layer | Celery Broker"]
        DatabaseNode[("MariaDB 11.x / MySQL 8.x<br/>Relational Storage & Auth")]
    end

    subgraph WorkerTier["Distributed Task Engine (Celery)"]
        CeleryWorker["Celery Worker Cluster<br/>Multi-threaded Thread Pool"]
        CeleryBeat["Celery Beat Scheduler<br/>Periodic Threat Sync"]
    end

    subgraph NeuralTier["Hardware-Accelerated Neural Computing"]
        EasyOCRNode["EasyOCR Engine<br/>NVIDIA CUDA GPU"]
        WhisperNode["Faster-Whisper STT<br/>NVIDIA CUDA GPU"]
        FAISSNode["FAISS Vector DB<br/>Nomic Embed 768-dim"]
    end

    subgraph SandboxTier["Zero-Trust Execution Sandbox (Docker)"]
        DockerSandbox["sentinel-sandbox:latest<br/>--network none | --read-only | --cap-drop ALL"]
        YARAEngine["YARA Multi-Vector Signature Rules"]
        OLEToolsEngine["OLETools VBA Macro Dissector"]
        PEFileEngine["PEFile Entropy & Imphash Inspector"]
        PyPDFEngine["PyPDF Stream & Exploit Decoder"]
        ClamAVEngine["ClamAV Antivirus Daemon"]
    end

    subgraph InferenceTier["Large Language Model Inference"]
        OllamaDaemon["Ollama Daemon (:11434)"]
        PrimaryLLM["Primary: deepseek-v4.1-flash:cloud"]
        ClassifierLLM["Classifier: gemma4"]
    end

    WebUI --> ReverseProxy
    MobileClient --> ReverseProxy
    MCPClient --> ReverseProxy
    APIClient --> ReverseProxy

    ReverseProxy --> DaphneServer
    DaphneServer --> PuppeteerCluster
    DaphneServer --> RedisNode
    DaphneServer --> DatabaseNode

    RedisNode <--> CeleryWorker
    CeleryBeat --> RedisNode
    CeleryWorker --> DatabaseNode

    CeleryWorker --> EasyOCRNode
    CeleryWorker --> WhisperNode
    CeleryWorker --> FAISSNode

    CeleryWorker --> DockerSandbox
    DockerSandbox --> YARAEngine
    DockerSandbox --> OLEToolsEngine
    DockerSandbox --> PEFileEngine
    DockerSandbox --> PyPDFEngine
    DockerSandbox --> ClamAVEngine

    DaphneServer --> OllamaDaemon
    CeleryWorker --> OllamaDaemon
    OllamaDaemon --> PrimaryLLM
    OllamaDaemon --> ClassifierLLM
```

---

## 2. Multi-Vector Threat Analysis Pipeline

The platform evaluates artifacts across six dedicated investigation vectors, aggregates findings into structured telemetry, and executes heuristic and neural risk classification:

```mermaid
flowchart LR
    subgraph Ingestion["Input Ingestion Layer"]
        InPhone["Telephony / MSISDN"]
        InBank["Financial Account"]
        InWeb["Domain / URL"]
        InMedia["Visual Media (Images)"]
        InAudio["Acoustic Audio (.wav/.mp3)"]
        InFile["Executable / Document File"]
    end

    subgraph Engines["Vector Processing Modules"]
        ModPhone["Phone Pipeline<br/>E.164 Normalize + Blacklist"]
        ModBank["Financial Pipeline<br/>VietQR Resolution + Fraud DB"]
        ModWeb["Web Intelligence<br/>DNS/MX + WHOIS + Puppeteer"]
        ModMedia["Vision Pipeline<br/>EasyOCR CUDA + QR Matrix"]
        ModAudio["Acoustic Pipeline<br/>Faster-Whisper CUDA + Voice Intel"]
        ModFile["Zero-Trust Sandbox<br/>Docker + YARA + PEFile + ClamAV"]
    end

    subgraph Synthesis["Intelligence Aggregation & LLM Reasoning"]
        Aggregator["Threat Intelligence Aggregator"]
        RAGIndex["FAISS Vector Search<br/>Local Knowledge Base"]
        LLMEval["Ollama Reasoning Engine<br/>DeepSeek-v4.1-Flash / Gemma4"]
    end

    subgraph Verdict["Standardized Verdict"]
        Score["Risk Score (0 - 100)"]
        Badge["Threat Level (SAFE / WARNING / CRITICAL)"]
        Guidance["Actionable Remediation Guidance"]
    end

    InPhone --> ModPhone
    InBank --> ModBank
    InWeb --> ModWeb
    InMedia --> ModMedia
    InAudio --> ModAudio
    InFile --> ModFile

    ModPhone --> Aggregator
    ModBank --> Aggregator
    ModWeb --> Aggregator
    ModMedia --> Aggregator
    ModAudio --> Aggregator
    ModFile --> Aggregator

    Aggregator --> RAGIndex
    RAGIndex --> LLMEval
    Aggregator --> LLMEval

    LLMEval --> Score
    LLMEval --> Badge
    LLMEval --> Guidance
```

### 2.1 Vector Analysis Capabilities
- **Telecommunication & Number Scoring**: Normalizes international and domestic Vietnamese MSISDN formats, cross-referencing threat telemetry, carrier assignments, and community scam reports.
- **Financial Account Verification**: Performs programmatic lookup and beneficiary name resolution via VietQR integration, cross-referencing fraud intelligence databases.
- **Domain & Web Intelligence**: Inspects DNS MX records, domain age (WHOIS), SSL reputation, and ScamAdviser / Trustpilot metrics via SSRF-isolated relays.
- **Email & Messaging Forensics**: Dissects `.eml` and text messages, validating SPF, DKIM, and DMARC DNS alignment to identify spoofed corporate or government origins.
- **Multi-Modal AI Analysis**:
  - **Audio Streams**: Acoustic transcription via `Faster-Whisper` running on NVIDIA CUDA followed by psychological manipulation and urgency indicator extraction.
  - **Visual Media**: Image OCR via `EasyOCR` (GPU accelerated) combined with QR code matrix decoding and phishing banner classification.
- **Malware & APK Sandbox**: Dissects Windows binaries and Android APK packages in isolated Docker environments using YARA rules, PEFile, and ClamAV.
- **Social Engineering & Crypto Forensics**: Tracks Telegram channels, Zalo groups, fake VNeID portals, and suspicious crypto wallet addresses.

### 2.2 Zero-Trust Local Malware Sandbox Engine
Replaces third-party external dependencies with an entirely isolated on-premise containment engine:
- **Containment Model**: Every suspicious file is mounted read-only inside an ephemeral container (`sentinel-sandbox:latest`) with strict enforcement:
  - `--network none`: Complete network isolation. Zero external telemetry or outbound egress.
  - `--read-only`: Read-only root filesystem prevents modification or persistent writes.
  - `--tmpfs /tmp:rw,size=256m,mode=1777`: Bounded writable scratch space (needed for archive unpacking / AV temp files) that never persists.
  - `--cap-drop ALL`: Drops all Linux kernel capabilities.
  - `--security-opt=no-new-privileges:true`: Prevents privilege escalation.
  - `--memory 1g --cpus 2.0 --pids-limit 64`: Throttles resource abuse and prevents fork bombs.

  > The long-running daemon (`sentinel-sandbox-daemon`, port 5005) runs with `--read-only`, `--security-opt=no-new-privileges:true`, and tmpfs mounts (`mode=1777`) for `/tmp` + `/var/run/clamav` (the latter lets the ClamAV daemon bind its socket); because it must accept inbound HTTP it keeps the default bridge network (no egress is performed by the analyzer).
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

### 2.4 Model Context Protocol (MCP) Remote Server
Exposes Sentinel threat tools directly to external AI agents, Claude Desktop, and IDE plugins over the standardized Model Context Protocol:

```mermaid
flowchart TD
    subgraph Clients["User & Agent Clients"]
        WebChat["Web AI Assistant (/ai-assistant/)"]
        ClaudeDesk["Claude Desktop / MCP Client Host"]
    end

    subgraph MCPGateway["Protocol Router & SSE Gateway"]
        SSEStream["SSE Event Stream (:8001/api/v1/mcp/sse/)"]
        JSONRPC["JSON-RPC Message Relay (:8001/api/v1/mcp/messages/)"]
    end

    subgraph Tools["Exposed Forensic MCP Tools"]
        ToolPhone["check_phone"]
        ToolURL["check_url_or_domain"]
        ToolBank["check_bank_account"]
        ToolMsg["analyze_message"]
        ToolEmail["check_email_sender"]
        ToolThreat["lookup_scam_db"]
        ToolTrends["get_scam_radar_trends"]
        ToolFull["scan_full_incident"]
    end

    subgraph Engine["Ollama / DeepSeek LLM"]
        Reasoning["Reasoning & Synthesis (DeepSeek-v4.1-Flash)"]
    end

    WebChat --> SSEStream
    ClaudeDesk --> SSEStream
    SSEStream --> JSONRPC
    JSONRPC --> Tools
    Tools --> Reasoning
    Reasoning --> SSEStream
```

- **Discovery Endpoint**: `GET /api/v1/mcp/`
- **SSE Transport Stream**: `GET /api/v1/mcp/sse/`
- **JSON-RPC Message Relay**: `POST /api/v1/mcp/messages/`
- **Exposed Tools (10)**: `check_phone`, `check_bank_account`, `check_url_or_domain`, `analyze_message`, `check_email_sender`, `get_supported_banks`, `lookup_scam_db`, `get_scam_radar_trends`, `scan_full_incident`, `report_scam`.
- **System Prompts (3)**: `shieldcall_sentry`, `emergency_advisor`, `scam_investigator`.

---

## 3. Technology Stack

| Layer | Technologies |
| :--- | :--- |
| **Runtime Environment** | Python 3.11 (Virtualenv), Node.js v24.x, Docker Engine v29.x |
| **Web & API Framework** | Django 5.2.x, Django REST Framework, Daphne ASGI, Channels 4.x |
| **Database & Caching** | MariaDB 11.x / MySQL 8.x (`PyMySQL`), Redis 8.x (`django-redis`, `channels-redis`) |
| **Distributed Tasks** | Celery 5.6.x (Thread Pool Worker + Periodic Beat Scheduler) |
| **Hardware Acceleration** | NVIDIA CUDA GPU (Compute Capability 7.5+), cuDNN |
| **Malware Sandbox** | Docker Isolated Ephemeral Containers, YARA, OLETools, PEFile, PyPDF, ClamAV |
| **Browser Cluster** | Puppeteer Extra, Chromium (Headless), Stealth Plugin, Anti-SSRF Relay |
| **AI & Neural Computing** | Ollama SDK, PyTorch 2.x CUDA, FAISS (`nomic-embed-text-v1`), Faster-Whisper, EasyOCR |
| **Process Manager** | PM2 (Production Ecosystem with Dynamic Path Resolution) |
| **Security & Auth** | Cloudflare Turnstile, Django-OTP (TOTP/Email MFA), Google OAuth2, WhiteNoise |

---

## 4. API Specification Overview

Base URL: `/api/v1` (Production: `https://<your-domain>/api/v1`)

| Endpoint | Method | Purpose | Authentication |
| :--- | :--- | :--- | :--- |
| `/scan/phone/` | `POST` | Comprehensive telephone threat assessment | Turnstile / Token |
| `/scan/message/` | `POST` | SMS and social messaging fraud analysis | Turnstile / Token |
| `/scan/domain/` | `POST` | URL, domain reputation, and DNS/WHOIS scan | Turnstile / Token |
| `/scan/account/` | `POST` | Bank account fraud verification | Turnstile / Token |
| `/scan/banks/` | `GET` | National VietQR bank list and metadata retrieval | Public |
| `/scan/email/` | `POST` | Email phishing and header forensics (SPF, DKIM, DMARC) | Turnstile / Token |
| `/scan/image/` | `POST` | OCR extraction and visual fraud detection | Turnstile / Token |
| `/scan/audio/` | `POST` | Speech-to-text and voice phishing detection | Turnstile / Token |
| `/scan/file/` | `POST` | Zero-Trust Docker sandbox file analysis | Turnstile / Token |
| `/scan/lookup/` | `GET` | Multi-vector threat intelligence search across reports | Public |
| `/scan/status/<scan_id>/` | `GET` | Asynchronous scan status and result retrieval | Session / Auth |
| `/scan/<scan_id>/report-admin/` | `POST` | Request administrator verification for scan verdict | Authenticated |
| `/scan/analyze/stream/` | `POST` | Server-Sent Events (SSE) stream for scan events | Public / Token |
| `/chat/stream/` | `POST` | Server-Sent Events (SSE) AI assistant stream | Session / Token |
| `/chat/sessions/` | `GET`, `POST` | Manage chat conversation history sessions | Session / Token |
| `/mcp/` | `GET` | Model Context Protocol discovery metadata | Public |
| `/mcp/sse/` | `GET` | MCP Server-Sent Events endpoint for agents | Public |
| `/mcp/messages/` | `POST` | MCP JSON-RPC message relay | Public |
| `/report/` | `POST` | Submit community cybercrime or scam incident report | Public / Auth |
| `/report/<id>/` | `GET` | Retrieve verified scam incident details | Public / Auth |
| `/trends/daily/` | `GET` | Daily threat trend telemetry and regional metrics | Public |
| `/trends/hot/` | `GET` | Emerging viral scam tactics and attack waves | Public |
| `/trends/radar-stats/` | `GET` | Aggregated Scam Radar multi-vector statistics | Public |
| `/push/public-key/` | `GET` | Retrieve VAPID public key for WebPush client | Public |
| `/push/subscribe/` | `POST` | Register browser push subscription endpoint | Authenticated |
| `/scam-iq/start/` | `POST` | Initialize dynamic Scam IQ examination session | Authenticated |
| `/scam-iq/submit/` | `POST` | Submit Scam IQ exam responses for AI evaluation | Authenticated |
| `/scam-iq/history/` | `GET` | Retrieve historical examination score records | Authenticated |
| `/user/scans/` | `GET` | Historical scan telemetry for user account | Authenticated |
| `/user/api-keys/` | `GET`, `POST` | Provision and manage developer API keys | Authenticated |
| `/auth/register/` | `POST` | User registration with OTP validation | Public |
| `/auth/login/` | `POST` | Credential validation and MFA challenge trigger | Public |
| `/auth/mfa/verify/` | `POST` | Multi-Factor Authentication verification | Pre-auth Token |
| `/auth/me/` | `GET` | Retrieve current authenticated user profile | Authenticated |

Interactive OpenAPI and Swagger documentation:
- **Swagger UI**: `/api/docs/` (or `https://<your-domain>/api/docs/`)
- **ReDoc**: `/api/redoc/` (or `https://<your-domain>/api/redoc/`)
- **OpenAPI Schema**: `/api/schema/` (or `https://<your-domain>/api/schema/`)

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
Create `backend/.env`:

```bash
# Core
DEBUG=False
SECRET_KEY='<cryptographically_secure_token>'
ALLOWED_HOSTS=<your-domain>,localhost,127.0.0.1
SITE_URL=https://<your-domain>

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
LLM_MODEL=deepseek-v4.1-flash:cloud
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
EMAIL_HOST=smtp.<your-domain>.com
EMAIL_PORT=587
EMAIL_USE_TLS=True
EMAIL_HOST_USER=noreply@<your-domain>.com
EMAIL_HOST_PASSWORD=<smtp_password>
DEFAULT_FROM_EMAIL=ShieldCall VN Support <noreply@<your-domain>.com>
```

### 5.2.1 Object storage (S3-compatible)

Lưu media (ảnh cover, avatar, biên lai…) lên object storage để **an toàn & dễ mở rộng**.
Backend dùng `django-storages` + `boto3` (đã có trong `backend/requirements.txt`). Bật bằng env:

```bash
USE_S3_MEDIA=true
USE_S3_STATIC=true
AWS_ACCESS_KEY_ID=<key>
AWS_SECRET_ACCESS_KEY=<secret>
AWS_STORAGE_BUCKET_NAME=shieldcall
AWS_S3_REGION_NAME=us-east-1
AWS_S3_ENDPOINT_URL=http://100.124.226.59:30900   # endpoint API (nhanh qua Tailscale)
AWS_S3_CUSTOM_DOMAIN=s3.fptoj.com/shieldcall       # domain công khai cho URL media/static
AWS_S3_ADDRESSING_STYLE=path
AWS_S3_URL_PROTOCOL=https:
AWS_QUERYSTRING_AUTH=false
AWS_DEFAULT_ACL=public-read
```

- **100% object storage**: khi bật, **media & static đều lưu trên S3** — upload mới **không ghi file cục bộ**
  (`MEDIA_URL`/`STATIC_URL` trỏ `https://s3.fptoj.com/shieldcall/…`).
- Chỉ mục RAG (FAISS) là artifact hệ thống, lưu tại `backend/vector_store/` (không phải media).
- `USE_S3_MEDIA=false`/`USE_S3_STATIC=false` → quay về `FileSystemStorage`/Whitenoise (không phá vận hành).
- **Đồng bộ media lên S3** (backfill + chạy định kỳ qua Celery Beat `sync-media-to-s3-daily`):

```bash
cd backend && python manage.py sync_media_to_s3 --dry-run   # xem trước
cd backend && python manage.py collectstatic --noinput       # đẩy static lên S3
```

- Trạng thái storage: `GET /api/v1/trust/storage/` · Trang công khai: `/trust/`.
- **Backup chỉ mục RAG lên S3** (quan trọng, tự khôi phục khi thiếu file cục bộ):

```bash
cd backend && python manage.py backup_vector_store    # sao lưu vector_store/ lên S3
# Tự động: sau mỗi rebuild RAG + Celery Beat 'backup-vector-store-6h'
```

- **Tối ưu RAG/vector DB**: cache truy vấn LRU, embedding tăng dần (chỉ embed tài liệu mới/đổi),
  thread-safe + tự nạp lại khi index đổi, dedup kết quả. Cấu hình: `VECTOR_DB_QUERY_CACHE`, `VECTOR_DB_SCORE_THRESHOLD`, `VECTOR_DB_EMBED_BATCH`.
- **Quản trị S3 từ xa bằng rclone** (client chuẩn):

```bash
sudo apt-get install -y rclone
# ~/.config/rclone/rclone.conf
# [acm-s3]
# type = s3
# provider = Other
# access_key_id = acm
# secret_access_key = <secret>
# endpoint = http://127.0.0.1:30900
# region = us-east-1
# force_path_style = true
rclone lsd acm-s3:                 # liệt kê bucket
rclone sync backend/media acm-s3:shieldcall   # đồng bộ media lên S3
```

> `python manage.py seed_vn_knowledge` sẽ đẩy ảnh cover (nếu có trong `backend/static/knowledge_images/`) lên S3.

### 5.3 Build the Docker Malware Sandbox Image
```bash
docker build -t sentinel-sandbox:latest ./backend/sandbox
```

### 5.4 Install Dependencies & Build Assets
```bash
# Python Virtual Environment
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# Database Migrations & Static Files
cd backend
python manage.py migrate
python manage.py collectstatic --noinput

# Build Tailwind CSS Assets
npm --prefix theme/static_src install
npm --prefix theme/static_src run build

# Install Puppeteer Node Dependencies
cd scripts/puppeteer_host && npm install && cd ../..
```

### 5.5 Process Management via PM2
The system is managed via [ecosystem.config.js](./ecosystem.config.js):

```bash
# Start all microservices
pm2 start ecosystem.config.js

# Persist process configuration across reboots
pm2 save

# Inspect cluster health
pm2 status
pm2 logs --lines 50
```

Managed cluster processes (configurable via `.env` or system environment variables):
- `pkv-web`: ASGI server handling HTTP requests and WebSocket/SSE streams (binds to `${WEB_HOST}:${WEB_PORT}`, defaults to `0.0.0.0:8001`).
- `pkv-celery`: Multi-threaded Celery worker handling CUDA OCR, speech transcription, and sandbox jobs (concurrency configured via `CELERY_CONCURRENCY`).
- `pkv-celery-beat`: Periodic task scheduler.
- `pkv-puppeteer`: Headless Chromium render cluster with SSRF protection (binds to `PUPPETEER_HOST_PORT`, defaults to port `3010`).

---

## 6. Verification & Test Suites

Execute test suites to validate database integrity, LLM reasoning, sandbox analysis, and API endpoints:

```bash
# 1. Validate Ollama Integration & Model Readiness
.venv/bin/python scripts/test_ollama.py

# 2. Execute Backend API Integration Suite
.venv/bin/python scripts/test_api.py

# 3. Execute Django Unit Tests
.venv/bin/python backend/manage.py test api.ai_chat.tests

# 4. Threshold/ROC evaluation on the labelled VN dataset (reproducible)
.venv/bin/python backend/scripts/eval/evaluate_thresholds.py   # → docs/EVAL_THRESHOLDS.md

# 5. Generic evaluator + labelling tooling (phone/domain/AI)
.venv/bin/python backend/scripts/eval/evaluate_generic.py --dataset <file.jsonl> --scorer <message|domain_lookalike|field>
.venv/bin/python backend/scripts/eval/cohen_kappa.py --csv backend/scripts/eval/labels_agreement.csv
#    Hướng dẫn từng bước: docs/EVAL_GUIDE.md
```

---

## 7. License & Authorship

Copyright (c) 2026 **Sentinel Team**. This project is free software licensed under the
**GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)** — see `LICENSE`.
Anyone running a modified version on a public server must offer the Corresponding Source
to remote users (AGPL §13); the canonical source is this repository.
Third-party components keep their own licenses — full compatibility matrix in
`docs/LEGAL_AND_LICENSE.md`.
