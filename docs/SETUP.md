# ShieldCall VN — Setup & Deployment

Complete installation and deployment guide for the ShieldCall VN stack.

> Backend commands run from within `backend/` (e.g., `cd backend && python manage.py check`).
> Frontend commands run from within `frontend/` (e.g., `cd frontend && npx tsc --noEmit`).
> Puppeteer commands run from within `puppeteer_host/` (e.g., `cd puppeteer_host && npm test`).

---

## 1. System Prerequisites

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
# Add current service user to docker group (least-privilege model)
sudo usermod -aG docker $USER
```

> **GPU Acceleration is Optional** (accelerates Whisper, VietOCR, and embeddings). Without GPU, set:
> `WHISPER_DEVICE=cpu`, `VIETOCR_DEVICE=cpu`, `VECTOR_DB_USE_GPU=False`.
> `tesseract-ocr` (optional fallback): `sudo apt-get install -y tesseract-ocr tesseract-ocr-vie`.

---

## 2. Environment Configuration (`.env`)

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

# OCR engine: VietOCR runs in the shared AI service (or .venv-ocr bridge as fallback)
OCR_ENGINE=vietocr # vietocr | tesseract
VIETOCR_DEVICE=auto # auto (GPU if available) | cpu | cuda:0
AI_SERVICE_URL=http://127.0.0.1:5010 # shared AI service: OCR + embedding + Whisper
OCR_SERVICE_PORT=5010

# Whisper / embeddings
WHISPER_DEVICE=cuda
WHISPER_MODEL_SIZE=large-v3-turbo # tốt cho tiếng Việt; small yếu hơn rõ rệt
AI_WHISPER_COMPUTE=int8_float16 # ~1GB VRAM
AI_WHISPER_LANGUAGE=auto # auto nhận cả vi/en; đặt vi để ép tiếng Việt
AI_WHISPER_PRELOAD=true # nạp sẵn để request đầu không phải chờ
AI_WHISPER_IDLE_UNLOAD_SEC=0 # >0 nếu muốn tự nhả VRAM khi rảnh
VECTOR_DB_USE_GPU=False # embedding chạy CPU trong AI service

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

---

## 3. Object Storage (S3-Compatible)

Store user uploads and static assets (cover images, avatars, report receipts) on object storage for high availability and elastic scalability.
Backend uses `django-storages` with `boto3` (included in `backend/requirements.txt`). Configure via `.env`:

```bash
USE_S3_MEDIA=true
USE_S3_STATIC=true
AWS_ACCESS_KEY_ID=<key>
AWS_SECRET_ACCESS_KEY=<secret>
AWS_STORAGE_BUCKET_NAME=shieldcall
AWS_S3_REGION_NAME=us-east-1
AWS_S3_ENDPOINT_URL=http://100.124.226.59:30900 # Direct S3 API endpoint (accelerated via Tailscale)
AWS_S3_CUSTOM_DOMAIN=s3.fptoj.com/shieldcall # Public CDN domain for media and static assets
AWS_S3_ADDRESSING_STYLE=path
AWS_S3_URL_PROTOCOL=https:
AWS_QUERYSTRING_AUTH=false
AWS_DEFAULT_ACL=public-read
```

- **100% Object Storage**: When enabled, **both media and static assets are persisted to S3**. New uploads write directly to remote storage without local filesystem persistence (`MEDIA_URL` and `STATIC_URL` resolve to `https://s3.fptoj.com/shieldcall/...`).
- System RAG indices (FAISS) remain classified as protected internal artifacts located at `backend/vector_store/` (isolated from public media).
- Setting `USE_S3_MEDIA=false` and `USE_S3_STATIC=false` falls back seamlessly to `FileSystemStorage` and Whitenoise without service disruption.
- **Media Synchronization & Backfill** (scheduled periodically via Celery Beat `sync-media-to-s3-daily`):

```bash
cd backend && python manage.py sync_media_to_s3 --dry-run # Preview synchronization diff
cd backend && python manage.py collectstatic --noinput # Push static assets to S3
```

- Storage Telemetry: Query endpoint `GET /api/v1/trust/storage/` or view public status page at `/trust/`.
- **RAG Vector Store Backup to S3** (automated replication with cold-start self-recovery):

```bash
cd backend && python manage.py backup_vector_store # Replicate vector_store/ to private S3 bucket
# Automated: Executed after every RAG rebuild and scheduled every 6 hours via Celery Beat
```

- **RAG & Vector DB Optimization**: Features LRU query cache (latency reduced from 16.7s to 0.0001s), content-hash incremental embeddings (rebuild speedup of 25x), thread-safe locks, and auto-reload on mtime changes. Configured via `VECTOR_DB_QUERY_CACHE`, `VECTOR_DB_SCORE_THRESHOLD`, `VECTOR_DB_EMBED_BATCH`.
- **Remote S3 Management via rclone** (industry-standard CLI client):

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
rclone lsd acm-s3: # List available buckets
rclone sync backend/media acm-s3:shieldcall # Sync local media to S3
```

> Executing `python manage.py seed_vn_knowledge` pushes featured article covers from `backend/static/knowledge_images/` directly to S3.

---

## 4. Build the Docker Malware Sandbox Image

```bash
docker build -t sentinel-sandbox:latest ./backend/sandbox
```

---

## 5. Install Dependencies & Build Assets

Repository structure: `backend/` (Django, Celery, Docker sandbox, OCR bridge), `frontend/` (Next.js 16), `puppeteer_host/` (TypeScript browser cluster at repository root).

```bash
# 1) Primary Python Virtual Environment (Backend + unified AI service). Requires Python 3.11:
python3.11 -m venv .venv
.venv/bin/pip install -U pip
.venv/bin/pip install -r backend/requirements.txt
# VietOCR for the shared AI service. --no-deps avoids pulling a second
# opencv/imgaug/torch stack into the primary venv (see backend/requirements-ai.txt):
.venv/bin/pip install gdown
.venv/bin/pip install --no-deps vietocr==0.3.13

# 2) OPTIONAL fallback OCR venv (only if you want OCR isolated from the AI service):
.venv/bin/python -m venv .venv-ocr
.venv-ocr/bin/pip install -U pip
# Install PyTorch: Select CPU or matching CUDA build (e.g. CUDA 13.0):
.venv-ocr/bin/pip install torch torchvision --index-url https://download.pytorch.org/whl/cu130
.venv-ocr/bin/pip install -r backend/requirements-ocr.txt # Installs vietocr

# 3) Database Migrations, Static Files & Threat Knowledge Seeding:
cd backend
python manage.py migrate
python manage.py collectstatic --noinput
python manage.py seed_vn_knowledge # Optional: Ingests 18 domestic intelligence articles into RAG
cd ..

# 4) Puppeteer Headless Cluster (TypeScript v2 at repository root):
cd puppeteer_host && npm install && npm run build && cd ..

# 5) Frontend Web Application (Next.js 16 App Router):
cd frontend && npm install && npm run build && cd ..

# 6) Zero-Trust Docker Malware Sandbox Container Image:
docker build -t sentinel-sandbox:latest ./backend/sandbox
```

> **Unified AI Service + OCR fallback:** Production runs `pkv-ai` (VietOCR + RAG embedding + Whisper) inside the primary `.venv`, sharing one CUDA context. If VietOCR or the AI service is unavailable, `backend/scripts/ocr_bridge.py` falls back to `.venv-ocr` (auto-detects `../.venv-ocr/bin/python`; override via `OCR_BRIDGE_PY`). `.venv-ocr/` is optional and ignored by git. Set `VIETOCR_DEVICE=auto` for automatic GPU acceleration. Technical details and CER benchmarks: `docs/OCR_VIETNAMESE.md`.

---

## 6. Process Management via PM2

The system is managed via [ecosystem.config.js](../ecosystem.config.js):

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
- `pkv-frontend`: Next.js 16.4.0 App Router cluster serving production web application (binds to `0.0.0.0:3000`).
- `pkv-celery`: Multi-threaded Celery worker for async scan jobs, RAG rebuilds, and malware sandbox tasks; OCR/speech inference is delegated to `pkv-ai`.
- `pkv-celery-beat`: Periodic task scheduler (RAG sync, S3 backups, daily threat analytics).
- `pkv-puppeteer`: Headless Chromium render cluster with multi-layer SSRF protection (binds to `PUPPETEER_HOST_PORT`, defaults to port `3010`).
- `pkv-ai`: Unified local AI service — VietOCR (GPU), RAG embedding (CPU), and preloaded Whisper `large-v3-turbo` for Vietnamese (GPU, `int8_float16`, ~1 GB VRAM; `POST /unload` frees it on demand) in one process sharing a single CUDA context (binds `AI_SERVICE_PORT`, default `5010`).
