<div align="center">
  <img src="PKV/static/logo.png" alt="ShieldCall VN Logo" width="200"/>
  <h1>ShieldCall VN 🛡️</h1>
  <p><b>Nền tảng Bảo vệ Người dùng Số Việt Nam Toàn diện bằng AI</b></p>
  
  [![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
  [![Django](https://img.shields.io/badge/Django-5.2.x-green.svg)](https://www.djangoproject.com/)
  [![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4-blueviolet.svg)](https://tailwindcss.com/)
  [![AI](https://img.shields.io/badge/AI-Multi--Agent-orange.svg)](https://ollama.ai/)
</div>

---

## 🌟 Giới thiệu
**ShieldCall VN** là giải pháp công nghệ tiên phong giúp phát hiện, ngăn chặn và giáo dục về các hình thức lừa đảo kỹ thuật số (cuộc gọi rác, tin nhắn giả mạo, website lừa đảo, tài khoản ngân hàng đen) dành riêng cho người dùng tại Việt Nam. Dự án được phát triển bởi **Sentinel Team** cho cuộc thi **AI Young Guru**.

## ✨ Tính năng nổi bật

### 1. Hệ thống Quét Đa nguyên (Multi-Vector Scan)
*   **Website Scan:** Kiểm tra WHOIS (độ tuổi tên miền), DNS MX, uy tín Hosting (ASN) và phân tích nội dung bằng AI Reasoning Engine.
*   **Audio Scan:** Chuyển đổi cuộc gọi thành văn bản bằng **Faster-Whisper** và phân tích kịch bản lừa đảo (giả danh công an, ngân hàng).
*   **Email Analysis:** Phân tích file `.eml`, xác thực SPF/DMARC và vạch trần kịch bản thao túng tâm lý.
*   **Phone & Account Check:** Tra cứu mức độ rủi ro dựa trên cơ sở dữ liệu cộng đồng và thuật toán trọng số.
*   **AI OCR Magic (Mắt thần):** Trích xuất thông tin lừa đảo từ ảnh chụp màn hình bằng EasyOCR kết hợp AI phân tích thực thể.

### 2. Hệ sinh thái Cộng đồng & Giáo dục
*   **Scam Radar:** Bản đồ nhiệt và xu hướng lừa đảo cập nhật theo thời gian thực.
*   **Learn Hub:** Kho bài giảng tương tác về an ninh mạng.
*   **Interactive Scenarios:** Thực hành đối đầu với kẻ gian trong môi trường giả lập AI.
*   **Forum:** Diễn đàn cộng đồng chia sẻ kinh nghiệm và cảnh báo lừa đảo.

### 3. Công nghệ Quản trị Đẳng cấp
*   **AI Magic Create:** Quy trình 5 giai đoạn (Phân tích -> Lesson -> Quiz -> Scenario -> Push) biến tin tức thô thành bài học hoàn chỉnh.
*   **Dashboard Thông minh:** Hệ thống giám sát dữ liệu và báo cáo lừa đảo chuyên sâu.
*   **RAG Knowledge Base:** Quản lý Vector DB (FAISS) với HTTP polling real-time, lịch đồng bộ tự động.

## 🛠️ Stack Công nghệ
| Layer | Technology |
|---|---|
| **Core** | Django 5.2 (Python 3.12), Django REST Framework |
| **AI Engine** | Multi-Agent Collaboration (Ollama LLM), Faster-Whisper (STT), RAG (FAISS), EasyOCR |
| **Async** | Celery & Redis (Background Tasks), Celery Beat (Scheduled Jobs) |
| **Real-time** | Django Channels (WebSocket), HTTP Polling |
| **Design** | Liquid Glass Aesthetic (TailwindCSS v4), Alpine.js |
| **Auth** | Django Allauth (Google OAuth), 2FA (django-otp), Cloudflare Turnstile |
| **Database** | MySQL 8.0, Redis 7.0 (Cache + Broker) |
| **Security** | VirusTotal API, WHOIS/DNS Analysis, Trust Score Engine |

---

## 🚀 Cài đặt & Khởi chạy (Development)

### Yêu cầu hệ thống
- **Python** 3.12+
- **MySQL** 8.0+
- **Redis** 7.0+
- **Ollama** (LLM local) — https://ollama.ai
- **Node.js** 18+ (cho TailwindCSS build)

### Cài đặt nhanh
```bash
# 1. Clone repository
git clone <repo-url>
cd PKV_TEAM

# 2. Tạo virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# .venv\Scripts\activate         # Windows

# 3. Cài dependencies
pip install -r requirements.txt

# 4. Cấu hình settings
cp PKV/settings.py.example PKV/settings.py
# → Sửa thông tin DB, API keys trong PKV/settings.py

# 5. Khởi tạo database
python manage.py migrate

# 6. Build TailwindCSS
python manage.py tailwind build

# 7. Collect static files
python manage.py collectstatic --noinput

# 8. Tạo superuser (admin)
python manage.py createsuperuser

# 9. Chạy dev server
python manage.py runserver 0.0.0.0:8000
```

### Khởi chạy Ollama (AI Engine)
```bash
# Cài Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull model (chọn 1)
ollama pull llama3              # Khuyên dùng
ollama pull qwen2.5:7b          # Hỗ trợ tiếng Việt tốt

# Ollama tự chạy background sau khi cài
# Kiểm tra: curl http://localhost:11434/api/tags
```

### Khởi chạy Background Workers
```bash
# Terminal 2 — Celery Worker (xử lý task nền)
celery -A PKV worker -l info --concurrency=4

# Terminal 3 — Celery Beat (lịch tự động: RAG rebuild mỗi 60 phút, ...)
celery -A PKV beat -l info
```

### Script tự động
```bash
chmod +x setup.sh
./setup.sh
```

---

## 🌐 Deploy Production

### Kiến trúc Production
```
                    ┌─────────────┐
     Internet ────▶│  Nginx/LB   │
                    │ (SSL + WS)  │
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼───┐  ┌────▼────┐ ┌─────▼───┐
        │ Daphne  │  │ Daphne  │ │ Daphne  │  ← ASGI Workers
        │  :8001  │  │  :8002  │ │  :8003  │
        └────┬────┘  └────┬────┘ └────┬────┘
             │            │           │
        ┌────▼────────────▼───────────▼────┐
        │           Redis 7.0              │ ← Cache + Broker + Channel Layer
        └──────────────────────────────────┘
                           │
        ┌──────────────────▼───────────────┐
        │          MySQL 8.0               │ ← Database chính
        └──────────────────────────────────┘
              │            │
        ┌─────▼───┐  ┌────▼────┐
        │ Celery  │  │ Celery  │  ← Background Workers
        │ Worker  │  │  Beat   │
        └─────────┘  └─────────┘
```

### Bước 1: Chuẩn bị Server

```bash
# Ubuntu 22.04+ / Debian 12+
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.12 python3.12-venv python3.12-dev \
    mysql-server redis-server nginx supervisor curl git

# Cài Ollama trên server
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
```

### Bước 2: Setup Database

```bash
# Đăng nhập MySQL
sudo mysql -u root

# Tạo database & user
CREATE DATABASE shieldcall_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'shieldcall'@'localhost' IDENTIFIED BY 'YOUR_STRONG_PASSWORD';
GRANT ALL PRIVILEGES ON shieldcall_db.* TO 'shieldcall'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

### Bước 3: Deploy Code

```bash
# Tạo user hệ thống
sudo useradd -m -s /bin/bash shieldcall
sudo su - shieldcall

# Clone & setup
git clone <repo-url> /home/shieldcall/PKV_TEAM
cd /home/shieldcall/PKV_TEAM
python3.12 -m venv .venv
source .venv/bin/activate

# Cài dependencies
pip install -r requirements.txt
pip install daphne gunicorn   # ASGI server

# Cấu hình production
cp PKV/settings.py.example PKV/settings.py
```

Sửa `PKV/settings.py` cho production:
```python
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com', 'YOUR_SERVER_IP']
SITE_URL = 'https://yourdomain.com'

# Database (thông tin đã tạo ở Bước 2)
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'shieldcall_db',
        'USER': 'shieldcall',
        'PASSWORD': 'YOUR_STRONG_PASSWORD',
        'HOST': 'localhost',
        'PORT': '3306',
        'OPTIONS': {'charset': 'utf8mb4'},
    }
}

# Static files - WhiteNoise production
STATICFILES_STORAGE = 'whitenoise.storage.CompressedManifestStaticFilesStorage'

# Security headers
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 31536000
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
```

```bash
# Migrate & build
python manage.py migrate
python manage.py tailwind build
python manage.py collectstatic --noinput
python manage.py createsuperuser
```

### Bước 4: Cấu hình Supervisor (Process Manager)

Sử dụng file cấu hình mẫu [supervisor_pkv.conf](supervisor_pkv.conf) có sẵn trong thư mục gốc. File này đã được tối ưu hóa cho môi trường production với cơ chế Group (pkv:*) giúp quản lý Daphne, Celery Worker và Celery Beat dễ dàng hơn.

```bash
# 1. Copy file cấu hình vào thư mục của Supervisor
sudo cp /data/PKV_TEAM/supervisor_pkv.conf /etc/supervisor/conf.d/pkv.conf

# 2. Tạo thư mục log (nếu chưa có)
sudo mkdir -p /var/log/supervisor
sudo chown -R $USER:$USER /var/log/supervisor

# 3. Cập nhật & Khởi động
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start pkv:*

# 4. Kiểm tra trạng thái
sudo supervisorctl status pkv:*
```

### Bước 5: Cấu hình Nginx (Reverse Proxy + SSL)

```nginx
# /etc/nginx/sites-available/shieldcall

upstream shieldcall_backend {
    server 127.0.0.1:8001;
}

server {
    listen 80;
    server_name yourdomain.com www.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com www.yourdomain.com;

    # SSL (Let's Encrypt)
    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 50M;

    # Static files (served by Nginx, bypass Django)
    location /static/ {
        alias /home/shieldcall/PKV_TEAM/PKV/static/;
        expires 30d;
        add_header Cache-Control "public, immutable";
    }

    # Media uploads
    location /media/ {
        alias /home/shieldcall/PKV_TEAM/media/;
        expires 7d;
    }

    # WebSocket connections
    location /ws/ {
        proxy_pass http://shieldcall_backend;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
    }

    # Django application
    location / {
        proxy_pass http://shieldcall_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
# Kích hoạt site
sudo ln -s /etc/nginx/sites-available/shieldcall /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx

# SSL miễn phí với Let's Encrypt
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com -d www.yourdomain.com
```

### Bước 6: Cấu hình Firewall

```bash
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable
```

### Bước 7: Kiểm tra

```bash
# Kiểm tra tất cả services
sudo supervisorctl status            # Daphne, Celery, Beat
sudo systemctl status nginx          # Nginx
sudo systemctl status mysql          # MySQL
sudo systemctl status redis          # Redis
systemctl status ollama              # Ollama

# Test endpoint
curl -I https://yourdomain.com
curl https://yourdomain.com/api/v1/health/
```

### Cập nhật code (Re-deploy)

```bash
cd /home/shieldcall/PKV_TEAM
git pull origin main
source .venv/bin/activate
pip install -r requirements.txt
python manage.py migrate
python manage.py tailwind build
python manage.py collectstatic --noinput
sudo supervisorctl restart all
```

---

## 📁 Cấu trúc dự án

```
PKV_TEAM/
├── PKV/                    # Django project settings & templates
│   ├── settings.py         # Cấu hình chính
│   ├── urls.py             # URL routing gốc
│   ├── asgi.py             # ASGI entry (Daphne + WebSocket)
│   ├── celery.py           # Celery app config
│   ├── templates/          # Jinja2/Django templates
│   │   ├── base.html       # Base layout (Alpine.js, SweetAlert2, marked.js)
│   │   ├── Home/           # Trang chủ
│   │   ├── Scan/           # Các trang quét (URL, Audio, Email, ...)
│   │   ├── Report/         # Trang báo cáo lừa đảo
│   │   ├── Admin/          # Admin dashboard & management
│   │   ├── Forum/          # Diễn đàn cộng đồng
│   │   ├── LearnHub/       # Hub giáo dục
│   │   └── AI/             # AI Assistant chat
│   ├── static/             # CSS, JS, images
│   └── views/              # Page views (non-API)
├── api/                    # Django REST Framework APIs
│   ├── core/               # Core models, views, consumers
│   ├── ai_chat/            # AI chatbot API
│   ├── maintenance/        # RAG, crash reports, error logs
│   ├── media_analysis/     # Image/OCR analysis
│   ├── phone_security/     # Phone & bank account lookup
│   ├── sessions_api/       # User sessions management
│   └── utils/              # Shared utilities
│       ├── ai_agent.py     # Multi-agent AI orchestration
│       ├── ollama_client.py# Ollama LLM client
│       ├── vector_db.py    # FAISS vector database
│       ├── vt_client.py    # VirusTotal integration
│       └── trust_score.py  # Trust scoring algorithm
├── media/                  # User uploads & vector index
├── requirements.txt        # Python dependencies
├── setup.sh                # Auto setup script
└── manage.py               # Django CLI
```

## ⚙️ Biến cấu hình quan trọng

| Biến | Mô tả | Bắt buộc |
|---|---|---|
| `SECRET_KEY` | Django secret key (random 50+ chars) | ✅ |
| `DATABASES` | MySQL connection | ✅ |
| `CELERY_BROKER_URL` | Redis broker URL | ✅ |
| `OLLAMA_BASE_URL` | Ollama API endpoint | ✅ |
| `LLM_MODEL` | Model name (llama3, qwen2.5, ...) | ✅ |
| `VT_API_KEY` | VirusTotal API key | ⚠️ Scan feature |
| `TURNSTILE_SITEKEY` / `TURNSTILE_SECRET` | Cloudflare anti-spam | ⚠️ Forms |
| `ONESIGNAL_APP_ID` | OneSignal push notifications | ❌ Optional |
| `EMAIL_HOST_USER` / `EMAIL_HOST_PASSWORD` | SMTP email | ❌ Optional |

---

## 👨‍💻 Đội ngũ phát triển
Dự án được thực hiện bởi **SENTINEL TEAM** (tiền thân là PKV Team).
- **Quy mô dự án:** ~40,000 dòng code production.
- **Phương trình phát triển:** **AI-Native Workflow**. Tận dụng mạng lưới **Multi-Agent Collaboration** (Đặc vụ AI cộng tác) và kỹ thuật **Prompt Engineering** nâng cao (Chain-of-Thought, Feedback Loop) để tối ưu hóa kiến trúc và đảm bảo độ ổn định của hệ thống.
- **Kiến trúc:** Cloud-native, AI-integrated.

**License:** MIT
