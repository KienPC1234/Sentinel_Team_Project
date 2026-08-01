# ShieldCall VN 🛡️ — Nền tảng Bảo vệ Người dùng Số Việt Nam

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://www.python.org/)
[![Django](https://img.shields.io/badge/Django-6.0-green.svg)](https://www.djangoproject.com/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-Glassmorphism-blueviolet.svg)](https://tailwindcss.com/)
[![AI](https://img.shields.io/badge/AI-Ollama%20%2B%20OCR-orange.svg)](https://ollama.ai/)

**ShieldCall VN** là giải pháp toàn diện giúp phát hiện, ngăn chặn và cảnh báo các hình thức lừa đảo kỹ thuật số (cuộc gọi rác, tin nhắn giả mạo, website lừa đảo, tài khoản ngân hàng đen) dành riêng cho người dùng tại Việt Nam.

---

## ✨ Tính năng cốt lõi (MVP)

### 1. Hệ thống Scan Đa tầng (5-Layer Scan)
*   **Phone Scan:** Kiểm tra mức độ rủi ro của số điện thoại dựa trên thuật toán trọng số (Weighted Risk Scoring).
*   **Message Analysis:** Phân tích nội dung tin nhắn bằng lớp luật (Regex) kết hợp AI (Ollama LLM) để nhận diện kịch bản lừa đảo.
*   **Website/Domain Checker:** Phát hiện trang web giả mạo (phishing) bằng thuật toán so khớp khoảng cách Levenshtein và kiểm tra danh sách trắng (Whitelist).
*   **Bank Account Verify:** Tra cứu tài khoản ngân hàng rủi ro từ cơ sở dữ liệu cộng đồng (dữ liệu được băm bảo mật).
*   **QR/Image OCR:** Quét ảnh chụp màn hình tin nhắn hoặc mã QR để trích xuất thực thể (số ĐT, link, số TK) và phân tích tự động.

### 2. Scam Radar & Intelligence
*   **Daily Trends:** Bản đồ nhiệt và thống kê các loại hình lừa đảo đang gia tăng theo ngày.
*   **Hot Targets:** Danh sách các "đầu số nóng" hoặc domain đang hoạt động mạnh trong 24h qua.
*   **Fraud Graph:** (Experimental) Liên kết các thực thể (số ĐT - domain - tài khoản) để tìm ra các nhóm lừa đảo có tổ chức.

### 3. Trung tâm Hỗ trợ & Giáo dục
*   **Learn Hub:** Kho kiến thức phòng chống lừa đảo với các bài học và bộ mẫu kịch bản phổ biến.
*   **Emergency Mode:** Quy trình xử lý khẩn cấp khi người dùng đã lỡ bị lừa (khóa tài khoản, lưu bằng chứng, báo cáo nhanh).

---

## 🛠️ Công nghệ sử dụng

*   **Backend:** Django 6.0, Django REST Framework (DRF)
*   **Frontend:** TailwindCSS v4 (Glassmorphism Design), Alpine.js
*   **Database:** MySQL 8.0 (Primary), Redis 7 (Cache & Queue)
*   **Asynchronous:** Celery & RabbitMQ/Redis (Xử lý OCR và AI dài hạn)
*   **AI/ML:**
    *   **Ollama:** Local LLM (Llama3/Gemma) để phân tích ngữ nghĩa tin nhắn.
    *   **Tesseract/PaddleOCR:** Trích xuất văn bản từ hình ảnh.
    *   **Phishing Detection:** Heuristics + Levenshtein Distance.

---

## 🚀 Cài đặt & Khởi chạy

### 1. Yêu cầu hệ thống
- Python 3.12+
- MySQL 8+, Redis 7+
- Node.js 18+
- Ollama (Để chạy tính năng phân tích AI nội bộ)

### 2. Thiết lập môi trường

```bash
# Clone repository
git clone <repo-url>
cd PKV_TEAM

# Tạo môi trường ảo và cài đặt dependencies
python -m venv venv
source venv/bin/activate  # Linux/macOS
# Hoặc: venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 3. Cấu hình Cơ sở dữ liệu
Sửa tệp `.env` từ `.env.example`:
```bash
cp .env.example .env
# Cập nhật DB_NAME, DB_USER, DB_PASSWORD...
```

### 4. Khởi tạo Database & Static Files
```bash
python manage.py makemigrations
python manage.py migrate
python manage.py tailwind install
python manage.py tailwind build
python manage.py collectstatic --noinput
```

### 5. Khởi chạy hệ thống

Hệ thống cần 3 tiến trình chạy song song:

```bash
# 1. Django Server
python manage.py runserver 0.0.0.0:8000

# 2. Celery Worker (Xử lý tác vụ ngầm)
celery -A PKV worker -l info

# 3. Ollama (Phục vụ AI)
ollama run gemma2:2b  # Hoặc model bạn cấu hình trong utils/ollama_client.py
```

---

## 📁 Cấu trúc thư mục Chính

*   `api/core/`: Logic cốt lõi của hệ thống (Models, Views, Serializers).
*   `api/utils/`: Các bộ máy phân tích (Ollama client, OCR, normalization).
*   `PKV/templates/`: Giao diện người dùng theo phong cách Glassmorphism.
*   `theme/`: Cấu hình TailwindCSS và Style hệ thống.
*   `docs/`: Tài liệu chi tiết về API và hướng dẫn tích hợp.

---

## 🔌 API Documentation

Sau khi chạy server, bạn có thể truy cập tài liệu API tự động tại:
*   **Swagger UI:** `http://localhost:8000/api/docs/`
*   **ReDoc:** `http://localhost:8000/api/redoc/`

---

## 🤝 Đóng góp & Bản quyền

Dự án được phát triển bởi **Sentinel Team (PKV Team)**.

**License:** MIT
