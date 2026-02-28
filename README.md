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
*   **AI OCR Magic:** Trích xuất thông tin lừa đảo từ ảnh chụp màn hình bằng EasyOCR kết hợp AI phân tích thực thể.

### 2. Hệ sinh thái Cộng đồng & Giáo dục
*   **Scam Radar:** Bản đồ nhiệt và xu hướng lừa đảo cập nhật theo thời gian thực.
*   **Learn Hub:** Kho bài giảng tương tác về an ninh mạng.
*   **Interactive Scenarios:** Thực hành đối đầu với kẻ gian trong môi trường giả lập AI.

### 3. Công nghệ Quản trị Đẳng cấp
*   **AI Magic Create:** Quy trình 5 giai đoạn (Phân tích -> Lesson -> Quiz -> Scenario -> Push) biến tin tức thô thành bài học hoàn chỉnh.
*   **Dashboard Thông minh:** Hệ thống giám sát dữ liệu và báo cáo lừa đảo chuyên sâu.

## 🛠️ Stack Công nghệ
- **Core:** Django 5.2 (Python 3.12), Django REST Framework.
- **AI Engine:** Multi-Agent Collaboration (Ollama LLM), Faster-Whisper (STT), RAG Architecture, AI OCR.
- **Performance:** Celery & Redis (Async Tasks), Django Channels (WebSocket Progress).
- **Design:** Liquid Glass Aesthetic (TailwindCSS v4), Alpine.js.

## 🚀 Cài đặt nhanh

### 1. Yêu cầu
- Python 3.12+, MySQL 8.0, Redis 7.0, Ollama.

### 2. Các bước khởi chạy
```bash
# Clone và cài đặt venv
git clone <repo-url>
cd PKV_TEAM
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Cấu hình môi trường
cp PKV/settings.py.example PKV/settings.py
# Sửa thông tin DB và API Key trong settings.py

# Migrate và Build UI
python manage.py migrate
python manage.py tailwind build
python manage.py collectstatic --noinput

# Chạy Server
python manage.py runserver 0.0.0.0:8000
```

---

## 👨‍💻 Đội ngũ phát triển
Dự án được thực hiện bởi **SENTINEL TEAM** (tiền thân là PKV Team).
- **Quy mô dự án:** ~40,000 dòng code tự viết.
- **Kiến trúc:** Cloud-native, AI-integrated.

**License:** MIT
