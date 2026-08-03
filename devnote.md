# ShieldCall VN – Dev Notes

Tài liệu này dành cho developer khi onboard hoặc phát triển tính năng cho backend ShieldCall VN.

## 1. Tech stack & kiến trúc

- Django 5.2.x (monolith) + Django REST Framework.
- MySQL 8 (DB chính), Redis (cache, session, Celery broker/result, Channels).
- Channels + daphne: hỗ trợ realtime (SSE/WebSocket) cho chat/scan.
- Celery: xử lý tác vụ nặng (scan, AI, OCR) không block request.
- Frontend web: template Django trong thư mục PKV/templates + Tailwind (app theme).
- Mobile app: tích hợp qua REST API ở prefix /api/v1/.

Thư mục chính:
- api/core/: API chính cho auth, MFA, scan, trends, forum, article, admin…
- api/sessions_api/: check-session cho mobile.
- api/phone_security/: check-phone.
- api/ai_chat/: chat-ai, chat-ai-stream.
- api/media_analysis/: analyze-images, analyze-audio.
- api/maintenance/: report-crash.
- api/utils/: helper cho auth, normalization, Ollama, media, VT, bảo mật…
- PKV/: project config, urls, views cho web pages.
- theme/: Tailwind config, static.

## 2. Chạy local cho dev

1. Tạo venv & cài dep:
   - python -m venv .venv
   - source .venv/bin/activate
   - pip install -r requirements.txt

2. Cấu hình môi trường:
   - Copy .env.example → .env nếu cần (DB, Redis, Ollama…).
   - Trong dev hiện tại settings.py đang hardcode DB/SECRET_KEY, khi deploy nên override bằng env.

3. DB & migrate:
   - python manage.py migrate
   - python manage.py createsuperuser (nếu cần vào admin).

4. Static/Tailwind (chỉ khi cần build UI):
   - python manage.py tailwind install
   - python manage.py tailwind build
   - python manage.py collectstatic --noinput

5. Các process cần chạy:
   - App chính: python manage.py runserver 0.0.0.0:8000
   - Celery worker: celery -A PKV worker -l info
   - Redis: redis-server (hoặc service tương đương).
   - Ollama: chạy model trùng với config trong api/utils/ollama_client.py.

## 3. API routing & versioning

- Root web pages: định nghĩa trong PKV/urls.py (home, scan/*, dashboard, forum,…).
- API v1: prefix /api/v1/ trong PKV/urls.py:
  - include api.sessions_api.urls
  - include api.phone_security.urls
  - include api.ai_chat.urls
  - include api.media_analysis.urls
  - include api.maintenance.urls
  - include api.core.urls
- Docs:
  - /api/schema/ – OpenAPI spec (drf-spectacular).
  - /api/docs/ – Swagger UI.
  - /api/redoc/ – ReDoc.

## 4. Auth, 2FA, CSRF

- Auth API nằm trong api/core/views.py (Register/Login/Logout/Me, password change…).
- Sử dụng Token Auth (rest_framework.authtoken) + Session (cho web).
- 2FA: dùng django-otp (TOTP, email OTP, static), endpoints nằm trong api/core/urls.py:
  - /auth/mfa/status/
  - /auth/mfa/setup/totp/
  - /auth/mfa/setup/email/
  - /auth/mfa/verify/
  - /auth/mfa/deactivate/
- Cloudflare Turnstile: helper verify ở api/utils/security.py, settings trong TURNSTILE_*.
- DRF dùng CsrfExemptSessionAuthentication trong api/utils/authentication.py cho một số endpoint phục vụ mobile.

## 5. Scan pipeline (high-level)

- Các endpoint scan chính (API): định nghĩa trong api/core/urls.py:
  - /scan/phone/, /scan/message/, /scan/domain/, /scan/account/, /scan/image/, /scan/email/, /scan/file/, /scan/status/<id>/.
  - /scan/analyze-sse/: SSE trả kết quả phân tích theo stream.
- Phone/domain normalization: api/utils/normalization.py.
- Media (ảnh/audio): api/utils/media_utils.py: EasyOCR + QR decode + phân tích nguy cơ bằng Ollama.
- LLM/Ollama: api/utils/ollama_client.py, được dùng bởi ai_chat, media_utils và các flow scan khác.

## 6. Utils quan trọng

- api/utils/authentication.py: custom CsrfExemptSessionAuthentication cho DRF.
- api/utils/normalization.py: chuẩn hoá số điện thoại, domain.
- api/utils/ollama_client.py: wrapper gọi Ollama, stream response, analyze_text_for_scam.
- api/utils/media_utils.py: OCR, QR detection, image/audio risk analysis.
- api/utils/vt_client.py: tích hợp VirusTotal (nếu dùng).
- api/utils/prompts.py: system prompt/template cho LLM.
- api/utils/security.py: verify_turnstile_token.
- api/utils/email_utils.py: helper gửi email (OTP, alert,…).

## 7. Core app (api/core)

- urls.py: định nghĩa tất cả API chính (auth, mfa, scan, trends, user, admin, forum, article, utils/editor upload…).
- models.py: UserProfile, Scan, Report, ForumPost, ForumComment, Article… (xem trực tiếp file để hiểu schema).
- serializers.py: ánh xạ model ↔ JSON.
- views/: chia nhỏ view theo page / feature cho web (PKV/views) và view API (api/core/views.py).
- tasks.py: Celery task cho các job scan/analysis.
- consumers.py + routing.py: Channels consumer cho realtime (chat, notifications nếu có).

## 8. Coding guideline ngắn

- API mới: đặt trong api/core hoặc tạo app chuyên biệt nếu domain rõ (theo pattern các app còn lại).
- Dùng DRF class-based view / generics trừ khi endpoint rất đơn giản.
- Response JSON:
  - Luôn có field status hoặc rõ ràng key chính (vd: risk_level, is_valid…).
  - Thống nhất message bằng tiếng Việt cho user-facing.
- Logging:
  - Dùng logging.getLogger(__name__) trong module.
  - LLM log: dùng pkv.llm (đã setup trong ollama_client.py).
- Background job: nếu tốn thời gian (OCR, scan file, VT…) thì đẩy qua Celery.

## 9. Tài liệu thêm

- docs/API.md – spec API gốc.
- docs/IMPLEMENTATION.md – guide chi tiết endpoint.
- docs/IMPLEMENTATION_SUMMARY.md – tóm tắt implementation.
- docs/OLLAMA_SETUP.md, OLLAMA_INTEGRATION.md, OLLAMA_COMPLETE.md – chi tiết về tích hợp Ollama.

## 10. TODO / lưu ý cho dev

- Refactor settings: SECRET_KEY, DB, TURNSTILE_SECRET, Google OAuth client_id/secret → đọc từ env khi deploy.
- Bổ sung test cho api/core (scan, auth, forum…) tương tự test_api.py.
- Xem lại rate limiting / throttling DRF cho các endpoint nhạy cảm (scan, auth, ai_chat).
- Cân nhắc tách config dev/prod (settings.py vs settings_prod.py hoặc env-driven).
