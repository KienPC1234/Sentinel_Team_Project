# ShieldCall VN – Nền tảng bảo vệ người dùng Việt Nam khỏi cuộc gọi lừa đảo & các hình thức lừa đảo số
> Tech stack thực tế: **Django (ASGI) + DRF**, **MySQL**, **Redis**, **Celery**, **TailwindCSS (Liquid Glass)**, **Ollama (Local LLM)**  
> Mục tiêu: mô tả **đầy đủ tính năng + kiến trúc hiện tại** (data, pipeline, DB, session, queue, OCR, AI) để team dev duy trì và phát triển.


---

## 1) Kiến trúc hệ thống (Thực tế)
### 1.1 Tổng quan
- **Django (ASGI/Daphne)**: Xử lý cả HTTP API và WebSockets (Real-time scans).
- **MySQL**: Lưu trữ dữ liệu quan hệ (Users, Reports, Phones, Domains).
- **Redis**: Làm Channel Layer cho WebSockets, Cache kết quả scan, và Broker cho Celery.
- **Celery Workers**: Xử lý các tác vụ nặng (Deep Scan, OCR, AI Analysis, Aggregating Trends).
- **Ollama (Local AI)**: Sử dụng các mô hình như `neural-chat`, `ministral` để phân tích nội dung lừa đảo, trích xuất thực thể và gán nhãn dữ liệu.

### 1.2 Luồng scan hiện tại (Phone/Message/URL/QR)
1) User gửi request (Hỗ trợ cả Scan nhanh qua HTTP và Deep Scan qua WebSocket).
2) Django Channels/Celery khởi tạo tiến trình scan.
3) **Metadata Phase**: Trích xuất thông tin cơ bản (Carrier, Country, SSL, Whois) sử dụng `phonenumbers` và `ipwhois`.
4) **AI/Analysis Phase**: 
   - Với Text/Image: Sử dụng `EasyOCR` và `Ollama` để phân tích ngữ cảnh.
   - Với Website: Kiểm tra redirect chains, SSL age, và Levenshtein distance cho "lookalike" domains.
5) **Risk Scoring**: Tính toán điểm rủi ro theo công thức weighted sum (Reports, Recency, AI Confidence, Trust Score).
6) **Real-time Feedback**: Cập nhật trạng thái từng bước (OCR -> Analysis -> Finalizing) qua WebSocket với cơ chế tự động reconnect và polling fallback.
7) **Result**: Lưu kết quả vào MySQL và Cache Redis, trả về UI Liquid Glass.

---

## 2) Navigation & Site Map (Glassmorphism UI)
### 2.1 Public Nav
- Home
- Scan (dropdown)
  - Scan Phone
  - Scan Message
  - Scan Website
  - Scan Bank Account
  - Scan QR / Image
- Report
- Scam Radar (Live)
- Learn Hub
- Emergency
- Login / Register

### 2.2 User Nav
- Scan
- Report
- Alerts (Saved)
- Dashboard
- Profile & Security
- Logout

### 2.3 Admin Nav
- Overview
- Moderation Queue
- Phone/Account/Domain DB
- AI Logs & Model Manager
- Fraud Graph
- Analytics & Trends
- Users & Roles

---

## 3) Data Strategy – Lấy dữ liệu ở đâu để làm được (quan trọng)
### 3.1 Data nguồn (không cần nhạy cảm cá nhân)
- **Crowdsourcing**: người dùng report số điện thoại / nội dung / link
- **Public sources**: danh sách cảnh báo từ báo chí, diễn đàn (lọc/verify), nguồn mở
- **Synthetic data**: tạo mẫu kịch bản lừa đảo (prompt) để bootstrap model
- **Admin curation**: đội kiểm duyệt gán nhãn (scam type, severity, verified)

> Lưu ý: Không cần thu âm cuộc gọi thật từ người dùng ở MVP. Nếu làm voice detection, chỉ cần cho phép upload audio tự nguyện + ẩn danh.

### 3.2 Labeling (gán nhãn)
- Scam types (enum): giả danh công an, ngân hàng, tuyển dụng, đầu tư, giao hàng, vay tiền người thân, OTP/2FA, phishing link, v.v.
- Severity: low/medium/high/critical
- Evidence types: screenshot, chat log, url, bank account, qr

### 3.3 Anti-abuse data
- Reputation score của reporter
- Duplicate detection (hash nội dung, similarity)
- Rate limit & spam detection

---

## 4) Cơ sở dữ liệu MySQL (bảng & index để dev)
### 4.1 Users & Security
**users**
- id (uuid)
- email (unique, indexed)
- password_hash
- role (user/mod/admin)
- is_verified
- created_at, updated_at

**sessions / tokens**
- refresh_tokens: id, user_id, token_hash, expires_at, revoked_at
- login_logs: id, user_id, ip, user_agent, created_at

### 4.2 Entities bị lừa đảo
**phones**
- id, phone_number (unique, indexed)
- risk_score (0-100, indexed)
- scam_type (enum)
- report_count
- verified_level (0..3)
- last_seen_at
- created_at, updated_at

**domains**
- id, domain_name (unique, indexed)
- risk_score (indexed)
- domain_age_days
- ssl_valid
- whois_snapshot_json
- created_at

**bank_accounts**
- id, bank_name (indexed)
- account_number_hash (indexed)  *(không lưu plain nếu không cần)*
- risk_score
- report_count
- created_at

### 4.3 Reports & Scans
**reports**
- id
- reporter_id (FK users)
- target_type (phone/domain/account/message/qr)
- target_value (normalized string)
- scam_type, severity
- description
- evidence_file_url
- status (pending/approved/rejected)
- moderator_id, moderation_note
- created_at

**scan_events**
- id
- user_id (nullable nếu guest)
- scan_type (phone/message/domain/account/qr)
- raw_input (text) *(có thể mã hoá)*
- normalized_input (indexed where applicable)
- result_json
- risk_score (indexed)
- created_at

### 4.4 Graph/Linking (để làm Fraud Network)
**entity_links**
- id
- from_type (phone/domain/account)
- from_id
- to_type (phone/domain/account)
- to_id
- link_reason (shared_text/shared_report/shared_url/ocr_match/manual)
- confidence (0..1)
- created_at
Indexes: (from_type, from_id), (to_type, to_id)

### 4.5 Trends (precompute)
**trend_daily**
- id
- date (indexed)
- region
- scam_type
- count
- created_at

---

## 5) Redis – dùng cụ thể như nào (để dev)
### 5.1 Cache
- `cache:phone:{number}` -> JSON scan result (TTL 10–30 phút)
- `cache:domain:{domain}` -> JSON result (TTL 1–6 giờ)
- `cache:account:{bank}:{hash}` -> JSON result

### 5.2 Rate limiting (theo IP + user)
- key: `rl:{ip}:{endpoint}:{minute}` counter
- limit gợi ý: 30 req/min guest, 120 req/min user

### 5.3 Session/Token blacklist
- key: `jwt:blacklist:{jti}` TTL = token exp

### 5.4 Celery broker + result backend
- Redis làm broker
- result backend để tracking job status

---

## 6) AI & Risk Features (Cập nhật cơ chế thực tế)
### 6.1 AI Text Analyzer (Ollama)
**Mục tiêu:** Nhận diện hội thoại, kịch bản lừa đảo qua tin nhắn.

**Cơ chế hiện tại:**
- **Local Engine**: `Ollama` chạy `neural-chat` hoặc các mô hình tinh chỉnh (Ministral).
- **Phân loại**: Scam types (mạo danh, đe dọa, mời gọi đầu tư) kèm độ tin cậy.
- **Trích xuất**: Tự động bóc tách số tài khoản ngân hàng, liên kết độc hại, số điện thoại từ đoạn chat.
- **Khuyến nghị**: Đưa ra các bước hành động cụ thể dựa trên mức độ rủi ro $R_{text}$.

### 6.2 Phone Reputation Engine (Weighted & Time Decay)
**Mục tiêu:** Tính điểm uy tín của số điện thoại.

**Công thức hiện tại:**
- **Risk Score** $S = \sum (w_i \times v_i) \times e^{-\lambda t}$
- **Yếu tố**: Số lần bị report (đã duyệt), độ tin cậy của reporter (Trust Score), tần suất bị report trong 24h qua.
- **Carrier/Geocoding**: Sử dụng `phonenumbers` để định danh Nhà mạng/Quốc gia (hỗ trợ toàn cầu, ưu tiên bản địa hóa VN).
- **Disposable Check**: Kiểm tra các đầu số điện thoại ảo (VOIP/Virtual numbers) qua metadata.

### 6.3 Phishing Website Analysis (Deep Scan)
**Mục tiêu:** Phát hiện trang web giả mạo, lừa đảo hoặc chứa mã độc.

**Cơ chế hiện tại:**
- **Network Check**: Phân tích SSL certificate (Tuổi đời SSL < 3 ngày được gán nhãn rủi ro cao), IP Reputation, Redirect Chains.
- **Brand Protection**: Thuật toán Levenshtein distance so sánh domain với whitelist các thương hiệu ngân hàng/ví điện tử Việt Nam.
- **Third-party Integration**: Kết hợp kết quả từ VirusTotal API và `ScamAdviser` (quét HTML động để lấy chỉ số trust).
- **Screenshot Analysis**: (Phase đang thực hiện) Chụp màn hình để OCR logo/text so khớp với whitelist.

### 6.4 OCR & QR Analysis (EasyOCR)
**Mục tiêu:** Phân tích hình ảnh chụp màn hình, biên lai chuyển khoản hoặc mã QR.

**Cơ chế hiện tại:**
- **OCR Engine**: `EasyOCR` xử lý đa ngôn ngữ (Tiếng Việt/Anh).
- **QR Decoding**: `pyzbar` để bóc tách URL/Payload.
- **Bounding Boxes**: Hiển thị trực quan cho người dùng vị trí phát hiện nội dung nhạy cảm.
- **Pipeline**: Text sau khi OCR được đẩy vào `AI Text Analyzer` để đánh giá risk toàn diện.

### 6.5 WebSocket Resilience (Real-time Scan)
**Mục tiêu:** Đảm bảo trải nghiệm quét không bị gián đoạn.

**Cơ chế:**
- **State Machine**: Theo dõi trạng thái `Connecting`, `Connected`, `Reconnecting`, `Disconnected`.
- **Exponential Backoff**: Tự động thử lại kết nối khi bị ngắt quãng với thời gian chờ tăng dần.
- **HTTP Polling Fallback**: Nếu WebSocket không thể khôi phục, client sẽ tự động chuyển sang cơ chế Poll API `/api/v1/scan/status/` liên tục để lấy kết quả từ Celery worker.

---

## 7) Tính năng theo trang (đủ chi tiết để dev)

### 7.1 Home
- Quick scan phone
- Banner cảnh báo mới nhất (từ trend_daily)
- Top scam types 7 ngày
- CTA Emergency

### 7.2 Scan Phone
- Input + normalize + validate
- Kết quả:
  - risk badge + score
  - scam_type + confidence
  - report_count + last_seen
  - reasons (top 3)
- Actions:
  - “Report số này”
  - “Save alert”
  - “Share cảnh báo”

### 7.3 Scan Message
- Text area + upload screenshot
- Nếu upload -> OCR -> show extracted text (editable)
- Output:
  - risk_score + explanation
  - highlight câu nguy hiểm
  - recommended action checklist

### 7.4 Scan Website
- Input URL + preview domain
- Output:
  - phishing risk
  - similarity suggestion: “có thể bạn muốn vào …”
  - technical details: domain age, ssl status

### 7.5 Scan Bank Account
- Bank select + account input
- Hash & store safely
- Output:
  - risk_score
  - linked entities (phone/domain) nếu có
  - recommended action (không chuyển)

### 7.6 Scan QR / Image
- Upload image -> QR decode + OCR
- Trả về:
  - detected: url/account/phone
  - link tới các scan tương ứng
  - tổng risk_score

### 7.7 Report
- Form có:
  - target type
  - target value
  - scam_type, severity
  - description
  - evidence upload
- Anti-spam:
  - captcha
  - rate limit
  - duplicate warning (similarity)

### 7.8 Scam Radar (Live)
- Heatmap (trend_daily)
- Filter: scam_type, time range
- “hot numbers” list (top risk increase)

### 7.9 Learn Hub
- Bài học theo chủ đề
- Quiz “phân biệt lừa đảo” (gamification)
- Bộ mẫu: “kịch bản lừa đảo phổ biến”
- Chatbot tư vấn

### 7.10 Emergency
- Nút “Tôi đang bị lừa”
- Flow:
  1) dừng chuyển tiền
  2) khóa tài khoản ngân hàng (hướng dẫn)
  3) lưu bằng chứng (ảnh, chat, số)
  4) tạo report tự động (prefill)
  5) xuất PDF checklist + timeline sự kiện

### 7.11 User Dashboard
- Scan history (lọc theo type)
- My reports (status)
- Saved alerts
- Security settings:
  - 2FA (phase 2)
  - device management
  - revoke refresh tokens

### 7.12 Admin Panel
- Moderation queue:
  - approve/reject
  - merge duplicates
  - label correction
- Entity manager:
  - phones/domains/accounts
  - adjust verified_level
- AI logs:
  - latency, model version, error rate
- Analytics:
  - daily reports, top scams
- Fraud graph viewer:
  - cluster list
  - drill-down entity links

---

## 8) API Spec (tối thiểu để dev)
### Auth
- `POST /api/auth/register`
- `POST /api/auth/login`
- `POST /api/auth/refresh`
- `POST /api/auth/logout` (revoke token)
- `GET  /api/me`

### Scan
- `POST /api/scan/phone`
- `POST /api/scan/message`
- `POST /api/scan/domain`
- `POST /api/scan/account`
- `POST /api/scan/image` (OCR + QR)

### Reports & Trends
- `POST /api/report`
- `GET  /api/trends/daily`
- `GET  /api/trends/hot`

### User
- `GET /api/user/scans`
- `GET /api/user/reports`
- `POST /api/user/alerts`

### Admin
- `GET  /api/admin/reports?status=pending`
- `POST /api/admin/reports/{id}/approve`
- `POST /api/admin/reports/{id}/reject`
- `GET  /api/admin/entities/phones`
- `GET  /api/admin/ai/logs`

---

## 9) Celery Jobs (async tasks làm cho “ra sản phẩm”)
- `scan_message_ocr_job(image_id)`
- `scan_domain_job(url)`
- `recompute_phone_risk_job(phone_id)`
- `daily_trend_aggregation_job(date)`
- `fraud_graph_cluster_job()`
- `deduplicate_reports_job()`

---

## 10) Bảo mật & vận hành (điểm kỹ thuật)
- Redis rate limit theo IP/user
- Validate input (DRF serializers)
- File upload: size limit + content-type + virus scan (phase 2)
- Encrypt sensitive fields (account number hash)
- Audit logs (admin actions)
- Monitoring: Sentry + Prometheus (optional)

---

## 11) UI – Tailwind Glassmorphism (guideline)
- Background: gradient dark
- Card:
  - `bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl shadow-lg`
- Risk badge:
  - green/yellow/red glow (class utilities)
- Animated risk meter (progress bar + pulse)
- Mobile-first responsive

---

## 12) Gợi ý cách bootstrap AI nhanh (để có demo)
- V1: Rule-based scoring + keyword patterns + regex entity extraction (OTP, link, số TK)
- V2: Train text classifier bằng dữ liệu report đã duyệt + data tổng hợp
- V3: Add OCR + domain features + graph clusters

---

## 13) Deliverables (để nộp dự án/thi)
- ERD + DB migration
- API docs (OpenAPI/Swagger)
- Demo dataset (ẩn danh)
- UI prototype (Glassmorphism)
- Model card (mô tả AI + hạn chế)
- Video demo “scan -> cảnh báo -> report -> admin duyệt -> trend”

---