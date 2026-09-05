# ShieldCall VN -- MVP & Kiến trúc Kỹ thuật

> Tech stack: **Django 5.x (ASGI) + DRF**, **MySQL 8.0**, **Redis**, **Celery**, **Tailwind CSS v4 (Liquid Glass)**, **Alpine.js**, **Ollama (Local LLM)**, **Docker Sandbox**
>
> Tài liệu này mô tả đầy đủ tính năng, kiến trúc, DB schema, API và pipeline AI để team dev duy trì và phát triển.

---

## 1. Kiến trúc Hệ thống

### 1.1 Tổng quan

- **Django (ASGI/Daphne)**: HTTP API + SSE streaming + WebSockets
- **MySQL 8.0**: Lưu trữ quan hệ (Users, Reports, Phones, Domains, ScanEvents)
- **Redis**: Cache kết quả scan, Celery broker, rate-limit counters
- **Celery Workers**: Tác vụ nặng (File Scan, OCR, AI Analysis, Trend Aggregation)
- **Ollama (Local LLM)**: Reasoning model chạy on-premise, không cloud
- **Docker Zero-Trust Sandbox**: Phân tích mã độc isolated (YARA + OLETools + PEFile + ClamAV)
- **PM2**: Process manager cho web server, celery, celery-beat, puppeteer

### 1.2 Luồng Scan File (Zero-Trust)

```
[User Upload] (max 500MB)
    |
    v
[Cloudflare Turnstile Verify] --> 400 nếu fail
    |
    v
[ScanEvent PENDING] --> [Celery: perform_file_scan_task]
    |
    v
[LocalSandboxAnalyzer.scan_file()]
    |-- [Docker Daemon Sandbox] (ưu tiên, daemon mode ~20ms)
    |       |-- YARA ruleset scan
    |       |-- OLETools (VBA macro forensics)
    |       |-- PEFile (PE section entropy, dangerous API imports)
    |       |-- ClamAV antivirus
    |       |-- extract_script_snippet() [content-based text detection]
    |
    |-- [Fallback: Local host] nếu Docker không có
            |-- ClamAV local
            |-- Heuristics (entropy, PE magic, PDF exploit patterns)
    |
    v
[ForensicEvidence[] + script_snippet + engines_status]
    |
    v
[ScanEvent COMPLETED] --> [SSE /api/v1/scan/analyze/stream/]
    |
    v
[Ollama LLM] phân tích forensic evidence + nội dung file (nếu text-readable)
    --> stream response to UI
```

### 1.3 Luồng Scan Khác (Phone/Message/Domain/Email)

1. User gửi request + Turnstile token
2. Serialize + validate (DRF)
3. Metadata extraction (carrier, WHOIS, DNS, SSL)
4. Risk scoring (weighted sum + time decay)
5. ScanEvent lưu DB + cache Redis
6. SSE stream AI analysis về UI

---

## 2. Sitemap

### Public
- Home (quick scan + trend banner)
- Scan: Phone, Message, Website, Bank Account, QR/Image, File, Audio, Email
- Report
- Scam Radar
- Learn Hub + Bài học + Quiz
- Scam IQ Exam
- Forum
- Emergency
- Login / Register

### User (authenticated)
- Dashboard (scan history, reports, alerts)
- AI Assistant (trang chat đầy đủ)
- Profile & Security (2FA, device management)

### Admin
- Dashboard tổng quan
- Moderation Queue
- Entity Manager (Phone/Domain/Account DB)
- Magic Create (AI-powered content creation)
- AI Logs
- Fraud Graph
- Analytics & Trends

---

## 3. Database Schema (MySQL)

### 3.1 Users & Auth

**users**
- id (uuid), email (unique), password_hash, role (user/mod/admin)
- is_verified, totp_secret (2FA), created_at, updated_at

**tokens / sessions**
- refresh_tokens: id, user_id, token_hash, expires_at, revoked_at
- login_logs: id, user_id, ip, user_agent, created_at

### 3.2 Scan Entities

**phones** -- id, phone_number (unique), risk_score, scam_type, report_count, verified_level, last_seen_at

**domains** -- id, domain_name (unique), risk_score, domain_age_days, ssl_valid, whois_snapshot_json

**bank_accounts** -- id, bank_name, account_number_hash, risk_score, report_count

### 3.3 Reports & Scans

**reports**
- id, reporter_id (FK), target_type, target_value, scam_type, severity
- description, evidence_file_url, status (pending/approved/rejected)
- moderator_id, moderation_note, created_at

**scan_events**
- id, user_id (nullable), scan_type (phone/message/domain/account/qr/file/audio/email/image)
- raw_input, normalized_input, result_json, risk_score
- status (PENDING/PROCESSING/COMPLETED/FAILED)
- created_at

### 3.4 Graph / Linking

**entity_links** -- id, from_type, from_id, to_type, to_id, link_reason, confidence

### 3.5 Content & Learning

**learn_posts** -- id, title, content (rich text), author_id, published_at

**quizzes** -- id, post_id, questions_json, passing_score

**trend_daily** -- id, date, region, scam_type, count

---

## 4. Redis

| Key pattern | Nội dung | TTL |
| :--- | :--- | :--- |
| `cache:phone:{number}` | JSON scan result | 10--30 phút |
| `cache:domain:{domain}` | JSON result | 1--6 giờ |
| `cache:account:{bank}:{hash}` | JSON result | 30 phút |
| `rl:{ip}:{endpoint}:{minute}` | Rate limit counter | 1 phút |
| `jwt:blacklist:{jti}` | Revoked token | token exp |

---

## 5. AI Pipeline

### 5.1 File Content Extraction (text-readable detection)

Không phụ thuộc extension file. Phân loại bằng content analysis:

| Kiểm tra | Logic |
| :--- | :--- |
| Magic bytes | Reject ELF, MZ/PE, ZIP, GZIP, RAR, PNG, JPEG, GIF, PDF, OLE2, v.v. |
| Null bytes | `b'\x00'` trong 8 KB đầu → binary |
| Printable ratio | < 90% printable chars → binary |
| Shannon entropy ≤ 6.2 | Plain text, đọc bình thường |
| Entropy 6.2--7.5 | Đọc + prepend cảnh báo cho AI (có thể obfuscate/base64/XOR) |
| Entropy > 7.5 | Reject (không thể phân biệt với encrypted random data) |
| File > 500 KB | Reject (không đọc nội dung) |

Output: tối đa 150 dòng đầu, strip control chars (chống prompt injection).

### 5.2 Ollama LLM Integration

- **Endpoint**: HTTP streaming tới Ollama server nội bộ
- **Thinking block**: Tách `__THINK__:` token, hiển thị accordion riêng
- **Status tokens**: `__STATUS__:thinking` / `__STATUS__:answering` để cập nhật UI
- **Chat Widget**: Hỗ trợ ảnh (base64), thinking accordion tự động mở/thu
- **File Scan**: Lọc sạch thinking tokens, chỉ stream phần analysis

### 5.3 AI Prompts (prompts.py)

Tất cả prompt theo nguyên tắc:
- Không spam emoji (chỉ dùng khi thực sự cần nhấn mạnh)
- Báo cáo nghiêm túc, dễ hiểu cho người dùng phổ thông
- `SCAN_FILE_PROMPT` nhận: `forensic_evidence`, `engines`, `file_metadata`, `script_snippet`
- AI được yêu cầu giải thích cụ thể từng đoạn lệnh đáng ngờ bằng ngôn ngữ đơn giản

### 5.4 AI Agent (Multi-Tool)

Agent có thể tự gọi:
- Web search (Google/Bing/DuckDuckGo)
- DB lookup (phone/domain/account)
- URL/domain analysis
- Image OCR

---

## 6. API Endpoints

### Auth
- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET  /api/v1/me`

### Scan
- `POST /api/v1/scan/phone/`
- `POST /api/v1/scan/message/`
- `POST /api/v1/scan/domain/`
- `POST /api/v1/scan/account/`
- `POST /api/v1/scan/image/`
- `POST /api/v1/scan/email/`
- `POST /api/v1/scan/file/`         -- multipart, Celery async
- `POST /api/v1/scan/audio/`
- `GET  /api/v1/scan/status/{id}/`  -- poll scan_event status
- `POST /api/v1/scan/analyze/stream/` -- SSE AI analysis

### Reports & Trends
- `POST /api/v1/report/`
- `GET  /api/v1/trends/daily/`
- `GET  /api/v1/trends/hot/`

### User
- `GET  /api/v1/user/scans/`
- `GET  /api/v1/user/reports/`

### Admin
- `GET  /api/v1/admin/reports/?status=pending`
- `POST /api/v1/admin/reports/{id}/approve/`
- `POST /api/v1/admin/reports/{id}/reject/`
- `GET  /api/v1/admin/entities/phones/`

### AI Chat
- `POST /api/v1/ai/chat/stream/`     -- SSE stream
- `POST /api/v1/ai/agent/stream/`    -- Agent với tools

### Utilities
- `POST /api/v1/utils/upload-image/` -- CKEditor image upload
- `GET  /api/v1/utils/vietqr-banks/` -- Danh sách ngân hàng

---

## 7. Celery Tasks

| Task | Mô tả |
| :--- | :--- |
| `perform_file_scan_task(scan_id, file_path)` | Chạy sandbox phân tích file |
| `scan_domain_job(url)` | Deep scan website |
| `recompute_phone_risk_job(phone_id)` | Tính lại risk score |
| `daily_trend_aggregation_job(date)` | Tổng hợp xu hướng |
| `fraud_graph_cluster_job()` | Cập nhật entity links |
| `deduplicate_reports_job()` | Loại bỏ báo cáo trùng |

---

## 8. Bảo mật

| Lớp | Cơ chế |
| :--- | :--- |
| Anti-spam | Cloudflare Turnstile (single-use token, auto-refresh khi expired) |
| Rate limiting | Redis counter, 30 req/min guest, 120 req/min user |
| File sandbox | Docker no-network, read-only, cap-dropped |
| SSRF | IP private/loopback block trước outbound HTTP |
| Filename | Path traversal + null byte sanitization |
| Input | DRF serializer validation toàn bộ |
| Auth | Token-based + 2FA TOTP |
| Script injection | Control char strip trong file snippet |

---

## 9. UI Guidelines

- Background: gradient dark (slate/zinc tones)
- Cards: `bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl`
- Risk badge: green/yellow/red với glow effect
- Animated progress bar + pulse indicator khi scan
- SSE stream text rendering: `window.renderMd()` toàn cục, sanitize trước khi hiển thị
- Thinking accordion: auto-open khi AI đang suy luận, auto-collapse khi xong
- Mobile-first responsive

---

## 10. Deliverables

- [x] ERD + DB migrations (Django ORM)
- [x] API docs (drf-spectacular / OpenAPI)
- [x] Zero-Trust Docker Sandbox engine
- [x] Multi-engine file analysis (YARA + OLETools + PEFile + ClamAV)
- [x] Content-based text/binary classifier (entropy + magic bytes)
- [x] SSE AI streaming với thinking display
- [x] Cloudflare Turnstile anti-spam (token refresh flow)
- [x] CKEditor 5 Community (GPL, không license fee)
- [ ] Video demo end-to-end
- [ ] Model card (mô tả AI + hạn chế + privacy policy)

---

*Cập nhật: 2026-09-02*