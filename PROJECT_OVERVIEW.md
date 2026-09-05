# ShieldCall VN -- Project Overview

**ShieldCall VN** là nền tảng an toàn số toàn diện, được xây dựng để bảo vệ người dùng Việt Nam khỏi lừa đảo (scam, phishing, malware) thông qua trí tuệ nhân tạo chạy hoàn toàn nội bộ (on-premise). Hệ thống không phụ thuộc bất kỳ dịch vụ cloud AI bên ngoài nào.

---

## Stack Công nghệ

| Thành phần | Công nghệ | Ghi chú |
| :--- | :--- | :--- |
| **Backend Core** | Django 5.x + Django REST Framework | ASGI, Monolith-first, API RESTful chuẩn |
| **Frontend UI** | Tailwind CSS v4 + Alpine.js | Liquid Glass Aesthetic, SSE streaming |
| **AI Engine** | Ollama (local LLM, reasoning model) | Chạy on-premise, không cloud |
| **AI Vision** | EasyOCR | Trích xuất văn bản từ ảnh/screenshot |
| **AI Audio** | Faster-Whisper | Phiên âm âm thanh cuộc gọi |
| **Rich Text Editor** | CKEditor 5 Community (GPL) | Không cần license thương mại |
| **Sandbox Phân tích mã độc** | Docker Zero-Trust Container | YARA + OLETools + PEFile + ClamAV |
| **Async Tasks** | Celery + Redis | Scan nặng, Celery Beat định kỳ |
| **Real-time Streaming** | Server-Sent Events (SSE) | Phản hồi AI stream trực tiếp |
| **Vector DB (RAG)** | FAISS + Sentence-Transformers | Tra cứu kiến thức bảo mật nội bộ |
| **Anti-spam** | Cloudflare Turnstile | Chặn bot, bảo vệ endpoint scan |
| **Infrastructure** | Nginx + MySQL 8.0 + Daphne + PM2 | Production-ready |

---

## Trang & Chức năng

### 1. Scan Hub -- Trung tâm Quét Đa hướng

| Loại quét | Mô tả |
| :--- | :--- |
| **Số điện thoại** | Tra cứu rủi ro từ DB cộng đồng + AI phân tích |
| **Tài khoản ngân hàng** | Đối soát dấu hiệu gian lận |
| **Website / URL** | WHOIS, DNS, SSL, Levenshtein lookalike domain |
| **Email (.eml upload)** | Parse header, SPF/DKIM/DMARC, phân tích nội dung |
| **Tin nhắn (SMS/Chat)** | Phát hiện kịch bản lừa đảo, yêu cầu OTP/chuyển tiền |
| **QR Code** | Giải mã + quét URL kết quả |
| **Hình ảnh (OCR)** | EasyOCR trích xuất + AI đánh giá ý đồ |
| **Tệp tin (File Scan)** | Zero-Trust Docker Sandbox: YARA, OLETools, PEFile, ClamAV |
| **Audio** | Faster-Whisper phiên âm + AI phân tích kịch bản giọng nói |

### 2. Cộng đồng & Giáo dục

- **Scam Radar**: Bản đồ xu hướng lừa đảo theo thời gian thực
- **Learn Hub**: Bài học, bài viết chuyên sâu về an toàn thông tin
- **Scam IQ Exam**: Bài thi đánh giá năng lực phòng chống lừa đảo
- **Forum**: Cộng đồng chia sẻ, cảnh báo lẫn nhau
- **Emergency**: Hướng dẫn xử lý khẩn cấp khi đã bị lừa

### 3. AI Assistant & Cá nhân hóa

- **ShieldCall AI (Chat Widget)**: Chatbot 24/7, hỗ trợ ảnh + văn bản, hiển thị quá trình suy luận (thinking)
- **AI Assistant (trang riêng)**: Giao diện chat đầy đủ với lịch sử hội thoại
- **Custom Personas**: Tùy chỉnh giọng điệu AI (thân thiện / chuyên nghiệp)
- **Profile Management**: Lịch sử scan, báo cáo, thành tích học tập

### 4. Quản trị (Admin CP)

- **Magic Create**: Tạo nội dung giáo dục từ tin tức thô bằng AI (5 bước tự động)
- **Dashboard**: Giám sát hệ thống, thống kê lừa đảo
- **Moderation Queue**: Duyệt/từ chối báo cáo từ cộng đồng
- **Entity Manager**: Quản lý phone/domain/account database

---

## Hệ thống Phân tích File (Zero-Trust Sandbox)

Đây là tính năng cốt lõi phân biệt ShieldCall VN với các sản phẩm thông thường:

```
[File Upload] --> [ClamAV Antivirus] + [YARA Rules] + [OLETools VBA] + [PEFile PE Analysis]
     |
     v
[Docker Zero-Trust Container] (no network, read-only, cap-dropped)
     |
     v
[Forensic Evidence Report] --> [Ollama LLM Analysis] --> [SSE Stream to User]
```

**Phân loại nội dung thông minh:**
- Script/text-readable (không phụ thuộc extension): đọc tối đa 150 dòng đầu, đưa vào ngữ cảnh cho AI
- Phân loại binary vs text bằng content analysis: magic bytes, null byte scan, Shannon entropy, tỉ lệ printable chars
- Entropy 6.2--7.5: đọc nhưng cảnh báo AI nghi ngờ obfuscate/encode
- Entropy >7.5 hoặc file >500 KB: từ chối đọc nội dung

---

## AI Pipeline

### Streaming Response (SSE)
Mọi phân tích AI đều stream trực tiếp về frontend qua Server-Sent Events. Người dùng thấy nội dung sinh ra từng từ trong thời gian thực, không phải chờ toàn bộ.

### Thinking / Reasoning Display
Khi model suy luận (thinking), hệ thống hiển thị block "Đang suy luận..." riêng biệt (accordion mở/thu tự động), sau đó stream phần trả lời chính. Áp dụng cho cả chat widget nhỏ lẫn AI assistant trang riêng.

### Multi-Agent (AI Agent với Tools)
AI Agent có thể tự gọi các công cụ nội bộ:
- Tìm kiếm web (Google/Bing/DuckDuckGo)
- Tra cứu thực thể trong DB hệ thống
- Phân tích URL/domain/phone realtime

### RAG (Retrieval-Augmented Generation)
FAISS Vector DB lưu toàn bộ nội dung Learn Hub. Khi user hỏi, AI tìm kiếm context chính xác nhất từ kho kiến thức nội bộ thay vì chỉ dùng trí nhớ tham số.

---

## Bảo mật Hệ thống

| Lớp | Cơ chế |
| :--- | :--- |
| **Anti-spam** | Cloudflare Turnstile (token single-use, auto-refresh on expiry) |
| **Rate limiting** | Redis counter theo IP + user |
| **File sandbox** | Docker isolated container, no network, read-only filesystem |
| **SSRF protection** | IP whitelist check trước mọi outbound HTTP |
| **Filename sanitization** | Path traversal + null byte strip |
| **Input validation** | DRF serializers, strict type checking |
| **Auth** | Token-based + 2FA (TOTP) |

---

## Kiến trúc Dữ liệu

Xem chi tiết trong [mvp.md](./mvp.md).

---

*Cập nhật: 2026-09-02*
