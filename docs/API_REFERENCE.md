# ShieldCall VN — API Reference

> **Status:** current · **Updated:** 2026-11-16 · **Audience:** API integrators, frontend/backend engineers

Base URL: `/api/v1` (Production: `https://<your-domain>/api/v1`)

## Endpoints

> Bảng dưới đây liệt kê các endpoint ổn định, dùng nhiều nhất. Danh sách đầy đủ (kể cả endpoint
> quản trị, forum, thông báo, học tập) nằm trong OpenAPI schema `/api/schema/` và Swagger UI.
> Khi thêm route mới, cập nhật cả bảng này và `drf_spectacular`.

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
| `/scan/status/<scan_id>/` | `GET` | Asynchronous scan status and result retrieval | Session / Auth / `scan_token` |
| `/scan/<scan_id>/report-admin/` | `POST` | Request administrator verification for scan verdict | Authenticated |
| `/scan/analyze/stream/` | `POST` | Server-Sent Events (SSE) stream for scan events | Turnstile / Session / Token |
| `/chat/stream/` | `POST` | Server-Sent Events (SSE) AI assistant stream | Session / Token |
| `/chat/sessions/` | `GET`, `POST` | Manage chat conversation history sessions | Session / Token |
| `/trust/sources/` | `GET` | Source reliability catalog, limits, and verification dates | Public |
| `/trust/channels/` | `GET` | Official Vietnamese verification channels | Public |
| `/trust/storage/` | `GET` | Object storage / S3 telemetry | Public |
| `/health/` | `GET` | Service health probe for uptime monitors | Public |
| `/notifications/` | `GET` | Authenticated user notification feed | Authenticated |
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
| `/auth/me/` | `GET` | Retrieve current authenticated user profile (no token in body) | Session / API Key |

## Pagination

List endpoints accept `?page=<n>&page_size=<n>` (max 200) and return:

```json
{
  "results": [],
  "count": 0,
  "page": 1,
  "page_size": 50,
  "pages": 1,
  "next": null,
  "previous": null
}
```

`page_size` and `limit` are accepted where the endpoint historically used `limit`.

## Authentication model

- Web browser: Django session cookie (`HttpOnly`, `SameSite=Lax`) + CSRF token. The frontend no
  longer stores a DRF token in `localStorage`, and `/auth/me/` does not return one.
- API clients/mobile: API keys (`/user/api-keys/`) or legacy `Authorization: Token ...`.
- Logging out one browser session does not revoke tokens belonging to other devices.

## Error envelope

DRF errors use:

```json
{"error": "Mô tả lỗi", "code": "VALIDATION_ERROR", "details": {"field": ["..."]}}
```

`code` is stable (`AUTH_REQUIRED`, `PERMISSION_DENIED`, `NOT_FOUND`, `RATE_LIMITED`, …);
`details` is only present for field/validation errors. Manual view responses keep the
same top-level `error` string so existing clients do not break.

## Scan access token

Every scan creation endpoint returns both `scan_id` and a signed `scan_token`. The token lets
token-only/mobile clients (or a Next.js deployment without session cookies) access the result:

- `GET /scan/status/<id>/?scan_token=<token>` or header `X-Scan-Token: <token>`
- `POST /scan/analyze-sse/` body `{"scan_id": ..., "scan_token": ...}`
- `POST /scan/<id>/report-admin/` body `{"scan_token": ...}`
- WebSocket `/ws/scan/<id>/?scan_token=<token>`

Tokens are bound to one scan id and expire after `SCAN_TOKEN_MAX_AGE` (default 24h). Session
ownership and `is_public_referable` remain supported as fallbacks.

## Streaming (SSE) event protocol

Các endpoint stream dùng chung giao thức: mỗi dòng `data:` là **một JSON có trường `type`**.

| `type` | Payload | Ý nghĩa |
| :--- | :--- | :--- |
| `status` | `{"value":"searching_knowledge"\|"thinking"\|"answering"\|"processing_images"\|"executing_tool:<tool>"}` | Trạng thái đang xử lý |
| `thinking` | `{"text":"..."}` | Nội dung suy luận (hiển thị trong khối "Đã suy nghĩ") |
| `delta` | `{"text":"..."}` | Một mẩu nội dung trả lời |
| `metadata` | `{"metadata":{"internal_knowledge":[...],"web_search":[...]}}` | Nguồn tham khảo (RAG / web) |
| `tool_calls` | `{"calls":[{"function":{"name":"scan_url","arguments":{...}}}]}` | AI bắt đầu gọi công cụ |
| `tool_result` | `{"tool":"scan_url","status":"done","args":{...},"result":{...}}` | Kết quả công cụ |
| `image` | `{"annotated_image":"data:image/png;base64,..."}` | Ảnh OCR đã khoanh vùng |
| `title` | `{"value":"..."}` | Tiêu đề phiên vừa được sinh tự động |
| `error` | `{"message":"..."}` | Lỗi (hiển thị toast, luồng vẫn kết thúc bằng `done`) |
| `done` | `{"session_id":"...","title":"...","action_suggested":"NONE"}` | Kết thúc luồng |

Ví dụ:

```text
data: {"type":"status","value":"searching_knowledge"}

data: {"type":"metadata","metadata":{"internal_knowledge":[{"title":"...","url":"..."}]}}

data: {"type":"delta","text":"Số điện thoại này "}

data: {"type":"done","session_id":"...","title":"Tra cứu SĐT","action_suggested":"NONE"}
```

- **Endpoints:** `POST /chat/stream/` (Trợ lý AI, chat box, Emergency), `POST /scan/analyze-sse/`
  và `POST /scan/analyze/stream/` (chỉ phát `delta` / `error` / `done`).
- **Turnstile:** anonymous `POST /scan/analyze-sse/` without a valid owned/public `scan_id`
  requires `cf-turnstile-response`; authenticated users and API keys are exempt. When `scan_id`
  is supplied, the server ignores client-provided `scan_data` and reads the stored record.
- **Client:** dùng `openSseStream()` trong `frontend/src/lib/chat/stream.ts`; callback `onEvent`
  nhận union `StreamEvent` đã chuẩn hoá. Payload không có trường `type` (hoặc type lạ) bị bỏ qua,
  nên backend phải phát đúng các event trong bảng trên.
- **Nội bộ:** tầng vận chuyển LLM (`api/utils/ollama_client.stream_chat_ai`) dùng marker chuỗi
  (`__THINK__`, `__TOOL_CALLS__`, …). `AIAgent.chat_stream` là ranh giới chuyển marker thành event
  có `type`; **marker không bao giờ ra tới client**.

## Interactive Documentation

- **Swagger UI**: `/api/docs/` (or `https://<your-domain>/api/docs/`)
- **ReDoc**: `/api/redoc/` (or `https://<your-domain>/api/redoc/`)
- **OpenAPI Schema**: `/api/schema/` (or `https://<your-domain>/api/schema/`)
