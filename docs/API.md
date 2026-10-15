# ShieldCall VN Backend API Specification

This document provides the technical details for implementing the backend services required by the ShieldCall VN Android application.

**Base URL:** `http://<your-server-ip>:3000`

---

## 1. Session Management

### 1.1 Check Session Status
Verifies if a session ID is still valid on the server and provides a new one if it has expired.

- **URL:** `/check-session`
- **Method:** `GET`
- **Query Params:**
    - `session_id` (string): The current UUID session ID.
- **Success Response (200 OK):**
```json
{
  "is_valid": true,
  "new_session_id": null 
}
```
- **Expired/Invalid Response (200 OK):**
```json
{
  "is_valid": false,
  "new_session_id": "new-uuid-v4-string"
}
```

---

## 2. Phone Security

### 2.1 Check Phone Number
Used to determine the risk level of an incoming call.

- **URL:** `/check-phone`
- **Method:** `GET`
- **Query Params:**
    - `phone` (string): The E.164 or local format phone number.
- **Success Response (200 OK):**
```json
{
  "risk_level": "RED", // Options: "SAFE", "GREEN", "YELLOW", "RED"
  "risk_label": "Cảnh báo: Giả mạo Công An",
  "recommendations": [
    "Tuyệt đối không nghe máy",
    "Không cung cấp thông tin cá nhân"
  ]
}
```

---

## 3. AI Assistant (Chat)

### 3.1 Standard Chat
- **URL:** `/chat-ai`
- **Method:** `POST`
- **Body:**
```json
{
  "user_message": "Tin nhắn này lừa đảo không?",
  "session_id": "uuid-v4-string",
  "context": "general"
}
```
- **Response:**
```json
{
  "ai_response": "Đây là tin nhắn lừa đảo...",
  "action_suggested": "BLOCK" // Optional: "NONE", "BLOCK", "REPORT"
}
```

### 3.2 Streaming Chat (SSE) — giao thức event có `type`

- **URL:** `POST /api/v1/chat/stream/`
- **Body:**
```json
{
  "user_message": "Kiểm tra SĐT 0373821456",
  "session_id": "uuid-v4 | null",
  "images": ["data:image/png;base64,..."],
  "preview_ocr": false,
  "safe_mode": false,
  "scan_context": ""
}
```
- **Response:** `text/event-stream`. Mỗi dòng `data:` là **một JSON có `type`**:

| `type` | Payload | Ý nghĩa |
|---|---|---|
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
```
data: {"type":"status","value":"searching_knowledge"}

data: {"type":"metadata","metadata":{"internal_knowledge":[{"title":"...","url":"..."}]}}

data: {"type":"delta","text":"Số điện thoại này "}

data: {"type":"done","session_id":"...","title":"Tra cứu SĐT","action_suggested":"NONE"}
```

- **Client:** dùng `openSseStream()` trong `frontend/src/lib/chat/stream.ts`; callback `onEvent` nhận union `StreamEvent` đã chuẩn hoá. Hàm `normalizeStreamEvent()` vẫn map được payload cũ (`{"chunk": ...}`) nên endpoint nào chưa chuyển cũng chạy được.
- **Endpoints cùng giao thức:** `POST /api/v1/chat/stream/` (Trợ lý AI + chat box + Emergency), `POST /api/v1/scan/analyze-sse/` và `/scan/analyze/stream/` (chỉ phát `delta`/`error`/`done`).

> Ghi chú nội bộ: tầng vận chuyển LLM (`api/utils/ollama_client.stream_chat_ai`) vẫn dùng marker chuỗi nội bộ (`__THINK__`, `__TOOL_CALLS__`, …). `AIAgent.chat_stream` là ranh giới chuyển chúng thành event có `type`; **marker không bao giờ ra tới client**.


---

## 4. Media Analysis

### 4.1 Analyze Multiple Images (OCR & Risk)
Handles one or more images selected by the user or captured from the screen.

- **URL:** `/analyze-images`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`
- **Form Data:**
    - `images`: Array of Files (binary, .jpg/.png)
- **Response:**
```json
{
  "ocr_text": "Số tài khoản: 123456789...",
  "risk_analysis": {
    "is_safe": false,
    "risk_level": "YELLOW",
    "details": "Ảnh chứa thông tin chuyển khoản ngân hàng đáng ngờ."
  }
}
```

### 4.2 Analyze Audio (Speech-to-Text & Risk)
Analyzes recorded call audio.

- **URL:** `/analyze-audio`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`
- **Form Data:**
    - `audio`: File (binary, .mp3/.m4a)
    - `phone_number`: String (e.g., "0912345678")
- **Response:**
```json
{
  "risk_score": 85,
  "is_scam": true,
  "transcript": "Yêu cầu anh chuyển tiền vào tài khoản tạm giữ...",
  "warning_message": "Phát hiện kịch bản lừa đảo mạo danh cơ quan điều tra."
}
```

---

## 5. Maintenance & Quality

### 5.1 Report Crash
Submits crash logs from the device when debug mode is disabled.

- **URL:** `/report-crash`
- **Method:** `POST`
- **Body:**
```json
{
  "device_info": "Samsung SM-G991B (SDK 34)",
  "stack_trace": "java.lang.NullPointerException...",
  "timestamp": 1706450000000
}
```
- **Response (200 OK):**
```json
{ "status": "success" }
```

---

## Technical Implementation Notes for Backend:
1. **Multipart Data:** Ensure the server correctly handles multiple files with the same key name (`images`) for the `/analyze-images` endpoint.
2. **Session Persistence:** Store session context (history) in a fast cache like Redis, keyed by `session_id`.
3. **OCR Engine:** It is recommended to use Tesseract or Google Vision API for high-quality OCR.
4. **NLP:** Use a LLM (like GPT-4 or Gemini) to analyze transcripts and OCR text for scam patterns.
