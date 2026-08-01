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

### 3.2 Streaming Chat (SSE)
Used for real-time text generation.

- **URL:** `/chat-ai-stream`
- **Method:** `POST`
- **Body:** Same as 3.1
- **Response:** `text/event-stream` or raw chunks. Each line should contain a portion of the AI response.

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
