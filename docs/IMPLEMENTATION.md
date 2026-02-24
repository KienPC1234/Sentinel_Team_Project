# ShieldCall VN Backend API - Implementation Guide

This document describes the complete implementation of the ShieldCall VN Backend API as specified in [API.md](API.md).

## Project Structure

```
api/
├── sessions_api/          # Session management endpoints
├── phone_security/        # Phone number risk checking
├── ai_chat/              # AI chat and streaming endpoints
├── media_analysis/       # Image OCR and audio transcription
├── maintenance/          # Crash reporting and error logging
└── utils/                # Utility functions
```

## Implemented Endpoints

### 1. Session Management

**Base Path:** `/`

#### Check Session Status
- **URL:** `/check-session`
- **Method:** `GET`
- **Query Params:**
  - `session_id` (string): UUID of the session
- **Response (200 OK):**
```json
{
  "is_valid": true,
  "new_session_id": null
}
```

**Features:**
- Validates session UUIDs
- Expires sessions after 24 hours of inactivity
- Creates new sessions automatically for expired ones
- Session data cached in Redis

**Database Model:** `UserSession`
- `session_id` (UUID): Primary key
- `is_active` (Boolean)
- `created_at`, `last_accessed` (Timestamps)

---

### 2. Phone Security

**Base Path:** `/`

#### Check Phone Number Risk
- **URL:** `/check-phone`
- **Method:** `GET`
- **Query Params:**
  - `phone` (string): E.164 or local format phone number
- **Response (200 OK):**
```json
{
  "risk_level": "SAFE",
  "risk_label": "Số điện thoại chưa được báo cáo",
  "recommendations": []
}
```

**Features:**
- Normalizes phone numbers automatically
- Caches results for 1 hour
- Risk levels: SAFE, GREEN, YELLOW, RED
- Returns recommendations for high-risk numbers

**Database Models:**
- `PhoneNumber`: Stores risk information
- `PhoneReport`: User reports for numbers

---

### 3. AI Assistant (Chat)

**Base Path:** `/`

#### Standard Chat
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
- **Response (200 OK):**
```json
{
  "ai_response": "Phân tích tin nhắn...",
  "action_suggested": "BLOCK"
}
```

#### Streaming Chat
- **URL:** `/chat-ai-stream`
- **Method:** `POST`
- **Body:** Same as standard chat
- **Response:** Server-Sent Events (SSE)

**Features:**
- Stores conversation history in Redis
- Supports multiple contexts (general, scam, etc.)
- Suggests actions: NONE, BLOCK, REPORT
- Streaming response for real-time updates
- CSRF protection disabled for mobile clients

**Database Models:**
- `ChatMessage`: Stores user and AI messages
- `ChatAction`: Suggested actions with confidence scores

---

### 4. Media Analysis

**Base Path:** `/`

#### Analyze Images
- **URL:** `/analyze-images`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`
- **Form Data:**
  - `images`: Array of image files (JPG/PNG)
  - `session_id` (optional): UUID
- **Response (200 OK):**
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

#### Analyze Audio
- **URL:** `/analyze-audio`
- **Method:** `POST`
- **Content-Type:** `multipart/form-data`
- **Form Data:**
  - `audio`: Audio file (MP3/M4A/WAV/OGG)
  - `phone_number`: Phone number string
  - `session_id` (optional): UUID
- **Response (200 OK):**
```json
{
  "risk_score": 85,
  "is_scam": true,
  "transcript": "Yêu cầu anh chuyển tiền vào tài khoản tạm giữ...",
  "warning_message": "Phát hiện kịch bản lừa đảo mạo danh cơ quan điều tra."
}
```

**Features:**
- OCR text extraction (placeholder for Google Vision API)
- Audio transcription (placeholder for Cloud Speech-to-Text)
- Scam pattern detection
- Risk scoring algorithm
- Supports multiple image formats

**Database Models:**
- `ImageAnalysis`: Stores OCR and risk results
- `AudioAnalysis`: Stores transcripts and scam detection

---

### 5. Maintenance & Quality

**Base Path:** `/`

#### Report Crash
- **URL:** `/report-crash`
- **Method:** `POST`
- **Body:**
```json
{
  "device_info": "Samsung SM-G991B (SDK 34)",
  "stack_trace": "java.lang.NullPointerException...",
  "timestamp": 1706450000000,
  "version": "1.0.0",
  "os_version": "14.0",
  "severity": "ERROR"
}
```
- **Response (200 OK):**
```json
{
  "status": "success",
  "report_id": "uuid"
}
```

**Features:**
- Accepts crash logs from mobile devices
- Stores device and stack trace information
- Supports severity levels: CRITICAL, ERROR, WARNING
- Logs to error tracking system

**Database Models:**
- `CrashReport`: Stores crash information
- `ErrorLog`: General error logging

---

## Installation & Setup

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Environment Setup
Add these packages if not already in requirements.txt:
```bash
pip install pillow requests mysqlclient
```

### 3. Database Setup
```bash
python manage.py makemigrations
python manage.py migrate
```

### 4. Create Admin User (Optional)
```bash
python manage.py createsuperuser
```

### 5. Run Development Server
```bash
python manage.py runserver 0.0.0.0:8000
```

---

## Testing

Run the comprehensive test suite:
```bash
python test_api.py
```

This will test:
- Session management (create, validate, refresh)
- Phone security checks
- AI chat responses
- Crash reporting

---

## Configuration

### Django Settings
- **Database:** MySQL (configured in `PKV/settings.py`)
- **Cache:** Redis (for session and phone number caching)
- **Celery:** Redis (for async tasks)
- **Session Engine:** Redis cache backend

### Environment Variables (Recommended)
Create a `.env` file:
```
DEBUG=True
SECRET_KEY=your-secret-key
DB_HOST=localhost
DB_NAME=django_db
DB_USER=django_user
DB_PASSWORD=your-password
REDIS_URL=redis://127.0.0.1:6379/1
```

---

## Future Enhancements

### 1. LLM Integration
Replace mock responses in `api/ai_chat/views.py` with real API calls:
```python
# Use OpenAI GPT-4
from openai import OpenAI

# Or Google Gemini
from google.generativeai import GenerativeModel
```

### 2. Image Recognition
Replace placeholder in `api/utils/media_utils.py`:
```python
# Use Google Cloud Vision API
from google.cloud import vision

# Or Tesseract OCR
import pytesseract
```

### 3. Audio Processing
Implement real speech-to-text:
```python
# Use Google Cloud Speech-to-Text
from google.cloud import speech_v1

# Or OpenAI Whisper
import openai
```

### 4. Async Processing
Use Celery for long-running tasks:
```python
# api/tasks.py
from celery import shared_task

@shared_task
def analyze_image_async(session_id, image_path):
    # Long-running image analysis
    pass
```

### 5. Authentication & Rate Limiting
```python
# Add API key authentication
# Implement rate limiting per session
# Add IP-based restrictions
```

---

## API Error Codes

| Code | Error | Solution |
|------|-------|----------|
| 400 | Bad Request | Invalid parameters or malformed JSON |
| 404 | Not Found | Endpoint doesn't exist |
| 405 | Method Not Allowed | Wrong HTTP method |
| 500 | Internal Server Error | Server error - check logs |

---

## Performance Considerations

1. **Caching Strategy:**
   - Phone risk data cached for 1 hour
   - Session data persisted in Redis
   - Consider caching frequently analyzed patterns

2. **Database Optimization:**
   - Proper indexes on `session_id`, `phone_number`, `created_at`
   - Regular database cleanup of old sessions

3. **Async Processing:**
   - Heavy image/audio processing should use Celery
   - Consider queuing large batch requests

---

## Security Notes

- CSRF protection disabled for mobile API endpoints (`@csrf_exempt`)
- Session validation ensures data integrity
- Input validation on all endpoints
- Sensitive information stored securely

**Recommendations for Production:**
- Enable HTTPS only
- Implement API key authentication
- Add rate limiting
- Use environment variables for secrets
- Enable CORS properly
- Add request logging
- Implement error tracking (Sentry, etc.)

---

## Testing with cURL

### Session Check
```bash
curl "http://localhost:8001/check-session?session_id=<uuid>"
```

### Phone Check
```bash
curl "http://localhost:8001/check-phone?phone=0912345678"
```

### Chat AI
```bash
curl -X POST http://localhost:8001/chat-ai \
  -H "Content-Type: application/json" \
  -d '{
    "user_message": "Tin nhắn này lừa đảo không?",
    "session_id": "<uuid>",
    "context": "general"
  }'
```

### Report Crash
```bash
curl -X POST http://localhost:8001/report-crash \
  -H "Content-Type: application/json" \
  -d '{
    "device_info": "Samsung SM-G991B",
    "stack_trace": "Error trace...",
    "timestamp": 1706450000000
  }'
```

---

## Support & Updates

For updates or issues, refer to the original [API Specification](API.md).

Last Updated: February 2026
