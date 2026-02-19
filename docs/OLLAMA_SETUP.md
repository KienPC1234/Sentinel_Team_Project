# ShieldCall VN Backend API - Ollama Integration Guide

This guide explains how to set up and use Ollama AI integration with the ShieldCall VN Backend API.

## What is Ollama?

Ollama is a tool for running large language models (LLMs) locally on your machine. It's perfect for:
- Privacy-preserving AI (no data sent to external servers)
- Fast inference with local models
- Cost-effective AI integration
- Easy model management

## Installation

### 1. Download and Install Ollama
- Visit: https://ollama.ai
- Download the installer for your OS
- Run the installer and follow instructions

### 2. Pull a Model
Open terminal and run:
```bash
# Neural Chat (recommended for Vietnamese - lightweight)
ollama pull neural-chat

# Alternative models:
ollama pull llama2          # General purpose, larger
ollama pull mistral         # Fast and capable
ollama pull dolphin-mixtral # Advanced reasoning
ollama pull openchat        # Fast alternative
```

### 3. Start Ollama Service
```bash
# Ollama starts as a background service automatically after installation
# To verify it's running:
curl http://localhost:11434/api/tags

# Or on Windows, look for Ollama in system tray
```

## Configuration

### Environment Variables (Optional)

Add to `.env` file:
```
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=neural-chat
OLLAMA_TIMEOUT=60
```

### Python Configuration

The default settings are in `api/utils/ollama_client.py`:
```python
OLLAMA_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "neural-chat"  # Change to your preferred model
TIMEOUT = 60  # seconds
```

To change the default model, edit `ollama_client.py`:
```python
DEFAULT_MODEL = "mistral"  # or any model you've pulled
```

## Integration Points

### 1. Chat AI Endpoints
**Files:** `api/ai_chat/views.py`

The `/chat-ai` and `/chat-ai-stream` endpoints now use Ollama when available:
- If Ollama is running: Uses real AI responses from your local model
- If Ollama is down: Falls back to mock responses automatically

```python
# Automatic fallback logic
if is_ollama_available():
    response = generate_response(prompt)
else:
    response = mock_response
```

### 2. Image Analysis
**Files:** `api/utils/media_utils.py`

The image risk analysis uses Ollama to understand OCR text:
- Analyzes extracted text for scam indicators
- Provides risk scoring based on AI analysis
- Falls back to keyword matching if Ollama unavailable

### 3. Audio Analysis
**Files:** `api/utils/media_utils.py`

Audio transcripts are analyzed by Ollama:
- Detects scam patterns in call recordings
- Provides risk scores and warning messages
- Supports Vietnamese language natively

## API Endpoints

### Check Ollama Status
```bash
curl http://localhost:11434/api/tags
```

### Get Available Models
```bash
curl http://localhost:11434/api/tags | python3 -m json.tool
```

### Generate Text
```bash
curl -X POST http://localhost:11434/api/generate \
  -H "Content-Type: application/json" \
  -d '{
    "model": "neural-chat",
    "prompt": "Xin chào",
    "stream": false
  }'
```

## Testing Integration

### 1. Check Ollama Connection
```bash
# In Python
python3 << 'EOF'
from api.utils.ollama_client import is_ollama_available, get_available_models

print("Ollama available:", is_ollama_available())
print("Models:", get_available_models())
EOF
```

### 2. Test Chat API with Ollama
```bash
# Generate a session ID
SESSION_ID=$(curl -s "http://localhost:8001/check-session?session_id=00000000-0000-0000-0000-000000000000" | python3 -c "import sys, json; print(json.load(sys.stdin)['new_session_id'])")

# Send a message
curl -X POST http://localhost:8001/chat-ai \
  -H "Content-Type: application/json" \
  -d "{
    \"user_message\": \"Xin chào, tin nhắn này có phải lừa đảo không?\",
    \"session_id\": \"$SESSION_ID\",
    \"context\": \"general\"
  }"
```

### 3. Run Test Suite
```bash
python test_api.py
```

The tests will work whether Ollama is running or not, using fallback responses.

## Model Selection Guide

### For Vietnamese Support
```
✅ neural-chat    - Best balance (lightweight, Vietnamese support)
✅ mistral        - Fast and capable
⚠️ llama2         - Good but larger (7B+)
⚠️ dolphin-mixtral - Advanced but resource-heavy
```

### Performance Comparison

| Model | Size | Speed | Quality |
|-------|------|-------|---------|
| neural-chat | 7.4B | Fast | Good |
| mistral | 7B | Very Fast | Good |
| llama2 | 7B/13B/70B | Medium | Excellent |
| dolphin-mixtral | 12B/46.7B | Slow | Excellent |
| openchat | 7B | Very Fast | Good |

### Memory Requirements
- 2GB minimum for 7B models
- 4GB recommended for good performance
- 8GB+ for 13B models
- 16GB+ for larger models

## Troubleshooting

### 1. Ollama not responding
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Restart Ollama service
# On macOS/Linux:
pkill ollama
ollama serve

# On Windows: Restart the Ollama application
```

### 2. Model not found
```bash
# List available models
ollama list

# Pull missing model
ollama pull neural-chat
```

### 3. Timeout errors
Increase `TIMEOUT` in `api/utils/ollama_client.py`:
```python
TIMEOUT = 120  # 2 minutes instead of 1 minute
```

### 4. Memory issues
Use a smaller model:
```bash
ollama pull mistral  # Lighter than neural-chat
```

## Advanced Usage

### 1. Custom Prompts
Edit the prompts in `api/ai_chat/views.py`:
```python
prompt = f"""Custom prompt for Vietnamese scam detection:
{user_message}
Analyze and provide risk assessment."""
```

### 2. Multiple Models
Pin specific models for different tasks:
```python
# In api/utils/ollama_client.py
CHAT_MODEL = "neural-chat"
ANALYSIS_MODEL = "mistral"
```

### 3. Streaming Responses
Already implemented in `/chat-ai-stream` endpoint:
```python
def stream_response(prompt):
    # Streams text chunks as model generates them
    yield from stream_response(prompt, model)
```

## Performance Notes

- **First request:** May take 10-30 seconds (model loading)
- **Subsequent requests:** Usually 2-5 seconds depending on model
- **Streaming:** Chunks arrive in real-time for better UX
- **Caching:** Chat history cached in Redis for context

## Next Steps

1. **Install Ollama** from https://ollama.ai
2. **Pull a model:** `ollama pull neural-chat`
3. **Start Ollama:** It runs in background
4. **Test integration:** `python3 test_api.py`
5. **Adjust model:** Update `DEFAULT_MODEL` in `ollama_client.py`

## Environment Setup Example

```bash
# 1. Install Ollama (from website)

# 2. Pull model
ollama pull neural-chat

# 3. Start Ollama (runs in background)
ollama serve &

# 4. Verify setup
curl http://localhost:11434/api/tags

# 5. Test Django API
cd /data/PKV_TEAM
source .venv/bin/activate
python manage.py runserver 0.0.0.0:8001

# 6. In another terminal, test API
python test_api.py
```

## References

- Ollama Documentation: https://github.com/ollama/ollama
- Available Models: https://ollama.ai/library
- API Reference: https://github.com/ollama/ollama/blob/main/docs/api.md

## Support

If you encounter issues:
1. Check Ollama is running: `curl http://localhost:11434/api/tags`
2. Check Django logs: `python manage.py runserver --verbosity=2`
3. Review model specs: `ollama list`
4. Try a smaller model if performance is slow
