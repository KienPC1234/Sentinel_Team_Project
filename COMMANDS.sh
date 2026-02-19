#!/bin/bash
# ShieldCall VN Backend - Quick Reference Commands

echo "=== ShieldCall VN Backend - Command Cheat Sheet ==="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "📋 SETUP COMMANDS"
echo "================="
echo "1. Install dependencies:"
echo "   pip install -r requirements.txt"
echo ""
echo "2. Setup database:"
echo "   python manage.py makemigrations"
echo "   python manage.py migrate"
echo ""
echo "3. Create admin user:"
echo "   python manage.py createsuperuser"
echo ""

echo "🚀 START SERVICES"
echo "================="
echo "1. Start Ollama (in separate terminal):"
echo "   ollama serve"
echo ""
echo "2. Pull Ollama model (first time only):"
echo "   ollama pull neural-chat"
echo ""
echo "3. Start API server:"
echo "   python manage.py runserver 0.0.0.0:8001"
echo ""

echo "🧪 TESTING"
echo "=========="
echo "1. Test Ollama integration:"
echo "   python test_ollama.py"
echo ""
echo "2. Test API endpoints:"
echo "   python test_api.py"
echo ""

echo "📡 API ENDPOINTS"
echo "================"
echo "Session: GET /check-session?session_id=UUID"
echo "Phone:   GET /check-phone?phone=0912345678"
echo "Chat:    POST /chat-ai"
echo "Stream:  POST /chat-ai-stream"
echo "Images:  POST /analyze-images"
echo "Audio:   POST /analyze-audio"
echo "Crash:   POST /report-crash"
echo ""

echo "📚 DOCUMENTATION"
echo "================"
echo "Main documentation:"
echo "  • IMPLEMENTATION_SUMMARY.md - Project overview"
echo "  • IMPLEMENTATION.md - Detailed implementation"
echo "  • OLLAMA_INTEGRATION.md - Ollama integration guide"
echo "  • OLLAMA_SETUP.md - Ollama setup instructions"
echo "  • API_EXAMPLES.sh - cURL examples"
echo ""

echo "Check Ollama Status:"
echo "  curl http://localhost:11434/api/tags | python3 -m json.tool"
echo ""

echo "View API logs:"
echo "  python manage.py runserver --verbosity 2"
echo ""

echo "For more info, see: OLLAMA_INTEGRATION.md"
