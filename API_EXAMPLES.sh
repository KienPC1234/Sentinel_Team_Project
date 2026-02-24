#!/bin/bash
# ShieldCall VN Backend API - cURL Command Examples

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

API_URL="http://localhost:8001"

echo -e "${BLUE}=== ShieldCall VN API Command Examples ===${NC}\n"

# Function to display commands
run_command() {
    local description="$1"
    local command="$2"
    echo -e "${GREEN}$description${NC}"
    echo "Command:"
    echo "$command"
    echo ""
    echo "Running..."
    eval "$command"
    echo ""
    echo "---"
    echo ""
}

# 1. Get a new session
echo -e "${BLUE}1. SESSION MANAGEMENT${NC}\n"

run_command "Get a new session (invalid UUID returns new session)" \
    "curl -s '${API_URL}/check-session?session_id=00000000-0000-0000-0000-000000000000' | python3 -m json.tool"

# Get the session ID from the previous response and store it
SESSION_ID=$(curl -s "${API_URL}/check-session?session_id=00000000-0000-0000-0000-000000000000" | python3 -c "import sys, json; print(json.load(sys.stdin)['new_session_id'])")

run_command "Check if session is valid" \
    "curl -s '${API_URL}/check-session?session_id=${SESSION_ID}' | python3 -m json.tool"

# 2. Phone Security
echo -e "${BLUE}2. PHONE SECURITY${NC}\n"

run_command "Check phone number safety" \
    "curl -s '${API_URL}/check-phone?phone=0912345678' | python3 -m json.tool"

run_command "Check phone with international format" \
    "curl -s '${API_URL}/check-phone?phone=%2B84912345678' | python3 -m json.tool"

# 3. AI Chat
echo -e "${BLUE}3. AI CHAT${NC}\n"

run_command "Chat with AI - Ask about message" \
    "curl -s -X POST ${API_URL}/chat-ai \
    -H 'Content-Type: application/json' \
    -d '{
      \"user_message\": \"Tin nhắn này lừa đảo không?\",
      \"session_id\": \"${SESSION_ID}\",
      \"context\": \"general\"
    }' | python3 -m json.tool"

run_command "Chat with AI - Scam context" \
    "curl -s -X POST ${API_URL}/chat-ai \
    -H 'Content-Type: application/json' \
    -d '{
      \"user_message\": \"Ngân hàng yêu cầu tôi cung cấp thông tin tài khoản\",
      \"session_id\": \"${SESSION_ID}\",
      \"context\": \"scam\"
    }' | python3 -m json.tool"

# 4. Crash Reporting
echo -e "${BLUE}4. CRASH REPORTING${NC}\n"

run_command "Report a crash from mobile device" \
    "curl -s -X POST ${API_URL}/report-crash \
    -H 'Content-Type: application/json' \
    -d '{
      \"device_info\": \"Samsung SM-G991B (SDK 34)\",
      \"stack_trace\": \"java.lang.NullPointerException: Attempt to invoke virtual method on null object reference\",
      \"timestamp\": 1706450000000,
      \"version\": \"1.0.0\",
      \"severity\": \"ERROR\"
    }' | python3 -m json.tool"

echo -e "${GREEN}=== Examples Complete ===${NC}"
echo ""
echo "Note: Replace ${SESSION_ID} with actual session IDs when testing manually"
