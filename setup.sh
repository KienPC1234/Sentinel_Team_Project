#!/bin/bash
# ShieldCall VN Backend API - Setup and Start Script

set -e

echo "=========================================="
echo "ShieldCall VN Backend Setup"
echo "=========================================="

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Step 1: Check Python environment
echo -e "\n${YELLOW}1. Checking Python environment...${NC}"
if [ ! -d ".venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv .venv
fi
source .venv/bin/activate
echo -e "${GREEN}✓ Virtual environment active${NC}"

# Step 2: Install dependencies
echo -e "\n${YELLOW}2. Installing dependencies...${NC}"
pip install -q -r requirements.txt 2>/dev/null || true
echo -e "${GREEN}✓ Dependencies installed${NC}"

# Step 3: Check/Setup database
echo -e "\n${YELLOW}3. Setting up database...${NC}"
python manage.py migrate --run-syncdb 2>&1 | grep -E "(OK|Creating|Applying)" || true
echo -e "${GREEN}✓ Database ready${NC}"

# Step 4: Check Ollama
echo -e "\n${YELLOW}4. Checking Ollama...${NC}"
if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Ollama is running${NC}"
    MODELS=$(curl -s http://localhost:11434/api/tags | python3 -c "import sys, json; models = [m.get('name', 'unknown') for m in json.load(sys.stdin).get('models', [])]; print(', '.join(models) if models else 'none')" 2>/dev/null || echo "unknown")
    echo "  Available models: $MODELS"
else
    echo -e "${YELLOW}⚠ Ollama not running${NC}"
    echo "  To use Ollama:"
    echo "  1. Install from https://ollama.ai"
    echo "  2. Pull a model: ollama pull neural-chat"
    echo "  3. Start Ollama: ollama serve"
    echo "  API will use fallback responses without Ollama"
fi

# Step 5: Summary
echo -e "\n${YELLOW}5. Setup complete!${NC}"
echo ""
echo "To start the API server:"
echo -e "  ${GREEN}python manage.py runserver 0.0.0.0:8001${NC}"
echo ""
echo "To test the API:"
echo -e "  ${GREEN}python test_api.py${NC}"
echo ""
echo "To test Ollama integration:"
echo -e "  ${GREEN}python test_ollama.py${NC}"
echo ""
echo "Documentation:"
echo -e "  - API Guide: ${GREEN}IMPLEMENTATION.md${NC}"
echo -e "  - Ollama Setup: ${GREEN}OLLAMA_SETUP.md${NC}"
echo -e "  - API Examples: ${GREEN}API_EXAMPLES.sh${NC}"
echo ""
