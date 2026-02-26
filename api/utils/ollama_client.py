"""
Ollama LLM Integration using the official 'ollama' Python library.
Connects to the configured Ollama endpoint.
Settings are read from django.conf.settings:
  - OLLAMA_BASE_URL
  - LLM_MODEL
  - LLM_TEMPERATURE
  - LLM_MAX_TOKENS
"""

import json
import logging
import re
from typing import Optional, Dict, Any, Generator

from django.conf import settings
import ollama

logger = logging.getLogger(__name__)

# Read from Django settings with sensible defaults
OLLAMA_BASE_URL = getattr(settings, 'OLLAMA_BASE_URL', 'http://localhost:11434')
DEFAULT_MODEL = getattr(settings, 'LLM_MODEL', 'neural-chat')
LLM_TEMPERATURE = getattr(settings, 'LLM_TEMPERATURE', 0.3)
LLM_MAX_TOKENS = getattr(settings, 'LLM_MAX_TOKENS', 1800)

# Tool definitions for ShieldCall AI
TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "scan_phone",
            "description": "Scan a phone number for scam/risk reports.",
            "parameters": {
                "type": "object",
                "properties": {
                    "phone": {"type": "string", "description": "The phone number to scan"}
                },
                "required": ["phone"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_url",
            "description": "Scan a domain or URL for phishing/malware risk.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The domain or URL to scan"}
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_bank_account",
            "description": "Scan a bank account number for fraud reports.",
            "parameters": {
                "type": "object",
                "properties": {
                    "account_number": {"type": "string", "description": "The bank account number"},
                    "bank_name": {"type": "string", "description": "Optional bank name (e.g. MB, VCB)"}
                },
                "required": ["account_number"]
            }
        }
    }
]

# Initialize client
client = ollama.Client(host=OLLAMA_BASE_URL)

# Specialized logger for LLM traffic
llm_logger = logging.getLogger('pkv.llm')
llm_logger.setLevel(logging.INFO)
if not llm_logger.handlers:
    fh = logging.FileHandler('llm_access.log')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    llm_logger.addHandler(fh)

def _log_llm(prompt: str, response: str, system_prompt: str = None):
    """Detailed logging of LLM interactions"""
    log_data = {
        'system_prompt': system_prompt,
        'prompt_length': len(prompt),
        'prompt_preview': prompt[:200] + '...' if len(prompt) > 200 else prompt,
        'response_length': len(response) if response else 0,
        'response_preview': response[:200] + '...' if response else ""
    }
    llm_logger.info(f"LLM Call: {json.dumps(log_data, ensure_ascii=False)}")

def filter_thinking(text: str) -> str:
    """
    Removes <think>...</think> blocks from model responses.
    Used for reasoning-capable models like DeepSeek.
    """
    if not text:
        return ""
    # Remove content between <think> and </think> tags
    return re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL).strip()

def is_ollama_available() -> bool:
    """Check if Ollama service is running."""
    try:
        client.list()
        return True
    except Exception as e:
        logger.warning(f"Ollama not available: {e}")
        return False

def get_available_models() -> list:
    """Get list of available models in Ollama."""
    try:
        models = client.list()
        return [m['name'] for m in models['models']]
    except Exception as e:
        logger.error(f"Error getting Ollama models: {e}")
    return []

def generate_response(prompt: str, model: str = None, system_prompt: str = None) -> Optional[str]:
    """
    Generate a non-streamed response from Ollama.
    """
    model = model or DEFAULT_MODEL
    try:
        messages = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': prompt})

        response = client.chat(
            model=model,
            messages=messages,
            options={
                'temperature': LLM_TEMPERATURE,
                'num_predict': LLM_MAX_TOKENS,
            }
        )
        
        reply = response['message']['content']
        filtered_reply = filter_thinking(reply)
        _log_llm(prompt, filtered_reply, system_prompt)
        return filtered_reply

    except Exception as e:
        logger.error(f"Error calling Ollama: {e}")
        return None

def stream_response(prompt: str, system_prompt: str = None, model: str = None) -> Generator[str, None, None]:
    """
    Stream a response from Ollama, filtering out <think> blocks in real-time.
    """
    model = model or DEFAULT_MODEL
    messages = []
    if system_prompt:
        messages.append({'role': 'system', 'content': system_prompt})
    messages.append({'role': 'user', 'content': prompt})

    try:
        stream = client.chat(
            model=model,
            messages=messages,
            options={
                'temperature': LLM_TEMPERATURE,
                'num_predict': LLM_MAX_TOKENS,
            },
            stream=True
        )

        is_thinking = False
        full_response = []
        think_buffer = ""

        for chunk in stream:
            content = chunk['message']['content']
            if not content:
                continue

            if not is_thinking:
                if "<think>" in content:
                    is_thinking = True
                    yield "__STATUS__:thinking"
                    parts = content.split("<think>", 1)
                    if parts[0]:
                        yield parts[0]
                        full_response.append(parts[0])
                    if "</think>" in parts[1]:
                        is_thinking = False
                        subparts = parts[1].split("</think>", 1)
                        if subparts[1]:
                            yield subparts[1]
                            full_response.append(subparts[1])
                    continue
                else:
                    yield content
                    full_response.append(content)
            else:
                if "</think>" in content:
                    is_thinking = False
                    parts = content.split("</think>", 1)
                    if len(parts) > 1 and parts[1]:
                        yield parts[1]
                        full_response.append(parts[1])
                else:
                    # Optional: periodically yield thinking status to keep connection alive
                    if len(full_response) % 20 == 0:
                        yield "__STATUS__:thinking"

        _log_llm(prompt, "".join(full_response), system_prompt)

    except Exception as e:
        logger.error(f"Error in Ollama stream: {e}")
        yield f"Lỗi kết nối AI: {str(e)}"

def stream_chat(messages: list, model: str = None, use_tools: bool = False) -> Generator[str, None, None]:
    """
    Stream a chat conversation with Ollama, using the same thinking filter.
    If use_tools is True, the model may return tool_calls.
    """
    model = model or DEFAULT_MODEL
    try:
        chat_params = {
            'model': model,
            'messages': messages,
            'options': {
                'temperature': LLM_TEMPERATURE,
                'num_predict': LLM_MAX_TOKENS,
            },
            'stream': True
        }
        if use_tools:
            chat_params['tools'] = TOOLS

        stream = client.chat(**chat_params)

        is_thinking = False
        full_response = []

        for chunk in stream:
            # Check for tool_calls in chunk
            msg = chunk.get('message', {})
            if msg.get('tool_calls'):
                yield f"__TOOL_CALLS__:{json.dumps(msg['tool_calls'])}"
                continue

            content = msg.get('content')
            if not content:
                continue

            if not is_thinking:
                if "<think>" in content:
                    is_thinking = True
                    yield "__STATUS__:thinking"
                    parts = content.split("<think>", 1)
                    if parts[0]:
                        yield parts[0]
                        full_response.append(parts[0])
                    if "</think>" in parts[1]:
                        is_thinking = False
                        subparts = parts[1].split("</think>", 1)
                        if subparts[1]:
                            yield subparts[1]
                            full_response.append(subparts[1])
                else:
                    yield content
                    full_response.append(content)
            else:
                if "</think>" in content:
                    is_thinking = False
                    parts = content.split("</think>", 1)
                    if len(parts) > 1 and parts[1]:
                        yield parts[1]
                        full_response.append(parts[1])
                else:
                    # Keep connection alive during thinking
                    yield "__STATUS__:thinking"

        _log_llm("Chat history...", "".join(full_response))

    except Exception as e:
        logger.error(f"Error in stream_chat: {e}")
        yield f"Error: {str(e)}"

def classify_message(message: str, model: str = None) -> Dict[str, Any]:
    """
    Classify a message and suggest actions.
    """
    prompt = f"""Classify this message and suggest an action if needed.
Response in PURE JSON format.
The JSON must have: classification (safe/suspicious/dangerous), suggested_action (NONE/BLOCK/REPORT), confidence (0-1).
Message: {message}"""

    response = generate_response(prompt, model)

    if response:
        try:
            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                json_str = match.group(0)
                json_str = re.sub(r'[\x00-\x1F\x7F]', '', json_str)
                return json.loads(json_str)
        except Exception as e:
            logger.warning(f"Could not parse classification response: {e}")

    return {
        "classification": "unknown",
        "suggested_action": "NONE",
        "confidence": 0.5,
    }

def analyze_text_for_scam(text: str, model: str = None) -> Dict[str, Any]:
    """
    Analyze text for potential scam indicators using Ollama.
    Forces JSON output from the model.
    """
    prompt = f"""Analyze the following text for scam/fraud indicators. 
Response in PURE JSON format.
The JSON must have: is_scam (true/false), risk_score (0-100), indicators (list of strings), explanation (string).
Text to analyze: {text}"""

    # We use generate_response which now filters thinking
    response = generate_response(prompt, model)
    
    if response:
        try:
            # Try to find JSON in the response
            match = re.search(r'\{.*\}', response, re.DOTALL)
            if match:
                json_str = match.group(0)
                # Clean control characters
                json_str = re.sub(r'[\x00-\x1F\x7F]', ' ', json_str)
                return json.loads(json_str)
        except Exception as e:
            logger.warning(f"Could not parse Ollama response as JSON: {e}. Raw: {response[:100]}")

    return {
        "is_scam": False,
        "risk_score": 0,
        "indicators": [],
        "explanation": "Analysis failed or timed out",
    }
