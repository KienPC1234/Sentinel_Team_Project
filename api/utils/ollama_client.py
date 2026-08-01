"""
Ollama LLM Integration
Connects to the configured Ollama endpoint with API key authentication.
Settings are read from django.conf.settings:
  - OLLAMA_BASE_URL
  - OLLAMA_API_KEY
  - LLM_MODEL
  - LLM_TEMPERATURE
  - LLM_MAX_TOKENS
"""

import requests
import json
import logging
import re
from typing import Optional, Dict, Any

from django.conf import settings

logger = logging.getLogger(__name__)

# Read from Django settings with sensible defaults
OLLAMA_BASE_URL = getattr(settings, 'OLLAMA_BASE_URL', 'http://localhost:11434')
OLLAMA_API_KEY = getattr(settings, 'OLLAMA_API_KEY', '')
DEFAULT_MODEL = getattr(settings, 'LLM_MODEL', 'neural-chat')
LLM_TEMPERATURE = getattr(settings, 'LLM_TEMPERATURE', 0.3)
LLM_MAX_TOKENS = getattr(settings, 'LLM_MAX_TOKENS', 1800)
TIMEOUT = 60  # seconds

# Specialized logger for LLM traffic
llm_logger = logging.getLogger('pkv.llm')
llm_logger.setLevel(logging.INFO)
# Ensure file handler exists
if not llm_logger.handlers:
    fh = logging.FileHandler('llm_access.log')
    fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    llm_logger.addHandler(fh)

def _log_llm(prompt: str, response: str, system_prompt: str = None, images: list = None):
    """Detailed logging of LLM interactions"""
    log_data = {
        'system_prompt': system_prompt,
        'prompt_length': len(prompt),
        'prompt_preview': prompt[:200] + '...' if len(prompt) > 200 else prompt,
        'has_images': bool(images),
        'response_length': len(response) if response else 0,
        'response': response
    }
    llm_logger.info(f"LLM Call: {json.dumps(log_data, ensure_ascii=False)}")


def _headers() -> dict:
    """Build request headers with optional API key."""
    h = {'Content-Type': 'application/json'}
    if OLLAMA_API_KEY:
        h['Authorization'] = f'Bearer {OLLAMA_API_KEY}'
    return h


def is_ollama_available() -> bool:
    """Check if Ollama service is running."""
    try:
        response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            headers=_headers(),
            timeout=5,
        )
        return response.status_code == 200
    except Exception as e:
        logger.warning(f"Ollama not available: {e}")
        return False


def get_available_models() -> list:
    """Get list of available models in Ollama."""
    try:
        response = requests.get(
            f"{OLLAMA_BASE_URL}/api/tags",
            headers=_headers(),
            timeout=10,
        )
        if response.status_code == 200:
            data = response.json()
            return [model.get("name") for model in data.get("models", [])]
    except Exception as e:
        logger.error(f"Error getting Ollama models: {e}")
    return []


def generate_response(prompt: str, model: str = None) -> Optional[str]:
    """
    Generate a response from Ollama using the specified model.

    Args:
        prompt: The input prompt/message
        model: The model name (default: from settings)

    Returns:
        The generated response text, or None if error occurs
    """
    model = model or DEFAULT_MODEL

    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": LLM_TEMPERATURE,
                "num_predict": LLM_MAX_TOKENS,
            },
        }

        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json=payload,
            headers=_headers(),
            timeout=TIMEOUT,
        )

        if response.status_code == 200:
            result = response.json()
            reply = result.get("response", "").strip()
            _log_llm(prompt, reply)
            return reply
        else:
            logger.error(f"Ollama error: {response.status_code} - {response.text}")
            return None

    except requests.exceptions.Timeout:
        logger.error(f"Ollama request timeout after {TIMEOUT}s")
        return None
    except Exception as e:
        logger.error(f"Error calling Ollama: {e}")
        return None


def stream_chat(messages: list, model: str = None):
    """
    Stream a chat conversation with Ollama.
    Yields chunks of text.
    """
    model = model or DEFAULT_MODEL
    try:
        payload = {
            "model": model,
            "messages": messages,
            "stream": True,
            "options": {
                "temperature": LLM_TEMPERATURE,
                "num_predict": LLM_MAX_TOKENS,
            },
        }
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/chat",
            json=payload,
            headers=_headers(),
            timeout=TIMEOUT,
            stream=True,
        )
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        if "message" in data:
                            chunk = data["message"].get("content", "")
                            if chunk:
                                yield chunk
                        elif "response" in data: # Fallback for non-chat endpoint
                             yield data.get("response", "")
                    except Exception:
                        continue
        else:
            yield f"Error: {response.status_code}"
    except Exception as e:
        yield f"Error: {str(e)}"


def stream_response(prompt: str, system_prompt: str = None, images: list = None, model: str = None):
    """
    Stream a single prompt response from Ollama.
    Yields chunks of text.
    """
    model = model or DEFAULT_MODEL
    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "system": system_prompt,
            "images": images,
            "stream": True,
            "options": {
                "temperature": LLM_TEMPERATURE,
                "num_predict": LLM_MAX_TOKENS,
            },
        }
        
        full_reply = []
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json=payload,
            headers=_headers(),
            timeout=TIMEOUT,
            stream=True,
        )
        if response.status_code == 200:
            for line in response.iter_lines():
                if line:
                    try:
                        data = json.loads(line)
                        chunk = data.get("response", "")
                        if chunk:
                            full_reply.append(chunk)
                            yield chunk
                        if data.get("done"):
                             _log_llm(prompt, "".join(full_reply), system_prompt, images)
                    except Exception:
                        continue
        else:
            err = f"Error: {response.status_code}"
            _log_llm(prompt, err, system_prompt, images)
            yield err
    except Exception as e:
        err = f"Error: {str(e)}"
        _log_llm(prompt, err, system_prompt, images)
        yield err


def analyze_text_for_scam(text: str, model: str = None) -> Dict[str, Any]:
    """
    Analyze text for potential scam indicators using Ollama.
    """
    prompt = f"""Analyze the following text for scam/fraud indicators. 
Response in PURE JSON format. Do not include markdown code blocks or any other text.
The JSON must have: is_scam (true/false), risk_score (0-100), indicators (list of strings), explanation (string).
Text to analyze: {text}"""

    response = generate_response(prompt, model)
    
    if response:
        try:
            # 1. Clean response - remove markdown blocks if present
            clean_res = response.strip()
            if "```json" in clean_res:
                clean_res = clean_res.split("```json")[1].split("```")[0].strip()
            elif "```" in clean_res:
                clean_res = clean_res.split("```")[1].split("```")[0].strip()
            
            # 2. Find the JSON object boundary
            start = clean_res.find('{')
            end = clean_res.rfind('}')
            if start != -1 and end != -1:
                json_str = clean_res[start:end+1]
                # Clean control characters
                json_str = re.sub(r'[\x00-\x1F\x7F]', ' ', json_str)
                return json.loads(json_str)
            else:
                logger.warning(f"No JSON object found in response: {response[:100]}")
        except Exception as e:
            logger.warning(f"Could not parse Ollama response as JSON: {e}. Raw: {response[:100]}")

    # Fallback response
    return {
        "is_scam": False,
        "risk_score": 0,
        "indicators": [],
        "explanation": "Analysis failed or timed out", # Use explanation to match models
    }


def classify_message(message: str, model: str = None) -> Dict[str, Any]:
    """
    Classify a message and suggest actions.

    Args:
        message: The message to classify
        model: The model to use

    Returns:
        Dictionary with classification and suggestion
    """
    prompt = f"""Classify this message and suggest an action if needed.
Response in PURE JSON format.
The JSON must have: classification (safe/suspicious/dangerous), suggested_action (NONE/BLOCK/REPORT), confidence (0-1).
Message: {message}"""

    response = generate_response(prompt, model)

    if response:
        try:
            json_str = response
            if "```json" in response:
                json_str = response.split("```json")[1].split("```")[0].strip()
            elif "```" in response:
                json_str = response.split("```")[1].split("```")[0].strip()
            
            json_str = re.sub(r'[\x00-\x1F\x7F]', '', json_str)
            
            start = json_str.find('{')
            end = json_str.rfind('}')
            if start != -1 and end != -1:
                json_str = json_str[start:end+1]
                return json.loads(json_str)
        except Exception as e:
            logger.warning(f"Could not parse classification response: {e}")

    return {
        "classification": "unknown",
        "suggested_action": "NONE",
        "confidence": 0.5,
    }
