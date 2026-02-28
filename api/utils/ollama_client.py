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
import os
import re
from typing import Optional, Dict, Any, Generator, List

from django.conf import settings
import ollama

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Read from Django settings with sensible defaults
OLLAMA_BASE_URL = getattr(settings, 'OLLAMA_BASE_URL', 'http://localhost:11434')
OLLAMA_API_KEY = getattr(settings, 'OLLAMA_API_KEY', None)

# Mirror OLLAMA_API_KEY into the environment for any ollama library internals
# that may read it (e.g. the search_agent client.chat call).
if OLLAMA_API_KEY:
    os.environ.setdefault('OLLAMA_API_KEY', OLLAMA_API_KEY)
DEFAULT_MODEL = getattr(settings, 'LLM_MODEL', 'neural-chat')
SMALL_MODEL = getattr(settings, 'SMALL_MODEL', DEFAULT_MODEL)
LLM_TEMPERATURE = getattr(settings, 'LLM_TEMPERATURE', 0.3)
LLM_MAX_TOKENS = getattr(settings, 'LLM_MAX_TOKENS', 1800)

# ---------------------------------------------------------------------------
# Custom tool schemas for the search agent.
# We define our OWN plain function objects so the model receives clean,
# auth-free tool specs.  When the model requests these tools we dispatch
# to web_search_query() / web_fetch_url() ourselves — the model never sees
# any authentication metadata and therefore never refuses to call them.
# ---------------------------------------------------------------------------

def _tool_web_search(query: str, max_results: int = 5):
    """Search the web for pages matching a query.

    Args:
        query: The search query string.
        max_results: Maximum number of results to return (default 5).

    Returns:
        A list of search results with title, url, and content fields.
    """
    return web_search_query(query, max_results=max_results)


def _tool_web_fetch(url: str):
    """Fetch the content of a web page by URL.

    Args:
        url: The URL of the web page to fetch.

    Returns:
        A dict containing title, content, and links of the fetched page.
    """
    return web_fetch_url(url)


def _tool_lookup_scamadviser(domain: str):
    """Check a domain or website against ScamAdviser's trust score database.

    Use this tool whenever you need to assess whether a website or domain is
    safe, suspicious, or a known scam site. ScamAdviser provides automated
    trust scores, registration details, hosting country, and risk indicators.

    Args:
        domain: The domain name to look up, e.g. 'example.com'. Strip any
                leading 'http://' or 'https://' scheme before passing.

    Returns:
        A dict with title and content fields containing the ScamAdviser trust
        assessment and risk indicators for the domain.
    """
    return lookup_scamadviser(domain)


def _tool_lookup_scamwave(query: str):
    """Search the ScamWave scammer database for reports matching a query.

    Use this tool to look up phone numbers, bank account numbers, names, or
    keywords in the ScamWave community-sourced scam report database. It
    surfaces victim-reported fraud cases, blacklisted numbers, and warnings.

    Args:
        query: Phone number, bank account number, full name, or keyword to
               search for in the ScamWave database.

    Returns:
        A dict with title and content fields containing matching scam reports
        and listings from the ScamWave database.
    """
    encoded = query.replace(' ', '+')
    return web_fetch_url(f"https://scamwave.com/scammers/?s={encoded}")


def _tool_lookup_trustpilot(domain: str):
    """Check a domain's reputation and user reviews on Trustpilot.

    Use this tool to find user feedback, star ratings, and complaint details
    for a specific domain. Trustpilot is a major source for verifying legitimacy.

    Args:
        domain: The domain name to check (e.g. 'example.com').
    """
    clean = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    return web_fetch_url(f"https://www.trustpilot.com/review/{clean}")


def _tool_lookup_sitejabber(domain: str):
    """Check a domain's reputation and user reviews on sitejabber.

    Use this tool to find consumer reviews and business ratings. sitejabber
    often has reviews for smaller online businesses that Trustpilot might miss.

    Args:
        domain: The domain name to check (e.g. 'example.com').
    """
    clean = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    return web_fetch_url(f"https://www.sitejabber.com/reviews/{clean}")


def _tool_lookup_tranco(domain: str):
    """Check a domain's popularity ranking on Tranco list.

    Args:
        domain: Domain name (e.g. 'example.com').

    Returns:
        A dict with rank and history if available.
    """
    return lookup_tranco(domain)


# Map tool name -> our Python dispatcher (used in search_agent loop)
WEB_TOOLS: Dict[str, Any] = {
    '_tool_web_search': _tool_web_search,
    '_tool_web_fetch': _tool_web_fetch,
    '_tool_lookup_scamadviser': _tool_lookup_scamadviser,
    '_tool_lookup_scamwave': _tool_lookup_scamwave,
    '_tool_lookup_trustpilot': _tool_lookup_trustpilot,
    '_tool_lookup_sitejabber': _tool_lookup_sitejabber,
    '_tool_lookup_tranco': _tool_lookup_tranco,
}

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
    },
    {
        "type": "function",
        "function": {
            "name": "web_search",
            "description": "Search the internet for real-time information and news.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "The search query"},
                    "max_results": {"type": "integer", "description": "Max results (1-10)"}
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "web_fetch",
            "description": "Fetch and read the content of a specific web page.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "The URL to fetch"}
                },
                "required": ["url"]
            }
        }
    }
]

# ---------------------------------------------------------------------------
# STRUCTURED OUTPUT SCHEMAS
# ---------------------------------------------------------------------------

# Schema for structured classification output
CLASSIFICATION_SCHEMA = {
    "type": "object",
    "properties": {
        "classification": {"type": "string", "enum": ["safe", "suspicious", "dangerous"]},
        "suggested_action": {"type": "string", "enum": ["NONE", "BLOCK", "REPORT"]},
        "confidence": {"type": "number"}
    },
    "required": ["classification", "suggested_action", "confidence"]
}

# Schema for structured scam analysis output
SCAM_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "is_scam": {"type": "boolean"},
        "risk_score": {"type": "integer"},
        "indicators": {"type": "array", "items": {"type": "string"}},
        "explanation": {"type": "string"},
        "web_sources": {"type": "array", "items": {"type": "string"}}
    },
    "required": ["is_scam", "risk_score", "indicators", "explanation", "web_sources"]
}

# Initialize client
# Auto-correct bare 'ollama.com' to 'api.ollama.com' — the former is the
# website, the latter is the Ollama cloud API endpoint used by the Python SDK.
_effective_base_url = OLLAMA_BASE_URL
if OLLAMA_API_KEY and 'ollama.com' in OLLAMA_BASE_URL and 'api.ollama.com' not in OLLAMA_BASE_URL:
    _effective_base_url = 'https://api.ollama.com'
    logger.info(
        f"OLLAMA_BASE_URL '{OLLAMA_BASE_URL}' corrected to '{_effective_base_url}' "
        f"(cloud API endpoint required for authenticated models)."
    )

client_kwargs = {'host': _effective_base_url}
if OLLAMA_API_KEY:
    client_kwargs['headers'] = {
        'Authorization': f'Bearer {OLLAMA_API_KEY}',
    }

client = ollama.Client(**client_kwargs)

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
    Removes igid blocks from model responses.
    Used for reasoning-capable models like DeepSeek.
    """
    if not text:
        return ""
    # Remove content between igid and igid tags
    return re.sub(r'igid.*?igid', '', text, flags=re.DOTALL).strip()


def filter_hallucinations(text: str) -> str:
    """
    Filter out common AI hallucinations like unexpected CJK characters
    in a non-CJK context, especially the 'strange unicode' characters
    reported by the user (e.g., 自称).
    """
    if not text:
        return text
    # Strip CJK Unified Ideographs if found in isolation or in strange spots
    # Range: \u4e00-\u9fff (Common Chinese)
    # We mainly target the "strange" ones like 自称 \u81ea\u79f0
    text = re.sub(r'[\u4e00-\u9fff]+', '', text)
    return text


def filter_tool_call_artifacts(text: str) -> str:
    """
    Remove accidental tool-call JSON artifacts from agent textual output.

    Some models occasionally emit raw objects like:
    {"name":"_tool_lookup_scamadviser","arguments":{...}}
    in plain content instead of structured ``tool_calls``.
    """
    if not text:
        return ""

    cleaned = text

    # Remove compact/raw tool call JSON objects (single or multiple objects).
    cleaned = re.sub(
        r'\{\s*"name"\s*:\s*"_tool_[^\"]+"\s*,\s*"arguments"\s*:\s*\{[^{}]*\}\s*\}\s*',
        '',
        cleaned,
        flags=re.DOTALL,
    )

    # Remove any line that still contains explicit tool invocations.
    cleaned = "\n".join(
        line for line in cleaned.splitlines()
        if '_tool_' not in line and '"arguments"' not in line
    )

    # Normalize excessive blank lines.
    cleaned = re.sub(r'\n{3,}', '\n\n', cleaned)
    return cleaned.strip()

def _extract_json(text: str) -> Optional[dict]:
    """
    Extract and parse the first JSON object from an LLM response.

    Handles markdown fenced code blocks, trailing commas, and ASCII control
    characters.  Works cleanly on `message.content` which, when the official
    chat-loop pattern is used with think=True, contains only the final answer
    (no thinking prose to confuse the extractor).
    """
    if not text:
        return None

    # 1. Prefer JSON inside a markdown code fence
    fence_match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', text, re.DOTALL)
    candidate = fence_match.group(1) if fence_match else None

    if candidate is None:
        # 2. Outermost { … } block
        brace_match = re.search(r'\{.*\}', text, re.DOTALL)
        if not brace_match:
            return None
        candidate = brace_match.group(0)

    # Strip ASCII control characters
    candidate = re.sub(r'[\x00-\x1F\x7F]', ' ', candidate)

    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        # Remove trailing commas (common model mistake) and retry
        fixed = re.sub(r',\s*([}\]])', r'\1', candidate)
        try:
            return json.loads(fixed)
        except json.JSONDecodeError:
            return None


def message_to_dict(msg) -> Dict[str, Any]:
    """
    Convert an ollama ``Message`` object (or any mapping) to a plain Python
    dict suitable for JSON serialisation, logging, or re-inserting into a
    messages list.

    Only fields that are actually set are included so the output stays clean.
    Handles:
      - ``role``        (str, always present)
      - ``content``     (str, omitted when None/empty)
      - ``thinking``    (str, omitted when None/empty)
      - ``tool_name``   (str, omitted when None)
      - ``tool_calls``  (list of dicts, omitted when empty/None)
      - ``images``      (list, omitted when empty/None)

    ``ToolCall`` objects are recursively converted to::

        {"function": {"name": "...", "arguments": {...}}}
    """
    # Already a plain dict — normalise and return
    if isinstance(msg, dict):
        return {k: v for k, v in msg.items() if v is not None}

    d: Dict[str, Any] = {'role': msg.role}

    content = getattr(msg, 'content', None)
    if content:
        d['content'] = content

    thinking = getattr(msg, 'thinking', None)
    if thinking:
        d['thinking'] = thinking

    tool_name = getattr(msg, 'tool_name', None)
    if tool_name:
        d['tool_name'] = tool_name

    tool_calls = getattr(msg, 'tool_calls', None)
    if tool_calls:
        serialised = []
        for tc in tool_calls:
            if isinstance(tc, dict):
                serialised.append(tc)
            else:
                # ollama ToolCall object
                fn = tc.function
                serialised.append({
                    'function': {
                        'name': fn.name,
                        'arguments': dict(fn.arguments) if fn.arguments else {},
                    }
                })
        d['tool_calls'] = serialised

    images = getattr(msg, 'images', None)
    if images:
        d['images'] = list(images)

    return d


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

def generate_response(
    prompt: str,
    model: str = None,
    system_prompt: str = None,
    num_ctx: int = None,
    max_tokens: int = None,
    tools: list = None,
    tool_dispatch: Dict[str, Any] = None,
    format_schema: dict = None,  # NEW: Structured output schema
    max_loop_iterations: int = 15,
) -> Optional[str]:
    """
    Generate a non-streamed response from Ollama.

    When ``format_schema`` is provided, the model is guaranteed to return
    valid JSON matching the schema, simplifying the loop logic.
    """
    model = model or DEFAULT_MODEL
    if tools is None:
        tools = TOOLS
    tool_dispatch = tool_dispatch or {}

    try:
        messages: List[Dict] = []
        if system_prompt:
            messages.append({'role': 'system', 'content': system_prompt})
        messages.append({'role': 'user', 'content': prompt})

        options: Dict[str, Any] = {
            'temperature': LLM_TEMPERATURE,
            'num_predict': max_tokens or LLM_MAX_TOKENS,
        }
        if num_ctx:
            options['num_ctx'] = num_ctx

        reply = ''
        response = None
        iteration = 0

        while iteration < max_loop_iterations:
            logger.info(f"[generate_response iter={iteration}] calling model '{model}' "
                        f"with {len(messages)} message(s), tools={'yes' if tools else 'no'}")

            chat_kwargs: Dict[str, Any] = {
                'model': model,
                'messages': messages,
                'options': options,
                'think': "low",
            }
            if tools:
                chat_kwargs['tools'] = tools
            if format_schema:
                chat_kwargs['format'] = format_schema

            response = client.chat(**chat_kwargs)
            assistant_msg = message_to_dict(response.message)
            messages.append(assistant_msg)

            part = response.message.content or ''
            tool_calls = response.message.tool_calls

            iteration += 1

            if tool_calls:
                for tool_call in tool_calls:
                    tool_name = tool_call.function.name
                    args = tool_call.function.arguments or {}
                    tool_func = tool_dispatch.get(tool_name)
                    result_str = tool_func(**args) if tool_func else f"Tool '{tool_name}' not available."
                    messages.append({'role': 'tool', 'content': result_str, 'tool_name': tool_name})
                iteration += 1
                continue
            elif part:
                reply = part.strip()
                logger.info(f"[generate_response iter={iteration}] ✅ final answer (no tools), exiting loop")
                break

        if iteration >= max_loop_iterations:
            logger.warning(f"[generate_response] hit max_loop_iterations={max_loop_iterations}, returning best content so far")

        _log_llm(prompt, reply, system_prompt)
        return filter_hallucinations(reply)

    except Exception as e:
        logger.error(f"Error calling Ollama: {e}")
        return None

def stream_response(prompt: str, system_prompt: str = None, model: str = None) -> Generator[str, None, None]:
    """
    Stream a response from Ollama, filtering out igid blocks in real-time.
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
            content = filter_hallucinations(chunk['message']['content'])
            if not content:
                continue

            if not is_thinking:
                if "igid" in content:
                    is_thinking = True
                    yield "__STATUS__:thinking"
                    parts = content.split("igid", 1)
                    if parts[0]:
                        yield parts[0]
                        full_response.append(parts[0])
                    if "igid" in parts[1]:
                        is_thinking = False
                        subparts = parts[1].split("igid", 1)
                        if subparts[1]:
                            yield subparts[1]
                            full_response.append(subparts[1])
                    continue
                else:
                    yield content
                    full_response.append(content)
            else:
                if "igid" in content:
                    is_thinking = False
                    parts = content.split("igid", 1)
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

def stream_chat_ai(messages: list, model: str = None, tool_dispatch: dict = None) -> Generator[str, None, None]:
    """
    Improved streaming chat for ShieldCall AI.
    Handles multi-turn tool loops, thinking streaming, and search result yielding.
    """
    model = model or DEFAULT_MODEL
    tool_dispatch = tool_dispatch or {}
    # Combine with standard tools
    all_dispatch = {
        'web_search': web_search_query,
        'web_fetch': web_fetch_url,
        'scan_phone': _tool_lookup_scamwave,
        'scan_url': _tool_lookup_scamadviser,
        'scan_bank_account': _tool_lookup_scamwave,
    }
    all_dispatch.update(tool_dispatch)

    max_loops = 10
    iteration = 0

    while iteration < max_loops:
        try:
            chat_params = {
                'model': model,
                'messages': messages,
                'options': {
                    'temperature': LLM_TEMPERATURE,
                    'num_predict': LLM_MAX_TOKENS,
                },
                'stream': True,
                'think': True  # Enable thinking if supported
            }
            if TOOLS:
                chat_params['tools'] = TOOLS

            stream = client.chat(**chat_params)
            
            current_tool_calls = []
            current_content = []
            is_thinking = False

            for chunk in stream:
                # Handle both dict-like and object-like access for chunk/message
                msg = getattr(chunk, 'message', {})
                if not msg and hasattr(chunk, 'get'):
                    msg = chunk.get('message', {})

                # Handle Thinking
                thinking = getattr(msg, 'thinking', "")
                if not thinking and hasattr(msg, 'get'):
                    thinking = msg.get('thinking', "")
                
                if thinking:
                    yield f"__THINK__:{thinking}"
                
                # Handle Content
                content = getattr(msg, 'content', "")
                if not content and hasattr(msg, 'get'):
                    content = msg.get('content', "")
                
                if content:
                    content = filter_hallucinations(content)
                    if content: # Could be empty after filtering
                        yield content
                        current_content.append(content)

                # Collect Tool Calls
                tool_calls = getattr(msg, 'tool_calls', [])
                if not tool_calls and hasattr(msg, 'get'):
                    tool_calls = msg.get('tool_calls', [])
                
                if tool_calls:
                    current_tool_calls.extend(tool_calls)

            # If no tool calls, we are done
            if not current_tool_calls:
                # Log the final response
                _log_llm("Chat history...", "".join(current_content))
                break

            # Handle Tool Calls
            messages.append({'role': 'assistant', 'content': "".join(current_content), 'tool_calls': current_tool_calls})
            
            serializable_calls = []
            for tc in current_tool_calls:
                tool_name = tc.function.name
                args = tc.function.arguments or {}
                
                # Yield marker for UI
                yield f"__STATUS__:executing_tool:{tool_name}"
                
                serializable_calls.append({
                    'function': {'name': tool_name, 'arguments': args}
                })

                # Execute
                tool_func = all_dispatch.get(tool_name)
                if tool_func:
                    try:
                        result = tool_func(**args)
                        
                        # Special handling for search results to show in UI
                        if tool_name == 'web_search' and isinstance(result, list):
                            yield f"__SEARCH_RESULTS__:{json.dumps(result)}"
                        
                        result_str = json.dumps(result, ensure_ascii=False)
                    except Exception as e:
                        result_str = f"Error: {str(e)}"
                else:
                    result_str = f"Tool '{tool_name}' not found."

                messages.append({
                    'role': 'tool',
                    'content': result_str,
                    'tool_name': tool_name
                })

            yield f"__TOOL_CALLS__:{json.dumps(serializable_calls)}"
            iteration += 1
            continue

        except Exception as e:
            logger.error(f"Error in stream_chat_ai: {e}")
            yield f"Error: {str(e)}"
            break

def classify_message(message: str, model: str = None) -> Dict[str, Any]:
    """
    Classify a message and suggest actions.
    """
    prompt = f"""Bạn là chuyên gia an ninh mạng. Hãy phân loại tin nhắn sau và đề xuất hành động xử lý.
Trả về KẾT QUẢ THUẦN JSON (không có markdown, không có văn bản thừa).
JSON phải có các trường: classification (safe/suspicious/dangerous), suggested_action (NONE/BLOCK/REPORT), confidence (số thực 0-1).
Tin nhắn cần phân loại: {message}"""

    response = generate_response(prompt, model, tools=[], format_schema=CLASSIFICATION_SCHEMA)

    if response:
        return json.loads(response)

    return {
        "classification": "unknown",
        "suggested_action": "NONE",
        "confidence": 0.5,
    }

# ---------------------------------------------------------------------------
# Web search / fetch helpers
# These call https://ollama.com/api/web_search and /web_fetch directly via
# requests so we control the Authorization header ourselves rather than
# relying on the ollama library's global client (which is initialised at
# import time and does not pick up our OLLAMA_API_KEY reliably).
# ---------------------------------------------------------------------------

_OLLAMA_WEB_API_BASE = "https://ollama.com/api"


def _web_api_headers() -> Dict[str, str]:
    """Build auth headers for the Ollama web API."""
    key = OLLAMA_API_KEY or os.environ.get('OLLAMA_API_KEY', '')
    return {
        'Authorization': f'Bearer {key}',
        'Content-Type': 'application/json',
    }


def web_search_query(query: str, max_results: int = 5) -> Optional[List[Dict]]:
    """
    Perform a web search via Ollama's web search REST API.
    (https://ollama.com/api/web_search)
    Requires OLLAMA_API_KEY in Django settings.

    Returns a list of result dicts with keys: title, url, content.
    """
    import requests as _requests
    try:
        resp = _requests.post(
            f"{_OLLAMA_WEB_API_BASE}/web_search",
            headers=_web_api_headers(),
            json={"query": query, "max_results": max_results},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get('results', [])
        return results
    except Exception as e:
        logger.error(f"web_search_query error: {e}")
        return None


def web_fetch_url(url: str) -> Optional[Dict]:
    """
    Fetch a single web page via Ollama's web fetch REST API.
    (https://ollama.com/api/web_fetch)
    Requires OLLAMA_API_KEY in Django settings.

    Returns a dict with keys: title, content, links.
    """
    import requests as _requests
    try:
        resp = _requests.post(
            f"{_OLLAMA_WEB_API_BASE}/web_fetch",
            headers=_web_api_headers(),
            json={"url": url},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            'title': data.get('title', ''),
            'content': data.get('content', ''),
            'links': data.get('links', []),
        }
    except Exception as e:
        logger.error(f"web_fetch_url error: {e}")
        return None


# ---------------------------------------------------------------------------
# Dedicated scam database lookup helpers
# ---------------------------------------------------------------------------

# Known credible scam-reporting databases consulted during analysis.
SCAM_DB_URLS = {
    'scamadviser': 'https://www.scamadviser.com/check-website/',
    'scamwave':    'https://scamwave.com/scammers/',
    'trustpilot':  'https://www.trustpilot.com/review/',
    'sitejabber':  'https://www.sitejabber.com/reviews/',
    'tranco':      'https://tranco-list.eu/api/ranks/domain/',
}


def lookup_scamadviser(domain: str) -> Optional[Dict]:
    """
    Fetch the ScamAdviser report for a domain.

    Prioritizes extracting ``ratingScore`` from the SPA bootstrap payload
    embedded in ``<div id="app" data-page="...">``. This is the same source
    used by client-side rendering and is more reliable than placeholder
    progress bars in static HTML. Falls back to textual verdict extraction
    (e.g. ``Very Likely Safe``, ``Caution Recommended``) when needed.

    Args:
        domain: Domain to look up (e.g. 'example.com').  Any leading scheme
                (``http://`` / ``https://``) is stripped automatically.

    Returns:
        Dict with keys ``source``, ``query_url``, ``title``, ``content``, and
        ``links``; or ``None`` on failure.
    """
    clean = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not clean:
        return None
    url = f"{SCAM_DB_URLS['scamadviser']}{clean}"

    trust_score_from_page = None
    verdict_from_page = None
    page_text = ""

    # 1) Direct HTML fetch to extract data-page JSON + human-readable verdict.
    try:
        import html as _html
        import requests
        from bs4 import BeautifulSoup

        response = requests.get(
            url,
            headers={
                'User-Agent': (
                    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) '
                    'Gecko/20100101 Firefox/137.0'
                )
            },
            timeout=12,
        )
        if response.ok:
            html_text = response.text or ''
            page_text = BeautifulSoup(html_text, 'html.parser').get_text(' ', strip=True)[:6000]

            # Parse <div id="app" data-page="..."> then read ratingScore.
            app_data_match = re.search(
                r'<div\s+id=["\']app["\']\s+data-page=["\']([^"\']+)["\']',
                html_text,
                flags=re.IGNORECASE | re.DOTALL,
            )
            if app_data_match:
                data_page_escaped = app_data_match.group(1)
                data_page_unescaped = _html.unescape(data_page_escaped)
                try:
                    data_page_obj = json.loads(data_page_unescaped)

                    score_candidates = [
                        data_page_obj.get('props', {}).get('score', {}).get('ratingScore'),
                        data_page_obj.get('props', {}).get('ratingScore'),
                        data_page_obj.get('ratingScore'),
                    ]
                    for candidate in score_candidates:
                        if isinstance(candidate, (int, float)):
                            numeric = int(candidate)
                            if 0 <= numeric <= 100:
                                trust_score_from_page = numeric
                                break

                    verdict_candidates = [
                        data_page_obj.get('props', {}).get('score', {}).get('ratingText'),
                        data_page_obj.get('props', {}).get('score', {}).get('ratingLabel'),
                        data_page_obj.get('props', {}).get('score', {}).get('conclusion'),
                        data_page_obj.get('props', {}).get('ratingText'),
                        data_page_obj.get('ratingText'),
                    ]
                    for candidate in verdict_candidates:
                        if isinstance(candidate, str) and candidate.strip():
                            verdict_from_page = candidate.strip()
                            break
                except Exception:
                    # Fallback: extract ratingScore directly from the unescaped data blob.
                    score_match = re.search(r'"ratingScore"\s*:\s*(\d+)', data_page_unescaped)
                    if score_match:
                        trust_score_from_page = int(score_match.group(1))

            # Secondary fallback: score may still appear in the HTML snapshot.
            if trust_score_from_page is None:
                score_match = re.search(r'"ratingScore"\s*:\s*(\d+)', html_text)
                if score_match:
                    trust_score_from_page = int(score_match.group(1))

            # Known ScamAdviser-style conclusions to prioritize.
            if not verdict_from_page:
                verdict_patterns = [
                    r'Very\s+Likely\s+Safe',
                    r'Likely\s+Safe',
                    r'Caution\s+Recommended',
                    r'Suspicious',
                    r'Unsafe',
                    r'Scam',
                ]
                for pattern in verdict_patterns:
                    match = re.search(pattern, page_text, flags=re.IGNORECASE)
                    if match:
                        verdict_from_page = match.group(0)
                        break
    except Exception as exc:
        logger.debug(f"lookup_scamadviser: direct HTML parse failed ({exc})")

    # 2) Keep existing web relay extraction as primary content source.
    result = web_fetch_url(url) or {
        'title': f'ScamAdviser report for {clean}',
        'content': page_text,
        'links': [],
    }

    # 2) If not found from direct page text, attempt extraction from relay content.
    if not verdict_from_page:
        relay_content = result.get('content', '') or ''
        verdict_patterns = [
            r'Very\s+Likely\s+Safe',
            r'Likely\s+Safe',
            r'Caution\s+Recommended',
            r'Suspicious',
            r'Unsafe',
            r'Scam',
        ]
        for pattern in verdict_patterns:
            match = re.search(pattern, relay_content, flags=re.IGNORECASE)
            if match:
                verdict_from_page = match.group(0)
                break

    existing_content = result.get('content', '') or ''
    prefix_lines = []

    if trust_score_from_page is not None:
        prefix_lines.append(f"ScamAdviser Trust Score (ratingScore): {trust_score_from_page}/100")

    if verdict_from_page:
        prefix_lines.append(f"ScamAdviser Verdict: {verdict_from_page}")

    if prefix_lines:
        prefix = '\n'.join(prefix_lines)
        if prefix not in existing_content:
            result['content'] = f"{prefix}\n{existing_content}".strip()

    result['source'] = 'scamadviser'
    result['query_url'] = url
    return result


def lookup_scamwave(query: str) -> Optional[Dict]:
    """
    Search the ScamWave community scam-report database.

    Submits *query* (phone number, bank account, name, or keyword) to
    ScamWave's public search endpoint and returns the page content, which
    lists victim-reported fraud cases and blacklisted identifiers.

    Args:
        query: Search term — phone number, bank account, domain, name, or
               any fraud-related keyword.

    Returns:
        Dict with keys ``source``, ``query_url``, ``title``, ``content``, and
        ``links``; or ``None`` on failure.
    """
    encoded = query.replace(' ', '+')
    url = f"{SCAM_DB_URLS['scamwave']}?s={encoded}"
    result = web_fetch_url(url)
    if result:
        result['source'] = 'scamwave'
        result['query_url'] = url
    return result


def lookup_trustpilot(domain: str) -> Optional[Dict]:
    """
    Look up a domain's reviews on Trustpilot.

    Args:
        domain: Domain name (e.g. 'example.com').

    Returns:
        Dict with keys ``source``, ``query_url``, ``title``, ``content``, and
        ``links``; or ``None`` on failure.
    """
    clean = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not clean:
        return None
    url = f"{SCAM_DB_URLS['trustpilot']}{clean}"
    result = web_fetch_url(url)
    if result:
        result['source'] = 'trustpilot'
        result['query_url'] = url
    return result


def lookup_sitejabber(domain: str) -> Optional[Dict]:
    """
    Look up a domain's reviews on sitejabber.

    Args:
        domain: Domain name (e.g. 'example.com').

    Returns:
        Dict with keys ``source``, ``query_url``, ``title``, ``content``, and
        ``links``; or ``None`` on failure.
    """
    clean = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not clean:
        return None
    url = f"{SCAM_DB_URLS['sitejabber']}{clean}"
    result = web_fetch_url(url)
    if result:
        result['source'] = 'sitejabber'
        result['query_url'] = url
    return result


def lookup_tranco(domain: str) -> Optional[Dict]:
    """
    Look up a domain's popularity ranking on Tranco list.

    Args:
        domain: Domain name (e.g. 'example.com').

    Returns:
        Dict with keys ``source``, ``query_url``, ``title``, ``content``, and
        ``links``; or ``None`` on failure.
    """
    import requests
    clean = re.sub(r'^https?://', '', domain).split('/')[0].strip()
    if not clean:
        return None
    url = f"{SCAM_DB_URLS['tranco']}{clean}"
    try:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/137.0"},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            ranks = data.get('ranks', [])
            if ranks:
                latest_rank = ranks[0].get('rank', 'N/A')
                content = f"Popularity Rank: {latest_rank}\nHistory: {json.dumps(ranks[:5])}"
            else:
                content = "No ranking data found (likely low popularity)."
            
            return {
                'source': 'tranco',
                'query_url': url,
                'title': f"Tranco Rank for {clean}",
                'content': content,
                'links': []
            }
        elif response.status_code == 404:
             return {
                'source': 'tranco',
                'query_url': url,
                'title': f"Tranco Rank for {clean}",
                'content': "Domain not found in top 1M list (Low Popularity)",
                'links': []
            }
    except Exception as e:
        logger.error(f"lookup_tranco error: {e}")
    return None



def search_agent(
    query: str,
    model: str = None,
    think=False,
    max_iterations: int = 10,
    max_context_chars: int = 8000,
) -> Optional[str]:
    """
    Agentic search loop that gives the model access to web_search and web_fetch
    tools, following the pattern from https://docs.ollama.com/capabilities/web-search.

    The loop continues until the model returns a non-empty final answer (no
    more tool_calls) or ``max_iterations`` is reached.

    Thinking-only turns (empty content, no tool_calls) are retried without
    appending the useless assistant message to history — preventing context
    overflow from accumulated thinking text.

    Args:
        query:             The user's question or task.
        model:             Ollama model to use (defaults to DEFAULT_MODEL).
        think:             Passed directly as the ``think`` kwarg to client.chat
                           (bool or 'low'/'medium'/'high').
        max_iterations:    Safety cap on total loop iterations.
        max_context_chars: Maximum characters of a single tool result kept in
                           the message history.
    """
    model = model or DEFAULT_MODEL
    messages: List[Dict] = [{'role': 'user', 'content': query}]

    agent_tools = {
        '_tool_web_search': _tool_web_search,
        '_tool_web_fetch': _tool_web_fetch,
        '_tool_lookup_scamadviser': _tool_lookup_scamadviser,
        '_tool_lookup_scamwave': _tool_lookup_scamwave,
        '_tool_lookup_trustpilot': _tool_lookup_trustpilot,
        '_tool_lookup_sitejabber': _tool_lookup_sitejabber,
        '_tool_lookup_tranco': _tool_lookup_tranco,
    }

    logger.info(f"[search_agent] START query='{query[:120]}', model={model}, "
                f"think={think}, max_iterations={max_iterations}")

    try:
        for iteration in range(max_iterations):
            logger.info(f"[search_agent iter={iteration}] calling model with "
                        f"{len(messages)} message(s)")

            chat_kwargs: Dict[str, Any] = {
                'model': model,
                'messages': messages,
                'tools': [
                    _tool_lookup_scamadviser,
                    _tool_lookup_scamwave,
                    _tool_lookup_trustpilot,
                    _tool_lookup_sitejabber,
                    _tool_lookup_tranco,
                    _tool_web_search,
                    _tool_web_fetch,
                ],
                'options': {
                    'temperature': LLM_TEMPERATURE,
                    'num_predict': 4000,  # Increased to prevent cutoff
                },
            }
            if think:
                chat_kwargs['think'] = think

            response = client.chat(**chat_kwargs)
            msg = response.message
            messages.append(message_to_dict(msg))

            content = getattr(msg, 'content', '') or ''
            tool_calls = getattr(msg, 'tool_calls', None)

            if tool_calls:
                # Append assistant message, then execute each tool
                for tool_call in tool_calls:
                    tool_name = tool_call.function.name
                    args = tool_call.function.arguments or {}
                    logger.debug(f"[search_agent iter={iteration}]   → tool '{tool_name}' "
                                f"args={json.dumps(args, ensure_ascii=False)[:200]}")
                    tool_func = agent_tools.get(tool_name)
                    if tool_func:
                        try:
                            result = tool_func(**args)
                            result_str = str(result)[:max_context_chars]
                        except Exception as exc:
                            result_str = f"Tool execution error: {exc}"
                            logger.error(f"[search_agent iter={iteration}]   ✗ {result_str}")
                    else:
                        result_str = f"Tool '{tool_name}' not found."
                        logger.warning(f"[search_agent iter={iteration}]   ✗ {result_str}")
                    messages.append({
                        'role': 'tool',
                        'content': result_str,
                        'tool_name': tool_name,
                    })
                # Continue loop so the model can read the tool results
                continue

            # No tool calls — check whether we actually have a final answer
            if content:
                filtered = filter_tool_call_artifacts(filter_thinking(content))
                # If the model only emitted tool-call artifacts, keep iterating.
                if not filtered:
                    continue
                _log_llm(query, filtered)
                return filtered
            else:
                # Thinking-only turn: discard (do NOT append to history) and retry
                continue

        logger.warning(f"[search_agent] Reached max_iterations={max_iterations} "
                       f"without a final answer.")
        return None

    except Exception as e:
        logger.error(f"[search_agent] error: {e}", exc_info=True)
        return None


def _extract_scam_subject(text: str) -> str:
    """
    Heuristically extract the primary subject (domain, phone, or account number)
    from a text snippet so it can be sent directly to scam databases.

    Returns the best candidate string, or the first 120 characters of *text*
    as a fallback.
    """
    # Domain / URL
    url_match = re.search(
        r'(?:https?://)?(?:www\.)?((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})(?:/[^\s]*)?',
        text,
    )
    if url_match:
        return url_match.group(1)

    # Vietnamese / international phone number (digits, optional +/spaces/-)
    phone_match = re.search(r'(?:\+?84|0)[\s.-]?\d[\s.-]?\d{3}[\s.-]?\d{4}', text)
    if phone_match:
        return re.sub(r'[\s.-]', '', phone_match.group(0))

    # Generic phone (7-15 digits, optional leading +)
    generic_phone = re.search(r'\+?\d[\d\s.-]{6,14}\d', text)
    if generic_phone:
        return re.sub(r'[\s.-]', '', generic_phone.group(0))

    return text[:120]


def analyze_text_for_scam(text: str, model: str = None, use_web_search: bool = False) -> Dict[str, Any]:
    """
    Analyze text for scam indicators, optionally enriching with web search.

    When ``use_web_search`` is ``True`` *and* ``OLLAMA_API_KEY`` is configured,
    the function performs two complementary enrichment steps:

    1. **Direct database lookups** — queries ScamAdviser and ScamWave directly
       for the primary subject (domain, phone, account) extracted from *text*.
       These lookups run in parallel with the agent call and do not consume
       extra agent iterations.

    2. **Search-agent enrichment** — runs the agentic loop with an extended
       tool set that includes ``_tool_lookup_scamadviser`` and
       ``_tool_lookup_scamwave`` so the model can proactively consult the same
       databases for any additional entities it discovers.
    """
    web_context = ""
    web_search_used = False
    db_context_parts: List[str] = []

    if use_web_search and OLLAMA_API_KEY:
        # ------------------------------------------------------------------
        # Step 1: Direct scam-database lookups (ScamAdviser + ScamWave)
        # ------------------------------------------------------------------
        subject = _extract_scam_subject(text)
        logger.debug(f"analyze_text_for_scam: extracted subject for DB lookup: {subject!r}")

        for db_name, lookup_fn in [
            ('ScamAdviser', lookup_scamadviser),
            ('ScamWave',    lookup_scamwave),
            ('Trustpilot',  lookup_trustpilot),
            ('Sitejabber',  lookup_sitejabber),
            ('Tranco',      lookup_tranco),
        ]:
            try:
                db_result = lookup_fn(subject)
                if db_result and db_result.get('content'):
                    snippet = db_result['content'][:1200]
                    db_context_parts.append(
                        f"### Kết quả {db_name} cho '{subject}'\n{snippet}"
                    )
                    logger.debug(
                        f"analyze_text_for_scam: {db_name} returned "
                        f"{len(db_result['content'])} chars"
                    )
                else:
                    logger.debug(f"analyze_text_for_scam: {db_name} returned no content")
            except Exception as exc:
                logger.warning(f"analyze_text_for_scam: {db_name} lookup failed ({exc})")

        # ------------------------------------------------------------------
        # Step 2: Agentic web-search enrichment
        # ------------------------------------------------------------------
        try:
            search_query = text[:300] + ('...' if len(text) > 300 else '')
            logger.debug(f"analyze_text_for_scam: search_agent query: {search_query!r}")

            agent_answer = search_agent(
                query=(
                    f"Kiểm tra xem trang/nội dung sau có phải là lừa đảo không: {search_query}\n"
                    "Sử dụng các công cụ theo thứ tự sau:\n"
                    f"1. _tool_lookup_scamadviser — kiểm tra độ tin cậy của tên miền chính trong văn bản\n"
                    f"2. _tool_lookup_scamwave    — tìm báo cáo lừa đảo về số điện thoại/tài khoản/tên trong văn bản\n"
                    f"3. _tool_lookup_trustpilot  — kiểm tra điểm số và đánh giá người dùng trên Trustpilot\n"
                    f"4. _tool_lookup_sitejabber  — kiểm tra điểm số và đánh giá người dùng trên Sitejabber\n"
                    f"5. _tool_lookup_tranco      — kiểm tra thứ hạng mức độ phổ biến (Tranco Rank). Xếp hạng càng nhỏ (vd < 1000) càng uy tín.\n"
                    "6. _tool_web_search         — tìm đánh giá trên Reddit, v.v. (dùng query 'site:reddit.com <domain>', ...)\n"
                    "QUAN TRỌNG: Tập trung vào việc kiểm tra chính trang/nội dung được cung cấp có phải là lừa đảo không.\n"
                    "Trình bày kết quả theo định dạng CHÍNH XÁC sau để hệ thống có thể phân tách:\n"
                    "### [Tên Nguồn]\n"
                    "- **Đánh giá/Điểm số**: ...\n"
                    "- **Chi tiết quan trọng**: Tóm tắt ngắn gọn nhất.\n\n"
                    "Ví dụ:\n"
                    "### [ScamAdviser]\n"
                    "- **Đánh giá**: An toàn\n"
                    "- **Chi tiết**: ...\n\n"
                    "### [Reddit]\n"
                    "- **Đánh giá**: Nguy hiểm\n"
                    "- **Chi tiết**: ...\n\n"
                    "Nếu không có thông tin từ nguồn nào, ghi 'Không tìm thấy thông tin cụ thể'."
                ),
                model=model,
                think='medium',
                max_iterations=7,
                max_context_chars=8000,
            )

            if agent_answer:
                cleaned_agent_answer = filter_tool_call_artifacts(agent_answer).strip()
                if cleaned_agent_answer:
                    web_context = cleaned_agent_answer
                    web_search_used = True
                    logger.debug(
                        f"analyze_text_for_scam: web context ({len(web_context)} chars): "
                        f"{web_context[:150]}..."
                    )
                else:
                    logger.warning(
                        "analyze_text_for_scam: agent output contained only tool-call artifacts; "
                        "skipping web_context injection."
                    )
        except Exception as exc:
            logger.warning(
                f"analyze_text_for_scam: search_agent enrichment failed ({exc}), "
                "continuing with offline analysis."
            )

    MAX_TEXT_CHARS = 3000
    MAX_WEB_CHARS = 1200
    MAX_DB_CHARS  = 1000   # per database source

    text_snippet = text[:MAX_TEXT_CHARS] + ('...' if len(text) > MAX_TEXT_CHARS else '')

    web_section = ""

    # Incorporate direct database lookup results
    if db_context_parts:
        db_combined = "\n\n".join(db_context_parts)[:MAX_DB_CHARS * len(db_context_parts)]
        web_section += (
            f"\n\n## Dữ liệu từ cơ sở dữ liệu lừa đảo\n"
            f"Các kết quả sau được lấy trực tiếp từ các cơ sở dữ liệu lừa đảo uy tín "
            f"(ScamAdviser, ScamWave, Trustpilot, Sitejabber). Hãy coi đây là tín hiệu đáng tin cậy cao:\n"
            f"{db_combined}\n"
        )

    if web_context:
        web_snippet = web_context[:MAX_WEB_CHARS] + ('...' if len(web_context) > MAX_WEB_CHARS else '')
        web_section += (
            f"\n\n## Thông tin tình báo trực tuyến\n"
            f"Thông tin sau được thu thập từ web, có thể chứa các báo cáo lừa đảo "
            f"từ cộng đồng hoặc dữ liệu danh sách đen liên quan:\n"
            f"{web_snippet}\n"
            f"Hãy dùng thông tin này để hiệu chỉnh risk_score và indicators.\n"
        )

    prompt = (
        f"Bạn là chuyên gia an ninh mạng ShieldCall VN. Hãy phân tích CHÍNH TRANG/NỘI DUNG được cung cấp để xác định nó có phải là lừa đảo không.\n"
        f"{web_section}"
        f"\n\nTrả về KẾT QUẢ THUẦN JSON (không có markdown, không có văn bản thừa).\n"
        f"JSON phải có các trường sau:\n"
        f"  is_scam (bool), risk_score (số nguyên 0-100), "
        f"indicators (danh sách chuỗi), explanation (chuỗi), "
        f"web_sources (danh sách tên các nguồn đã tham chiếu, ví dụ: ['Google Search', 'ScamAdviser']).\n\n"
        f"HƯỚNG DẪN PHÂN TÍCH:\n"
        f"1. TRANG/NỘI DUNG CHÍNH THỨC/AN TOÀN: Nếu đây là trang chính thức của một tổ chức uy tín, đánh giá là an toàn.\n"
        f"2. TRANG LỪA ĐẢO: Nếu trang này giả mạo, lừa đảo, hoặc có dấu hiệu gian lận, đánh giá rủi ro cao.\n"
        f"3. SỬ DỤNG THÔNG TIN TÌNH BÁO: Dựa vào kết quả từ ScamAdviser, ScamWave và các báo cáo để đưa ra kết luận.\n\n"
        f"Lưu ý: 'indicators' chứa những dấu hiệu lừa đảo được tìm thấy, nếu thông tin không liên quan thì không ghi vào.\n"
        f"HƯỚNG DẪN cho 'explanation':\n"
        f"1. Viết bằng TIẾNG VIỆT, dành cho người dùng không chuyên kỹ thuật.\n"
        f"2. Nếu AN TOÀN: Chỉ nêu đây là trang chính thức/hợp lệ của tổ chức.\n"
        f"3. Nếu LỪA ĐẢO: Giải thích rõ tại sao (giả mạo thương hiệu, yêu cầu thông tin nhạy cảm, v.v.).\n"
        f"4. Tập trung vào CHÍNH TRANG này, không nhắc đến việc tìm kiếm trang giả mạo khác.\n\n"
        f"Nội dung cần phân tích:\n{text_snippet}"
    )

    response = generate_response(
        prompt, model, num_ctx=8192, max_tokens=2048, tools=[], format_schema=SCAM_ANALYSIS_SCHEMA
    )

    db_sources_consulted = ['scamadviser', 'scamwave', 'trustpilot', 'sitejabber', 'tranco'] if db_context_parts else []

    if response:
        result = json.loads(response)
        if result:
            result['web_context'] = web_context
            result['web_search_used'] = web_search_used
            result['db_sources_consulted'] = db_sources_consulted
            return result
        logger.warning("analyze_text_for_scam: _extract_json returned None — raw response: %s",
                       response[:300])

    return {
        "is_scam": False,
        "risk_score": 0,
        "indicators": [],
        "explanation": "Phân tích thất bại hoặc quá thời gian",
        "web_sources": db_sources_consulted if db_sources_consulted else ["Offline Analysis"],
        "web_context": web_context,
        "web_search_used": web_search_used,
        "db_sources_consulted": db_sources_consulted,
    }
