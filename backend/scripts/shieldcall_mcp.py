#!/usr/bin/env python3
"""
ShieldCall VN - Standalone Model Context Protocol (MCP) Server
Integrates cybersecurity, anti-fraud intelligence, and threat detection
into any MCP-compatible AI client: Claude Desktop, Cursor, Windsurf, Claude Code, Cline, ChatGPT.

Architecture:
    - Standard library only (sys, json, urllib, http, ssl). Zero external package dependencies.
    - Full compliance with Model Context Protocol specification (JSON-RPC 2.0).
    - Supports both stdio (desktop AI clients) and SSE transport modes.

Usage:
1. Claude Desktop (claude_desktop_config.json):
{
  "mcpServers": {
    "shieldcall": {
      "command": "python",
      "args": ["/absolute/path/to/shieldcall_mcp.py"],
      "env": {
        "SHIELDCALL_API_KEY": "sc_live_your_api_key_here",
        "SHIELDCALL_API_URL": "https://sc.fptoj.com/api/v1"
      }
    }
  }
}

2. Cursor IDE (.cursor/mcp.json):
{
  "mcpServers": {
    "shieldcall": {
      "command": "python",
      "args": ["/absolute/path/to/shieldcall_mcp.py"],
      "env": {
        "SHIELDCALL_API_KEY": "sc_live_your_api_key_here",
        "SHIELDCALL_API_URL": "https://sc.fptoj.com/api/v1"
      }
    }
  }
}

3. Network SSE Transport:
    python shieldcall_mcp.py --transport sse --host 127.0.0.1 --port 8002
"""

import os
import sys
import json
import time
import logging
import argparse
import inspect
import queue
import threading
import uuid
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Callable, Tuple
from urllib import request as urllib_request
from urllib import error as urllib_error
from urllib import parse as urllib_parse
import ssl

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("shieldcall_mcp")


def _mask_identifier(kind: str, value: str) -> str:
    """Minimize PII in human-readable MCP threat summaries without blinding identifiers."""
    raw = (value or "").strip()
    if not raw:
        return ""
    if kind == "phone":
        digits = re.sub(r"\s+", "", raw)
        return f"{digits[:4]}****{digits[-2:]}" if len(digits) > 6 else "***"
    if kind == "account":
        return f"****{raw[-4:]}" if len(raw) > 4 else "****"
    if kind == "email" and "@" in raw:
        local, dom = raw.split("@", 1)
        head = local[:2] if len(local) >= 2 else (local[:1] or "*")
        return f"{head}***@{dom}"
    return raw


# ==============================================================================
# 1. SHIELDCALL REST API CLIENT (urllib implementation)
# ==============================================================================

class ShieldCallClient:
    """Client for querying ShieldCall VN cybersecurity and scam intelligence REST APIs."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        raw_url = api_url or os.getenv("SHIELDCALL_API_URL", "https://sc.fptoj.com/api/v1")
        self.api_url = raw_url.rstrip("/")
        self.api_key = api_key or os.getenv("SHIELDCALL_API_KEY", "")
        self.timeout = timeout
        self._ssl_ctx = ssl.create_default_context()
        self._cache: Dict[str, Tuple[float, Any]] = {}
        self._cache_lock = threading.Lock()

    def _cached(self, key: str, ttl_sec: int, loader: Callable[[], Any]) -> Any:
        now = time.monotonic()
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is not None and entry[0] > now:
                return entry[1]
        val = loader()
        if isinstance(val, (dict, list)) and not (isinstance(val, dict) and val.get("error")):
            with self._cache_lock:
                self._cache[key] = (time.monotonic() + ttl_sec, val)
        return val

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ShieldCall-MCP-Client/1.0",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(
        self,
        method: str,
        endpoint: str,
        data: Optional[Dict] = None,
        params: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        url = f"{self.api_url}/{endpoint.lstrip('/')}"
        if params:
            query_str = urllib_parse.urlencode(params)
            url = f"{url}?{query_str}"

        req_body = None
        if data is not None and method in ("POST", "PUT", "PATCH"):
            req_body = json.dumps(data).encode("utf-8")

        req = urllib_request.Request(
            url=url,
            data=req_body,
            headers=self._headers(),
            method=method,
        )

        try:
            with urllib_request.urlopen(req, timeout=self.timeout, context=self._ssl_ctx) as response:
                resp_bytes = response.read()
                resp_text = resp_bytes.decode("utf-8")
                try:
                    return json.loads(resp_text)
                except Exception:
                    return {"raw": resp_text}
        except urllib_error.HTTPError as e:
            status_code = e.code
            try:
                err_text = e.read().decode("utf-8")
                err_data = json.loads(err_text)
            except Exception:
                err_data = None
                err_text = ""

            if status_code == 401:
                return {
                    "error": (
                        "API Key authentication failed (401 Unauthorized). "
                        "Please verify the SHIELDCALL_API_KEY environment variable."
                    )
                }
            if status_code == 429:
                detail = (err_data.get("detail") if isinstance(err_data, dict) else err_text) or "Daily or rate quota exceeded."
                return {"error": f"API rate limit or quota exceeded (429): {detail}"}

            if err_data and isinstance(err_data, dict):
                return {"error": f"API Error ({status_code}): {err_data.get('error') or err_data}"}
            return {"error": f"API Error ({status_code}): {err_text[:300]}"}
        except urllib_error.URLError as e:
            return {
                "error": (
                    f"Unable to connect to ShieldCall host at {self.api_url}. "
                    f"Reason: {e.reason}. Please verify network connectivity."
                )
            }
        except TimeoutError:
            return {"error": f"Request timeout after {self.timeout}s from ShieldCall API."}
        except Exception as e:
            return {"error": f"Exception during ShieldCall API request: {str(e)}"}

    def scan_phone(self, phone: str) -> Dict[str, Any]:
        """Scan and evaluate fraud risk for a phone number."""
        return self._request("POST", "scan/phone/", data={"phone": (phone or "").strip()})

    def scan_bank_account(self, bank: str, account: str) -> Dict[str, Any]:
        """Verify a bank account number against financial scam databases."""
        return self._request("POST", "scan/account/", data={"bank": (bank or "").strip(), "account": (account or "").strip()})

    def scan_domain(self, url: str) -> Dict[str, Any]:
        """Analyze a URL or domain for phishing, lookalike indicators, and security status."""
        return self._request("POST", "scan/domain/", data={"url": (url or "").strip(), "deep_scan": False})

    def scan_message(self, message: str) -> Dict[str, Any]:
        """Analyze message text or SMS content for scam scripts and social engineering patterns."""
        return self._request("POST", "scan/message/", data={"message": (message or "").strip(), "sync": True})

    def scan_email(self, email: str, content: str = "", subject: str = "") -> Dict[str, Any]:
        """Inspect email address, authentication headers (SPF/DMARC), and content for fraud."""
        return self._request(
            "POST",
            "scan/email/",
            data={
                "email": (email or "").strip(),
                "content": (content or "").strip(),
                "subject": (subject or "").strip(),
                "sync": True,
            },
        )

    def get_supported_banks(self) -> Any:
        """Retrieve verified Vietnamese banks with BIN codes and identifiers."""
        return self._cached("scan/banks/", 3600, lambda: self._request("GET", "scan/banks/"))

    def lookup_scam_db(self, query: str, entity_type: str = "all") -> Dict[str, Any]:
        """Query threat and scam database records by keyword or identifier."""
        return self._request("GET", "scan/lookup/", params={"q": (query or "").strip(), "type": (entity_type or "all").strip()})

    def get_scam_radar_trends(self) -> Dict[str, Any]:
        """Retrieve real-time scam statistics and prevalent regional threat patterns."""
        return self._cached("trends/radar-stats/", 300, lambda: self._request("GET", "trends/radar-stats/"))

    def get_trust_sources(self) -> Dict[str, Any]:
        """Retrieve reliability catalog, source update timestamps, and limitations."""
        return self._cached("trust/sources/", 1800, lambda: self._request("GET", "trust/sources/"))

    def get_trust_channels(self) -> Dict[str, Any]:
        """Retrieve verified Vietnamese official anti-fraud channels and hotlines."""
        return self._cached("trust/channels/", 1800, lambda: self._request("GET", "trust/channels/"))

    def get_trust_policy(self) -> Dict[str, Any]:
        """Retrieve ShieldCall Trust Guardrail and privacy policy metadata."""
        return self._cached("trust/policy/", 1800, lambda: self._request("GET", "trust/policy/"))

    @staticmethod
    def normalize_scam_type(scam_type: str) -> str:
        s = (scam_type or "").strip().lower()
        mapping = {
            "impersonation": "police_impersonation",
            "police": "police_impersonation",
            "bank": "bank_impersonation",
            "otp": "otp_steal",
            "recruitment": "recruitment_scam",
            "job": "recruitment_scam",
            "investment": "investment_scam",
            "delivery": "delivery_scam",
            "loan": "loan_scam",
            "romance": "romance_scam",
        }
        valid = {
            "police_impersonation",
            "bank_impersonation",
            "recruitment_scam",
            "investment_scam",
            "delivery_scam",
            "loan_scam",
            "otp_steal",
            "phishing",
            "romance_scam",
            "other",
        }
        return s if s in valid else mapping.get(s, "other")

    def report_scam(
        self,
        target_type: str,
        target_value: str,
        scam_type: str,
        description: str,
        evidence_note: str = "",
    ) -> Dict[str, Any]:
        """Submit a scam incident report to the moderation database."""
        norm_val = (target_value or "").strip()
        if target_type == "phone":
            cleaned = re.sub(r"[\s\-\.]", "", norm_val)
            if cleaned.startswith("0") and len(cleaned) == 10:
                norm_val = "+84" + cleaned[1:]

        payload = {
            "target_type": (target_type or "").strip(),
            "target_value": norm_val,
            "scam_type": self.normalize_scam_type(scam_type),
            "description": (description or "").strip(),
            "evidence_note": (evidence_note or "").strip(),
        }
        return self._request("POST", "report/", data=payload)


# ==============================================================================
# 2. SYSTEM PERSONA PROMPTS
# ==============================================================================

SHIELDCALL_SENTRY_PROMPT = """You are the ShieldCall Sentry assistant, an automated cybersecurity and anti-fraud copilot integrated with the ShieldCall VN threat intelligence platform.

### Core Operational Principles:
1. Proactive Tool Dispatch:
   - For multi-entity incidents (phone numbers, URLs, bank accounts, emails, messages), invoke `scan_full_incident` to run parallel multi-vector inspection in one call.
   - For isolated indicators, invoke the corresponding MCP tool before formulating conclusions:
     - `check_phone`: Inspect phone numbers (+84, local prefixes) against blacklists, telecom metadata, and VoIP/virtual indicators.
     - `check_bank_account`: Verify bank account numbers and beneficiary institutions against financial fraud records (separates verified vs pending reports).
     - `check_url_or_domain`: Inspect domains/URLs for phishing signatures, lookalike domains, Tín nhiệm mạng, VirusTotal, SSL, and WHOIS age.
     - `analyze_message`: Parse SMS/chat text for Vietnamese social engineering scripts and scam patterns.
     - `check_email_sender`: Inspect sender domains for SPF/DKIM/DMARC alignment and phishing heuristics.
     - `get_supported_banks`: Retrieve Vietnamese bank codes and BIN registry.
     - `lookup_scam_db` / `get_scam_radar_trends`: Query archived scam reports and live regional trends.
   - Use MCP resources (`shieldcall://trust/sources`, `shieldcall://trust/channels`, `shieldcall://trust/policy`) when users ask for data sources, update dates, or official VN verification hotlines.

2. Trust Guardrail & Risk Tiers (MANDATORY):
   - Always check `guardrail.tier`, `guardrail.is_conclusive`, `guardrail.has_contradiction`, and `evidence[]` (with `source` + `updated_at`) returned by ShieldCall tools.
   - `INSUFFICIENT` (`CHƯA ĐỦ CƠ SỞ XÁC MINH`): Missing data, gray-zone signals (10-39 without confirmation), pending community reports only, or conflicting sources (`has_contradiction=true`). NEVER claim an entity is "safe" or "definitely a scammer".
   - `LIKELY_SAFE`: Score < 10 backed by high-reliability benign verification (`tinnhiemmang` trusted or VirusTotal clean) and zero contradictions. Still advise verifying OTP/transfers carefully.
   - `SUSPICIOUS` (10-69 / unverified warnings): Recommend pausing transactions and verifying independently.
   - `HIGH_RISK` (>= 70 or verified community reports) & `CONFIRMED_RISK` (only domain/url/file corroborated by NCSC/ClamAV/YARA/VirusTotal >= 3): Recommend halting transfers immediately.
   - Strict Anti-Accusation Rule: For individuals, phone numbers, and bank accounts (`is_conclusive=false`), NEVER declare the holder is definitively a criminal/scammer. Cite the exact records and advise verification via official channels.

3. Privacy & Response Protocol:
   - Respect PII masking (`[SĐT đã ẩn]`, `****1234`, `ab***@domain`); analyze context normally without demanding unmasked personal IDs.
   - Always cite source `updated_at` / tool evidence and provide VN official channels when warning or uncertain (113 Police, 156 VNCERT/NCSC spam hotline, https://khonggianmang.vn, or the user's official bank hotline).
   - Direct users to `report_scam` only when corroborated scam evidence is confirmed.
"""

SHIELDCALL_EMERGENCY_PROMPT = """You are the ShieldCall Emergency Incident Responder for active Vietnamese financial fraud, credential phishing, or suspicious APK compromises.

### 4-Step Incident Response Protocol:
1. Step 1: Immediate Containment:
   - Instruct the user to call their issuing bank's official hotline immediately (refer to `shieldcall://trust/channels`) to lock cards, accounts, and suspend digital banking.
   - If an unverified `.APK` file was installed: enable Airplane Mode immediately to cut network access, revoke Accessibility permissions, and run malware scan without transferring funds or OTPs.
2. Step 2: Parallel Entity Triage:
   - Query `scan_full_incident`, `check_bank_account`, `check_phone`, or `lookup_scam_db` and report both `guardrail.tier` and cited `evidence[]` transparently (clearly distinguishing `pending` vs `verified` reports).
3. Step 3: Evidence Preservation:
   - Advise preserving screenshots of chat logs, transfer receipts / transaction reference codes, beneficiary bank details, URLs, and call timestamps without alerting suspects.
4. Step 4: Official Reporting:
   - Direct the user to file an official report with Police (113 / local cybercrime division) and NCSC/VNCERT (156 / `https://khonggianmang.vn`), and optionally log anonymized indicators via `report_scam`.
"""

SHIELDCALL_INVESTIGATOR_PROMPT = """You are a Cyber Fraud Investigation and Forensic Analyst with ShieldCall VN.
Conduct evidence-cited technical triage across entities while respecting uncertainty guardrails:
- Domain Analysis: Check Tín nhiệm mạng status, VirusTotal consensus, typosquatting distance, WHOIS domain age, DNS, and SSL validity via `check_url_or_domain`.
- Email Authentication: Validate SPF, DKIM, DMARC alignment and phishing cues via `check_email_sender`.
- Telephony Infrastructure: Check carrier prefix metadata, VoIP/virtual indicators, and moderation status via `check_phone` (without concluding subscriber criminal guilt).
- Banking Verification: Validate bank BIN/name via `get_supported_banks` and separate `reports_verified` from `reports_pending` via `check_bank_account`.
- Composite Triage: Run `scan_full_incident` for parallel correlation, report any `has_contradiction` explicitly as `INSUFFICIENT`, and list cited sources with `updated_at`.
"""


# ==============================================================================
# 3. ZERO-DEPENDENCY MCP PROTOCOL ENGINE
# ==============================================================================

class ZeroDepMCPServer:
    """
    Model Context Protocol (JSON-RPC 2.0) server implementation
    supporting stdio, SSE, and Streamable HTTP transports.
    """

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, name: str = "shieldcall-vn", version: str = "1.1.0"):
        self.name = name
        self.version = version
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.prompts: Dict[str, Dict[str, Any]] = {}
        self.resources: Dict[str, Dict[str, Any]] = {}

    def tool(self, name: Optional[str] = None):
        """Decorator to register an MCP tool."""
        def decorator(func: Callable):
            tool_name = name or func.__name__
            sig = inspect.signature(func)
            props: Dict[str, Any] = {}
            required: List[str] = []

            doc = (func.__doc__ or "").strip()
            param_docs: Dict[str, str] = {}
            if "Args:" in doc:
                args_section = doc.split("Args:")[1].split("Returns:")[0]
                for match in re.finditer(r"^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.+)$", args_section, re.MULTILINE):
                    param_docs[match.group(1).strip()] = match.group(2).strip()

            for param_name, param in sig.parameters.items():
                param_type = "string"
                if param.annotation is int:
                    param_type = "integer"
                elif param.annotation is bool:
                    param_type = "boolean"
                elif param.annotation is float:
                    param_type = "number"

                prop_def: Dict[str, Any] = {"type": param_type}
                if param_name in param_docs:
                    prop_def["description"] = param_docs[param_name]

                props[param_name] = prop_def
                if param.default is inspect.Parameter.empty:
                    required.append(param_name)

            self.tools[tool_name] = {
                "name": tool_name,
                "description": doc,
                "inputSchema": {
                    "type": "object",
                    "properties": props,
                    "required": required,
                },
                "param_names": set(sig.parameters.keys()),
                "required_params": list(required),
                "func": func,
            }
            return func
        return decorator

    def prompt(self, name: Optional[str] = None):
        """Decorator to register an MCP prompt."""
        def decorator(func: Callable):
            prompt_name = name or func.__name__
            self.prompts[prompt_name] = {
                "name": prompt_name,
                "description": (func.__doc__ or "").strip(),
                "func": func,
            }
            return func
        return decorator

    def resource(self, uri: str, name: str, description: str = "", mime_type: str = "application/json"):
        """Decorator to register a read-only MCP resource."""
        def decorator(func: Callable):
            self.resources[uri] = {
                "uri": uri,
                "name": name,
                "description": description or (func.__doc__ or "").strip(),
                "mimeType": mime_type,
                "func": func,
            }
            return func
        return decorator

    def handle_payload(self, payload: Any) -> Any:
        """Process either a single JSON-RPC 2.0 object or a JSON-RPC 2.0 batch list."""
        if isinstance(payload, list):
            if not payload:
                return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request: empty batch"}}
            responses = []
            for item in payload:
                if not isinstance(item, dict):
                    responses.append({"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}})
                    continue
                resp = self.handle_request(item)
                if resp is not None:
                    responses.append(resp)
            return responses if responses else None
        if not isinstance(payload, dict):
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "Invalid Request"}}
        return self.handle_request(payload)

    def handle_request(self, req: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Process a JSON-RPC 2.0 request and return the response."""
        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {}) or {}

        # Notifications (no id) -> do not send response
        if req_id is None and method:
            logger.debug("Received notification: %s", method)
            return None

        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": self.PROTOCOL_VERSION,
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "prompts": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                        "logging": {},
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version,
                    },
                },
            }

        if method == "ping":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "tools/list":
            tools_list = [
                {
                    "name": t["name"],
                    "description": t["description"],
                    "inputSchema": t["inputSchema"],
                }
                for t in self.tools.values()
            ]
            return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": tools_list}}

        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}

            if tool_name not in self.tools:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Error: Tool '{tool_name}' not found."}],
                        "isError": True,
                    },
                }

            tool_def = self.tools[tool_name]
            if not isinstance(arguments, dict):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: 'arguments' must be an object."},
                }
            param_names = tool_def.get("param_names")
            filtered_args = (
                {k: v for k, v in arguments.items() if k in param_names}
                if isinstance(param_names, set)
                else arguments
            )
            missing = [p for p in tool_def.get("required_params", []) if p not in filtered_args]
            if missing:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Missing required parameter(s) for {tool_name}: {', '.join(missing)}"}],
                        "isError": True,
                    },
                }
            try:
                result_val = tool_def["func"](**filtered_args)
                text_out = result_val if isinstance(result_val, str) else json.dumps(result_val, ensure_ascii=False)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": text_out}],
                        "isError": False,
                    },
                }
            except Exception as ex:
                logger.exception("Error executing tool %s: %s", tool_name, ex)
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{"type": "text", "text": f"Execution error in {tool_name}: {str(ex)}"}],
                        "isError": True,
                    },
                }

        if method == "prompts/list":
            prompts_list = [
                {"name": p["name"], "description": p["description"], "arguments": []}
                for p in self.prompts.values()
            ]
            return {"jsonrpc": "2.0", "id": req_id, "result": {"prompts": prompts_list}}

        if method == "prompts/get":
            prompt_name = params.get("name")
            lookup_key = (
                prompt_name.replace("-", "_")
                if isinstance(prompt_name, str) and prompt_name not in self.prompts
                else prompt_name
            )
            if lookup_key not in self.prompts:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Prompt '{prompt_name}' not found."},
                }

            prompt_def = self.prompts[lookup_key]
            prompt_text = prompt_def["func"]()
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "description": prompt_def["description"],
                    "messages": [
                        {
                            "role": "user",
                            "content": {"type": "text", "text": prompt_text},
                        }
                    ],
                },
            }

        if method == "resources/list":
            resources_list = [
                {
                    "uri": r["uri"],
                    "name": r["name"],
                    "description": r["description"],
                    "mimeType": r["mimeType"],
                }
                for r in self.resources.values()
            ]
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": resources_list}}

        if method == "resources/read":
            uri = params.get("uri")
            if uri not in self.resources:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": f"Resource '{uri}' not found."},
                }
            res_def = self.resources[uri]
            raw_val = res_def["func"]()
            text_out = raw_val if isinstance(raw_val, str) else json.dumps(raw_val, ensure_ascii=False)
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": res_def["mimeType"],
                            "text": text_out,
                        }
                    ]
                },
            }

        if method == "resources/templates/list":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resourceTemplates": []}}

        if method == "logging/setLevel":
            return {"jsonrpc": "2.0", "id": req_id, "result": {}}

        if method == "completion/complete":
            return {"jsonrpc": "2.0", "id": req_id, "result": {"completion": {"values": []}}}

        # Fallback for unsupported methods
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not implemented."},
        }

    def run_stdio(self):
        """Standard JSON-RPC 2.0 stdio read-write loop."""
        for stream in (sys.stdin, sys.stdout):
            if hasattr(stream, "reconfigure"):
                try:
                    stream.reconfigure(encoding="utf-8")
                except Exception:
                    pass

        logger.info("ShieldCall MCP Server listening on stdio...")
        stdin = sys.stdin
        stdout = sys.stdout

        while True:
            line = stdin.readline()
            if not line:
                break
            clean_line = line.strip()
            if not clean_line:
                continue

            try:
                req = json.loads(clean_line)
                res = self.handle_request(req)
                if res is not None:
                    out_json = json.dumps(res, ensure_ascii=False)
                    stdout.write(out_json + "\n")
                    stdout.flush()
            except json.JSONDecodeError:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": "Parse error: Invalid JSON"},
                }
                stdout.write(json.dumps(err_resp) + "\n")
                stdout.flush()
            except Exception as e:
                logger.exception("Unexpected error processing stdio line: %s", e)

    def run_sse(self, host: str = "127.0.0.1", port: int = 8002):
        """Standalone HTTP server handling Server-Sent Events (SSE) and JSON-RPC message posts."""
        from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler

        server_instance = self
        sessions: Dict[str, queue.Queue] = {}

        class SSEHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                logger.info("%s - - [%s] %s", self.client_address[0], self.log_date_time_string(), format % args)

            def do_OPTIONS(self):
                self.send_response(200)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
                self.end_headers()

            def do_GET(self):
                parsed = urllib_parse.urlparse(self.path)
                if parsed.path == "/sse":
                    session_id = uuid.uuid4().hex
                    q: queue.Queue = queue.Queue()
                    sessions[session_id] = q

                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.send_header("Cache-Control", "no-cache")
                    self.send_header("Connection", "keep-alive")
                    self.send_header("Access-Control-Allow-Origin", "*")
                    self.end_headers()

                    qs = urllib_parse.parse_qs(parsed.query)
                    api_key = qs.get("api_key", [None])[0]

                    messages_path = f"/messages?session_id={session_id}"
                    if api_key:
                        messages_path += f"&api_key={urllib_parse.quote(api_key)}"

                    # Send mandatory endpoint event
                    endpoint_msg = f"event: endpoint\ndata: {messages_path}\n\n"
                    self.wfile.write(endpoint_msg.encode("utf-8"))
                    self.wfile.flush()

                    logger.info("SSE client connected: session=%s", session_id)
                    try:
                        while True:
                            try:
                                msg = q.get(timeout=20)
                                event_payload = f"event: message\ndata: {json.dumps(msg, ensure_ascii=False)}\n\n"
                                self.wfile.write(event_payload.encode("utf-8"))
                                self.wfile.flush()
                            except queue.Empty:
                                self.wfile.write(b": keepalive\n\n")
                                self.wfile.flush()
                    except (ConnectionResetError, BrokenPipeError):
                        logger.info("SSE client disconnected: session=%s", session_id)
                    finally:
                        sessions.pop(session_id, None)
                else:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not Found")

            def do_POST(self):
                parsed = urllib_parse.urlparse(self.path)
                if parsed.path == "/messages":
                    qs = urllib_parse.parse_qs(parsed.query)
                    session_id = qs.get("session_id", [None])[0]

                    content_length = int(self.headers.get("Content-Length", 0))
                    body = self.rfile.read(content_length).decode("utf-8")

                    try:
                        req_data = json.loads(body)
                        res = server_instance.handle_request(req_data)
                        if res and session_id and session_id in sessions:
                            sessions[session_id].put(res)

                        self.send_response(202)
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(b'{"status": "accepted"}')
                    except Exception as err:
                        self.send_response(400)
                        self.send_header("Access-Control-Allow-Origin", "*")
                        self.end_headers()
                        self.wfile.write(json.dumps({"error": str(err)}).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()

        httpd = ThreadingHTTPServer((host, port), SSEHandler)
        logger.info(f"ShieldCall SSE Server listening at http://{host}:{port}/sse")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            logger.info("Stopping SSE server.")
            httpd.server_close()

    def run(self, transport: str = "stdio", host: str = "127.0.0.1", port: int = 8002):
        if transport == "stdio":
            self.run_stdio()
        elif transport in ("sse", "streamable-http"):
            self.run_sse(host=host, port=port)
        else:
            raise ValueError(f"Unknown transport: {transport}")


# ==============================================================================
# 4. SERVER INITIALIZATION & TOOL REGISTRATION
# ==============================================================================

def _dump_compact(data: Any) -> str:
    """Serialize tool output compactly without wasted indentation tokens."""
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def synthesize_incident_guardrail(entities_scanned: Dict[str, Any], max_score: int) -> Dict[str, Any]:
    """Synthesize evidence-aware multi-entity guardrail verdict for scan_full_incident."""
    tier_rank = {
        "CONFIRMED_RISK": 4,
        "HIGH_RISK": 3,
        "SUSPICIOUS": 2,
        "INSUFFICIENT": 1,
        "LIKELY_SAFE": 0,
    }
    tiers: List[str] = []
    has_contradiction = False
    evidences: List[Dict[str, Any]] = []
    seen_ev = set()
    official_channels: List[Dict[str, Any]] = []
    seen_ch = set()

    for kind, res in entities_scanned.items():
        if not isinstance(res, dict):
            continue
        g = res.get("guardrail") or {}
        if isinstance(g, dict):
            t = str(g.get("tier") or "")
            if t in tier_rank:
                tiers.append(t)
            if g.get("has_contradiction"):
                has_contradiction = True
            for ch in (g.get("official_channels") or []):
                if isinstance(ch, dict):
                    ch_key = ch.get("name") or ch.get("phone") or ch.get("url")
                    if ch_key and ch_key not in seen_ch:
                        seen_ch.add(ch_key)
                        official_channels.append(ch)
        for ev in (res.get("evidence") or []):
            if isinstance(ev, dict):
                ev_key = (ev.get("source"), ev.get("detail") or ev.get("summary"))
                if ev_key not in seen_ev:
                    seen_ev.add(ev_key)
                    evidences.append(ev)

    has_benign = any(t == "LIKELY_SAFE" for t in tiers)
    has_risk = any(t in ("SUSPICIOUS", "HIGH_RISK", "CONFIRMED_RISK") for t in tiers) or max_score >= 40
    if has_benign and has_risk:
        has_contradiction = True

    if not entities_scanned or has_contradiction:
        overall_tier = "INSUFFICIENT"
    elif tiers:
        top_tier = max(tiers, key=lambda t: tier_rank.get(t, 1))
        if top_tier == "LIKELY_SAFE" and any(t != "LIKELY_SAFE" for t in tiers):
            overall_tier = "INSUFFICIENT"
        else:
            overall_tier = top_tier
    else:
        if max_score >= 70:
            overall_tier = "HIGH_RISK"
        elif max_score >= 10:
            overall_tier = "SUSPICIOUS"
        else:
            overall_tier = "INSUFFICIENT"

    personal_only_flag = set(entities_scanned.keys()) <= {"phone", "bank_account"}
    is_conclusive = bool(
        overall_tier == "CONFIRMED_RISK"
        and not has_contradiction
        and not personal_only_flag
    )

    if overall_tier in ("CONFIRMED_RISK", "HIGH_RISK"):
        overall_level = "red"
        recommended_actions = [
            "[DANGER] Tạm dừng mọi giao dịch chuyển tiền tới tài khoản liên quan.",
            "[WARNING] Tuyệt đối không bấm liên kết lạ, cài tệp APK hoặc đọc mã OTP.",
            "[ACTION] Liên hệ ngay tổng đài chính thức của ngân hàng nếu đã phát sinh giao dịch.",
            "[VERIFY] Đối chiếu qua Công an (113), VNCERT/NCSC (156) hoặc https://khonggianmang.vn.",
        ]
    elif overall_tier == "SUSPICIOUS":
        overall_level = "yellow"
        recommended_actions = [
            "[WARNING] Có dấu hiệu đáng ngờ nhưng chưa đủ xác thực độc lập; tạm hoãn giao dịch.",
            "[VERIFY] Gọi trực tiếp tổng đài chính thức của tổ chức/ngân hàng để kiểm chứng.",
        ]
    elif overall_tier == "LIKELY_SAFE":
        overall_level = "green"
        recommended_actions = [
            "[INFO] Tín hiệu sạch từ nguồn tin cậy và chưa phát hiện mâu thuẫn; vẫn cảnh giác với yêu cầu chuyển tiền hoặc OTP.",
        ]
    else:
        overall_level = "yellow"
        recommended_actions = [
            "[INSUFFICIENT] Chưa đủ căn cứ nhất quán để kết luận an toàn hoặc lừa đảo.",
            "[VERIFY] Không kết luận vội; hãy xác minh qua kênh chính thức (113, 156, hotline ngân hàng) trước khi giao dịch.",
        ]

    return {
        "overall_tier": overall_tier,
        "overall_risk_level": overall_level,
        "recommended_actions": recommended_actions,
        "guardrail": {
            "tier": overall_tier,
            "is_conclusive": is_conclusive,
            "requires_verification": not is_conclusive,
            "has_contradiction": has_contradiction,
            "evidence_count": len(evidences),
            "official_channels": official_channels[:6],
            "cautions": [
                "Không tự khẳng định cá nhân/chủ tài khoản chắc chắn lừa đảo; chỉ trình bày bằng chứng đã đối chiếu.",
            ],
        },
        "evidence": evidences[:20],
    }


def create_server(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    server_name: str = "shieldcall-vn",
    client: Optional[Any] = None,
) -> ZeroDepMCPServer:
    """Initialize and register all tools, prompts, and resources for ShieldCall MCP Server."""
    client = client or ShieldCallClient(api_url=api_url, api_key=api_key)
    server = ZeroDepMCPServer(server_name)

    @server.tool()
    def check_phone(phone_number: str) -> str:
        """
        Evaluate scam and fraud risk for a phone number.
        Inspects blacklists, community reports, carrier metadata, and VoIP/virtual indicators.

        Args:
            phone_number: Phone number to evaluate (e.g., '0912345678', '+84988776655').
        """
        data = client.scan_phone((phone_number or "").strip())
        return _dump_compact(data)

    @server.tool()
    def check_bank_account(bank_name: str, account_number: str) -> str:
        """
        Check a bank account against financial fraud and community scam databases.

        Args:
            bank_name: Bank code or name (e.g., 'MB', 'Techcombank', 'VCB', 'VietinBank').
            account_number: Bank account number to verify.
        """
        data = client.scan_bank_account(bank=(bank_name or "").strip(), account=(account_number or "").strip())
        return _dump_compact(data)

    @server.tool()
    def check_url_or_domain(url: str) -> str:
        """
        Analyze a URL or domain to detect phishing sites, brand lookalike domains,
        SSL certificate issues, and suspicious domain registration age.

        Args:
            url: URL or domain name to inspect (e.g., 'https://vietcombank-ebank.xyz', 'dichvucong-vn.top').
        """
        data = client.scan_domain((url or "").strip())
        return _dump_compact(data)

    @server.tool()
    def analyze_message(message_content: str) -> str:
        """
        Analyze message or SMS text to detect social engineering and scam scripts
        (impersonation, lottery scams, fake law enforcement, urgent OTP requests).

        Args:
            message_content: Full text of the suspicious message or dialogue.
        """
        data = client.scan_message((message_content or "").strip())
        return _dump_compact(data)

    @server.tool()
    def lookup_scam_db(query: str, entity_type: str = "all") -> str:
        """
        Search the ShieldCall community threat and scam database.

        Args:
            query: Keyword, phone number, account number, target name, or URL.
            entity_type: Filter category ('all', 'phone', 'account', 'domain', 'report').
        """
        data = client.lookup_scam_db(query=(query or "").strip(), entity_type=(entity_type or "all").strip())
        return _dump_compact(data)

    @server.tool()
    def get_scam_radar_trends() -> str:
        """
        Retrieve real-time regional scam trends and prevalent threat patterns (Scam Radar).
        """
        data = client.get_scam_radar_trends()
        return _dump_compact(data)

    @server.tool()
    def get_supported_banks() -> str:
        """
        Retrieve the list of supported Vietnamese banks with BIN codes, short names, and identifiers.
        """
        data = client.get_supported_banks()
        return _dump_compact(data)

    @server.tool()
    def check_email_sender(
        sender_email: str,
        email_content: str = "",
        email_subject: str = "",
    ) -> str:
        """
        Evaluate email fraud risk: check SPF, DKIM, DMARC, blacklist status, and phishing heuristics.

        Args:
            sender_email: Sender email address (e.g., 'alert@support-vietcombank.com').
            email_content: Body content of the email.
            email_subject: Subject line of the email.
        """
        data = client.scan_email(
            email=(sender_email or "").strip(),
            content=(email_content or "").strip(),
            subject=(email_subject or "").strip(),
        )
        return _dump_compact(data)

    @server.tool()
    def scan_full_incident(
        message_content: str = "",
        phone_number: str = "",
        bank_name: str = "",
        account_number: str = "",
        url: str = "",
        sender_email: str = "",
    ) -> str:
        """
        Perform a unified parallel multi-entity security assessment for a suspected scam incident.
        Concurrently checks phone numbers, bank accounts, domains, emails, and message text,
        then synthesizes an evidence-backed guardrail assessment without echoing raw PII.

        Args:
            message_content: Suspicious message or narrative text.
            phone_number: Associated phone number.
            bank_name: Bank name or code provided by the suspect.
            account_number: Bank account number provided by the suspect.
            url: Suspicious link or domain.
            sender_email: Sender email address.
        """
        t0 = time.monotonic()
        p_val = (phone_number or "").strip()
        b_name = (bank_name or "").strip()
        a_val = (account_number or "").strip()
        u_val = (url or "").strip()
        e_val = (sender_email or "").strip()
        m_val = (message_content or "").strip()

        wrap_worker = getattr(client, "_wrap_worker", None)
        jobs: List[Tuple[str, Callable[[], Any]]] = []
        if p_val:
            jobs.append(("phone", lambda: client.scan_phone(p_val)))
        if a_val:
            jobs.append(("bank_account", lambda: client.scan_bank_account(bank=b_name or "Other", account=a_val)))
        if u_val:
            jobs.append(("url", lambda: client.scan_domain(u_val)))
        if e_val:
            jobs.append(("email", lambda: client.scan_email(email=e_val, content=m_val)))
        if m_val:
            jobs.append(("message", lambda: client.scan_message(m_val)))

        entities_scanned: Dict[str, Any] = {}
        if len(jobs) > 1:
            with ThreadPoolExecutor(max_workers=min(5, len(jobs))) as pool:
                future_map = {
                    pool.submit(wrap_worker(fn) if callable(wrap_worker) else fn): key
                    for key, fn in jobs
                }
                for fut in as_completed(future_map):
                    key = future_map[fut]
                    try:
                        entities_scanned[key] = fut.result()
                    except Exception as exc:
                        entities_scanned[key] = {"error": str(exc)}
        elif len(jobs) == 1:
            key, fn = jobs[0]
            try:
                entities_scanned[key] = fn()
            except Exception as exc:
                entities_scanned[key] = {"error": str(exc)}

        all_threats: List[str] = []
        max_score = 0

        for key in ("phone", "bank_account", "url", "email", "message"):
            res = entities_scanned.get(key)
            if not isinstance(res, dict):
                continue
            max_score = max(max_score, int(res.get("risk_score", 0) or 0))
            if key == "phone":
                masked_p = res.get("phone_masked") or _mask_identifier("phone", p_val)
                for d in (res.get("details") or []):
                    all_threats.append(f"[Phone {masked_p}] {d}")
            elif key == "bank_account":
                masked_a = res.get("account_masked") or _mask_identifier("account", a_val)
                bank_lbl = res.get("bank") or b_name or "Bank"
                for d in (res.get("details") or []):
                    all_threats.append(f"[Bank {bank_lbl} {masked_a}] {d}")
            elif key == "url":
                for d in (res.get("details") or []):
                    all_threats.append(f"[URL {res.get('domain') or u_val}] {d}")
            elif key == "email":
                masked_e = res.get("email") or _mask_identifier("email", e_val)
                for c in (res.get("security_checks") or []):
                    all_threats.append(f"[Email {masked_e}] {c}")
            elif key == "message":
                for p in (res.get("patterns_found") or []):
                    all_threats.append(f"[Message Pattern] {p}")
                if res.get("explanation"):
                    all_threats.append(f"[AI Assessment] {res.get('explanation')}")

        synth = synthesize_incident_guardrail(entities_scanned, max_score)
        composite_report = {
            "overall_risk_score": max_score,
            "overall_risk_level": synth["overall_risk_level"],
            "overall_tier": synth["overall_tier"],
            "guardrail": synth["guardrail"],
            "evidence": synth["evidence"],
            "entities_scanned": entities_scanned,
            "detected_threats": all_threats,
            "recommended_actions": synth["recommended_actions"],
            "entities_count": len(entities_scanned),
            "latency_ms": round((time.monotonic() - t0) * 1000.0, 1),
        }
        return _dump_compact(composite_report)

    @server.tool()
    def report_scam(
        target_type: str,
        target_value: str,
        scam_type: str,
        description: str,
        evidence_note: str = "",
    ) -> str:
        """
        Submit a new scam report to the ShieldCall moderation system.

        Args:
            target_type: Target category ('phone', 'account', 'domain', 'message', 'qr', 'email', 'file', 'audio', 'social', 'crypto').
            target_value: Target identifier (phone number, account number, URL, etc.).
            scam_type: Scam classification ('police_impersonation', 'bank_impersonation', 'recruitment_scam', 'investment_scam', 'delivery_scam', 'phishing', 'other').
            description: Detailed incident narrative and sequence of events.
            evidence_note: Supporting evidence notes (transaction ID, timestamps, etc.).
        """
        data = client.report_scam(
            target_type=(target_type or "").strip(),
            target_value=(target_value or "").strip(),
            scam_type=(scam_type or "other").strip(),
            description=(description or "").strip(),
            evidence_note=(evidence_note or "").strip(),
        )
        return _dump_compact(data)

    # --------------------------------------------------------------------------
    # RESOURCES (VN Official Channels, Source Reliability Catalog, Trust Policy)
    # --------------------------------------------------------------------------

    @server.resource(
        uri="shieldcall://trust/sources",
        name="ShieldCall Source Catalog",
        description="Danh mục 16 nguồn phân tích, ngày cập nhật (updated_at), độ tin cậy và giới hạn công cụ.",
    )
    def trust_sources_resource() -> Any:
        return client.get_trust_sources() if hasattr(client, "get_trust_sources") else {"sources": []}

    @server.resource(
        uri="shieldcall://trust/channels",
        name="Vietnam Official Verification Channels",
        description="Kênh xác minh & trình báo chính thức tại Việt Nam (113, 156, NCSC, 39 ngân hàng/ví).",
    )
    def trust_channels_resource() -> Any:
        return client.get_trust_channels() if hasattr(client, "get_trust_channels") else {"channels": []}

    @server.resource(
        uri="shieldcall://trust/policy",
        name="ShieldCall Trust Guardrail & Privacy Policy",
        description="Nguyên tắc kiểm soát kết luận vùng xám, vai trò AI và chính sách che PII.",
    )
    def trust_policy_resource() -> Any:
        return client.get_trust_policy() if hasattr(client, "get_trust_policy") else {}

    # --------------------------------------------------------------------------
    # PROMPTS
    # --------------------------------------------------------------------------

    @server.prompt()
    def shieldcall_sentry() -> str:
        """Operational prompt configuring the model as a proactive cybersecurity sentry."""
        return SHIELDCALL_SENTRY_PROMPT

    @server.prompt()
    def emergency_advisor() -> str:
        """Incident response prompt for acute fraud emergencies and containment."""
        return SHIELDCALL_EMERGENCY_PROMPT

    @server.prompt()
    def scam_investigator() -> str:
        """Technical investigation prompt for deep forensic indicator inspection."""
        return SHIELDCALL_INVESTIGATOR_PROMPT

    return server


# ==============================================================================
# 5. CLI ENTRYPOINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ShieldCall VN - Model Context Protocol (MCP) Server"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="MCP transport mode (default: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8002,
        help="Port for SSE network transport (default: 8002)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address for network transport (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default=None,
        help="ShieldCall backend API endpoint (e.g., https://sc.fptoj.com/api/v1)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="ShieldCall API Key (e.g., sc_live_...)",
    )

    args = parser.parse_args()

    server = create_server(api_url=args.api_url, api_key=args.api_key)

    if args.transport == "stdio":
        server.run(transport="stdio")
    elif args.transport in ("sse", "streamable-http"):
        server.run(transport="sse", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
