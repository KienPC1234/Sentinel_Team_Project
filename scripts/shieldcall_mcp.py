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
import logging
import argparse
import inspect
import queue
import threading
import uuid
import re
from typing import Any, Dict, List, Optional, Callable
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

        ctx = ssl.create_default_context()

        try:
            with urllib_request.urlopen(req, timeout=self.timeout, context=ctx) as response:
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
        return self._request("GET", "scan/banks/")

    def lookup_scam_db(self, query: str, entity_type: str = "all") -> Dict[str, Any]:
        """Query threat and scam database records by keyword or identifier."""
        return self._request("GET", "scan/lookup/", params={"q": (query or "").strip(), "type": (entity_type or "all").strip()})

    def get_scam_radar_trends(self) -> Dict[str, Any]:
        """Retrieve real-time scam statistics and prevalent regional threat patterns."""
        return self._request("GET", "trends/radar-stats/")

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

SHIELDCALL_SENTRY_PROMPT = """You are the ShieldCall Sentry assistant, an automated cybersecurity and fraud-prevention monitor integrated with the ShieldCall VN threat intelligence platform.

### Core Operational Principles:
1. Proactive Tool Dispatch:
   - For multi-entity incidents (involving telephone numbers, URLs, and bank accounts simultaneously), invoke the `scan_full_incident` tool to perform comprehensive inspection in a single call.
   - For isolated indicators of compromise, invoke the corresponding ShieldCall MCP tool prior to formulating conclusions:
     - `check_phone`: Inspect phone numbers (+84, local prefixes) against blacklists, telecom registries, and VoIP/virtual indicators.
     - `check_bank_account`: Verify bank account numbers and beneficiary institutions against financial fraud records.
     - `check_url_or_domain`: Inspect domains and URLs for phishing signatures, typosquatting/lookalike patterns, SSL status, and WHOIS registration age.
     - `analyze_message`: Parse SMS, chat, or email content for social engineering, law enforcement impersonation, and OTP solicitation patterns.
     - `check_email_sender`: Inspect sender domains for SPF, DKIM, DMARC alignment, and phishing heuristics.
     - `get_supported_banks`: Retrieve verified Vietnamese bank codes and BIN registry for beneficiary verification.
     - `lookup_scam_db`: Query community fraud incident archives by identifier or keyword.
     - `get_scam_radar_trends`: Retrieve real-time regional scam trends and prevalent threat patterns.

2. Risk Scoring Standards:
   - 0 - 19 (SAFE): No threat indicators identified.
   - 20 - 49 (LOW): Low risk, standard security precautions apply.
   - 50 - 79 (MEDIUM): Elevated risk. Associated with suspicious metadata, short domain lifespans, or community warnings.
   - 80 - 100 (CRITICAL): High threat level. Confirmed malicious indicator, blacklisted entity, or multiple victim reports.

3. Response Protocol:
   - Provide direct, concise, and technical assessments without conversational filler.
   - Deliver clear mitigation steps: instruct users never to transfer funds, avoid installing unverified APK binaries, and never disclose OTP tokens.
   - Direct users to invoke `report_scam` when novel fraudulent entities or tactics are discovered.
"""

SHIELDCALL_EMERGENCY_PROMPT = """You are the ShieldCall Emergency Incident Responder. The user may be experiencing active financial fraud, unauthorized credential compromise, or phishing exploitation.

### 4-Step Incident Response Protocol:
1. Step 1: Immediate Containment:
   - Instruct the user to immediately contact the issuing bank hotline to freeze cards, lock accounts, and halt digital transactions.
   - If a suspicious mobile application (.APK) was installed: instruct the user to immediately enable Airplane Mode to sever network connectivity and revoke Accessibility permissions.
2. Step 2: Entity Identification and Profiling:
   - Query threat intelligence via `scan_full_incident`, `check_bank_account`, `check_phone`, or `lookup_scam_db` to profile the adversary infrastructure.
3. Step 3: Evidence Preservation:
   - Guide the user to capture comprehensive digital evidence: screenshots of chat logs, transfer receipts with reference numbers, beneficiary bank details, and call records.
4. Step 4: Formal Escalation and Reporting:
   - Advise the user to submit an official crime report to local law enforcement with the preserved digital evidence.
   - Invoke `report_scam` to submit the threat actor parameters to the ShieldCall database.
"""

SHIELDCALL_INVESTIGATOR_PROMPT = """You are a Cyber Fraud Investigation and Forensic Analyst with ShieldCall VN.
Your objective is to conduct technical entity inspection on suspicious indicators:
- Domain Analysis: Assess typosquatting distance (Levenshtein lookalike metrics), domain registration age via WHOIS, DNS records, and SSL certificate validity.
- Email Authentication: Validate SPF, DKIM, DMARC policies, and MX server configurations via `check_email_sender`.
- Telephony Infrastructure: Classify carrier networks, detect VoIP/virtual allocations, and flag premium-rate number prefixes via `check_phone`.
- Banking Verification: Validate institution BIN codes via `get_supported_banks` and cross-reference structured fraud syndicate accounts.
- Incident Correlation: Correlate multiple indicators using `scan_full_incident` and synthesize structured findings into a clear technical summary.
"""


# ==============================================================================
# 3. ZERO-DEPENDENCY MCP PROTOCOL ENGINE
# ==============================================================================

class ZeroDepMCPServer:
    """
    Model Context Protocol (JSON-RPC 2.0) server implementation
    supporting stdio and Server-Sent Events (SSE) transports.
    """

    PROTOCOL_VERSION = "2024-11-05"

    def __init__(self, name: str = "shieldcall-vn", version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.tools: Dict[str, Dict[str, Any]] = {}
        self.prompts: Dict[str, Dict[str, Any]] = {}

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
            try:
                result_val = tool_def["func"](**arguments)
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
            return {"jsonrpc": "2.0", "id": req_id, "result": {"resources": []}}

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

def create_server(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    server_name: str = "shieldcall-vn",
    client: Optional[Any] = None,
) -> ZeroDepMCPServer:
    """Initialize and register all tools and prompts for ShieldCall MCP Server."""
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
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def check_bank_account(bank_name: str, account_number: str) -> str:
        """
        Check a bank account against financial fraud and community scam databases.

        Args:
            bank_name: Bank code or name (e.g., 'MB', 'Techcombank', 'VCB', 'VietinBank').
            account_number: Bank account number to verify.
        """
        data = client.scan_bank_account(bank=(bank_name or "").strip(), account=(account_number or "").strip())
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def check_url_or_domain(url: str) -> str:
        """
        Analyze a URL or domain to detect phishing sites, brand lookalike domains,
        SSL certificate issues, and suspicious domain registration age.

        Args:
            url: URL or domain name to inspect (e.g., 'https://vietcombank-ebank.xyz', 'dichvucong-vn.top').
        """
        data = client.scan_domain((url or "").strip())
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def analyze_message(message_content: str) -> str:
        """
        Analyze message or SMS text to detect social engineering and scam scripts
        (impersonation, lottery scams, fake law enforcement, urgent OTP requests).

        Args:
            message_content: Full text of the suspicious message or dialogue.
        """
        data = client.scan_message((message_content or "").strip())
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def lookup_scam_db(query: str, entity_type: str = "all") -> str:
        """
        Search the ShieldCall community threat and scam database.

        Args:
            query: Keyword, phone number, account number, target name, or URL.
            entity_type: Filter category ('all', 'phone', 'account', 'domain', 'report').
        """
        data = client.lookup_scam_db(query=(query or "").strip(), entity_type=(entity_type or "all").strip())
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def get_scam_radar_trends() -> str:
        """
        Retrieve real-time regional scam trends and prevalent threat patterns (Scam Radar).
        """
        data = client.get_scam_radar_trends()
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def get_supported_banks() -> str:
        """
        Retrieve the list of supported Vietnamese banks with BIN codes, short names, and identifiers.
        """
        data = client.get_supported_banks()
        return json.dumps(data, ensure_ascii=False, indent=2)

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
        return json.dumps(data, ensure_ascii=False, indent=2)

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
        Perform a unified multi-entity security assessment for a suspected scam incident.
        Concurrently checks phone numbers, bank accounts, domains, emails, and message text,
        then synthesizes an overall risk assessment.

        Args:
            message_content: Suspicious message or narrative text.
            phone_number: Associated phone number.
            bank_name: Bank name or code provided by the suspect.
            account_number: Bank account number provided by the suspect.
            url: Suspicious link or domain.
            sender_email: Sender email address.
        """
        entities_scanned = {}
        all_threats = []
        max_score = 0

        p_val = (phone_number or "").strip()
        b_name = (bank_name or "").strip()
        a_val = (account_number or "").strip()
        u_val = (url or "").strip()
        e_val = (sender_email or "").strip()
        m_val = (message_content or "").strip()

        if p_val:
            p_res = client.scan_phone(p_val)
            entities_scanned["phone"] = p_res
            p_score = int(p_res.get("risk_score", 0)) if isinstance(p_res, dict) else 0
            max_score = max(max_score, p_score)
            if isinstance(p_res, dict) and p_res.get("details"):
                all_threats.extend([f"[Phone {p_val}] {d}" for d in p_res.get("details", [])])

        if a_val:
            b_res = client.scan_bank_account(bank=b_name or "Other", account=a_val)
            entities_scanned["bank_account"] = b_res
            b_score = int(b_res.get("risk_score", 0)) if isinstance(b_res, dict) else 0
            max_score = max(max_score, b_score)
            if isinstance(b_res, dict) and b_res.get("details"):
                all_threats.extend([f"[Bank {b_name} {a_val}] {d}" for d in b_res.get("details", [])])

        if u_val:
            u_res = client.scan_domain(u_val)
            entities_scanned["url"] = u_res
            u_score = int(u_res.get("risk_score", 0)) if isinstance(u_res, dict) else 0
            max_score = max(max_score, u_score)
            if isinstance(u_res, dict) and u_res.get("details"):
                all_threats.extend([f"[URL {u_val}] {d}" for d in u_res.get("details", [])])

        if e_val:
            e_res = client.scan_email(email=e_val, content=m_val)
            entities_scanned["email"] = e_res
            e_score = int(e_res.get("risk_score", 0)) if isinstance(e_res, dict) else 0
            max_score = max(max_score, e_score)
            if isinstance(e_res, dict) and e_res.get("security_checks"):
                all_threats.extend([f"[Email {e_val}] {c}" for c in e_res.get("security_checks", [])])

        if m_val:
            m_res = client.scan_message(m_val)
            entities_scanned["message"] = m_res
            m_score = int(m_res.get("risk_score", 0)) if isinstance(m_res, dict) else 0
            max_score = max(max_score, m_score)
            if isinstance(m_res, dict) and m_res.get("patterns_found"):
                all_threats.extend([f"[Message Pattern] {p}" for p in m_res.get("patterns_found", [])])
            if isinstance(m_res, dict) and m_res.get("explanation"):
                all_threats.append(f"[AI Assessment] {m_res.get('explanation')}")

        if max_score >= 70:
            overall_level = "red"
            recommended_actions = [
                "[DANGER] DO NOT TRANSFER FUNDS to the specified account.",
                "[WARNING] Do not click links or disclose OTP credentials under any circumstances.",
                "[ACTION] Immediately contact issuing bank support to freeze accounts if funds were already transferred.",
                "[REPORT] Submit formal report to law enforcement and preserve all digital evidence.",
            ]
        elif max_score >= 40:
            overall_level = "yellow"
            recommended_actions = [
                "[WARNING] Suspected fraud patterns detected. Halt all pending transactions.",
                "[VERIFY] Independently verify counterparty credentials through official communication channels.",
                "[REPORT] Submit details to ShieldCall threat database to alert the community.",
            ]
        elif max_score >= 10:
            overall_level = "green"
            recommended_actions = [
                "[INFO] Low risk detected. Exercise standard security diligence for any unexpected financial requests.",
            ]
        else:
            overall_level = "safe"
            recommended_actions = [
                "[SAFE] No confirmed threat indicators recorded in the security database.",
            ]

        composite_report = {
            "overall_risk_score": max_score,
            "overall_risk_level": overall_level,
            "entities_scanned": entities_scanned,
            "detected_threats": all_threats,
            "recommended_actions": recommended_actions,
            "entities_count": len(entities_scanned),
        }
        return json.dumps(composite_report, ensure_ascii=False, indent=2)

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
            target_type: Target category ('phone', 'account', 'domain', 'message', 'other').
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
        return json.dumps(data, ensure_ascii=False, indent=2)

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
