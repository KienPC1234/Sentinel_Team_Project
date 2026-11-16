"""
ShieldCall VN - MCP Server Implementation
Exposes cybersecurity, scam detection, risk analysis tools, prompts, and resources to MCP clients.
"""
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, List, Optional, Tuple
from mcp.server.mcpserver import MCPServer
from mcp_server.client import ShieldCallClient
from mcp_server.prompts import (
    SHIELDCALL_SENTRY_PROMPT,
    SHIELDCALL_EMERGENCY_PROMPT,
    SHIELDCALL_INVESTIGATOR_PROMPT,
)
from scripts.shieldcall_mcp import (
    _dump_compact,
    _mask_identifier,
    synthesize_incident_guardrail,
)

logger = logging.getLogger("shieldcall_mcp.server")


def create_server(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    server_name: str = "shieldcall-vn",
) -> MCPServer:
    """Creates and configures a ShieldCall Model Context Protocol server instance."""
    client = ShieldCallClient(api_url=api_url, api_key=api_key)
    server = MCPServer(server_name)

    # --------------------------------------------------------------------------
    # TOOLS
    # --------------------------------------------------------------------------

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
        t0 = time.monotonic()
        p_val = (phone_number or "").strip()
        b_name = (bank_name or "").strip()
        a_val = (account_number or "").strip()
        u_val = (url or "").strip()
        e_val = (sender_email or "").strip()
        m_val = (message_content or "").strip()

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
                future_map = {pool.submit(fn): key for key, fn in jobs}
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
                all_threats.extend([f"[Phone {masked_p}] {d}" for d in (res.get("details") or [])])
            elif key == "bank_account":
                masked_a = res.get("account_masked") or _mask_identifier("account", a_val)
                bank_lbl = res.get("bank") or b_name or "Bank"
                all_threats.extend([f"[Bank {bank_lbl} {masked_a}] {d}" for d in (res.get("details") or [])])
            elif key == "url":
                all_threats.extend([f"[URL {res.get('domain') or u_val}] {d}" for d in (res.get("details") or [])])
            elif key == "email":
                masked_e = res.get("email") or _mask_identifier("email", e_val)
                all_threats.extend([f"[Email {masked_e}] {c}" for c in (res.get("security_checks") or [])])
            elif key == "message":
                all_threats.extend([f"[Message Pattern] {p}" for p in (res.get("patterns_found") or [])])
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
        return _dump_compact(data)

    # --------------------------------------------------------------------------
    # RESOURCES
    # --------------------------------------------------------------------------

    @server.resource("shieldcall://trust/sources", mime_type="application/json")
    def resource_trust_sources() -> str:
        """Vietnamese anti-fraud data sources, last-updated timestamps, and tool limitations."""
        return _dump_compact(client.get_trust_sources())

    @server.resource("shieldcall://trust/channels", mime_type="application/json")
    def resource_trust_channels() -> str:
        """Official Vietnamese police, VNCERT/NCSC, and bank verification hotlines."""
        return _dump_compact(client.get_trust_channels())

    @server.resource("shieldcall://trust/policy", mime_type="application/json")
    def resource_trust_policy() -> str:
        """ShieldCall Trust Guardrail 5-tier verdict and PII minimization policy."""
        return _dump_compact(client.get_trust_policy())

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
