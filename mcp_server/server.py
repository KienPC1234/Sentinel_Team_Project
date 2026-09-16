"""
ShieldCall VN - MCP Server Implementation
Exposes cybersecurity, scam detection, and risk analysis tools to MCP clients.
"""
import os
import json
import logging
from typing import Optional
from mcp.server.mcpserver import MCPServer
from mcp_server.client import ShieldCallClient
from mcp_server.prompts import (
    SHIELDCALL_SENTRY_PROMPT,
    SHIELDCALL_EMERGENCY_PROMPT,
    SHIELDCALL_INVESTIGATOR_PROMPT,
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
