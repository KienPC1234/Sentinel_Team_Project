"""
ShieldCall VN – MCP Server Implementation
Exposes cybersecurity, scam detection, and risk analysis tools to any MCP client.
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

    # ──────────────────────────────────────────────────────────────────────────
    # TOOLS
    # ──────────────────────────────────────────────────────────────────────────

    @server.tool()
    def check_phone(phone_number: str) -> str:
        """
        Tra cứu và đánh giá độ rủi ro lừa đảo của số điện thoại tại Việt Nam.
        Kiểm tra danh sách đen, lịch sử báo cáo cộng đồng, nhà mạng và dấu hiệu số ảo (VoIP).
        
        Args:
            phone_number: Số điện thoại cần kiểm tra (ví dụ: '0912345678', '+84988776655').
        """
        data = client.scan_phone(phone_number)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def check_bank_account(bank_name: str, account_number: str) -> str:
        """
        Tra cứu số tài khoản ngân hàng trong cơ sở dữ liệu gian lận tài chính và lừa đảo trực tuyến.
        
        Args:
            bank_name: Tên ngân hàng hoặc mã ngân hàng (ví dụ: 'MB', 'Techcombank', 'VCB', 'VietinBank').
            account_number: Số tài khoản ngân hàng cần kiểm tra.
        """
        data = client.scan_bank_account(bank=bank_name, account=account_number)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def check_url_or_domain(url: str) -> str:
        """
        Phân tích đường link, URL hoặc tên miền để phát hiện website giả mạo (phishing),
        tên miền nhái thương hiệu (lookalike domain), chứng chỉ SSL và tuổi đời tên miền.
        
        Args:
            url: Đường dẫn hoặc domain cần kiểm tra (ví dụ: 'https://vietcombank-ebank.xyz', 'dichvucong-vn.top').
        """
        data = client.scan_domain(url)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def analyze_message(message_content: str) -> str:
        """
        Phân tích nội dung tin nhắn văn bản, SMS hoặc đoạn chat để phát hiện kịch bản lừa đảo
        (mạo danh công an/tòa án, thông báo khóa tài khoản, tuyển dụng việc nhẹ lương cao, dụ dỗ nạp tiền OTP).
        
        Args:
            message_content: Toàn bộ nội dung tin nhắn hoặc đoạn hội thoại nghi vấn.
        """
        data = client.scan_message(message_content)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def lookup_scam_db(query: str, entity_type: str = "all") -> str:
        """
        Tìm kiếm tổng hợp trong kho dữ liệu cộng đồng ShieldCall VN.
        
        Args:
            query: Từ khóa, số điện thoại, số tài khoản, tên đối tượng hoặc URL cần tra cứu.
            entity_type: Loại thực thể lọc ('all', 'phone', 'account', 'domain', 'report').
        """
        data = client.lookup_scam_db(query=query, entity_type=entity_type)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def get_scam_radar_trends() -> str:
        """
        Lấy thống kê xu hướng lừa đảo trực tuyến theo thời gian thực (Scam Radar).
        Bao gồm các thủ đoạn scam phổ biến nhất hiện nay tại Việt Nam.
        """
        data = client.get_scam_radar_trends()
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def get_supported_banks() -> str:
        """
        Lấy danh sách các ngân hàng được hỗ trợ tại Việt Nam (kèm mã ngân hàng, tên viết tắt, BIN code).
        Sử dụng khi cần xác minh mã ngân hàng chính xác hoặc tra cứu ngân hàng thụ hưởng.
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
        Kiểm tra độ rủi ro lừa đảo của email: xác thực SPF, DKIM, DMARC, danh sách đen,
        và phân tích nội dung email lừa đảo (phishing/mạo danh cơ quan hoặc dịch vụ).
        
        Args:
            sender_email: Địa chỉ email người gửi (ví dụ: 'alert@support-vietcombank.com').
            email_content: Nội dung văn bản của email cần phân tích.
            email_subject: Tiêu đề email (nếu có).
        """
        data = client.scan_email(email=sender_email, content=email_content, subject=email_subject)
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
        Phân tích tổng hợp một vụ việc nghi vấn lừa đảo đa thực thể trong một lần gọi duy nhất.
        Hệ thống sẽ đồng thời kiểm tra số điện thoại, tài khoản ngân hàng, đường link/domain,
        địa chỉ email và nội dung tin nhắn, sau đó tổng hợp thành bản giám định an ninh hoàn chỉnh.
        
        Args:
            message_content: Nội dung tin nhắn, kịch bản lừa đảo (nếu có).
            phone_number: Số điện thoại kẻ lừa đảo hoặc tổng đài gọi đến (nếu có).
            bank_name: Tên ngân hàng đối tượng yêu cầu chuyển tiền (nếu có).
            account_number: Số tài khoản đối tượng cung cấp (nếu có).
            url: Đường dẫn, link website lạ đối tượng gửi (nếu có).
            sender_email: Địa chỉ email người gửi (nếu có).
        """
        entities_scanned = {}
        all_threats = []
        max_score = 0

        if phone_number.strip():
            p_res = client.scan_phone(phone_number.strip())
            entities_scanned["phone"] = p_res
            p_score = int(p_res.get("risk_score", 0)) if isinstance(p_res, dict) else 0
            max_score = max(max_score, p_score)
            if isinstance(p_res, dict) and p_res.get("details"):
                all_threats.extend([f"[SĐT {phone_number}] {d}" for d in p_res.get("details", [])])

        if account_number.strip():
            b_res = client.scan_bank_account(bank=bank_name.strip() or "Other", account=account_number.strip())
            entities_scanned["bank_account"] = b_res
            b_score = int(b_res.get("risk_score", 0)) if isinstance(b_res, dict) else 0
            max_score = max(max_score, b_score)
            if isinstance(b_res, dict) and b_res.get("details"):
                all_threats.extend([f"[STK {bank_name} {account_number}] {d}" for d in b_res.get("details", [])])

        if url.strip():
            u_res = client.scan_domain(url.strip())
            entities_scanned["url"] = u_res
            u_score = int(u_res.get("risk_score", 0)) if isinstance(u_res, dict) else 0
            max_score = max(max_score, u_score)
            if isinstance(u_res, dict) and u_res.get("details"):
                all_threats.extend([f"[URL {url}] {d}" for d in u_res.get("details", [])])

        if sender_email.strip():
            e_res = client.scan_email(email=sender_email.strip(), content=message_content.strip())
            entities_scanned["email"] = e_res
            e_score = int(e_res.get("risk_score", 0)) if isinstance(e_res, dict) else 0
            max_score = max(max_score, e_score)
            if isinstance(e_res, dict) and e_res.get("security_checks"):
                all_threats.extend([f"[Email {sender_email}] {c}" for c in e_res.get("security_checks", [])])

        if message_content.strip():
            m_res = client.scan_message(message_content.strip())
            entities_scanned["message"] = m_res
            m_score = int(m_res.get("risk_score", 0)) if isinstance(m_res, dict) else 0
            max_score = max(max_score, m_score)
            if isinstance(m_res, dict) and m_res.get("patterns_found"):
                all_threats.extend([f"[Nội dung tin nhắn] Dấu hiệu: {p}" for p in m_res.get("patterns_found", [])])
            if isinstance(m_res, dict) and m_res.get("explanation"):
                all_threats.append(f"[AI nhận định] {m_res.get('explanation')}")

        if max_score >= 70:
            overall_level = "red"
            recommended_actions = [
                "🚫 TUYỆT ĐỐI KHÔNG CHUYỂN TIỀN vào tài khoản được chỉ định.",
                "🚫 KHÔNG bấm link hoặc cung cấp OTP/mật khẩu dưới bất kỳ hình thức nào.",
                "📞 Liên hệ ngay hotline ngân hàng để khóa tài khoản nếu đã lỡ chuyển tiền.",
                "🚨 Báo cáo vụ việc cho Cơ quan Công an gần nhất và ghi lại toàn bộ bằng chứng.",
            ]
        elif max_score >= 40:
            overall_level = "yellow"
            recommended_actions = [
                "⚠️ Nghi ngờ có dấu hiệu gian lận, cần tạm dừng mọi giao dịch.",
                "🔍 Xác minh lại thông tin người liên hệ qua kênh chính thống.",
                "📝 Gửi báo cáo lên ShieldCall để cộng đồng cùng cảnh giác.",
            ]
        elif max_score >= 10:
            overall_level = "green"
            recommended_actions = [
                "ℹ️ Độ rủi ro thấp nhưng cần thận trọng nếu có yêu cầu tài chính bất thường.",
            ]
        else:
            overall_level = "safe"
            recommended_actions = [
                "✅ Chưa ghi nhận dấu hiệu lừa đảo nào trong hệ thống cơ sở dữ liệu.",
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
        Gửi báo cáo hành vi hoặc đối tượng lừa đảo mới lên hệ thống kiểm duyệt ShieldCall VN
        để bảo vệ cộng đồng.
        
        Args:
            target_type: Loại đối tượng ('phone', 'account', 'domain', 'message', 'other').
            target_value: Giá trị đối tượng (SĐT, STK, đường link...).
            scam_type: Phân loại scam ('police_impersonation', 'bank_impersonation', 'recruitment_scam', 'investment_scam', 'delivery_scam', 'phishing', 'other').
            description: Mô tả chi tiết thủ đoạn và quá trình diễn ra sự việc.
            evidence_note: Ghi chú bằng chứng (mã giao dịch, thời gian xảy ra...).
        """
        data = client.report_scam(
            target_type=target_type,
            target_value=target_value,
            scam_type=scam_type,
            description=description,
            evidence_note=evidence_note,
        )
        return json.dumps(data, ensure_ascii=False, indent=2)

    # ──────────────────────────────────────────────────────────────────────────
    # PROMPTS
    # ──────────────────────────────────────────────────────────────────────────

    @server.prompt()
    def shieldcall_sentry() -> str:
        """Prompt khởi tạo biến chatbot thành Chuyên viên An ninh Số thường trực (Sentry)"""
        return SHIELDCALL_SENTRY_PROMPT

    @server.prompt()
    def emergency_advisor() -> str:
        """Prompt ứng cứu khẩn cấp 4 bước khi nạn nhân vừa bị lừa hoặc chuyển tiền"""
        return SHIELDCALL_EMERGENCY_PROMPT

    @server.prompt()
    def scam_investigator() -> str:
        """Prompt giám định kỹ thuật và thẩm định dấu vết số chuyên sâu"""
        return SHIELDCALL_INVESTIGATOR_PROMPT

    return server

