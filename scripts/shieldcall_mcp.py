#!/usr/bin/env python3
"""
ShieldCall VN - Standalone Model Context Protocol (MCP) Server
Tich hop co so du lieu an ninh so, phong chong lua dao cua ShieldCall VN
vao bat ky chatbot AI nao: Claude Desktop, Cursor, Windsurf, Claude Code, Cline, ChatGPT.

YEU CAU HE THONG:
    pip install "mcp>=1.0.0" requests

CACH SU DUNG:
1. Claude Desktop (claude_desktop_config.json):
{
  "mcpServers": {
    "shieldcall": {
      "command": "python",
      "args": ["/duong_dan_toi/shieldcall_mcp.py"],
      "env": {
        "SHIELDCALL_API_KEY": "sc_live_your_api_key_here",
        "SHIELDCALL_API_URL": "http://127.0.0.1:8001/api/v1"
      }
    }
  }
}

2. Cursor IDE (.cursor/mcp.json):
{
  "mcpServers": {
    "shieldcall": {
      "command": "python",
      "args": ["/duong_dan_toi/shieldcall_mcp.py"],
      "env": {
        "SHIELDCALL_API_KEY": "sc_live_your_api_key_here",
        "SHIELDCALL_API_URL": "http://127.0.0.1:8001/api/v1"
      }
    }
  }
}

3. Chay qua mang (SSE Server cho nhieu may dung chung):
    python shieldcall_mcp.py --transport sse --host 0.0.0.0 --port 8002
"""

import os
import sys
import json
import logging
import argparse
from typing import Any, Dict, Optional

# Setup logger to stderr (stdio transport reserves stdout for JSON-RPC)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("shieldcall_mcp")

# Import MCP Server with cross-version compatibility (mcp 1.x FastMCP vs mcp 2.x MCPServer)
try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as MCPServer
    except ImportError:
        logger.error(
            "Chua cai dat thu vien mcp. Vui long chay: pip install \"mcp>=1.0.0\" requests"
        )
        sys.exit(1)

try:
    import requests
except ImportError:
    logger.error("Chua cai dat thu vien requests. Vui long chay: pip install requests")
    sys.exit(1)


# ==============================================================================
# 1. SHIELDCALL REST API CLIENT
# ==============================================================================

class ShieldCallClient:
    """Client goi truc tiep cac API kiem tra an ninh so cua ShieldCall VN."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: int = 30,
    ):
        raw_url = api_url or os.getenv("SHIELDCALL_API_URL", "http://127.0.0.1:8001/api/v1")
        self.api_url = raw_url.rstrip("/")
        self.api_key = api_key or os.getenv("SHIELDCALL_API_KEY", "")
        self.timeout = timeout

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "ShieldCall-MCP-Server/1.0",
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
        try:
            resp = requests.request(
                method=method,
                url=url,
                headers=self._headers(),
                json=data if method in ("POST", "PUT", "PATCH") else None,
                params=params,
                timeout=self.timeout,
            )

            if resp.status_code == 401:
                return {
                    "error": (
                        "Xac thuc API Key that bai (401 Unauthorized). "
                        "Vui long kiem tra bien moi truong SHIELDCALL_API_KEY."
                    )
                }
            if resp.status_code == 429:
                try:
                    detail = resp.json().get("detail", "Vuot qua han muc request.")
                except Exception:
                    detail = resp.text
                return {"error": f"Han muc API Key da het hoac bi gioi han toc do: {detail}"}

            if not resp.ok:
                try:
                    err_json = resp.json()
                    return {"error": f"Loi API ({resp.status_code}): {err_json}"}
                except Exception:
                    return {"error": f"Loi API ({resp.status_code}): {resp.text[:300]}"}

            return resp.json()
        except requests.exceptions.ConnectionError:
            return {
                "error": (
                    f"Khong the ket noi den may chu ShieldCall tai {self.api_url}. "
                    "Vui long kiem tra xem backend ShieldCall dang chay hay khong."
                )
            }
        except requests.exceptions.Timeout:
            return {"error": f"Het thoi gian cho phan hoi ({self.timeout}s) tu ShieldCall API."}
        except Exception as e:
            return {"error": f"Loi ngoai le khi goi ShieldCall API: {str(e)}"}

    def scan_phone(self, phone: str) -> Dict[str, Any]:
        """Quet va tra cuu muc do rui ro cua so dien thoai."""
        return self._request("POST", "scan/phone/", data={"phone": phone})

    def scan_bank_account(self, bank: str, account: str) -> Dict[str, Any]:
        """Tra cuu so tai khoan ngan hang trong danh sach den lua dao."""
        return self._request("POST", "scan/account/", data={"bank": bank, "account": account})

    def scan_domain(self, url: str) -> Dict[str, Any]:
        """Phan tich website, URL, phat hien ten mien gia mao (phishing/lookalike)."""
        return self._request("POST", "scan/domain/", data={"url": url, "deep_scan": False})

    def scan_message(self, message: str) -> Dict[str, Any]:
        """Phan tich noi dung tin nhan, SMS, kich ban lua dao chuyen tien/OTP."""
        return self._request("POST", "scan/message/", data={"message": message, "sync": True})

    def scan_email(self, email: str, content: str = "", subject: str = "") -> Dict[str, Any]:
        """Phan tich dia chi email, SPF/DMARC va noi dung email lua dao."""
        return self._request(
            "POST",
            "scan/email/",
            data={"email": email, "content": content, "subject": subject, "sync": True},
        )

    def get_supported_banks(self) -> Any:
        """Lay danh sach cac ngan hang duoc ho tro tai Viet Nam."""
        return self._request("GET", "scan/banks/")

    def lookup_scam_db(self, query: str, entity_type: str = "all") -> Dict[str, Any]:
        """Tra cuu thuc the trong kho du lieu cong dong ShieldCall VN."""
        return self._request("GET", "scan/lookup/", params={"q": query, "type": entity_type})

    def get_scam_radar_trends(self) -> Dict[str, Any]:
        """Lay so lieu radar va xu huong thu doan lua dao moi nhat."""
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
        """Gui bao cao hanh vi lua dao vao he thong kiem duyet cong dong."""
        import re

        norm_val = (target_value or "").strip()
        if target_type == "phone":
            cleaned = re.sub(r"[\s\-\.]", "", norm_val)
            if cleaned.startswith("0") and len(cleaned) == 10:
                norm_val = "+84" + cleaned[1:]

        payload = {
            "target_type": target_type,
            "target_value": norm_val,
            "scam_type": self.normalize_scam_type(scam_type),
            "description": description,
            "evidence_note": evidence_note,
        }
        return self._request("POST", "report/", data=payload)


# ==============================================================================
# 2. SYSTEM PERSONA PROMPTS
# ==============================================================================

SHIELDCALL_SENTRY_PROMPT = """Ban la ShieldCall Sentry - Tro ly Giam sat An toan So va Phong chong Lua dao Truc tuyen hang dau tai Viet Nam, tich hop truc tiep co so du lieu tu he thong ShieldCall VN.

NGUYEN TAC HOAT DONG COT LOI:
1. Chu dong Kich hoat Cong cu (Proactive Tool Triggering):
   - Khi nguoi dung mo ta mot tinh huong chua nhieu thuc the (vua co so dien thoai, link la va so tai khoan nhan tien), ban PHAI goi ngay cong cu 'scan_full_incident' de giam dinh tong the trong mot lan goi.
   - Khi co tung thuc the don le, tu dong goi cong cu ShieldCall MCP tuong ung TRUOC KHI dua ra ket luan:
     - check_phone: Khi co so dien thoai (vi du: '0912xxx', '+84...').
     - check_bank_account: Khi co so tai khoan va ten ngan hang (vi du: '1903xxx Techcombank', 'MB').
     - check_url_or_domain: Khi co lien ket, website, ten mien (vi du: 'https://...', 'dichvucong-vn.top').
     - analyze_message: Khi co noi dung tin nhan dang ngo, thong bao trung thuong, de doa tu co quan cong an gia mao.
     - check_email_sender: Khi co email nguoi gui hoac noi dung thu dien tu nghi van gia mao.
     - get_supported_banks: Khi can tra cuu danh sach ngan hang chinh thong tai Viet Nam va ma BIN.
     - lookup_scam_db: Tra cuu nhanh ten nguoi, tu khoa hoac doi tuong trong co so du lieu cong dong.
     - get_scam_radar_trends: Cap nhat xu huong lua dao truc tuyen moi nhat theo thoi gian thuc.
2. Thang Diem Rui ro (Risk Score):
   - 0 - 19 (SAFE): An toan, chua ghi nhan dau hieu rui ro.
   - 20 - 49 (LOW/GREEN): Rui ro thap, can than trong thong thuong.
   - 50 - 79 (MEDIUM/YELLOW): CANH BAO RUI RO CAO. Co bao cao xau tu cong dong hoac su dung dau so ao/ten mien moi lap.
   - 80 - 100 (CRITICAL/RED): NGUY HIEM CAO. Nam trong danh sach den hoac co nhieu nan nhan to giac.
3. Phong cach Giao tiep va Khuyen nghi Hanh dong:
   - Dut khoat, di thang vao ban chat ky thuat, khong vong vo.
   - Luon dua ra checklist ung pho: Tuyet doi khong chuyen tien, khong cai file APK la, khong cung cap OTP.
   - Huong dan goi report_scam neu phat hien dau hieu lua dao moi de bao ve cong dong.
"""

SHIELDCALL_EMERGENCY_PROMPT = """Ban la Chuyen vien Ung cuu Su co Lua dao Khan cap (ShieldCall Emergency Incident Responder). Nguoi dung dang trong trang thai lo lang, vua chuyen tien cho ke lua dao, vua bam vao lien ket doc hai, hoac bi thao tung tam ly chiem doat tai khoan.

QUY TRINH PHAN UNG KHAN CAP 4 BUOC:
1. Buoc 1: CO LAP VA NGAN CHAN THIET HAI NGAY LAP TUC:
   - Yeu cau nguoi dung goi ngay Hotline ngan hang de YEU CAU KHOA THE VA TAM DUNG MOI GIAO DICH TRUC TUYEN.
   - Neu cai nham ung dung la (.APK): Bat che do may bay ngay lap tuc de ngat ket noi mang va thu hoi quyen tro nang (Accessibility).
2. Buoc 2: XAC MINH VA LAP HO SO DOI TUONG:
   - Su dung cong cu scan_full_incident hoac check_bank_account, check_phone, lookup_scam_db de kiem tra toan bo thong tin ke lua dao.
3. Buoc 3: BAO TOAN CHUNG CU SO:
   - Huong dan chup man hinh toan bo tin nhan, bien lai chuyen tien (ma giao dich, so tai khoan, ngan hang thu huong), ghi am cuoc goi neu co.
4. Buoc 4: BAO CAO VA TO GIAC:
   - Huong dan lien he Co quan Cong an gan nhat kem bo ho so chung cu.
   - Goi tool report_scam de gui thong tin len co so du lieu canh bao toan quoc cua ShieldCall VN.
"""

SHIELDCALL_INVESTIGATOR_PROMPT = """Ban la Chuyen gia Dieu tra Ky thuat Gian lan Khong gian Mang (Forensic Scam Analyst) cua ShieldCall VN.
Nhiem vu cua ban la phan tich cau truc ky thuat sau ve cac thuc the nghi van:
- Ten mien: Doi soat ten mien nhai (Lookalike/Typosquatting bang khoang cach Levenshtein), tuoi doi ten mien (WHOIS registration age), dich vu DNS, SSL Certificate.
- Email: Danh gia xac thuc SPF, DKIM, DMARC, MX records cua ten mien gui thu qua check_email_sender.
- Dau so dien thoai: Phan loai nha mang, phat hien thue bao ao VoIP, OTT, cac dau so dich vu cuoc cao.
- Tai khoan ngan hang: Doi chieu BIN ngan hang qua get_supported_banks, tra cuu ho so tai khoan lua dao co to chuc.
- Tong hop vu viec phuc tap qua scan_full_incident va lap bang phan tich ky thuat chi tiet cho nguoi dung.
"""


# ==============================================================================
# 3. SERVER INITIALIZATION & TOOL REGISTRATION
# ==============================================================================

def create_server(
    api_url: Optional[str] = None,
    api_key: Optional[str] = None,
    server_name: str = "shieldcall-vn",
) -> MCPServer:
    """Khoi tao va dang ky toan bo 10 tools va 3 prompts cho ShieldCall MCP Server."""
    client = ShieldCallClient(api_url=api_url, api_key=api_key)
    server = MCPServer(server_name)

    @server.tool()
    def check_phone(phone_number: str) -> str:
        """
        Tra cuu va danh gia do rui ro lua dao cua so dien thoai tai Viet Nam.
        Kiem tra danh sach den, lich su bao cao cong dong, nha mang va dau hieu so ao (VoIP).
        """
        data = client.scan_phone(phone_number)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def check_bank_account(bank_name: str, account_number: str) -> str:
        """
        Tra cuu so tai khoan ngan hang trong co so du lieu gian lan tai chinh va lua dao truc tuyen.
        """
        data = client.scan_bank_account(bank=bank_name, account=account_number)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def check_url_or_domain(url: str) -> str:
        """
        Phan tich duong link, URL hoac ten mien de phat hien website gia mao (phishing),
        ten mien nhai thuong hieu (lookalike domain), chung chi SSL va tuoi doi ten mien.
        """
        data = client.scan_domain(url)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def analyze_message(message_content: str) -> str:
        """
        Phan tich noi dung tin nhan van ban, SMS hoac doan chat de phat hien kich ban lua dao.
        """
        data = client.scan_message(message_content)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def lookup_scam_db(query: str, entity_type: str = "all") -> str:
        """
        Tim kiem tong hop trong kho du lieu cong dong ShieldCall VN.
        """
        data = client.lookup_scam_db(query=query, entity_type=entity_type)
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def get_scam_radar_trends() -> str:
        """
        Lay thong ke xu huong lua dao truc tuyen theo thoi gian thuc (Scam Radar).
        """
        data = client.get_scam_radar_trends()
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.tool()
    def get_supported_banks() -> str:
        """
        Lay danh sach cac ngan hang duoc ho tro tai Viet Nam (ma ngan hang, ten viet tat, BIN code).
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
        Kiem tra do rui ro lua dao cua email: xac thuc SPF, DKIM, DMARC, danh sach den va noi dung phishing.
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
        Phan tich tong hop mot vu viec nghi van lua dao da thuc the trong mot lan goi duy nhat.
        Dong thoi kiem tra so dien thoai, tai khoan ngan hang, duong link/domain, dia chi email va noi dung.
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
                all_threats.extend([f"[SDT {phone_number}] {d}" for d in p_res.get("details", [])])

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
                all_threats.extend([f"[Noi dung tin nhan] Dau hieu: {p}" for p in m_res.get("patterns_found", [])])
            if isinstance(m_res, dict) and m_res.get("explanation"):
                all_threats.append(f"[AI nhan dinh] {m_res.get('explanation')}")

        if max_score >= 70:
            overall_level = "red"
            recommended_actions = [
                "[NGUY HIEM] TUYET DOI KHONG CHUYEN TIEN vao tai khoan duoc chi dinh.",
                "[CANH BAO] KHONG bam link hoac cung cap OTP/mat khau duoi bat ky hinh thuc nao.",
                "[UNG CUU] Lien he ngay hotline ngan hang de khoa tai khoan neu da lo chuyen tien.",
                "[TO GIAC] Bao cao vu viec cho Co quan Cong an gan nhat va ghi lai toan bo bang chung.",
            ]
        elif max_score >= 40:
            overall_level = "yellow"
            recommended_actions = [
                "[CANH BAO] Nghi ngo co dau hieu gian lan, can tam dung moi giao dich.",
                "[XAC MINH] Xac minh lai thong tin nguoi lien he qua kenh chinh thong.",
                "[DONG GOP] Gui bao cao len ShieldCall de cong dong cung canh giac.",
            ]
        elif max_score >= 10:
            overall_level = "green"
            recommended_actions = [
                "[CHU Y] Do rui ro thap nhung can than trong neu co yeu cau tai chinh bat thuong.",
            ]
        else:
            overall_level = "safe"
            recommended_actions = [
                "[AN TOAN] Chua ghi nhan dau hieu lua dao nao trong he thong co so du lieu.",
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
        Gui bao cao hanh vi hoac doi tuong lua dao moi len he thong kiem duyet ShieldCall VN.
        """
        data = client.report_scam(
            target_type=target_type,
            target_value=target_value,
            scam_type=scam_type,
            description=description,
            evidence_note=evidence_note,
        )
        return json.dumps(data, ensure_ascii=False, indent=2)

    @server.prompt()
    def shieldcall_sentry() -> str:
        """Prompt khoi tao bien chatbot thanh Chuyen vien An ninh So thuong truc (Sentry)."""
        return SHIELDCALL_SENTRY_PROMPT

    @server.prompt()
    def emergency_advisor() -> str:
        """Prompt ung cuu khan cap 4 buoc khi nan nhan vua bi lua hoac chuyen tien."""
        return SHIELDCALL_EMERGENCY_PROMPT

    @server.prompt()
    def scam_investigator() -> str:
        """Prompt giam dinh ky thuat va tham dinh dau vet so chuyen sau."""
        return SHIELDCALL_INVESTIGATOR_PROMPT

    return server


# ==============================================================================
# 4. CLI ENTRYPOINT
# ==============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="ShieldCall VN - Model Context Protocol (MCP) Server"
    )
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "streamable-http"],
        default="stdio",
        help="Che do MCP Transport (mac dinh: stdio)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8002,
        help="Port cho network transport SSE hoac HTTP (mac dinh: 8002)",
    )
    parser.add_argument(
        "--host",
        type=str,
        default="127.0.0.1",
        help="Host address cho network transport (mac dinh: 127.0.0.1)",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default=None,
        help="Dia chi ShieldCall API backend (vi du: http://127.0.0.1:8001/api/v1)",
    )
    parser.add_argument(
        "--api-key",
        type=str,
        default=None,
        help="ShieldCall API Key (vi du: sc_live_...)",
    )

    args = parser.parse_args()

    server = create_server(api_url=args.api_url, api_key=args.api_key)

    if args.transport == "stdio":
        logger.info("Starting ShieldCall MCP Server in stdio transport mode...")
        server.run(transport="stdio")
    elif args.transport == "sse":
        logger.info(f"Starting ShieldCall MCP Server in SSE mode on {args.host}:{args.port}...")
        server.run(transport="sse", host=args.host, port=args.port)
    elif args.transport == "streamable-http":
        logger.info(f"Starting ShieldCall MCP Server in HTTP mode on {args.host}:{args.port}...")
        server.run(transport="streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
