"""
ShieldCall VN – MCP Server HTTP Client
Handles communication with the ShieldCall backend API using API Key authentication.
"""
import os
import json
import logging
import requests
from typing import Any, Dict, Optional

logger = logging.getLogger("shieldcall_mcp.client")


class ShieldCallClient:
    """Client for querying ShieldCall VN anti-fraud REST APIs."""

    def __init__(self, api_url: Optional[str] = None, api_key: Optional[str] = None, timeout: int = 30):
        # Default API endpoint (falls back to local dev or production URL)
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

    def _request(self, method: str, endpoint: str, data: Optional[Dict] = None, params: Optional[Dict] = None) -> Dict[str, Any]:
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
                    "error": "Xác thực API Key thất bại (401 Unauthorized). "
                             "Vui lòng kiểm tra biến môi trường SHIELDCALL_API_KEY."
                }
            if resp.status_code == 429:
                try:
                    detail = resp.json().get("detail", "Vượt quá hạn mức request.")
                except Exception:
                    detail = resp.text
                return {"error": f"Hạn mức API Key đã hết hoặc bị giới hạn tốc độ: {detail}"}

            if not resp.ok:
                try:
                    err_json = resp.json()
                    return {"error": f"Lỗi API ({resp.status_code}): {err_json}"}
                except Exception:
                    return {"error": f"Lỗi API ({resp.status_code}): {resp.text[:300]}"}

            return resp.json()
        except requests.exceptions.ConnectionError:
            return {
                "error": f"Không thể kết nối đến máy chủ ShieldCall tại {self.api_url}. "
                         "Vui lòng kiểm tra xem backend Django đang chạy hay không."
            }
        except requests.exceptions.Timeout:
            return {"error": f"Hết thời gian chờ phản hồi ({self.timeout}s) từ ShieldCall API."}
        except Exception as e:
            return {"error": f"Lỗi ngoại lệ khi gọi ShieldCall API: {str(e)}"}

    def scan_phone(self, phone: str) -> Dict[str, Any]:
        """Quét và tra cứu mức độ rủi ro của số điện thoại."""
        return self._request("POST", "scan/phone/", data={"phone": phone})

    def scan_bank_account(self, bank: str, account: str) -> Dict[str, Any]:
        """Tra cứu số tài khoản ngân hàng trong danh sách đen lừa đảo."""
        return self._request("POST", "scan/account/", data={"bank": bank, "account": account})

    def scan_domain(self, url: str) -> Dict[str, Any]:
        """Phân tích website, URL, phát hiện tên miền giả mạo (phishing/lookalike)."""
        return self._request("POST", "scan/domain/", data={"url": url, "deep_scan": False})

    def scan_message(self, message: str) -> Dict[str, Any]:
        """Phân tích nội dung tin nhắn, SMS, kịch bản lừa đảo chuyển tiền/OTP."""
        return self._request("POST", "scan/message/", data={"message": message, "sync": True})

    def scan_email(self, email: str, content: str = "", subject: str = "") -> Dict[str, Any]:
        """Phân tích địa chỉ email, SPF/DMARC và nội dung email lừa đảo."""
        return self._request("POST", "scan/email/", data={"email": email, "content": content, "subject": subject, "sync": True})

    def get_supported_banks(self) -> Any:
        """Lấy danh sách các ngân hàng được hỗ trợ tại Việt Nam từ VietQR."""
        return self._request("GET", "scan/banks/")

    def lookup_scam_db(self, query: str, entity_type: str = "all") -> Dict[str, Any]:
        """Tra cứu thực thể trong kho dữ liệu cộng đồng ShieldCall VN."""
        return self._request("GET", "scan/lookup/", params={"q": query, "type": entity_type})

    def get_scam_radar_trends(self) -> Dict[str, Any]:
        """Lấy số liệu radar và xu hướng thủ đoạn lừa đảo mới nhất."""
        return self._request("GET", "trends/radar-stats/")

    @staticmethod
    def normalize_scam_type(scam_type: str) -> str:
        s = (scam_type or '').strip().lower()
        mapping = {
            'impersonation': 'police_impersonation',
            'police': 'police_impersonation',
            'bank': 'bank_impersonation',
            'otp': 'otp_steal',
            'recruitment': 'recruitment_scam',
            'job': 'recruitment_scam',
            'investment': 'investment_scam',
            'delivery': 'delivery_scam',
            'loan': 'loan_scam',
            'romance': 'romance_scam',
        }
        valid = {
            'police_impersonation', 'bank_impersonation', 'recruitment_scam',
            'investment_scam', 'delivery_scam', 'loan_scam', 'otp_steal',
            'phishing', 'romance_scam', 'other'
        }
        if s in valid:
            return s
        return mapping.get(s, 'other')

    def report_scam(
        self,
        target_type: str,
        target_value: str,
        scam_type: str,
        description: str,
        evidence_note: str = "",
    ) -> Dict[str, Any]:
        """Gửi báo cáo hành vi lừa đảo vào hệ thống kiểm duyệt cộng đồng."""
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

