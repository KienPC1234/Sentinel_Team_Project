"""Conservative Vietnamese numbering checks; structure is not caller authentication.

Uses libphonenumber metadata for allocation, length and country-code parsing.
Never declares a number safe, fraudulent, or owned by an organization.
"""
from __future__ import annotations

import re
from typing import Any, Dict

import phonenumbers
from phonenumbers import PhoneNumberType

NUMBERING_SOURCE = "https://mst.gov.vn/bo-tttt-day-manh-dinh-danh-cuoc-goi-de-ngan-ngua-lua-dao-tren-khong-gian-mang-19724111208351436.htm"
SPOOFING_SOURCE = "https://congan.angiang.gov.vn/canh-bao-thu-doan-gia-mao-so-dien-thoai-hien-thi-de-lua-dao-chiem-doat-tai-san"
INTERNATIONAL_SOURCE = "https://mst.gov.vn/canh-bao-lua-dao-tu-cuoc-goi-dien-thoai-quoc-te-197159134.htm"

def analyze_number_structure(number: str, *, claimed_vietnamese_entity: bool = False) -> Dict[str, Any]:
    """Explain numbering facts, never infer scammer identity from a number alone."""
    original = (number or "").strip()
    compact = re.sub(r"[\s().-]", "", original)
    if compact.startswith("00"):
        compact = "+" + compact[2:]
    info: Dict[str, Any] = {
        "status": "unverified_format",
        "type": "unknown",
        "valid_format": False,
        "possible_number": False,
        "is_vietnam": False,
        "country_calling_code": None,
        "national_prefix": None,
        "claimed_vietnamese_entity": bool(claimed_vietnamese_entity),
        "foreign_claim_mismatch": False,
        "label": "CHƯA XÁC MINH CẤU TRÚC SỐ",
        "warnings": [],
        "source": {
            "name": "Bộ quản lý viễn thông Việt Nam — định danh và cấu trúc số",
            "url": NUMBERING_SOURCE,
            "limitation": "Kiểm tra cấu trúc và dữ liệu kho số, không xác thực chủ thuê bao hay nguồn cuộc gọi.",
        },
        "caller_id_verified": False,
    }
    if not re.fullmatch(r"(?:\+[1-9][0-9]{1,14}|0[0-9]{7,14})", compact):
        info["status"] = "invalid_format"
        info["label"] = "ĐỊNH DẠNG KHÔNG HỢP LỆ / CHƯA ĐƯỢC XÁC MINH"
        info["warnings"].append("Không khớp định dạng số thuê bao thông thường. Điều này chưa chứng minh lừa đảo.")
        return info
    try:
        parsed = phonenumbers.parse(compact, None if compact.startswith("+") else "VN")
    except phonenumbers.NumberParseException:
        info["status"] = "invalid_format"
        info["label"] = "ĐỊNH DẠNG KHÔNG HỢP LỆ / CHƯA ĐƯỢC XÁC MINH"
        info["warnings"].append("Không phân tích được mã quốc gia hoặc mã mạng.")
        return info
    cc = int(parsed.country_code)
    info["country_calling_code"] = "+" + str(cc)
    info["is_vietnam"] = cc == 84
    info["possible_number"] = phonenumbers.is_possible_number(parsed)
    info["valid_format"] = phonenumbers.is_valid_number(parsed)
    if cc != 84:
        info["status"] = "foreign_number"
        info["type"] = "international"
        info["label"] = "ĐẦU SỐ QUỐC TẾ — KHÔNG THUỘC MÃ +84"
        info["warnings"].append("Số quốc tế không tự động là số lừa đảo. Không suy luận quốc gia chỉ từ một vài chữ số sau dấu +.")
        if claimed_vietnamese_entity:
            info["foreign_claim_mismatch"] = True
            info["warnings"].append(
                "Người gọi tự nhận là cơ quan/doanh nghiệp Việt Nam nhưng số hiển thị mang mã quốc gia khác +84; cần xác minh độc lập."
            )
        return info
    national = phonenumbers.national_significant_number(parsed)
    domestic = "0" + national
    kind = phonenumbers.number_type(parsed)
    if kind in (PhoneNumberType.MOBILE, PhoneNumberType.FIXED_LINE_OR_MOBILE) and len(domestic) == 10 and domestic.startswith(("03","05","07","08","09")):
        info["type"] = "mobile"
        info["national_prefix"] = domestic[:3]
        info["status"] = "valid_vn_mobile" if info["valid_format"] else "unverified_vn_prefix"
    elif kind == PhoneNumberType.FIXED_LINE and domestic.startswith("02"):
        info["type"] = "landline"
        info["national_prefix"] = domestic[:3] if domestic.startswith(("024","028")) else domestic[:4]
        info["status"] = "valid_vn_landline" if info["valid_format"] else "unverified_vn_prefix"
    elif info["valid_format"]:
        info["type"] = "other_vn_service"
        info["status"] = "valid_vn_other"
    else:
        info["status"] = "invalid_vn_number"
    if info["status"] in ("valid_vn_mobile", "valid_vn_landline", "valid_vn_other"):
        info["label"] = "CẤU TRÚC PHÙ HỢP KHO SỐ VIỆT NAM — CHƯA XÁC THỰC NGƯỜI GỌI"
    else:
        info["label"] = "CHƯA KHỚP QUY HOẠCH SỐ VIỆT NAM"
        info["warnings"].append("Độ dài hoặc đầu số chưa khớp dữ liệu phân bổ hiện có; không đủ để khẳng định giả mạo.")
    info["warnings"].append("Caller ID có thể bị giả mạo dù số hiển thị đúng định dạng. Không cung cấp OTP, mật khẩu hay chuyển tiền trước khi xác minh.")
    return info
