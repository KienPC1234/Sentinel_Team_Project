"""
ShieldCall VN — Privacy / PII redaction (điểm cải tiến #5: độ bảo mật dữ liệu).

Mục tiêu:
- Không để lộ thông tin cá nhân (SĐT, email, số tài khoản, CCCD, thẻ, token,
  API key...) qua log hệ thống hoặc qua các mô hình ngôn ngữ (đặc biệt mô hình
  bên thứ ba / cloud).
- Redaction diễn ra NGAY TRƯỚC khi ghi log hoặc trước khi gửi dữ liệu ra ngoài.
- Giữ nhãn loại dữ liệu để vẫn debug được (ví dụ "[SĐT đã ẩn]").

Lưu ý thiết kế: redaction KHÔNG được dùng để che bằng chứng khi phân tích cục bộ
(kẻ lừa đảo có thể nhét nội dung vào bằng chứng). Vì vậy module này chỉ áp dụng
cho: (a) logging, (b) gửi tới mô hình cloud, (c) hiển thị/lưu trữ tuỳ chọn.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Mapping

REDACTED = {
    "phone": "[SĐT đã ẩn]",
    "email": "[email đã ẩn]",
    "bank_account": "[số tài khoản đã ẩn]",
    "order_code": "[mã tra cứu đã ẩn]",
    "identifier": "[mã định danh đã ẩn]",
    "cccd": "[CCCD/CMND đã ẩn]",
    "card": "[số thẻ đã ẩn]",
    "secret": "[khoá/bí mật đã ẩn]",
    "address": "[địa chỉ đã ẩn]",
}

# 1. Bí mật, API key và Token
_SECRET = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_\-]{10,}"          # OpenAI
    r"|AIza[0-9A-Za-z_\-]{20,}"                  # Google API key
    r"|gh[pousr]_[A-Za-z0-9]{20,}"               # GitHub token
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"            # Slack
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"  # JWT
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"       # PEM
    r")\S*"
)
_BEARER = re.compile(r"(?i)\b(?:bearer\s+|x-apikey[\"']?\s*[:=]\s*)[A-Za-z0-9._\-]{16,}")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# 2. Ngữ cảnh mã đơn hàng / vận đơn / hóa đơn / khách hàng / hồ sơ / hợp đồng (tránh ngộ nhận thành STK)
_ORDER_PREFIX_RE = re.compile(
    r"(?i)\b((?:(?:mã|ma)\s+(?:đơn\s*hàng|don\s*hang|vận\s*đơn|van\s*don|giao\s*dịch|giao\s*dich|hóa\s*đơn|hoa\s*don|khách\s*hàng|khach\s*hang|hồ\s*sơ|ho\s*so|hợp\s*đồng|hop\s*dong|bưu\s*gửi|buu\s*gui|tra\s*cứu|tra\s*cuu|xác\s*nhận|xac\s*nhan|đặt\s*chỗ|dat\s*cho|vé|ve|chuyến\s*bay|chuyen\s*bay)|order\s*(?:id|code)|tracking\s*(?:no|number)|(?:mã|ma)\s*(?:đh|dh|kh|hd|vd))[\s:#]{1,6})([0-9A-Za-z\-_]{6,25})\b"
)

# 3. Ngữ cảnh CCCD / CMND có tiền tố nhận diện
_CCCD_PREFIX_RE = re.compile(
    r"(?i)\b((?:cccd|cmnd|(?:căn|can)\s*(?:cước|cuoc)(?:\s*(?:công\s*dân|cong\s*dan))?|(?:chứng|chung)\s*(?:minh|thư)(?:\s*(?:nhân\s*dân|nhan\s*dan))?|(?:số|so)\s*(?:định\s*danh|dinh\s*danh))[\s:#]{1,6})(\d{9,12})\b"
)

# 4. Ngữ cảnh tài khoản ngân hàng có tiền tố xác thực rõ ràng
_BANK_PREFIX_RE = re.compile(
    r"(?i)\b((?:stk|(?:số|so)\s*(?:tài\s*khoản|tai\s*khoan)|(?:tài\s*khoản|tai\s*khoan)(?:\s*(?:ngân\s*hàng|ngan\s*hang))?|tk\s*(?:nhận|nhan)|vào\s*tk|chuyển\s*(?:tiền\s*)?vào)[\s:#]{1,6})(\d{8,19})\b"
)

# 5. Số điện thoại Việt Nam (≥10 chữ số)
_PHONE = re.compile(r"(?<!\d)(?:\+?84|0)(?:[\s.\-]?\d){9,10}(?!\d)")

# 6. Số thẻ thanh toán quốc tế (13-19 số)
_CARD = re.compile(r"(?<!\d)(?:\d[\s\-]?){15,19}(?!\d)")

# 7. CMND cũ 9 chữ số độc lập
_CCCD_STANDALONE = re.compile(r"(?<!\d)\d{9}(?!\d)")

# 8. Dãy số định danh dài 8-19 số còn lại không có tiền tố ngân hàng -> dùng nhãn trung tính [mã định danh đã ẩn]
#    Tuyệt đối không mặc định là tài khoản ngân hàng để tránh làm LLM hiểu lầm loại thực thể.
_GENERIC_NUMERIC = re.compile(r"(?<!\d)\d{8,19}(?!\d)")


def redact_pii(text: str, *, keep_labels: bool = True) -> str:
    """
    Ẩn PII theo ngữ cảnh (Context-Aware Entity Redaction).
    Bảo toàn loại thực thể ngữ nghĩa chính xác, tránh Over-masking mã đơn hàng/hóa đơn thành STK.
    """
    if not text:
        return text
    if not isinstance(text, str):
        text = str(text)
    out = text
    out = _SECRET.sub(REDACTED["secret"] if keep_labels else "[X]", out)
    out = _BEARER.sub(lambda m: m.group(0).split()[-1][:4] + "…", out)
    out = _EMAIL.sub(REDACTED["email"] if keep_labels else "[X]", out)

    # 1. Bóc tách thực thể theo ngữ cảnh tiền tố trước
    out = _ORDER_PREFIX_RE.sub(r"\g<1>" + (REDACTED["order_code"] if keep_labels else "[X]"), out)
    out = _CCCD_PREFIX_RE.sub(r"\g<1>" + (REDACTED["cccd"] if keep_labels else "[X]"), out)
    out = _BANK_PREFIX_RE.sub(r"\g<1>" + (REDACTED["bank_account"] if keep_labels else "[X]"), out)

    # 2. Nhận diện các định dạng chuẩn đặc thù
    out = _PHONE.sub(REDACTED["phone"] if keep_labels else "[X]", out)
    out = _CARD.sub(REDACTED["card"] if keep_labels else "[X]", out)
    out = _CCCD_STANDALONE.sub(REDACTED["cccd"] if keep_labels else "[X]", out)

    # 3. Dãy số dài không xác định -> nhãn trung tính
    out = _GENERIC_NUMERIC.sub(REDACTED["identifier"] if keep_labels else "[X]", out)
    return out


def redact_obj(obj: Any) -> Any:
    """Ẩn PII đệ quy trong dict/list/str (dùng trước khi log/gửi cloud)."""
    if isinstance(obj, str):
        return redact_pii(obj)
    if isinstance(obj, Mapping):
        return {k: redact_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact_obj(v) for v in obj]
    return obj


def pii_redaction_enabled() -> bool:
    """Bật/tắt qua biến môi trường LLM_PII_REDACTION (mặc định BẬT)."""
    val = os.getenv("LLM_PII_REDACTION", "true").strip().lower()
    return val not in ("0", "false", "no", "off")


def redact_for_external_llm(text: str) -> str:
    """
    Bắt buộc ẩn PII trước khi gửi dữ liệu tới mô hình cloud hoặc dịch vụ bên ngoài.
    BẤT BIẾN AN NINH (Security Invariant - Audit P0):
    Không cho phép bất kỳ cấu hình hay biến môi trường nào (kể cả LLM_PII_REDACTION=false)
    vô hiệu hoá việc che dữ liệu cá nhân khi đẩy dữ liệu ra bên ngoài quy trình nội bộ.
    """
    if not text:
        return text
    return redact_pii(text)


class PIIRedactionFilter(logging.Filter):
    """Filter gắn vào logging handler để làm sạch PII mọi bản ghi log."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            if isinstance(record.msg, str) and record.msg:
                record.msg = redact_pii(record.msg)
            if record.args:
                if isinstance(record.args, Mapping):
                    record.args = {k: (redact_pii(v) if isinstance(v, str) else v) for k, v in record.args.items()}
                elif isinstance(record.args, tuple):
                    record.args = tuple(
                        redact_pii(a) if isinstance(a, str) else a for a in record.args
                    )
            # Nếu ai đó set record.__dict__ extra
            if record.exc_text:
                record.exc_text = redact_pii(record.exc_text)
        except Exception:  # tuyệt đối không được làm vỡ logging
            pass
        return True


def privacy_notice() -> Dict[str, Any]:
    """Mô tả chính sách xử lý dữ liệu để hiển thị cho người dùng."""
    return {
        "enabled": pii_redaction_enabled(),
        "summary": (
            "ShieldCall xử lý dữ liệu theo nguyên tắc tối thiểu hoá: nhật ký hệ thống và "
            "các lời gọi mô hình ngôn ngữ bên thứ ba đều được ẩn thông tin cá nhân "
            "(SĐT, email, số tài khoản, CCCD, thẻ, khoá bí mật) trước khi ghi/gửi."
        ),
        "protected_fields": list(REDACTED.keys()),
        "local_first": "Phân tích chính chạy cục bộ (Ollama + sandbox tắt mạng); dữ liệu thô không rời máy chủ khi không cần thiết.",
        "retention": "Kết quả quét lưu kèm mã định danh; nội dung thô có thể yêu cầu xoá.",
    }
