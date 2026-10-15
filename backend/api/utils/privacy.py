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
    "cccd": "[CCCD/CMND đã ẩn]",
    "card": "[số thẻ đã ẩn]",
    "secret": "[khoá/bí mật đã ẩn]",
    "address": "[địa chỉ đã ẩn]",
}

# Thứ tự áp dụng quan trọng: bí mật/ token trước, rồi tới dữ liệu dạng số dài.
# SĐT VN hợp lệ luôn ≥10 chữ số (0 + 9, hoặc +84 + 9) → yêu cầu ≥9 số sau tiền tố
# để số 9 chữ số (CMND cũ) rơi đúng nhãn CCCD/CMND thay vì bị nhận nhầm là SĐT.
_PHONE = re.compile(r"(?<!\d)(?:\+?84|0)(?:[\s.\-]?\d){9,10}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[\s\-]?){13,19}(?!\d)")
# CMND cũ 9 số (CCCD 12 số trùng dải số tài khoản nên được ẩn dưới nhãn tài khoản).
_CCCD = re.compile(r"(?<!\d)\d{9}(?!\d)")
_BANK = re.compile(r"(?<!\d)\d{8,19}(?!\d)")
_EMAIL = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_SECRET = re.compile(
    r"(?i)\b(?:sk-[A-Za-z0-9_\-]{10,}"          # OpenAI
    r"|AIza[0-9A-Za-z_\-]{20,}"                  # Google API key
    r"|gh[pousr]_[A-Za-z0-9]{20,}"               # GitHub token
    r"|xox[baprs]-[A-Za-z0-9\-]{10,}"            # Slack
    r"|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"  # JWT
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----"       # PEM
    r")\S*"
)
# Bearer / header token ngắn
_BEARER = re.compile(r"(?i)\b(?:bearer\s+|x-apikey[\"']?\s*[:=]\s*)[A-Za-z0-9._\-]{16,}")


def redact_pii(text: str, *, keep_labels: bool = True) -> str:
    """Ẩn PII trong một chuỗi. Trả về chuỗi đã ẩn (an toàn để log)."""
    if not text:
        return text
    if not isinstance(text, str):
        text = str(text)
    out = text
    out = _SECRET.sub(REDACTED["secret"], out)
    out = _BEARER.sub(lambda m: m.group(0).split()[-1][:4] + "…", out)
    out = _EMAIL.sub(REDACTED["email"] if keep_labels else "[X]", out)
    # Thứ tự: SĐT (định dạng VN) trước để không bị nhầm với số tài khoản; rồi thẻ,
    # CCCD 9 số (CMND cũ), cuối cùng số tài khoản chung 8–19 số.
    out = _PHONE.sub(REDACTED["phone"] if keep_labels else "[X]", out)
    out = _CARD.sub(REDACTED["card"] if keep_labels else "[X]", out)
    out = _CCCD.sub(REDACTED["cccd"] if keep_labels else "[X]", out)
    out = _BANK.sub(REDACTED["bank_account"] if keep_labels else "[X]", out)
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
    """Dùng trước khi gửi dữ liệu tới mô hình cloud (không phải Ollama local)."""
    return redact_pii(text) if pii_redaction_enabled() else text


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
