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

import copy
import logging
import os
import re
from typing import Any, Dict, Iterable, List, Mapping, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

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
    out = _BEARER.sub(lambda m: ("Bearer " if m.group(0).lower().startswith("bearer") else "") + (REDACTED["secret"] if keep_labels else "[X]"), out)
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


_SENSITIVE_QUERY_KEYS = frozenset({
    "token", "access_token", "auth", "authorization", "key", "api_key", "apikey",
    "secret", "password", "passwd", "pwd", "otp", "code", "session", "sid",
    "email", "mail", "phone", "tel", "mobile", "sdt", "stk", "account", "cccd",
    "cmnd", "user", "userid", "uid", "signature", "sig",
})


def parse_strict_bool(val: Any) -> bool:
    """Parse giá trị boolean nghiêm ngặt cho consent (opt-in PII/LLM)."""
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val == 1
    if isinstance(val, str):
        return val.strip().lower() in ("true", "1", "yes")
    return False


def parse_mask_pii_flag(data: Any, default: bool = True) -> bool:
    """Đọc tùy chọn bật/tắt che PII (`mask_pii`) từ JSON hoặc FormData."""
    if not isinstance(data, Mapping) and not hasattr(data, "get"):
        return default
    raw = data.get("mask_pii", data.get("hide_pii", None))
    if raw is None or raw == "":
        return default
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, (int, float)):
        return bool(raw)
    if isinstance(raw, str):
        val = raw.strip().lower()
        if val in ("0", "false", "no", "off"):
            return False
        if val in ("1", "true", "yes", "on"):
            return True
    return default


def is_scan_privacy_masked(scan_event: Any, default: bool = True) -> bool:
    """Đọc trạng thái `privacy_masked` đã lưu trên ScanEvent."""
    rj = getattr(scan_event, "result_json", None)
    if isinstance(rj, Mapping) and "privacy_masked" in rj:
        return bool(rj.get("privacy_masked"))
    return default


def mask_phone_display(phone: Any) -> str:
    """Che phần giữa SĐT, giữ 3-4 ký tự đầu và 3 số cuối để vẫn đối chiếu được."""
    text = str(phone or "").strip()
    if not text:
        return text
    if text.startswith("+") and len(text) > 7:
        return f"{text[:4]}****{text[-3:]}"
    if len(text) > 6:
        return f"{text[:3]}****{text[-3:]}"
    return "****"


def mask_email_display(email: Any) -> str:
    """Che phần local-part của email nhưng giữ nguyên domain để đối chiếu uy tín."""
    text = str(email or "").strip()
    if not text or "@" not in text:
        return redact_pii(text)
    local, domain = text.split("@", 1)
    prefix = local[:2] if len(local) >= 2 else (local[:1] or "*")
    return f"{prefix}***@{domain}"


def mask_account_display(account: Any) -> str:
    """Che số tài khoản ngân hàng, chỉ giữ tối đa 4 ký tự cuối."""
    digits = str(account or "").strip()
    if not digits:
        return "****"
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_target_identifier(target_type: Any, value: Any) -> str:
    """Che SĐT/STK dùng chung cho bảng tin xu hướng và bộ chọn lượt quét."""
    raw = str(value or "").strip()
    if len(raw) <= 6:
        return raw
    if target_type == "phone":
        return f"{raw[:4]}****{raw[-2:]}"
    if target_type == "account":
        return f"{raw[:3]}*****{raw[-3:]}"
    return raw


def mask_person_name(name: Any) -> str:
    """Che tên cá nhân hiển thị công khai, chỉ giữ họ hoặc 2 ký tự đầu."""
    clean = str(name or "").strip()
    if not clean:
        return ""
    parts = clean.split()
    if len(parts) > 1:
        return f"{parts[0]} ***"
    return f"{clean[:2]}***" if len(clean) > 2 else "***"


def mask_url_query(url: Any) -> str:
    """Ẩn các tham số query/fragment chứa token, email, SĐT hoặc chuỗi định danh dài."""
    raw = str(url or "").strip()
    if not raw:
        return raw
    try:
        parsed = urlsplit(raw)
    except Exception:
        return redact_pii(raw)
    if not parsed.query and not parsed.fragment:
        return redact_pii(raw)

    safe_pairs: List[Tuple[str, str]] = []
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        key_l = k.strip().lower()
        val_redacted = redact_pii(v)
        if key_l in _SENSITIVE_QUERY_KEYS or val_redacted != v or len(v) >= 24:
            safe_pairs.append((k, "[đã ẩn]"))
        else:
            safe_pairs.append((k, v))

    new_query = urlencode(safe_pairs, doseq=True) if parsed.query else ""
    new_frag = redact_pii(parsed.fragment) if parsed.fragment else ""
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, new_frag))


def mask_scan_raw_input(scan_type: str, raw_input: Any, *, mask_pii: bool = True) -> str:
    """Chuẩn hóa/che `raw_input` theo đúng loại scan khi cần lưu ScanEvent."""
    text = str(raw_input or "")
    if not text or not mask_pii:
        return text
    if scan_type == "phone":
        return mask_phone_display(text)
    if scan_type == "email":
        return mask_email_display(text)
    if scan_type == "domain":
        return mask_url_query(text)
    if scan_type == "account":
        if ":" in text:
            bank, acc = text.split(":", 1)
            return f"{bank}:{mask_account_display(acc)}"
        return mask_account_display(text)
    return redact_pii(text)


def _mask_osint_dict(entities: Mapping[str, Any], touched: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = dict(entities)
    if isinstance(entities.get("phones"), list):
        out["phones"] = [mask_phone_display(p) for p in entities["phones"]]
        if out["phones"]:
            touched.append("phone")
    if isinstance(entities.get("emails"), list):
        out["emails"] = [mask_email_display(e) for e in entities["emails"]]
        if out["emails"]:
            touched.append("email")
    if isinstance(entities.get("bank_accounts"), list):
        out["bank_accounts"] = [mask_account_display(a) for a in entities["bank_accounts"]]
        if out["bank_accounts"]:
            touched.append("bank_account")
    if isinstance(entities.get("urls"), list):
        out["urls"] = [mask_url_query(u) for u in entities["urls"]]
        if out["urls"]:
            touched.append("url_query")
    if isinstance(entities.get("handles"), list):
        out["handles"] = [redact_pii(str(h)) for h in entities["handles"]]
    return out


def _mask_list_strings(items: Iterable[Any]) -> List[Any]:
    res = []
    for item in items:
        res.append(redact_obj(item))
    return res


def apply_scan_privacy(
    scan_type: str,
    result: Dict[str, Any],
    *,
    mask_pii: bool = True,
    raw_input: str = "",
    normalized_input: str = "",
) -> Tuple[str, str, Dict[str, Any]]:
    """
    Áp dụng chính sách ẩn dữ liệu nhạy cảm thống nhất cho mọi loại quét trước khi lưu DB / trả về UI.

    - Khi `mask_pii=True`: che SĐT, email, STK, CCCD, bí mật, query token trong URL, OCR/transcript.
    - Khi `mask_pii=False`: giữ nguyên dữ liệu hiển thị cho người dùng nhưng vẫn gắn metadata minh bạch;
      log hệ thống và lời gọi LLM ngoài vẫn bị buộc che qua `PIIRedactionFilter` / `redact_for_external_llm`.
    """
    safe_result: Dict[str, Any] = copy.deepcopy(result) if isinstance(result, dict) else {}
    safe_raw = str(raw_input or "")
    safe_norm = str(normalized_input or "")
    touched: List[str] = []

    if not mask_pii:
        safe_result["privacy_masked"] = False
        safe_result["privacy_mode"] = "full"
        safe_result["privacy_protected_fields"] = []
        safe_result["privacy_redacted_count"] = 0
        safe_result["privacy_note"] = (
            "Đang ở chế độ nguyên văn theo lựa chọn của bạn: lưu lịch sử và cho phép AI phân tích đầy đủ ngữ cảnh; nhật ký hệ thống (log) vẫn luôn tự động che thông tin cá nhân."
        )
        return safe_raw, safe_norm, safe_result

    safe_raw = mask_scan_raw_input(scan_type, safe_raw, mask_pii=True)
    if safe_norm:
        if scan_type == "phone":
            safe_norm = mask_phone_display(safe_norm)
            touched.append("phone")
        elif scan_type == "email":
            safe_norm = mask_email_display(safe_norm)
            touched.append("email")
        elif scan_type == "domain":
            safe_norm = mask_url_query(safe_norm)
        elif scan_type != "account":
            safe_norm = redact_pii(safe_norm)

    redacted_count = 0

    def _redact_field(container: Dict[str, Any], key: str, tag: str) -> None:
        nonlocal redacted_count
        val = container.get(key)
        if isinstance(val, str) and val:
            masked = redact_pii(val)
            if masked != val:
                redacted_count += 1
                touched.append(tag)
            container[key] = masked

    if scan_type == "phone":
        if safe_result.get("phone"):
            safe_result["phone"] = mask_phone_display(safe_result["phone"])
            touched.append("phone")
            redacted_count += 1
        for key in ("analysis_result", "explanation"):
            _redact_field(safe_result, key, "text_pii")
        if isinstance(safe_result.get("reasons"), list):
            safe_result["reasons"] = _mask_list_strings(safe_result["reasons"])
        ol = safe_result.get("online_lookup")
        if isinstance(ol, dict) and isinstance(ol.get("matches"), list):
            ol["matches"] = [redact_obj(m) for m in ol["matches"]]

    elif scan_type == "account":
        if safe_result.get("account_masked"):
            safe_result["account_display"] = safe_result["account_masked"]
            touched.append("bank_account")
            redacted_count += 1

    elif scan_type == "email":
        if safe_result.get("email"):
            safe_result["email"] = mask_email_display(safe_result["email"])
            touched.append("email")
            redacted_count += 1
        _redact_field(safe_result, "content_snippet", "email_body")
        _redact_field(safe_result, "explanation", "text_pii")
        info = safe_result.get("extracted_info")
        if isinstance(info, dict):
            for addr_k in ("from", "to"):
                if info.get(addr_k):
                    info[addr_k] = mask_email_display(info[addr_k]) if "@" in str(info[addr_k]) else redact_pii(str(info[addr_k]))
                    touched.append("email")
            if isinstance(info.get("subject"), str) and info.get("subject"):
                _redact_field(info, "subject", "email_subject")
        for list_k in ("indicators", "security_checks", "prevention_measures", "advice"):
            if isinstance(safe_result.get(list_k), list):
                safe_result[list_k] = _mask_list_strings(safe_result[list_k])

    elif scan_type == "domain":
        if isinstance(safe_result.get("url"), str) and safe_result["url"]:
            orig_u = safe_result["url"]
            masked_u = mask_url_query(orig_u)
            if masked_u != orig_u:
                touched.append("url_query")
                redacted_count += 1
            safe_result["url"] = masked_u
        for key in ("page_title", "explanation", "web_context"):
            _redact_field(safe_result, key, "text_pii")
        if isinstance(safe_result.get("network_details"), list):
            safe_result["network_details"] = _mask_list_strings(safe_result["network_details"])

    elif scan_type in ("message", "qr"):
        for key in ("ocr_text", "explanation", "ai_insight", "web_context"):
            _redact_field(safe_result, key, key if key == "ocr_text" else "text_pii")
        if isinstance(safe_result.get("qr_contents"), list):
            masked_qr = []
            for item in safe_result["qr_contents"]:
                s = str(item)
                m = mask_url_query(s) if "://" in s else redact_pii(s)
                if m != s:
                    redacted_count += 1
                    touched.append("qr_payload")
                masked_qr.append(m)
            safe_result["qr_contents"] = masked_qr
        for ent_key in ("osint_entities", "entities"):
            ent = safe_result.get(ent_key)
            if isinstance(ent, Mapping):
                safe_result[ent_key] = _mask_osint_dict(ent, touched)
                redacted_count += 1
        if isinstance(safe_result.get("vision_details"), list):
            safe_result["vision_details"] = [redact_obj(v) for v in safe_result["vision_details"]]

    elif scan_type == "audio":
        for key in ("transcript", "explanation", "web_context"):
            _redact_field(safe_result, key, "transcript" if key == "transcript" else "text_pii")
        if isinstance(safe_result.get("segments"), list):
            safe_segs = []
            for seg in safe_result["segments"]:
                if isinstance(seg, dict) and isinstance(seg.get("text"), str):
                    seg_copy = dict(seg)
                    masked_seg = redact_pii(seg_copy["text"])
                    if masked_seg != seg_copy["text"]:
                        redacted_count += 1
                        touched.append("transcript")
                    seg_copy["text"] = masked_seg
                    safe_segs.append(seg_copy)
                else:
                    safe_segs.append(redact_obj(seg))
            safe_result["segments"] = safe_segs

    elif scan_type == "file":
        for key in ("file_name", "ai_explanation", "summary", "script_snippet"):
            _redact_field(safe_result, key, "file_meta" if key == "file_name" else "text_pii")
        if isinstance(safe_result.get("details"), list):
            safe_result["details"] = _mask_list_strings(safe_result["details"])
        if isinstance(safe_result.get("forensic_evidence"), list):
            safe_result["forensic_evidence"] = [redact_obj(ev) for ev in safe_result["forensic_evidence"]]

    dedup_fields = list(dict.fromkeys(touched))
    safe_result["privacy_masked"] = True
    safe_result["privacy_mode"] = "masked"
    safe_result["privacy_protected_fields"] = dedup_fields
    safe_result["privacy_redacted_count"] = max(redacted_count, len(dedup_fields))
    safe_result["privacy_note"] = (
        "Đã bật chế độ che PII: phân tích lõi thực hiện cục bộ, dữ liệu định danh (SĐT, Email, STK, CCCD, URL token) được che trước khi lưu lịch sử & gửi mô hình AI ngoài."
    )
    return safe_raw, safe_norm, safe_result

