"""
ShieldCall VN — Heuristic scam-scoring rules (nguồn chân lý duy nhất cho tầng luật).

Tách khỏi view/AI để:
- Dễ kiểm thử & đánh giá định lượng (ROC/AUC, tuning ngưỡng — mục C6).
- Tránh trùng lặp từ điển giữa nơi này nơi khác.

Thuần tuý (không I/O, không Django) → chạy được cả trong script đánh giá độc lập.
"""

from __future__ import annotations

import re
from typing import Dict, List

from api.utils.vn_sources import VN_SCAM_PATTERNS

# Nhãn cơ sở (giữ để tương thích logic phân loại scam_type ở view, không trùng lặp với VN_SCAM_PATTERNS).
BASE_PATTERNS: Dict[str, str] = {
    r"otp|ma xac|mã xác|mã bảo mật|ma bao mat": "Yêu cầu OTP",
    r"chuyen khoan|chuyen tien|chuyển khoản|chuyển tiền": "Giao dịch tài chính",
    r"cong an|vien kiem sat|công an|viện kiểm sát|co quan dieu tra|cơ quan điều tra|toa an|tòa án": "Mạo danh cơ quan chức năng",
    r"trung thuong|qua tang|trúng thưởng|quà tặng|nhan thuong|nhận thưởng|trung xe|trúng xe|trung giai|trúng giải|trung phan qua|trúng phần quà": "Dụ dỗ trúng thưởng",
    r"khoa tai khoan|phong toa|khóa tài khoản|phong tỏa|tam giu|tạm giữ|khoa the|khóa thẻ|khoa dich vu|khóa dịch vụ": "Đe dọa tài khoản",
    r"viec nhe luong cao|tuyen dung|việc nhẹ lương cao|tuyển dụng|ctv|cộng tác viên|cong tac vien|chốt đơn|chot don": "Tuyển dụng lừa đảo",
}


def _merged_patterns() -> Dict[str, str]:
    # Từ điển VN mở rộng trước, nhãn cơ sở bổ sung (không trùng khái niệm).
    merged: Dict[str, str] = dict(VN_SCAM_PATTERNS)
    merged.update(BASE_PATTERNS)
    return merged


PATTERNS: Dict[str, str] = _merged_patterns()

# Mẫu nhận diện khuyến cáo / cảnh báo phòng chống lừa đảo chính thức (có dấu & không dấu)
ADVISORY_PATTERNS: List[str] = [
    r'(?:bộ\s*công\s*an|bo\s*cong\s*an|công\s*an[^\n,.:;]*|cong\s*an[^\n,.:;]*|cục\s*an\s*toàn\s*thông\s*tin|cuc\s*an\s*toan\s*thong\s*tin)\s*(?:khuyến\s*cáo|khuyen\s*cao|cảnh\s*báo|canh\s*bao|cảnh\s*giác|canh\s*giac)',
    r'(?:khuyến\s*cáo|khuyen\s*cao|cảnh\s*giác|canh\s*giac|phòng\s*ngừa|phong\s*ngua|phòng\s*chống|phong\s*chong)\s*(?:người\s*dân|nguoi\s*dan|tội\s*phạm|toi\s*pham|lừa\s*đảo|lua\s*dao|với|voi)',
    r'(?:tuyệt\s*đối\s*không|tuyet\s*doi\s*khong)\s*(?:cung\s*cấp|cung\s*cap|cài\s*đặt|cai\s*dat|chuyển|chuyen|chia\s*sẻ|chia\s*se)',
    r'(?:không|khong|tuyệt\s*đối\s*không|tuyet\s*doi\s*khong)\s*(?:chia\s*sẻ|chia\s*se|cung\s*cấp|cung\s*cap)\s*(?:mã|ma)\s*(?:otp|xác\s*thực|xac\s*thuc)',
    r'(?:cơ\s*quan\s*điều\s*tra|co\s*quan\s*dieu\s*tra|công\s*an|cong\s*an)\s*(?:không|khong)\s*(?:làm\s*việc|lam\s*viec|yêu\s*cầu|yeu\s*cau)',
    r'mọi\s*trường\s*hợp\s*yêu\s*cầu\s*chuyển\s*tiền\s*đều\s*là\s*lừa\s*đảo',
    r'(?:phản\s*ánh|phan\s*anh|báo\s*cáo|bao\s*cao)[^.\n]{0,40}?(?:tổng\s*đài|tong\s*dai)\s*(?:156|113)',
]

# Hành vi thôi thúc hành động (Call to action) — dấu hiệu lừa đảo mượn danh khuyến cáo
CALL_TO_ACTION_PATTERNS: List[str] = [
    r'https?://[^\s<>\"\'\)]+',
    r'(?:chuyển|chuyen|bắn|ban|nộp|nop|đóng|dong)\s*(?:[^\n,.;:]{0,30}?\s+)?(?:tiền|tien|phí|phi|cọc|coc)\s*(?:vào|vao|qua|tới|toi)\s*(?:stk|số\s*tài\s*khoản|so\s*tai\s*khoan|tài\s*khoản|tai\s*khoan)',
    r'(?:chuyển|chuyen|nộp|nop)\s*(?:tiền\s*)?(?:vào|vao|qua|tới|toi)\s*(?:stk|số\s*tài\s*khoản|so\s*tai\s*khoan|tài\s*khoản|tai\s*khoan)',
    r'liên\s*hệ\s*(?:qua\s*)?(?:zalo|telegram|sđt|hotline)\s*[:\d]',
    r'cài\s*(?:file\s*)?\.?apk',
    r'đọc\s*(?:lại\s*)?mã\s*otp',
    r'(?:yêu\s*cầu|bắt\s*buộc|đề\s*nghị|phải)\s*cung\s*cấp\s*(?:mã\s*)?otp',
    r'nhập\s*mã\s*otp\s*để\s*hủy',
]

# Định dạng tin nhắn OTP chuẩn kèm cảnh báo an toàn
OTP_AUTH_PATTERN: str = (
    r'(?:ma|mã)\s*(?:otp|smart\s*otp|xac\s*thuc(?:\s*smart)?\s*otp)'
    r'[^.\n]{0,70}?(?:la|là|:)?\s*\d{4,8}\b'
)
OTP_SECURITY_WARNING: str = (
    r'(?:khong|không|tuyet\s*doi\s*khong|tuyệt\s*đối\s*không)\s*'
    r'(?:chia\s*se|chia\s*sẻ|cung\s*cap|cung\s*cấp)\s*'
    r'(?:ma|mã)?\s*(?:nay|này|otp)?'
)

_OBFUSCATED_TOKEN_RE = re.compile(r'(?<![^\W_])(?:[^\W\d_][.\-_*•·]){2,}[^\W\d_](?![^\W_])', re.UNICODE)
_OBFUSCATED_PAIR_RE = re.compile(r'(?<![^\W_])[^\W\d_][.\-_*•·][^\W\d_](?![^\W_])', re.UNICODE)
_BENIGN_KINSHIP_POLICE_RE = re.compile(
    r'(?:bạn\s*trai|ban\s*trai|bạn\s*gái|ban\s*gai|người\s*yêu|nguoi\s*yeu|chồng|chong|vợ|vo|'
    r'bố|bo|mẹ|me|anh\s*trai|chị\s*gái|chi\s*gai|em\s*trai|em\s*gái|em\s*gai|'
    r'bạn\s*thân|ban\s*than|bạn\s*tớ|ban\s*to|bạn\s*mình|ban\s*minh|bạn\s*em|ban\s*em|'
    r'anh\s*họ|chú|bác)[^.\n,;]{0,20}?(?:là|làm|lam)\s*(?:công\s*an|cong\s*an)',
    re.IGNORECASE | re.UNICODE,
)


def _deobfuscate_obfuscated_chars(text: str) -> str:
    """Chuẩn hoá chữ bị chèn ký tự phân cách kiểu C.ô.n.g a.n -> công an."""
    raw = text or ''
    hits = _OBFUSCATED_TOKEN_RE.findall(raw)
    if not hits:
        return raw
    cleaned = _OBFUSCATED_TOKEN_RE.sub(lambda m: re.sub(r'[.\-_*•·]', '', m.group(0)), raw)
    # Khi câu đã có nhiều từ bị chèn dấu (>= 2 từ >= 3 ký tự), chuẩn hoá tiếp từ 2 ký tự như a.n, á.n, v.ụ
    if len(hits) >= 2:
        cleaned = _OBFUSCATED_PAIR_RE.sub(lambda m: re.sub(r'[.\-_*•·]', '', m.group(0)), cleaned)
    return cleaned


def match_patterns(text: str) -> List[str]:
    """Trả về danh sách nhãn dấu hiệu khớp trong văn bản (có dấu, không dấu và chữ bị chèn dấu)."""
    t = (text or "").lower()
    deobf = _deobfuscate_obfuscated_chars(t)
    # Bỏ qua nhắc nghề nghiệp người thân/bạn bè đời thường ("bạn trai tớ là công an") khi không có bối cảnh đe dọa
    t_clean = _BENIGN_KINSHIP_POLICE_RE.sub(' ', t)
    deobf_clean = _BENIGN_KINSHIP_POLICE_RE.sub(' ', deobf)
    return [
        label
        for pattern, label in PATTERNS.items()
        if re.search(pattern, t_clean) or (deobf_clean != t_clean and re.search(pattern, deobf_clean))
    ]


def heuristic_score(text: str, *, per_hit: int = 20, cap: int = 100) -> int:
    """Điểm heuristic 0–100 theo số dấu hiệu khớp, có nhận biết ngữ cảnh khuyến cáo và phủ định."""
    t = (text or "").lower()
    deobf = _deobfuscate_obfuscated_chars(t)
    raw_patterns = match_patterns(text)
    if not raw_patterns:
        return 0

    has_adv = any(re.search(p, t) or (deobf != t and re.search(p, deobf)) for p in ADVISORY_PATTERNS)
    has_cta = any(re.search(p, t) or (deobf != t and re.search(p, deobf)) for p in CALL_TO_ACTION_PATTERNS)

    # 1. Khuyến cáo chính thức của cơ quan nhà nước không kèm link hay STK nộp tiền
    if has_adv and not has_cta:
        return 0

    # 2. SMS thông báo mã OTP chuẩn ngân hàng kèm câu cảnh báo không chia sẻ
    has_otp_auth = bool(re.search(OTP_AUTH_PATTERN, t))
    has_otp_warn = bool(re.search(OTP_SECURITY_WARNING, t))
    if has_otp_auth and has_otp_warn and not has_cta:
        return 5

    return min(cap, len(raw_patterns) * per_hit)
