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

# Nhãn cơ sở (giữ để tương thích logic phân loại scam_type ở view).
BASE_PATTERNS: Dict[str, str] = {
    r"otp|ma xac|mã xác": "Yêu cầu OTP",
    r"chuyen khoan|chuyen tien|chuyển khoản|chuyển tiền": "Giao dịch tài chính",
    r"cong an|vien kiem sat|công an|viện kiểm sát": "Mạo danh cơ quan chức năng",
    r"trung thuong|qua tang|trúng thưởng|quà tặng": "Dụ dỗ trúng thưởng",
    r"khoa tai khoan|phong toa|khóa tài khoản|phong tỏa": "Đe dọa tài khoản",
    r"viec nhe luong cao|tuyen dung|việc nhẹ lương cao|tuyển dụng": "Tuyển dụng lừa đảo",
}


def _merged_patterns() -> Dict[str, str]:
    # Từ điển VN mở rộng trước, nhãn cơ sở ghi đè (ưu tiên tương thích).
    merged: Dict[str, str] = dict(VN_SCAM_PATTERNS)
    merged.update(BASE_PATTERNS)
    return merged


PATTERNS: Dict[str, str] = _merged_patterns()

# Mẫu nhận diện khuyến cáo / cảnh báo phòng chống lừa đảo chính thức
ADVISORY_PATTERNS: List[str] = [
    r'(?:bộ\s*công\s*an|công\s*an[^\n,.:;]*)\s*(?:khuyến\s*cáo|cảnh\s*báo|thông\s*báo|phát\s*đi)',
    r'(?:khuyến\s*cáo|cảnh\s*báo|phòng\s*ngừa|phòng\s*chống)\s*(?:người\s*dân|tội\s*phạm|lừa\s*đảo)',
    r'tuyệt\s*đối\s*không\s*(?:cung\s*cấp|cài\s*đặt|chuyển|chia\s*sẻ)',
    r'(?:không|tuyệt\s*đối\s*không)\s*chia\s*sẻ\s*mã\s*(?:otp|xác\s*thực)',
    r'(?:cơ\s*quan\s*điều\s*tra|công\s*an)\s*không\s*(?:làm\s*việc|yêu\s*cầu\s*người\s*dân\s*chuyển)',
    r'mọi\s*trường\s*hợp\s*yêu\s*cầu\s*chuyển\s*tiền\s*đều\s*là\s*lừa\s*đảo',
]

# Hành vi thôi thúc hành động (Call to action) — dấu hiệu lừa đảo mượn danh khuyến cáo
CALL_TO_ACTION_PATTERNS: List[str] = [
    r'https?://[^\s<>\"\'\)]+',
    r'(?:chuyển|bắn|nộp)\s*(?:tiền\s*)?(?:vào|qua|tới)\s*(?:stk|số\s*tài\s*khoản|tài\s*khoản)',
    r'liên\s*hệ\s*(?:qua\s*)?(?:zalo|telegram|sđt|hotline)\s*[:\d]',
    r'cài\s*(?:file\s*)?\.?apk',
    r'đọc\s*(?:lại\s*)?mã\s*otp',
    r'(?:yêu\s*cầu|bắt\s*buộc|đề\s*nghị|phải)\s*cung\s*cấp\s*(?:mã\s*)?otp',
    r'nhập\s*mã\s*otp\s*để\s*hủy',
]

# Định dạng tin nhắn OTP chuẩn kèm cảnh báo an toàn
OTP_AUTH_PATTERN: str = r'(?:ma|mã)\s*otp\s*(?:cua\s*ban|xac\s*nhan|xác\s*nhận|smart\s*otp|của\s*quy\s*khach|của\s*quý\s*khách)?\s*(?:la|là)?\s*[:\s]?\s*\d{4,8}'
OTP_SECURITY_WARNING: str = r'(?:khong|không|tuyet\s*doi\s*khong|tuyệt\s*đối\s*không)\s*(?:chia\s*se|chia\s*sẻ|cung\s*cap|cung\s*cấp)\s*(?:ma|mã)?\s*(?:nay|này|otp)?'


def match_patterns(text: str) -> List[str]:
    """Trả về danh sách nhãn dấu hiệu khớp trong văn bản (có dấu & không dấu)."""
    t = (text or "").lower()
    return [label for pattern, label in PATTERNS.items() if re.search(pattern, t)]


def heuristic_score(text: str, *, per_hit: int = 20, cap: int = 100) -> int:
    """Điểm heuristic 0–100 theo số dấu hiệu khớp, có nhận biết ngữ cảnh khuyến cáo và phủ định."""
    t = (text or "").lower()
    raw_patterns = match_patterns(text)
    if not raw_patterns:
        return 0

    has_adv = any(re.search(p, t) for p in ADVISORY_PATTERNS)
    has_cta = any(re.search(p, t) for p in CALL_TO_ACTION_PATTERNS)

    # 1. Khuyến cáo chính thức của cơ quan nhà nước không kèm link hay STK nộp tiền
    if has_adv and not has_cta:
        return 0

    # 2. SMS thông báo mã OTP chuẩn ngân hàng kèm câu cảnh báo không chia sẻ
    has_otp_auth = bool(re.search(OTP_AUTH_PATTERN, t))
    has_otp_warn = bool(re.search(OTP_SECURITY_WARNING, t))
    if has_otp_auth and has_otp_warn and not has_cta:
        return 5

    return min(cap, len(raw_patterns) * per_hit)
