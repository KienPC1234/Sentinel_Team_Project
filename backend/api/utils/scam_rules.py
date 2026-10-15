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


def match_patterns(text: str) -> List[str]:
    """Trả về danh sách nhãn dấu hiệu khớp trong văn bản (có dấu & không dấu)."""
    t = (text or "").lower()
    return [label for pattern, label in PATTERNS.items() if re.search(pattern, t)]


def heuristic_score(text: str, *, per_hit: int = 20, cap: int = 100) -> int:
    """Điểm heuristic 0–100 theo số dấu hiệu khớp (mỗi dấu hiệu `per_hit`)."""
    return min(cap, len(match_patterns(text)) * per_hit)
