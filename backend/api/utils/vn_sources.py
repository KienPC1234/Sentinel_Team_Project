"""
ShieldCall VN — Nguồn dữ liệu & kênh chính thức tại Việt Nam (điểm cải tiến #2).

Bổ sung dữ liệu nguồn gốc Việt Nam:
- Kênh/đầu mối chính thức để người dùng xác minh & trình báo (NCSC, Bộ Công an,
  tổng đài ngân hàng, BHXH, VNCERT/CC…).
- Từ điển dấu hiệu lừa đảo tiếng Việt (có/không dấu) dùng cho tầng heuristic.
- Tên miền tin cậy VN (ngân hàng, ví, cơ quan nhà nước, tiện ích) để phát hiện giả mạo.
- Danh mục tham chiếu VN (báo chí/cổng thông tin) để trích dẫn bằng chứng.

Lưu ý độ tin cậy: danh mục này được biên soạn thủ công từ nguồn công khai; nên
định kỳ đối chiếu lại với website chính thức của từng đơn vị (URL/SĐT có thể đổi).
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Kênh chính thức (để guardrail khuyến nghị khi chưa đủ cơ sở / khi rủi ro cao)
# ---------------------------------------------------------------------------
VN_OFFICIAL_CHANNELS: List[Dict[str, Any]] = [
    {
        "name": "Tổng đài Quốc gia phòng chống lừa đảo (NCSC)",
        "phone": "156",
        "url": "https://khonggianmang.vn",
        "description": "Báo cáo lừa đảo trực tuyến, kiểm tra tên miền/app độc hại do Cục An toàn thông tin vận hành.",
        "reliability": "official",
    },
    {
        "name": "Cục An toàn thông tin (A05/NCSC)",
        "phone": None,
        "url": "https://canhbao.ncsc.gov.vn",
        "description": "Cảnh báo lừa đảo, mã độc, giả mạo thương hiệu do cơ quan nhà nước phát hành.",
        "reliability": "official",
    },
    {
        "name": "Cơ quan Công an — Đường dây nóng 113",
        "phone": "113",
        "url": "https://bocongan.gov.vn",
        "description": "Trình báo tội phạm, khẩn cấp khi đã chuyển tiền hoặc bị đe dọa.",
        "reliability": "official",
    },
    {
        "name": "Cảnh sát hình sự — 069.2342609",
        "phone": "069.2342609",
        "url": "https://bocongan.gov.vn",
        "description": "Đầu mối điều tra tội phạm sử dụng công nghệ cao.",
        "reliability": "official",
    },
    {
        "name": "Tổng đài Quốc gia Bảo vệ Trẻ em — 111",
        "phone": "111",
        "url": "https://tongdai111.vn",
        "description": "Hỗ trợ, bảo vệ trẻ em (kể cả bị lừa đảo/xâm hại trên mạng).",
        "reliability": "official",
    },
    {
        "name": "VNCERT/CC — Ứng cứu sự cố an ninh mạng",
        "phone": "0869 100 001",
        "url": "https://vncert.vn",
        "description": "Báo cáo sự cố tấn công mạng, mã độc.",
        "reliability": "official",
    },
    {
        "name": "Bảo hiểm xã hội Việt Nam",
        "phone": "1900 9068",
        "url": "https://bhxh.gov.vn",
        "description": "Xác minh thông tin BHXH/BHYT; cảnh giác cuộc gọi giả danh 'cập nhật sổ BHXH'.",
        "reliability": "official",
    },
    {
        "name": "Ngân hàng Nhà nước Việt Nam",
        "phone": None,
        "url": "https://sbv.gov.vn",
        "description": "Cơ quan quản lý tiền tệ/ngân hàng; tra cứu cảnh báo tín dụng đen, tổ chức tín dụng hợp pháp.",
        "reliability": "official",
    },
    {
        "name": "Cổng Dịch vụ công Quốc gia",
        "phone": None,
        "url": "https://dichvucong.gov.vn",
        "description": "Xác minh dịch vụ công trực tuyến chính thức; cảnh giác dịch vụ công 'giả'.",
        "reliability": "official",
    },
    {
        "name": "Bộ Thông tin và Truyền thông",
        "phone": None,
        "url": "https://mic.gov.vn",
        "description": "Quản lý viễn thông, báo chí, không gian mạng.",
        "reliability": "official",
    },
]

# Tổng đài ngân hàng/ ví điện tử phổ biến (từ chối & xác minh giao dịch)
# phone có thể là None khi chưa xác thực; url là website chính thức để đối chiếu.
VN_BANK_HOTLINES: List[Dict[str, Any]] = [
    {"name": "BIDV", "phone": "1900 9247", "url": "https://www.bidv.com.vn"},
    {"name": "Vietcombank", "phone": "1800 1106", "url": "https://www.vietcombank.com.vn"},
    {"name": "VietinBank", "phone": "1800 1268", "url": "https://www.vietinbank.vn"},
    {"name": "Agribank", "phone": "1900 558818", "url": "https://www.agribank.com.vn"},
    {"name": "Techcombank", "phone": "1800 588822", "url": "https://www.techcombank.com.vn"},
    {"name": "VPBank", "phone": "1800 589989", "url": "https://www.vpbank.com.vn"},
    {"name": "MBBank", "phone": "1900 545426", "url": "https://www.mbbank.com.vn"},
    {"name": "ACB", "phone": "1900 545486", "url": "https://www.acb.com.vn"},
    {"name": "Sacombank", "phone": "1800 585888", "url": "https://www.sacombank.com.vn"},
    {"name": "TPBank", "phone": "1900 585885", "url": "https://tpb.vn"},
    {"name": "VIB", "phone": "1800 8180", "url": "https://www.vib.com.vn"},
    {"name": "HDBank", "phone": "1900 6060", "url": "https://www.hdbank.com.vn"},
    {"name": "SHB", "phone": "1800 567869", "url": "https://www.shb.com.vn"},
    {"name": "MSB", "phone": "1800 599901", "url": "https://www.msb.com.vn"},
    {"name": "OCB", "phone": "1800 667766", "url": "https://www.ocb.com.vn"},
    {"name": "MoMo", "phone": "1900 6099", "url": "https://momo.vn"},
    {"name": "ZaloPay", "phone": "1900 5656", "url": "https://zalopay.vn"},
    {"name": "VNPay", "phone": "1900 555577", "url": "https://vnpay.vn"},
    # Các ngân hàng/ví bổ sung (chưa xác thực tổng đài → chỉ kèm website chính thức)
    {"name": "Eximbank", "phone": None, "url": "https://www.eximbank.com.vn"},
    {"name": "SeABank", "phone": None, "url": "https://www.seabank.com.vn"},
    {"name": "LPBank", "phone": None, "url": "https://www.lpbank.com.vn"},
    {"name": "Nam A Bank", "phone": None, "url": "https://www.namabank.com.vn"},
    {"name": "KienlongBank", "phone": None, "url": "https://kienlongbank.com"},
    {"name": "Bac A Bank", "phone": None, "url": "https://www.baca-bank.vn"},
    {"name": "ABBank", "phone": None, "url": "https://www.abbank.vn"},
    {"name": "PGBank", "phone": None, "url": "https://www.pgbank.com.vn"},
    {"name": "SCB", "phone": None, "url": "https://www.scb.com.vn"},
    {"name": "NCB", "phone": None, "url": "https://www.ncb-bank.vn"},
    {"name": "OceanBank", "phone": None, "url": "https://www.oceanbank.vn"},
    {"name": "Co-opBank", "phone": None, "url": "https://www.coopbank.com.vn"},
    {"name": "PVcomBank", "phone": None, "url": "https://www.pvcombank.vn"},
    {"name": "VietBank", "phone": None, "url": "https://www.vietbank.com.vn"},
    {"name": "SaigonBank", "phone": None, "url": "https://www.saigonbank.com.vn"},
    {"name": "VietABank", "phone": None, "url": "https://www.vietabank.com.vn"},
    {"name": "BVBank", "phone": None, "url": "https://www.bvbank.vn"},
    {"name": "Viettel Money", "phone": None, "url": "https://viettelmoney.vn"},
    {"name": "ShopeePay", "phone": None, "url": "https://shopeepay.vn"},
    {"name": "Timo", "phone": None, "url": "https://timo.vn"},
    {"name": "Cake", "phone": None, "url": "https://cake.vn"},
]

# ---------------------------------------------------------------------------
# Từ điển dấu hiệu lừa đảo tiếng Việt (hỗ trợ có dấu & không dấu)
# ---------------------------------------------------------------------------
VN_SCAM_PATTERNS: Dict[str, str] = {
    r"otp|mã xác|ma xac|mã otp|mã bảo mật": "Yêu cầu OTP / mã xác thực",
    r"chuyển khoản|chuyen khoan|chuyển tiền|chuyen tien|nộp phí|nop phi|đặt cọc|dat coc": "Yêu cầu chuyển tiền/nộp phí",
    r"công an|cong an|viện kiểm sát|vien kiem sat|cơ quan điều tra|co quan dieu tra|tòa án|toa an": "Mạo danh cơ quan chức năng",
    r"trúng thưởng|trung thuong|quà tặng|qua tang|nhận thưởng|nhan thuong|trúng xe|trúng giải": "Dụ dỗ trúng thưởng",
    r"khóa tài khoản|khoa tai khoan|phong tỏa|phong toa|tạm giữ|tam giu|khóa thẻ": "Đe dọa khóa/phong tỏa tài khoản",
    r"việc nhẹ lương cao|viec nhe luong cao|tuyển dụng|tuyen dung|ctv|cộng tác viên|làm thêm|chốt đơn": "Tuyển dụng lừa đảo",
    r"đầu tư|dau tu|lợi nhuận|loi nhuan|chứng khoán|chung khoan|forex|tiền ảo|tien ao|crypto|usdt|sàn giao dịch": "Đầu tư / tiền ảo rủi ro",
    r"cài app|cai app|tải app|tai app|apk|đăng nhập lại|dang nhap lai|ultraviewer|anydesk|teamviewer|điều khiển từ xa": "Dụ cài app / chiếm quyền điều khiển",
    r"link lạ|link la|bấm vào|bam vao|truy cập|truy cap|xác minh danh tính|xac minh danh tinh": "Dụ bấm link / xác minh danh tính",
    r"vay tiền|vay tien|lãi suất|lai suat|giải ngân|giai ngan|hồ sơ vay|app vay|tín dụng đen": "Vay tiền lừa đảo / tín dụng đen",
    r"chuyển phát|chuyen phat|bưu phẩm|buu pham|ship|shipper|đơn hàng|don hang|giao hàng": "Giả mạo giao hàng/bưu phẩm",
    r"nạp thẻ|nap the|game|nạp tiền|nap tien|thẻ cào": "Lừa đảo nạp thẻ/game",
    r"zalo|telegram|whatsapp|kết bạn|ket ban|nhóm kín|nhom kin": "Kênh liên hệ không chính thức",
    r"cơ hội vàng|co hoi|duy nhất hôm nay|duy nhat hom nay|gấp|gap|khẩn cấp|khan cap": "Tạo áp lực thời gian",
    r"deepfake|giả giọng|giong noi gia|nhân bản giọng|video call|lộ mặt": "Deepfake / giả mạo giọng nói-hình ảnh",
    r"vneid|dịch vụ công|dich vu cong|định danh điện tử|dinh danh dien tu|căn cước|can cuoc": "Giả mạo VNeID / dịch vụ công",
    r"hoàn thuế|hoan thue|thuế|thue|thông quan|thong quan|hải quan|hai quan": "Giả mạo hoàn thuế/hải quan",
    r"bảo hiểm xã hội|bao hiem xa hoi|sổ bhxh|so bhxh|lương hưu|luong huu|trợ cấp|tro cap": "Giả mạo bảo hiểm xã hội",
    r"đăng kiểm|dang kiem|kiểm định xe|kiem dinh xe|phí đường bộ|phi duong bo|phạt nguội|phat nguoi": "Giả mạo đăng kiểm/phí đường bộ",
    r"tình cảm|tinh cam|người yêu|nguoi yeu|kết hôn|ket hon|người nước ngoài|quà từ nước ngoài": "Lừa đảo tình cảm (romance)",
    r"con bị tai nạn|tai nạn|tai nan|cấp cứu|cap cuu|bệnh viện|benh vien|nhập viện": "Giả mạo tai nạn/cấp cứu",
    r"hack nick|chiếm tài khoản|chiem tai khoan|mượn tiền|muon tien|bạn bè|facebook bị khóa": "Chiếm tài khoản mạng xã hội",
    r"từ thiện|tu thien|quyên góp|quyen gop|ủng hộ|ung ho|giải cứu": "Lừa đảo từ thiện",
    r"đặt cọc thuê nhà|thuê nhà|thue nha|mua bán xe|mua ban xe|đặt cọc mua": "Lừa đảo đặt cọc/ mua bán",
    r"xuất khẩu lao động|xuat khau lao dong|visa|đi nước ngoài|đưa người đi làm": "Lừa đảo xuất khẩu lao động",
    r"hoàn tiền|hoan tien|đơn hàng lỗi|don hang loi|hỗ trợ khách hàng|sàn thương mại": "Giả mạo hoàn tiền/CSKH",
    r"chứng minh tài chính|chung minh tai chinh|vay vốn|vay von|hỗ trợ vốn": "Lừa đảo chứng minh tài chính",
    r"hoa hồng|hoa hong|affiliate|kiếm tiền online|kiem tien online|review sản phẩm|dropship": "Việc làm online/hoa hồng ảo",
    r"sim|số chính chủ|so chinh chu|định danh sim|dinh danh sim": "Mạo danh định danh SIM/số điện thoại",
    r"mã độc|ma doc|malware|trojan|đánh cắp thông tin|danh cap thong tin": "Nguy cơ mã độc / đánh cắp dữ liệu",
    r"chuyển nhầm|chuyen nham|chuyển khoản nhầm|đòi lại tiền": "Chiêu 'chuyển nhầm tiền' rồi đòi lại",
}

# ---------------------------------------------------------------------------
# Tên miền tin cậy VN (ngân hàng, ví, cơ quan, tiện ích) — để phát hiện giả mạo
# ---------------------------------------------------------------------------
VN_TRUSTED_DOMAINS: Dict[str, str] = {
    # Ngân hàng / ví điện tử
    "vietcombank.com.vn": "Vietcombank",
    "bidv.com.vn": "BIDV",
    "vietinbank.vn": "VietinBank",
    "agribank.com.vn": "Agribank",
    "techcombank.com.vn": "Techcombank",
    "vpbank.com.vn": "VPBank",
    "mbbank.com.vn": "MBBank",
    "acb.com.vn": "ACB",
    "sacombank.com.vn": "Sacombank",
    "tpb.vn": "TPBank",
    "vib.com.vn": "VIB",
    "hdbank.com.vn": "HDBank",
    "shb.com.vn": "SHB",
    "msb.com.vn": "MSB",
    "ocb.com.vn": "OCB",
    "eximbank.com.vn": "Eximbank",
    "seabank.com.vn": "SeABank",
    "lpbank.com.vn": "LPBank",
    "namabank.com.vn": "Nam A Bank",
    "kienlongbank.com": "KienlongBank",
    "baca-bank.vn": "Bac A Bank",
    "abbank.vn": "ABBank",
    "pgbank.com.vn": "PGBank",
    "scb.com.vn": "SCB",
    "ncb-bank.vn": "NCB",
    "oceanbank.vn": "OceanBank",
    "coopbank.com.vn": "Co-opBank",
    "pvcombank.vn": "PVcomBank",
    "vietbank.com.vn": "VietBank",
    "saigonbank.com.vn": "SaigonBank",
    "vietabank.com.vn": "VietABank",
    "bvbank.vn": "BVBank",
    "shinhan.com.vn": "Shinhan Bank",
    "uob.com.vn": "UOB Việt Nam",
    "cimb.com.vn": "CIMB Việt Nam",
    "hsbc.com.vn": "HSBC Việt Nam",
    "momo.vn": "MoMo",
    "zalopay.vn": "ZaloPay",
    "vnpay.vn": "VNPay",
    "shopeepay.vn": "ShopeePay",
    "viettelmoney.vn": "Viettel Money",
    "timo.vn": "Timo",
    "cake.vn": "Cake",
    # Cơ quan nhà nước
    "chinhphu.vn": "Cổng thông tin Chính phủ",
    "bocongan.gov.vn": "Bộ Công an",
    "canhbao.ncsc.gov.vn": "NCSC",
    "khonggianmang.vn": "Không gian mạng VN",
    "vncert.vn": "VNCERT",
    "dichvucong.gov.vn": "Dịch vụ công Quốc gia",
    "baohiemxahoi.gov.vn": "Bảo hiểm xã hội VN",
    "bhxh.gov.vn": "Bảo hiểm xã hội VN",
    "gdt.gov.vn": "Tổng cục Thuế",
    "thuedientu.gdt.gov.vn": "Thuế điện tử",
    "sbv.gov.vn": "Ngân hàng Nhà nước VN",
    "mof.gov.vn": "Bộ Tài chính",
    "moit.gov.vn": "Bộ Công Thương",
    "mic.gov.vn": "Bộ TT&TT",
    "moh.gov.vn": "Bộ Y tế",
    "moet.gov.vn": "Bộ GD&ĐT",
    "dangkiem.gov.vn": "Cục Đăng kiểm VN",
    # Tiện ích / thương mại / viễn thông
    "viettel.vn": "Viettel",
    "vnpt.vn": "VNPT",
    "mobifone.vn": "MobiFone",
    "vietnamobile.vn": "Vietnamobile",
    "fpt.vn": "FPT",
    "fptshop.com.vn": "FPT Shop",
    "evn.com.vn": "EVN",
    "evnhcmc.vn": "EVNHCMC",
    "pvn.vn": "PetroVietnam",
    "vnpost.vn": "Vietnam Post",
    "viettelpost.com.vn": "Viettel Post",
    "ghtk.vn": "Giao Hàng Tiết Kiệm",
    "ghn.vn": "Giao Hàng Nhanh",
    "shopee.vn": "Shopee",
    "lazada.vn": "Lazada",
    "tiki.vn": "Tiki",
    "vietnamairlines.com": "Vietnam Airlines",
    "vietjetair.com": "Vietjet Air",
}

# ---------------------------------------------------------------------------
# Nguồn tham chiếu VN (để trích dẫn bằng chứng — điểm #4)
# ---------------------------------------------------------------------------
VN_REFERENCE_SOURCES: List[Dict[str, str]] = [
    {"title": "Cục An toàn thông tin — Cảnh báo lừa đảo trực tuyến", "url": "https://canhbao.ncsc.gov.vn", "type": "government"},
    {"title": "Không gian mạng Việt Nam — Tổng đài 156", "url": "https://khonggianmang.vn", "type": "government"},
    {"title": "Bộ Công an — Cảnh báo tội phạm công nghệ cao", "url": "https://bocongan.gov.vn", "type": "government"},
    {"title": "Cổng thông tin Chính phủ — Phòng chống lừa đảo", "url": "https://chinhphu.vn", "type": "government"},
    {"title": "Ngân hàng Nhà nước — Cảnh báo an toàn thanh toán", "url": "https://sbv.gov.vn", "type": "government"},
    {"title": "Bảo hiểm xã hội Việt Nam — Cảnh báo giả mạo", "url": "https://bhxh.gov.vn", "type": "government"},
    {"title": "Bộ Thông tin và Truyền thông", "url": "https://mic.gov.vn", "type": "government"},
    {"title": "Cổng Dịch vụ công Quốc gia", "url": "https://dichvucong.gov.vn", "type": "government"},
]

# Nguồn báo chí chính thống (dùng trích dẫn bằng chứng — điểm cải tiến #2/#4)
VN_PRESS_SOURCES: List[Dict[str, str]] = [
    {"title": "VnExpress — An ninh mạng", "url": "https://vnexpress.net", "type": "press"},
    {"title": "Tuổi Trẻ — An ninh mạng", "url": "https://tuoitre.vn", "type": "press"},
    {"title": "Thanh Niên — Chuyển đổi số", "url": "https://thanhnien.vn", "type": "press"},
    {"title": "Dân Trí — Công nghệ", "url": "https://dantri.com.vn", "type": "press"},
    {"title": "VietnamNet — An ninh mạng", "url": "https://vietnamnet.vn", "type": "press"},
    {"title": "VTV — Cảnh báo lừa đảo", "url": "https://vtv.vn", "type": "press"},
    {"title": "VietnamPlus (TTXVN)", "url": "https://vietnamplus.vn", "type": "press"},
    {"title": "Báo Chính phủ", "url": "https://baochinhphu.vn", "type": "press"},
    {"title": "Báo Công an nhân dân", "url": "https://cand.com.vn", "type": "press"},
    {"title": "Người Lao Động", "url": "https://nld.com.vn", "type": "press"},
    {"title": "Tiền Phong", "url": "https://tienphong.vn", "type": "press"},
    {"title": "Pháp luật TP.HCM", "url": "https://plo.vn", "type": "press"},
    {"title": "An ninh Thủ đô", "url": "https://anninhthudo.vn", "type": "press"},
    {"title": "VnEconomy", "url": "https://vneconomy.vn", "type": "press"},
    {"title": "ICTNews", "url": "https://ictnews.vn", "type": "press"},
]


def _norm_key(s: str) -> str:
    """Chuẩn hoá tên để so khớp (bỏ dấu cách & ký tự không phải chữ/số)."""
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def vn_channels() -> List[Dict[str, Any]]:
    return [dict(c) for c in VN_OFFICIAL_CHANNELS]


def bank_hotline(bank_name: str) -> Optional[Dict[str, Any]]:
    """Tìm ngân hàng/ví theo tên (khớp chính xác trước, rồi khớp dài nhất).

    Tránh lỗi khớp chuỗi con ngắn (VD 'mb' khớp nhầm trong 'Vietcombank').
    """
    if not bank_name:
        return None
    low = _norm_key(bank_name)
    if not low:
        return None
    # 1. Khớp chính xác
    for b in VN_BANK_HOTLINES:
        if _norm_key(b["name"]) == low:
            return b
    # 2. Khớp theo tên đơn vị dài nhất xuất hiện trong chuỗi truy vấn
    best: Optional[Dict[str, Any]] = None
    best_len = 0
    for b in VN_BANK_HOTLINES:
        key = _norm_key(b["name"])
        if key and key in low and len(key) > best_len:
            best, best_len = b, len(key)
    if best:
        return best
    # 3. Dự phòng: khớp tiền tố (VD 'MB' → 'MBBank') khi chuỗi truy vấn ngắn
    for b in VN_BANK_HOTLINES:
        key = _norm_key(b["name"])
        if len(low) >= 2 and key.startswith(low):
            return b
    return None


def lookup_vn_bank_hotline(bank_name: str) -> Optional[Dict[str, Any]]:
    """Alias công khai cho tầng view."""
    return bank_hotline(bank_name)


def bank_official_site(bank_name: str) -> Optional[Dict[str, str]]:
    """Trả về website chính thức của ngân hàng (từ danh mục tên miền tin cậy VN)."""
    if not bank_name:
        return None
    low = _norm_key(bank_name)
    if not low:
        return None
    # Ưu tiên tên trong VN_BANK_HOTLINES (có url chính thức)
    b = bank_hotline(bank_name)
    if b and b.get("url"):
        return {"name": b["name"], "url": b["url"]}
    # Dự phòng: dò trong tên miền tin cậy theo nhãn
    for domain, label in VN_TRUSTED_DOMAINS.items():
        if _norm_key(label) == low:
            return {"name": label, "url": f"https://{domain}"}
    return None


def vn_reference_sources() -> List[Dict[str, str]]:
    return [dict(s) for s in VN_REFERENCE_SOURCES]


def vn_press_sources() -> List[Dict[str, str]]:
    return [dict(s) for s in VN_PRESS_SOURCES]
