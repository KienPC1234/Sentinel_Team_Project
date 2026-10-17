"""
ShieldCall VN — Trust Guardrail, Evidence & Source Reliability (điểm #1, #3, #4).

Ba trách nhiệm:
1. **Guardrail độ bất định (uncertainty)**: khi bằng chứng yếu/không đủ cơ sở,
   hệ thống KHÔNG được khẳng định "an toàn" hay kết luận dứt khoát — thay vào đó
   trả về nhãn "CHƯA ĐỦ CƠ SỞ XÁC MINH" + cảnh báo + kênh xác minh chính thức.
2. **Bằng chứng cho mọi nhận định**: chuẩn hoá mọi phát hiện thành danh sách
   `evidence[]` kèm nguồn, độ tin cậy và (nếu có) liên kết tham chiếu.
3. **Danh mục nguồn & giới hạn công cụ**: mô tả từng nguồn (VirusTotal, ClamAV,
   YARA, heuristic, RAG, cộng đồng, mô hình AI...) kèm độ tin cậy và giới hạn rõ
   ràng để minh bạch năng lực ứng dụng.

Tất cả hàm ở đây thuần tuý (không I/O) để dễ kiểm thử.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

from api.utils.vn_sources import VN_OFFICIAL_CHANNELS, lookup_vn_bank_hotline, bank_official_site

DISCLAIMER = (
    "Kết quả phân tích tự động chỉ mang tính tham khảo, hỗ trợ ra quyết định — "
    "không thay thế kết luận của cơ quan chức năng. Hãy luôn xác minh qua kênh chính thức."
)

# Ngưỡng phân tầng rủi ro CANONICAL cho MỌI loại quét (điểm #1 — tính nhất quán).
# Trước đây mỗi loại quét dùng băng ngưỡng khác nhau (80/50/20 vs 70/40/10) khiến
# cùng một điểm cho nhãn khác nhau giữa sync/async và giữa các trang.
RISK_RED_MIN = 70
RISK_YELLOW_MIN = 40
RISK_GREEN_MIN = 10


def level_from_score(score: Any) -> str:
    """Trả `risk_level` ('RED'|'YELLOW'|'GREEN'|'SAFE') theo ngưỡng canonical."""
    try:
        s = int(score or 0)
    except (TypeError, ValueError):
        s = 0
    if s >= RISK_RED_MIN:
        return "RED"
    if s >= RISK_YELLOW_MIN:
        return "YELLOW"
    if s >= RISK_GREEN_MIN:
        return "GREEN"
    return "SAFE"

# ---------------------------------------------------------------------------
# 1. Danh mục nguồn & độ tin cậy (điểm #3)
# ---------------------------------------------------------------------------
_HIGH, _MEDIUM, _LOW = "high", "medium", "low"

SOURCE_CATALOG: Dict[str, Dict[str, Any]] = {
    "virustotal": {
        "name": "VirusTotal (70+ engine AV)",
        "reliability": _HIGH,
        "kind": "external_cloud",
        "description": "Đối chiếu hash/URL với hàng chục engine antivirus & sandbox thương mại.",
        "limits": "Phụ thuộc dữ liệu cộng đồng; tệp/URL mới có thể chưa có báo cáo; bản miễn phí giới hạn số lượt/phút.",
        "url": "https://www.virustotal.com",
    },
    "clamav": {
        "name": "ClamAV (mã độc cục bộ)",
        "reliability": _HIGH,
        "kind": "local_engine",
        "description": "Antivirus mã nguồn mở quét chữ ký mã độc ngay trên máy chủ.",
        "limits": "Chỉ nhận diện chữ ký đã biết; có thể bỏ sót mã độc mới (zero-day).",
        "url": "https://www.clamav.net",
    },
    "yara": {
        "name": "YARA (luật phát hiện)",
        "reliability": _HIGH,
        "kind": "local_engine",
        "description": "Khớp mẫu hành vi/nội dung đặc trưng của mã độc.",
        "limits": "Phụ thuộc bộ luật; luật chưa bao phủ hết biến thể.",
        "url": "https://virustotal.github.io/yara/",
    },
    "sandbox": {
        "name": "Zero-Trust Sandbox (cô lập, tắt mạng)",
        "reliability": _HIGH,
        "kind": "local_sandbox",
        "description": "Chạy mẫu trong môi trường cô lập, tắt mạng, giới hạn tài nguyên để quan sát hành vi.",
        "limits": "Phân tích tĩnh/hành vi hạn chế; mẫu cần mạng hoặc kích hoạt trễ có thể không bộc lộ.",
        "url": None,
    },
    "pefile": {
        "name": "PEFile (giải phẫu PE)",
        "reliability": _MEDIUM,
        "kind": "local_engine",
        "description": "Trích xuất cấu trúc tệp thực thi Windows (import, section, packing).",
        "limits": "Chỉ áp dụng tệp PE; không kết luận độc hại, chỉ cung cấp dấu hiệu.",
        "url": None,
    },
    "oletools": {
        "name": "OLEtools (macro Office)",
        "reliability": _MEDIUM,
        "kind": "local_engine",
        "description": "Phát hiện macro độc hại trong tài liệu Office.",
        "limits": "Chỉ phát hiện macro rõ ràng; macro hợp lệ cũng có thể bị đánh dấu.",
        "url": "https://github.com/decalage2/oletools",
    },
    "network_analysis": {
        "name": "Phân tích kết nối/SSL (network)",
        "reliability": _MEDIUM,
        "kind": "local_engine",
        "description": "Kiểm tra chứng chỉ SSL, chuyển hướng, header bảo mật, thời điểm tạo cert.",
        "limits": "Phụ thuộc khả năng kết nối; trang chặn bot có thể không lấy được dữ liệu.",
        "url": None,
    },
    "tranco": {
        "name": "Tranco (thứ hạng phổ biến)",
        "reliability": _MEDIUM,
        "kind": "external_ref",
        "description": "Xếp hạng độ phổ biến tên miền toàn cầu (danh sách nghiên cứu).",
        "limits": "Chỉ là chỉ báo phổ biến, KHÔNG đồng nghĩa an toàn.",
        "url": "https://tranco-list.eu",
    },
    "heuristic": {
        "name": "Heuristic tiếng Việt (luật nội bộ)",
        "reliability": _MEDIUM,
        "kind": "local_engine",
        "description": "Từ điển dấu hiệu lừa đảo tiếng Việt + kiểm tra tên miền giả mạo.",
        "limits": "Có thể dương tính giả nếu nội dung hợp pháp trùng từ khoá; không thay thế phân tích chuyên sâu.",
        "url": None,
    },
    "rag": {
        "name": "Kho tri thức ShieldCall (RAG)",
        "reliability": _MEDIUM,
        "kind": "internal_kb",
        "description": "Tài liệu & kịch bản phòng chống lừa đảo do hệ thống biên soạn.",
        "limits": "Có thể chưa cập nhật hết; cần đối chiếu nguồn chính thức khi quan trọng.",
        "url": None,
    },
    "community": {
        "name": "Báo cáo cộng đồng",
        "reliability": _MEDIUM,
        "kind": "user_generated",
        "description": "Báo cáo do người dùng gửi (đã kiểm duyệt một phần).",
        "limits": "Chưa được xác minh đầy đủ; có thể sai hoặc bị lợi dụng; dùng để tham khảo.",
        "url": None,
    },
    "web_search": {
        "name": "Tìm kiếm/OSINT web",
        "reliability": _MEDIUM,
        "kind": "external_ref",
        "description": "Đối chiếu thông tin công khai trên web.",
        "limits": "Nguồn mở đa dạng, độ tin cậy khác nhau; cần kiểm chứng lại.",
        "url": None,
    },
    "ai_model": {
        "name": "Mô hình ngôn ngữ (LLM)",
        "reliability": _LOW,
        "kind": "ai",
        "description": "Sinh giải thích, khuyến nghị hành động và kịch bản từ chối dựa trên bằng chứng.",
        "limits": (
            "Mô hình có thể nhận diện SAI (hallucination). Đây là lớp hỗ trợ diễn giải, "
            "KHÔNG phải bằng chứng gốc; mọi kết luận phải dựa trên evidence dữ liệu."
        ),
        "url": None,
    },
    "vn_official": {
        "name": "Kênh chính thức Việt Nam (NCSC, Bộ Công an, ngân hàng)",
        "reliability": _HIGH,
        "kind": "government",
        "description": "Đầu mối xác minh & trình báo chính thức.",
        "limits": "Kênh để xác minh thủ công, không tự động trả kết quả.",
        "url": "https://khonggianmang.vn",
    },
    "tinnhiemmang": {
        "name": "Tín nhiệm mạng (tinnhiemmang.vn — NCSC/VNCERT)",
        "reliability": _HIGH,
        "kind": "government",
        "description": (
            "Danh bạ chính thống: website/tổ chức/hệ thống/ứng dụng tín nhiệm đã được "
            "chứng nhận và danh sách website lừa đảo (mạo danh tổ chức/thương hiệu). "
            "Dùng để đối chiếu tên miền tin cậy ↔ lừa đảo."
        ),
        "limits": (
            "Chỉ gồm thực thể đã đăng ký/chứng nhận hoặc đã bị ghi nhận — KHÔNG có nghĩa "
            "mọi tên miền vắng mặt đều an toàn. Dữ liệu cập nhật theo từng đợt; luôn đối "
            "chiếu trang gốc khi trích dẫn."
        ),
        "url": "https://tinnhiemmang.vn",
    },
}


def source_meta(key: str) -> Dict[str, Any]:
    return SOURCE_CATALOG.get(key, {
        "name": key,
        "reliability": _MEDIUM,
        "kind": "unknown",
        "description": "Nguồn chưa được phân loại.",
        "limits": "Chưa xác định rõ độ tin cậy.",
        "url": None,
    })


def source_catalog() -> List[Dict[str, Any]]:
    """Danh mục công khai cho UI/API."""
    out = []
    for key, meta in SOURCE_CATALOG.items():
        out.append({"key": key, **meta})
    return out


# ---------------------------------------------------------------------------
# 2. Chuẩn hoá bằng chứng (điểm #4)
# ---------------------------------------------------------------------------
_SEV_WEIGHT = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "INFO": 0}


def _mk_evidence(source: str, detail: str, severity: str = "INFO",
                 *, url: Optional[str] = None, supports: str = "context") -> Dict[str, Any]:
    meta = source_meta(source)
    return {
        "source": source,
        "source_name": meta["name"],
        "reliability": meta["reliability"],
        "severity": (severity or "INFO").upper(),
        "detail": str(detail or "").strip(),
        "supports": supports,          # 'malicious' | 'benign' | 'context'
        "url": url or meta.get("url"),
        "limits": meta.get("limits"),
    }


def build_evidence(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Trích bằng chứng từ nhiều dạng kết quả quét khác nhau thành một danh sách thống nhất."""
    ev: List[Dict[str, Any]] = []

    # (a) VirusTotal object (nếu provider gắn vào kết quả)
    vt = result.get("virustotal") or {}
    if isinstance(vt, dict) and vt.get("available") and vt.get("stats"):
        s = vt["stats"]
        mal, sus = int(s.get("malicious", 0) or 0), int(s.get("suspicious", 0) or 0)
        if mal or sus:
            ev.append(_mk_evidence(
                "virustotal",
                f"{mal} engine gắn cờ ĐỘC HẠI, {sus} engine NGHI NGỜ trên {vt.get('total_engines', '?')} engine.",
                "CRITICAL" if mal else "MEDIUM",
                url=vt.get("permalink") or None,
                supports="malicious",
            ))
        else:
            ev.append(_mk_evidence(
                "virustotal",
                f"Sạch trên {vt.get('total_engines', '?')} engine antivirus.",
                "INFO", url=vt.get("permalink") or None, supports="benign",
            ))

    # (a2) Danh bạ Tín nhiệm mạng (tinnhiemmang.vn) — nguồn chính thống NCSC/VNCERT
    tk = result.get("tinnhiem")
    if isinstance(tk, dict) and tk.get("status") in ("scam", "trusted"):
        rec = tk.get("record") or {}
        if tk.get("status") == "scam":
            imp = rec.get("impersonated") or rec.get("owner")
            detail = "Tên miền nằm trong DANH SÁCH LỪA ĐẢO do NCSC/VNCERT công bố"
            if imp:
                detail += f" (mạo danh: {imp})"
            ev.append(_mk_evidence("tinnhiemmang", detail, "CRITICAL",
                                   url=rec.get("url"), supports="malicious"))
        else:
            owner = rec.get("owner") or rec.get("name")
            detail = "Website đã được chứng nhận TÍN NHIỆM" + (f" — {owner}" if owner else "")
            if rec.get("badge"):
                detail += f" ({rec['badge']})"
            ev.append(_mk_evidence("tinnhiemmang", detail, "INFO",
                                   url=rec.get("url"), supports="benign"))

    # (b) forensic_evidence (file scan) — list dict hoặc list str
    for item in (result.get("forensic_evidence") or []):
        if isinstance(item, dict):
            src = item.get("source") or item.get("engine") or "sandbox"
            ev.append(_mk_evidence(
                src, item.get("description") or item.get("category") or "",
                item.get("severity") or "MEDIUM",
                url=item.get("url"), supports="malicious" if _SEV_WEIGHT.get((item.get("severity") or "").upper(), 0) >= 2 else "context",
            ))
        else:
            ev.append(_mk_evidence("sandbox", str(item), "MEDIUM"))

    # (c) forensic_proofs / details / network_details / reasons (URL, message, phone)
    for field, src in (("forensic_proofs", "heuristic"), ("details", "heuristic"),
                       ("network_details", "network_analysis"),
                       ("reasons", "heuristic"), ("check_descriptions", "heuristic")):
        raw = result.get(field)
        if isinstance(raw, dict):
            raw = list(raw.values())  # check_descriptions có thể là dict
        for line in (raw or []):
            if isinstance(line, str) and line.strip():
                low = line.lower()
                sev = "MEDIUM" if any(k in low for k in ("độc hại", "malicious", "lừa đảo", "giả", "rủi ro cao")) else "INFO"
                supports = "malicious" if sev != "INFO" else "context"
                ev.append(_mk_evidence(src, line.strip(), sev, supports=supports))

    # (d) patterns_found / domain_risks (message scan)
    for line in (result.get("patterns_found") or []):
        if isinstance(line, str) and line.strip():
            ev.append(_mk_evidence("heuristic", line.strip(), "MEDIUM", supports="malicious"))

    # (e) sources list → ghi nhận nguồn đã dùng
    for s in (result.get("sources") or []):
        key = "virustotal" if "virus" in str(s).lower() else "heuristic" if "local" in str(s).lower() else str(s)
        if not any(e["source"] == key for e in ev):
            ev.append(_mk_evidence(key, "Nguồn đã được truy vấn.", "INFO", supports="context"))

    return ev


# ---------------------------------------------------------------------------
# 3. Guardrail & phân loại độ bất định (điểm #1)
# ---------------------------------------------------------------------------
def _official_channels_for(result: Dict[str, Any]) -> List[Dict[str, Any]]:
    channels = [dict(c) for c in VN_OFFICIAL_CHANNELS]
    bank = result.get("bank_name") or result.get("bank")
    if bank:
        hot = lookup_vn_bank_hotline(str(bank))
        site = bank_official_site(str(bank))
        if hot:
            has_phone = bool(hot.get("phone"))
            channels.insert(0, {
                "name": (f"Tổng đài {hot['name']} (khoá thẻ/xác minh giao dịch)"
                         if has_phone else f"{hot['name']} — website chính thức (khoá thẻ/xác minh)"),
                "phone": hot.get("phone"),
                "url": hot.get("url") or (site or {}).get("url"),
                "description": "Liên hệ ngân hàng phát hành để khoá thẻ/tra soát giao dịch.",
                "reliability": "official",
            })
        elif site:
            channels.insert(0, {
                "name": f"{site['name']} — website chính thức (xác minh giao dịch)",
                "phone": None, "url": site["url"],
                "description": "Đối chiếu website/giao dịch qua kênh chính thức của ngân hàng.",
                "reliability": "official",
            })
    return channels


def assess(result: Dict[str, Any], *, kind: str = "generic") -> Dict[str, Any]:
    """
    Trả về khối `guardrail` cho một kết quả quét.

    Nguyên tắc then chốt (theo yêu cầu giám khảo): nếu KHÔNG đủ cơ sở xác minh,
    tuyệt đối không kết luận "an toàn"; trả nhãn INSUFFICIENT + cảnh báo.
    """
    try:
        score = int(result.get("risk_score", 0) or 0)
    except (TypeError, ValueError):
        score = 0
    evidence = result.get("evidence") if isinstance(result.get("evidence"), list) else build_evidence(result)

    mal_ev = [e for e in evidence if e.get("supports") == "malicious"]
    benign_ev = [e for e in evidence if e.get("supports") == "benign"]
    high_mal = [e for e in mal_ev if e.get("reliability") == "high"]
    high_benign = [e for e in benign_ev if e.get("reliability") == "high"]
    strong_signal = any(_SEV_WEIGHT.get((e.get("severity") or "INFO").upper(), 0) >= 2 for e in mal_ev)

    has_error = bool(result.get("error") or result.get("insufficient_input"))

    if has_error:
        tier, conf = "INSUFFICIENT", 0.1
    elif high_mal or (mal_ev and strong_signal):
        tier, conf = "CONFIRMED_RISK", 0.95
    elif score >= 70:
        tier, conf = "HIGH_RISK", 0.85
    elif score >= 40:
        tier, conf = "SUSPICIOUS", 0.6
    elif score >= 10:
        # Vùng xám: có dấu hiệu nhưng chưa đủ kết luận
        tier, conf = ("SUSPICIOUS" if mal_ev else "INSUFFICIENT"), (0.45 if mal_ev else 0.3)
    else:
        # Điểm thấp: chỉ coi là "có khả năng an toàn" khi CÓ bằng chứng sạch độ tin cậy cao
        if high_benign:
            tier, conf = "LIKELY_SAFE", 0.7
        else:
            tier, conf = "INSUFFICIENT", 0.3

    labels = {
        "CONFIRMED_RISK": "NGUY HIỂM — Có bằng chứng xác thực",
        "HIGH_RISK": "NGUY CƠ CAO",
        "SUSPICIOUS": "ĐÁNG NGỜ — Cần thận trọng",
        "INSUFFICIENT": "CHƯA ĐỦ CƠ SỞ XÁC MINH",
        "LIKELY_SAFE": "CÓ KHẢ NĂNG AN TOÀN (không bảo đảm 100%)",
    }

    cautions: List[str] = []
    if tier == "INSUFFICIENT":
        cautions.append(
            "Hệ thống chưa thu thập đủ bằng chứng để kết luận. KHÔNG xem đây là 'an toàn' — "
            "hãy xác minh qua kênh chính thức trước khi giao dịch/chia sẻ thông tin."
        )
    if tier in ("HIGH_RISK", "SUSPICIOUS"):
        cautions.append("Không chuyển tiền, không cung cấp OTP/mật khẩu, không cài ứng dụng lạ.")
    if tier == "LIKELY_SAFE":
        cautions.append("Không có dấu hiệu xấu từ các nguồn hiện có, nhưng luôn cảnh giác với yêu cầu bất thường.")
    if any(e.get("reliability") == "low" for e in mal_ev):
        cautions.append("Một phần nhận định đến từ mô hình AI — cần đối chiếu bằng chứng gốc bên dưới.")
    if not evidence:
        cautions.append("Không có bằng chứng nào được ghi nhận cho nội dung này.")

    conclusive = tier in ("CONFIRMED_RISK", "HIGH_RISK")

    return {
        "tier": tier,
        "label": labels.get(tier, tier),
        "confidence": round(conf, 2),
        "is_conclusive": conclusive,
        "requires_verification": tier in ("INSUFFICIENT", "SUSPICIOUS", "LIKELY_SAFE"),
        "cautions": cautions,
        "disclaimer": DISCLAIMER,
        "official_channels": _official_channels_for(result),
        "refusal_script": (
            "Cảm ơn, nhưng tôi chưa đủ cơ sở để xác nhận điều này. Bạn vui lòng cho tôi thời gian "
            "kiểm tra qua kênh chính thức; tôi sẽ không thực hiện giao dịch hay cung cấp thông tin "
            "cho đến khi xác minh xong."
        ),
        "evidence_count": len(evidence),
        "sources_used": sorted({e["source"] for e in evidence}),
        "kind": kind,
    }


def apply_guardrail(result: Dict[str, Any], *, kind: str = "generic") -> Dict[str, Any]:
    """Gắn `evidence` + `guardrail` vào kết quả quét và trả về (in-place + return)."""
    if not isinstance(result, dict):
        return result
    evidence = build_evidence(result)
    result["evidence"] = evidence
    result["guardrail"] = assess(result, kind=kind)
    # Không còn cờ "SAFE" dứt khoát: thêm nhãn hiển thị chuẩn hoá cho UI.
    result["verdict_label"] = result["guardrail"]["label"]
    result["verdict_conclusive"] = result["guardrail"]["is_conclusive"]
    return result


def trust_policy() -> Dict[str, Any]:
    """Tóm tắt chính sách tin cậy để hiển thị (điểm #3)."""
    return {
        "principle": "Không kết luận khi chưa đủ cơ sở; mọi nhận định phải kèm bằng chứng & nguồn.",
        "gray_zone": "Điểm rủi ro 10–39 được coi là vùng xám: chỉ cảnh báo, không kết luận an toàn.",
        "ai_role": "Mô hình AI chỉ diễn giải/hỗ trợ; không phải bằng chứng gốc.",
        "sources": source_catalog(),
        "disclaimer": DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# 5. Guardrail có cấu trúc cho CHAT (điểm #1 — đồng nhất với luồng quét)
# ---------------------------------------------------------------------------
# Câu trả lời chat không có `risk_score` sẵn như các luồng quét. Guardrail suy ra từ:
#   (a) kết quả công cụ kiểm chứng đã chạy (scan_phone/url/bank/... trả bằng chứng thực), và
#   (b) phân tích các khẳng định "an toàn" mang tính chắc chắn trong chính câu trả lời.
_LEVEL_SCORE = {
    "CRITICAL": 90, "RED": 80, "HIGH": 80, "YELLOW": 50, "MEDIUM": 50,
    "GREEN": 0, "SAFE": 0, "LOW": 0, "UNKNOWN": 0, "": 0,
}

# Các cụm khẳng định an toàn dứt khoát mà trợ lý AI có thể lỡ dùng khi chưa đủ cơ sở.
# Hỗ trợ cả dạng có dấu lẫn không dấu (người dùng/LLM hay gõ thiếu dấu).
_SAFE_AN = r"(?:an toàn|an toan)"
_SAFE_HAS_ISSUE = r"(?:vấn đề|van de|rủi ro|rui ro|nguy hiểm|nguy hiem|gì|gi)"
_ABSOLUTE_SAFE_PATTERN = re.compile(
    r"(?i)("
    r"(?:chắc chắn|chac chan) (?:là |la )?" + _SAFE_AN +
    r"|(?:100\s*%|tuyệt đối|tuyet doi|hoàn toàn|hoan toan)\s*(?:là |la )?" + _SAFE_AN +
    r"|" + _SAFE_AN + r" (?:tuyệt đối|tuyet doi|100\s*%)"
    r"|(?:không|khong) (?:có|co) " + _SAFE_HAS_ISSUE +
    r"|(?:yên tâm|yen tam) (?:tuyệt đối|tuyet doi|100\s*%)"
    r")"
)

# Câu trả lời có ĐƯA RA NHẬN ĐỊNH an toàn/rủi ro (để quyết định có gắn guardrail hay không).
# Chỉ những lượt chat liên quan an toàn – rủi ro mới cần guardrail; chat kiến thức chung
# (định nghĩa, hướng dẫn thông thường) KHÔNG bị gắn nhãn để giữ sự quyết đoán, tránh nhiễu.
_RISK_ASSERT_PATTERN = re.compile(
    r"(?i)(lừa đảo|lua dao|scam|nguy hiểm|nguy hiem|đáng ngờ|dang ngo|cảnh báo|canh bao|"
    r"mạo danh|mao danh|giả mạo|gia mao|phishing|rủi ro|rui ro|bất thường|bat thuong|"
    r"độc hại|doc hai|tấn công|tan cong|dính bẫy|dinh bay)"
)

CHAT_AI_CAUTION = (
    "Trợ lý AI có thể nhận diện SAI. Câu trả lời này là ý kiến tham khảo, KHÔNG phải "
    "kết luận đã xác minh — hãy kiểm chứng qua kênh chính thức trước khi giao dịch/chia sẻ thông tin."
)


def detect_absolute_safety_claim(text: str) -> Optional[str]:
    """Trả về cụm khẳng định an toàn dứt khoát nếu câu trả lời có (để gắn cảnh báo)."""
    m = _ABSOLUTE_SAFE_PATTERN.search(text or "")
    return m.group(0).strip() if m else None


def asserts_risk_or_safety(text: str) -> bool:
    """Có nhận định liên quan an toàn – rủi ro không (cần guardrail)."""
    return bool(_RISK_ASSERT_PATTERN.search(text or ""))


def _result_risk_score(result: Dict[str, Any]) -> int:
    """Suy điểm rủi ro từ kết quả công cụ: ưu tiên risk_score, rồi is_scam/risk_level."""
    try:
        score = int(result.get("risk_score", 0) or 0)
    except (TypeError, ValueError):
        score = 0
    if score:
        return score
    if result.get("is_scam"):
        return 80
    return _LEVEL_SCORE.get(str(result.get("risk_level") or "").upper(), 0)


def chat_guardrail(answer_text: str = "", tool_results: Optional[List[Any]] = None,
                   *, used_web_search: bool = False, used_knowledge: bool = False) -> Optional[Dict[str, Any]]:
    """Khối guardrail có cấu trúc cho hội thoại chat (đồng nhất với luồng quét).

    Nguyên tắc (cân bằng an toàn & QUYẾT ĐOÁN):
    - CHỈ gắn guardrail cho lượt chat có nội dung an toàn – rủi ro (có công cụ kiểm chứng
      đã chạy, có tra cứu web/OSINT, hoặc câu trả lời đưa ra nhận định an toàn/rủi ro).
      Chat kiến thức/hướng dẫn thông thường KHÔNG bị gắn nhãn -> trả `None`.
    - Khi CÓ bằng chứng, dùng đúng phân tầng của `assess()` và **kết luận dứt khoát**
      (CONFIRMED/HIGH/SUSPICIOUS/LIKELY_SAFE) — không hạ nhãn xuống "chưa đủ cơ sở".
    - CHỈ trả `INSUFFICIENT` khi bằng chứng thực sự thiếu (đúng vùng xám).
    - Nếu câu trả lời khẳng định quá mức ("100% an toàn", "chắc chắn không sao"...) thì
      gắn cảnh báo riêng, KHÔNG tự ý xoá bỏ kết luận dựa trên bằng chứng.
    - Luôn kèm disclaimer + kênh xác minh chính thức + cảnh báo AI có thể sai.
    """
    results = [r for r in (tool_results or []) if isinstance(r, dict)]

    score = 0
    evidence: List[Dict[str, Any]] = []
    seen = set()
    for r in results:
        score = max(score, _result_risk_score(r))
        found = build_evidence(r)
        if not found and _result_risk_score(r) >= 10:
            # Công cụ trả mức rủi ro nhưng chưa có evidence chuẩn hoá -> tạo một mục từ summary.
            found = [_mk_evidence(
                "heuristic",
                r.get("summary") or f"Công cụ nội bộ trả mức rủi ro {r.get('risk_level') or 'cao'}.",
                "HIGH" if _result_risk_score(r) >= 70 else "MEDIUM",
                supports="malicious",
            )]
        for e in found:
            key = (e.get("source"), e.get("detail"))
            if key not in seen:
                seen.add(key)
                evidence.append(e)

    if used_web_search and not any(e.get("source") == "web_search" for e in evidence):
        evidence.append(_mk_evidence(
            "web_search", "Đã tham khảo nguồn mở trên web (chưa được xác minh độc lập).",
            "INFO", supports="context"))
    if used_knowledge and not any(e.get("source") == "rag" for e in evidence):
        evidence.append(_mk_evidence(
            "rag", "Có tham chiếu kho tri thức nội bộ ShieldCall.", "INFO", supports="context"))

    claim = detect_absolute_safety_claim(answer_text)

    # Cổng phát guardrail: chỉ khi có việc-để-xác-minh thực sự.
    relevant = bool(results) or used_web_search or bool(claim) or asserts_risk_or_safety(answer_text)
    if not relevant:
        return None

    g = assess({"risk_score": score, "evidence": evidence}, kind="chat")
    g["answer_asserts_absolute_safety"] = bool(claim)

    cautions = list(g.get("cautions") or [])
    if claim:
        cautions.insert(0,
            f'Câu trả lời chứa khẳng định mang tính chắc chắn (“{claim}”). Hệ thống KHÔNG xác nhận '
            "mức độ an toàn tuyệt đối — hãy tự kiểm chứng qua kênh chính thức.")
    cautions.insert(0, CHAT_AI_CAUTION)
    g["cautions"] = cautions

    # Giữ nguyên kết luận của assess() (quyết đoán khi có bằng chứng); chỉ đánh dấu "AI có thể sai".
    g["kind"] = "chat"
    g["evidence"] = evidence  # nhúng kèm để UI chat hiển thị được bằng chứng
    return g


# ---------------------------------------------------------------------------
# 4. Nhãn & tông hiển thị thống nhất cho UI (điểm #1)
# ---------------------------------------------------------------------------
_TIER_TONE = {
    "CONFIRMED_RISK": "RED",
    "HIGH_RISK": "RED",
    "SUSPICIOUS": "YELLOW",
    "LIKELY_SAFE": "SAFE",
    "INSUFFICIENT": "UNVERIFIED",
}


def verdict_tone(result: Dict[str, Any]) -> str:
    """Tông hiển thị (RED/YELLOW/SAFE/UNVERIFIED) — ưu tiên theo guardrail.

    Không có guardrail (dữ liệu cũ) thì KHÔNG coi GREEN/SAFE là đã xác minh —
    trả UNVERIFIED để khớp với `verdict_display` (không tự nhận "an toàn").
    """
    g = result.get("guardrail") if isinstance(result, dict) else None
    if isinstance(g, dict):
        tone = _TIER_TONE.get(str(g.get("tier")))
        if tone:
            return tone
    level = str((result or {}).get("risk_level") or "").upper()
    if level in ("RED", "HIGH", "CRITICAL"):
        return "RED"
    if level in ("YELLOW", "MEDIUM"):
        return "YELLOW"
    if level in ("GREEN", "SAFE", ""):
        return "UNVERIFIED"
    return level


def verdict_display(result: Dict[str, Any]) -> str:
    """Nhãn hiển thị cho UI: ưu tiên nhãn guardrail.

    Không bao giờ nói 'An toàn' khi thiếu cơ sở — vùng GREEN/SAFE không có
    bằng chứng sạch vẫn hiển thị 'CHƯA ĐỦ CƠ SỞ XÁC MINH'.
    """
    g = result.get("guardrail") if isinstance(result, dict) else None
    if isinstance(g, dict) and g.get("label"):
        return str(g["label"])
    level = str((result or {}).get("risk_level") or "").upper()
    if level in ("RED", "HIGH", "CRITICAL"):
        return "Nguy hiểm"
    if level in ("YELLOW", "MEDIUM"):
        return "Cảnh báo"
    if level in ("GREEN", "SAFE", ""):
        return "CHƯA ĐỦ CƠ SỞ XÁC MINH"
    return level
