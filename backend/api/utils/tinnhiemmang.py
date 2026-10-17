"""
ShieldCall VN — Thư viện truy vấn & thu thập dữ liệu tinnhiemmang.vn.

`tinnhiemmang.vn` là hệ thống "Tín nhiệm mạng" (Cục An ninh mạng / NCSC-VNCERT)
công bố danh bạ:

- **Website tín nhiệm**   → ``website-tin-nhiem``   (type=``web``)
- **Tổ chức tín nhiệm**   → ``to-chuc-tin-nhiem``   (type=``org``)
- **Hệ thống tín nhiệm**   → ``he-thong-tin-nhiem``  (type=``sys``)
- **Ứng dụng tín nhiệm**   → ``ung-dung-tin-nhiem``  (type=``app``)
- **Thiết bị tín nhiệm**   → ``thiet-bi-tin-nhiem``  (type=``iot``)
- **Website lừa đảo**      → ``website-lua-dao``     (type=``fake``)  ← danh sách đen

Cách lấy dữ liệu (đã kiểm chứng 2026-10-15):

* Danh bạ render phía máy chủ, phân trang bằng ``?page=N`` (mỗi trang ~10–20 mục).
* Ô tìm kiếm gọi ``GET /filterObj?type=<cat>&name_obj=<kw>`` → trả về một đoạn
  HTML ``<ul><li class="item1">…</li></ul>`` (không phải JSON). Khi không có kết
  quả, trả về một ``<p>`` thông báo.
* Trang chi tiết: ``/danh-ba-tin-nhiem/<slug>-<id>`` chứa khối ``ul.org-info``
  (tổ chức sở hữu, SĐT, địa chỉ, email, ngày duyệt), ``.expire_date`` (hạn chứng
  nhận) và ``ul.list`` (các tiêu chí đạt được).

Về thu thập: client mặc định có *delay* giữa các request, ghi rõ User-Agent, có
retry/backoff và cache đĩa tuỳ chọn. **Mặc định bỏ qua `robots.txt`** của site (site
chặn `/*?page=` nên nếu tôn trọng sẽ không lấy được danh bạ); vẫn có thể bật lại bằng
`respect_robots=True` / `--respect-robots` khi cần. Chỉ dùng cho mục đích an toàn thông
tin; dữ liệu có thể thay đổi — luôn đối chiếu trang gốc khi trích dẫn.

Module này **không phụ thuộc Django** để dễ kiểm thử và tái sử dụng ở script/cron.
"""

from __future__ import annotations

import hashlib
import html as _html
import json
import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlsplit

import requests

try:
    from api.utils.normalization import is_major_platform_domain
except Exception:
    def is_major_platform_domain(domain_or_url: str) -> bool:
        return False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Hằng số
# ---------------------------------------------------------------------------
BASE_URL = "https://tinnhiemmang.vn"
DETAIL_PREFIX = "danh-ba-tin-nhiem"
DEFAULT_USER_AGENT = (
    "ShieldCall-TinnhiemBot/1.0 (+https://sc.fptoj.com; "
    "phuc vu an toan thong tin; lien he qua website)"
)
DEFAULT_DELAY = 1.0          # giây giữa 2 request (lịch sự)
DEFAULT_TIMEOUT = 30.0
DEFAULT_RETRIES = 3

# Bảng danh mục: khoá ngắn ↔ đường dẫn ↔ mã ``type`` dùng cho filterObj
CATEGORIES: Dict[str, Dict[str, Any]] = {
    "web": {
        "path": "website-tin-nhiem",
        "type": "web",
        "label": "Website tín nhiệm",
        "kind": "trusted",
    },
    "org": {
        "path": "to-chuc-tin-nhiem",
        "type": "org",
        "label": "Tổ chức tín nhiệm",
        "kind": "trusted",
    },
    "sys": {
        "path": "he-thong-tin-nhiem",
        "type": "sys",
        "label": "Hệ thống tín nhiệm",
        "kind": "trusted",
    },
    "app": {
        "path": "ung-dung-tin-nhiem",
        "type": "app",
        "label": "Ứng dụng tín nhiệm",
        "kind": "trusted",
    },
    "iot": {
        "path": "thiet-bi-tin-nhiem",
        "type": "iot",
        "label": "Thiết bị tín nhiệm",
        "kind": "trusted",
    },
    "fake": {
        "path": "website-lua-dao",
        "type": "fake",
        "label": "Website lừa đảo",
        "kind": "scam",
    },
}
SCAM_CATEGORIES = tuple(k for k, v in CATEGORIES.items() if v["kind"] == "scam")

# Thư mục dataset cục bộ: backend/api/core/data/tinnhiemmang/
DATA_DIR = Path(__file__).resolve().parents[1] / "core" / "data" / "tinnhiemmang"

# ---------------------------------------------------------------------------
# Tiện ích text / HTML
# ---------------------------------------------------------------------------
_TAG_RE = re.compile(r"<[^>]+>")
_SVG_RE = re.compile(r"<svg\b.*?</svg>", re.I | re.S)
_SCRIPT_RE = re.compile(r"<(script|style)\b.*?</\1>", re.I | re.S)
_WS_RE = re.compile(r"\s+")


def _clean(fragment: Any) -> str:
    """Bỏ thẻ HTML/SVG, giải mã entity, gộp khoảng trắng."""
    if not fragment:
        return ""
    s = str(fragment)
    s = _SCRIPT_RE.sub(" ", s)
    s = _SVG_RE.sub(" ", s)
    s = _TAG_RE.sub(" ", s)
    s = _html.unescape(s)
    s = s.replace("\xa0", " ")
    return _WS_RE.sub(" ", s).strip()


def normalize_domain(value: str) -> str:
    """Chuẩn hoá domain/URL về dạng ``host`` (bỏ scheme, path, ``www.``)."""
    s = (value or "").strip().lower()
    if not s:
        return ""
    s = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", s)
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.split("@")[-1]          # bỏ user:pass@
    s = s.split(":", 1)[0]        # bỏ port
    s = s.strip(".")
    if s.startswith("www."):
        s = s[4:]
    return s


def looks_like_domain(value: str) -> bool:
    """True nếu chuỗi trông giống tên miền (có dấu chấm, không khoảng trắng)."""
    s = (value or "").strip()
    if not s or " " in s or "." not in s:
        return False
    host = normalize_domain(s)
    return bool(re.match(r"^(?:[\w\-]+\.)+[a-z]{2,}$", host, re.I))


def parse_vn_date(value: str) -> Optional[str]:
    """``22/09/2026`` → ``2026-09-22`` (None nếu không khớp)."""
    m = re.search(r"(\d{1,2})/(\d{1,2})/(\d{4})", value or "")
    if not m:
        return None
    day, month, year = (int(x) for x in m.groups())
    try:
        return datetime(year, month, day).date().isoformat()
    except ValueError:
        return None


def _first_group(pattern: str, text: str, flags: int = re.S | re.I) -> str:
    m = re.search(pattern, text or "", flags)
    return m.group(1) if m else ""


# Hậu tố/tên site dính vào tiêu đề/mô tả trên tinnhiemmang.vn (vd "Tín nhiệm mạng | ...")
_SITE_PREFIX_RE = re.compile(r"^\s*(?:Tín nhiệm mạng|Tin nhiem mang|Tinnhiemmang)\s*[|\-–—:•]\s*", re.I)


def _strip_site_prefix(text: str) -> str:
    """Bỏ tiền tố tên site ('Tín nhiệm mạng | ...') khỏi tiêu đề/mô tả."""
    return _SITE_PREFIX_RE.sub("", (text or "").strip()).strip()


def _node_text(el, separator: str = " ") -> str:
    """Lấy text của một phần tử, GIỮ khoảng trắng giữa các tag inline.

    Dùng ``get_text(strip=False)`` rồi gom khoảng trắng (kể cả ``\\xa0``) — tránh lỗi
    dính chữ kiểu "họđang" khi HTML là ``...họ\\xa0<a>đang</a>``.
    """
    if el is None:
        return ""
    raw = el.get_text(separator, strip=False) if separator else el.get_text()
    raw = raw.replace("\xa0", " ")
    return _WS_RE.sub(" ", raw).strip()


_INLINE_KEEP = {"strong": "strong", "b": "strong", "em": "em", "i": "em"}
_INLINE_URL_RE = re.compile(r"^(?:https?:)?//|^/", re.I)


def _abs_url(src: str, base_url: str = BASE_URL) -> str:
    """Chuẩn hoá URL ảnh/liên kết tương đối thành tuyệt đối."""
    src = (src or "").strip()
    if not src or src.startswith("data:") or src.startswith("javascript:"):
        return ""
    if src.startswith("//"):
        return "https:" + src
    if src.startswith("http"):
        return src
    return urljoin(base_url + "/", src.lstrip("/"))


def _img_src(img, base_url: str = BASE_URL) -> str:
    """URL tuyệt đối của ảnh (ưu tiên data-src/ảnh lazy)."""
    if img is None:
        return ""
    src = (img.get("data-src") or img.get("data-original") or img.get("src")
           or img.get("data-srcset") or img.get("srcset") or "")
    if not src:
        return ""
    return _abs_url(src.split(",")[0].strip().split(" ")[0], base_url)


def _norm_img_key(src: str) -> str:
    """Khoá so trùng ảnh (bỏ query CDN, giải mã ``&amp;``)."""
    s = (src or "").replace("&amp;", "&")
    return re.sub(r"[?#].*$", "", s).rstrip("/")


def _img_html(img, base_url: str = BASE_URL, state: Optional[Dict[str, Any]] = None) -> str:
    """Sinh thẻ <img>, có bỏ ảnh lead (trùng cover) và khử trùng ảnh lặp."""
    src = _img_src(img, base_url)
    if not src:
        return ""
    if state is not None:
        key = _norm_img_key(src)
        seen = state.setdefault("seen", set())
        if state.get("drop_first"):
            # Ảnh đầu trong body thường trùng ảnh bìa (cover) → bỏ để tránh lặp
            state["drop_first"] = False
            seen.add(key)
            return ""
        if key in seen:
            return ""
        seen.add(key)
    alt = img.get("alt") or img.get("title") or ""
    return (f'<img src="{_html.escape(src, quote=True)}" '
            f'alt="{_html.escape(alt, quote=True)}" loading="lazy">')


def _inline_html(el, base_url: str = BASE_URL, state: Optional[Dict[str, Any]] = None) -> str:
    """Chuyển nội dung inline của một phần tử thành HTML an toàn.

    Giữ **đậm/nghiêng/liên kết/ảnh** (kể cả ``<picture><source><img>``) để không mất
    ảnh minh hoạ/header của bài.
    """
    from bs4 import NavigableString, Tag

    parts: List[str] = []

    def walk(node) -> None:
        for child in getattr(node, "children", []):
            if isinstance(child, NavigableString):
                parts.append(_html.escape(str(child)))
            elif isinstance(child, Tag):
                name = (child.name or "").lower()
                if name == "br":
                    parts.append("<br>")
                elif name == "img":
                    parts.append(_img_html(child, base_url, state))
                elif name in _INLINE_KEEP:
                    inner = _inline_html(child, base_url, state)
                    if inner:
                        parts.append(f"<{_INLINE_KEEP[name]}>{inner}</{_INLINE_KEEP[name]}>")
                elif name == "a":
                    href = _abs_url(child.get("href") or "", base_url)
                    inner = _inline_html(child, base_url, state)
                    if href:
                        parts.append(
                            f'<a href="{_html.escape(href, quote=True)}" '
                            f'target="_blank" rel="noopener noreferrer">{inner}</a>'
                        )
                    else:
                        parts.append(inner)
                else:
                    inner = _inline_html(child, base_url, state)
                    if inner:
                        # Tag lạ (span/div/picture…) bị làm phẳng → chèn khoảng trắng ranh giới
                        parts.append(f" {inner} ")

    walk(el)
    html = "".join(parts)
    # Bảo đảm khoảng trắng ở ranh giới: sau thẻ ĐÓNG / thẻ void, và trước thẻ MỞ
    html = re.sub(r"(</[a-zA-Z][^>]*>)(?=[^\s<])", r"\1 ", html)
    html = re.sub(r"(<(?:br|img|hr)\b[^>]*>)(?=[^\s<])", r"\1 ", html)
    html = re.sub(r"([^\s>])(<[a-zA-Z])", r"\1 \2", html)
    html = re.sub(r"\s+(</)", r"\1", html)
    html = re.sub(r"\s+([,.;:!?%])", r"\1", html)
    return _WS_RE.sub(" ", html).strip()


# Đoạn rác (kêu gọi chia sẻ / tương tác) cần bỏ khỏi nội dung bài viết
_NEWS_JUNK_MARKERS = (
    "Hãy chia sẻ câu chuyện của bạn với chúng tôi",
    "Like Fapage của chúng tôi",
    "remove_circle",
)


_BLOCK_TAGS = ["p", "h2", "h3", "h4", "h5", "ul", "ol", "table", "figure", "blockquote"]


def _blocks_to_html(container, base_url: str = BASE_URL,
                    state: Optional[Dict[str, Any]] = None) -> List[str]:
    """Chuyển thân bài thành danh sách block HTML (<p>/<h2>/<ul>/<figure>/<blockquote>).

    ``state`` giữ tập ảnh đã dùng để khử trùng và bỏ ảnh lead trùng cover.
    """
    blocks: List[str] = []
    if container is None:
        return blocks
    if state is None:
        state = {"seen": set()}
    for el in container.find_all(_BLOCK_TAGS):
        # bỏ qua phần tử nằm trong một phần tử block khác đã xử lý (tránh trùng)
        if el.find_parent(_BLOCK_TAGS):
            continue
        name = (el.name or "").lower()
        if name == "table":
            html = str(el)
            if html and len(html) > 20:
                blocks.append(html)
        elif name == "figure":
            img_html = _img_html(el.find("img"), base_url, state)
            cap = el.find("figcaption")
            cap_html = _inline_html(cap, base_url, state) if cap else ""
            if img_html:
                blocks.append(
                    f"<figure>{img_html}"
                    + (f"<figcaption>{cap_html}</figcaption>" if cap_html else "")
                    + "</figure>"
                )
            elif cap_html:
                blocks.append(f"<p><em>{cap_html}</em></p>")
        elif name == "blockquote":
            t = _inline_html(el, base_url, state)
            if t:
                blocks.append(f"<blockquote>{t}</blockquote>")
        elif name in ("ul", "ol"):
            items = []
            for li in el.find_all("li", recursive=False):
                t = _inline_html(li, base_url, state)
                if t:
                    items.append(f"<li>{t}</li>")
            if items:
                blocks.append(f"<{name}>" + "".join(items) + f"</{name}>")
        elif name in ("h2", "h3", "h4", "h5"):
            t = _inline_html(el, base_url, state)
            if t:
                blocks.append(f"<h{'2' if name == 'h2' else '3'}>{t}</h{'2' if name == 'h2' else '3'}>")
        else:
            t = _inline_html(el, base_url, state)
            if t and len(t) >= 4 and not any(j in t for j in _NEWS_JUNK_MARKERS):
                blocks.append(f"<p>{t}</p>")
    return blocks



# ---------------------------------------------------------------------------
# Bản ghi
# ---------------------------------------------------------------------------
@dataclass
class TinnhiemRecord:
    """Một mục trong danh bạ tinnhiemmang.vn."""

    category: str
    kind: str                       # "trusted" | "scam"
    name: str = ""
    url: str = ""
    slug: str = ""
    ref_id: Optional[str] = None
    domain: Optional[str] = None    # chỉ với web/fake
    trusted_since: Optional[str] = None   # web
    detected_on: Optional[str] = None     # fake
    owner: Optional[str] = None           # "Sở hữu bởi" / khối org
    impersonated: Optional[str] = None    # "Mạo danh tổ chức"
    badge: Optional[str] = None           # mức chứng nhận / trạng thái
    date: Optional[str] = None            # ISO (tổng hợp)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TinnhiemArticle:
    """Bài viết tin tức hoặc cảnh báo lừa đảo thu thập từ tinnhiemmang.vn."""

    title: str
    url: str
    slug: str
    feed_key: str                        # "canh_bao_lua_dao" | "noi_bat"
    category: str                        # "alert" | "news"
    summary: str = ""
    content: str = ""
    cover_image_url: Optional[str] = None
    published_date: Optional[str] = None  # YYYY-MM-DD
    source_type: str = "tinnhiemmang"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


NEWS_FEED_CONFIGS: Dict[str, Dict[str, str]] = {
    "canh_bao_lua_dao": {
        "path": "canh-bao-lua-dao",
        "category": "alert",
        "label": "Cảnh báo lừa đảo",
        "url": "https://tinnhiemmang.vn/canh-bao-lua-dao",
    },
    "noi_bat": {
        "path": "noi-bat",
        "category": "news",
        "label": "Tin tức nổi bật",
        "url": "https://tinnhiemmang.vn/noi-bat",
    },
}

# Nguồn báo chí: VnExpress — tag "Lừa đảo qua mạng"
VNEXPRESS_BASE_URL = "https://vnexpress.net"
VNEXPRESS_FEED_CONFIGS: Dict[str, Dict[str, str]] = {
    "lua_dao_qua_mang": {
        "path": "tag/lua-dao-qua-mang-27298",
        "category": "alert",
        "label": "VnExpress — Lừa đảo qua mạng",
        "url": "https://vnexpress.net/tag/lua-dao-qua-mang-27298",
    },
}


# ---------------------------------------------------------------------------
# Bộ phân tích HTML (tách riêng để dễ test)
# ---------------------------------------------------------------------------
_ITEM_BOUNDARY_RE = re.compile(r'<li\s+class="item([12])"\s*>', re.I)
_LIST_LINK_RE = re.compile(r'href="([^"]*' + re.escape(DETAIL_PREFIX) + r'/([^"#?]+))"', re.I)


def _md_inline(el) -> str:
    """Chuyển nội dung inline HTML → Markdown (giữ đậm/nghiêng/link/ảnh)."""
    from bs4 import NavigableString, Tag

    out: List[str] = []

    def walk(node) -> None:
        for ch in getattr(node, "children", []):
            if isinstance(ch, NavigableString):
                out.append(str(ch))
            elif isinstance(ch, Tag):
                n = (ch.name or "").lower()
                if n == "img":
                    src = ch.get("src") or ch.get("data-src") or ""
                    if src:
                        out.append(f"![{ch.get('alt') or ''}]({src})")
                elif n in ("strong", "b"):
                    out.append(f"**{_md_inline(ch)}**")
                elif n in ("em", "i"):
                    out.append(f"*{_md_inline(ch)}*")
                elif n == "a":
                    href = ch.get("href") or ""
                    txt = _md_inline(ch)
                    out.append(f"[{txt}]({href})" if href else txt)
                elif n == "br":
                    out.append("  \n")
                else:
                    out.append(_md_inline(ch))

    walk(el)
    return re.sub(r"[ \t\xa0]+", " ", "".join(out)).strip()


def html_to_markdown(html_text: str) -> str:
    """Chuyển nội dung HTML (do parser tạo) sang Markdown sạch (giữ ảnh/đậm/link)."""
    if not html_text:
        return ""
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text, "html.parser")
    except Exception:
        return html_text

    lines: List[str] = []
    for el in soup.find_all(_BLOCK_TAGS):
        if el.find_parent(_BLOCK_TAGS):
            continue
        name = (el.name or "").lower()
        if name == "figure":
            img = el.find("img")
            cap = el.find("figcaption")
            cap_txt = _md_inline(cap) if cap else ""
            if img:
                src = img.get("src") or ""
                alt = cap_txt or (img.get("alt") or "")
                lines.append(f"![{alt}]({src})")
                if cap_txt:
                    lines.append(f"*{cap_txt}*")
            elif cap_txt:
                lines.append(f"*{cap_txt}*")
        elif name in ("ul", "ol"):
            for i, li in enumerate(el.find_all("li", recursive=False), 1):
                t = _md_inline(li)
                if t:
                    lines.append(f"{i}. {t}" if name == "ol" else f"- {t}")
        elif name in ("h2", "h3", "h4", "h5"):
            t = _md_inline(el)
            if t:
                lines.append(("#" * (2 if name == "h2" else 3)) + " " + t)
        elif name == "blockquote":
            t = _md_inline(el)
            if t:
                lines.append("> " + t)
        elif name == "table":
            for tr in el.find_all("tr"):
                cells = [c.get_text(" ", strip=True) for c in tr.find_all(["td", "th"])]
                if cells:
                    lines.append("| " + " | ".join(cells) + " |")
        else:
            t = _md_inline(el)
            if t:
                lines.append(t)
    return "\n\n".join(lines).strip()


def _iter_item_blocks(html_text: str) -> Iterator[Tuple[str, str]]:
    """Cắt HTML danh bạ thành từng khối ``<li class="itemN">…``."""
    marks = list(_ITEM_BOUNDARY_RE.finditer(html_text or ""))
    for idx, m in enumerate(marks):
        end = marks[idx + 1].start() if idx + 1 < len(marks) else len(html_text)
        yield m.group(1), html_text[m.end():end]


def _parse_item_block(item_no: str, block: str, category: str) -> Optional[TinnhiemRecord]:
    meta = CATEGORIES.get(category)
    if not meta:
        return None
    link = _LIST_LINK_RE.search(block)
    if not link:
        return None
    rel_url, slug = link.group(1), link.group(2)
    url = rel_url if rel_url.startswith("http") else urljoin(BASE_URL + "/", rel_url.lstrip("/"))
    ref = re.search(r"-(\d{3,})$", slug)

    name = _clean(_first_group(r"<span[^>]*>(.*?)</span>", block))
    raw_date = _clean(_first_group(r'class="date[^"]*"[^>]*>(.*?)</div>', block))
    label_text = label_value = ""
    m = re.search(r"<label>(.*?)</label>(.*?)</a>", block, re.S | re.I)
    if m:
        label_text = _clean(m.group(1))
        label_value = _clean(m.group(2))

    owner_block = _clean(_first_group(r'class="[^"]*\borg\b[^"]*"[^>]*>(.*?)</div>', block))

    # Mức chứng nhận (trusted) hoặc trạng thái (scam)
    badge = _clean(_first_group(r'class="medal_basic1[^"]*"[^>]*>(.*?)</div>', block))
    if not badge:
        badge = _clean(_first_group(r'class="[^"]*\bstatus\b[^"]*"[^>]*>(.*?)</div>\s*</div>', block))

    rec = TinnhiemRecord(
        category=category,
        kind=meta["kind"],
        name=name,
        url=url,
        slug=slug,
        ref_id=ref.group(1) if ref else None,
        badge=badge or None,
    )
    if meta["kind"] == "scam":
        rec.detected_on = parse_vn_date(raw_date)
        rec.impersonated = label_value if "mạo danh" in label_text.lower() else None
        rec.owner = owner_block or None
    else:
        rec.trusted_since = parse_vn_date(raw_date)
        rec.owner = label_value if "sở hữu" in label_text.lower() else (owner_block or None)
    rec.date = rec.detected_on or rec.trusted_since

    if category in ("web", "fake") and looks_like_domain(name):
        rec.domain = normalize_domain(name)
    return rec


def parse_listing(html_text: str, category: str) -> List[TinnhiemRecord]:
    """Phân tích HTML danh bạ → danh sách :class:`TinnhiemRecord`."""
    out: List[TinnhiemRecord] = []
    seen = set()
    for item_no, block in _iter_item_blocks(html_text):
        rec = _parse_item_block(item_no, block, category)
        if not rec or not rec.slug:
            continue
        if rec.slug in seen:
            continue
        seen.add(rec.slug)
        out.append(rec)
    return out


def max_page(html_text: str, path: str) -> int:
    """Số trang lớn nhất suy ra từ khối phân trang (0 nếu không có)."""
    pages = [int(x) for x in re.findall(re.escape(path) + r"\?page=(\d+)", html_text or "")]
    return max(pages) if pages else 0


def listing_total_pages(html_text: str, category: str) -> int:
    meta = CATEGORIES.get(category)
    if not meta:
        return 0
    return max_page(html_text, meta["path"])


_ORG_INFO_RE = re.compile(r'<ul class="org-info">(.*?)</ul>', re.I | re.S)
_ORG_INFO_LI_RE = re.compile(r"<li>(.*?)</li>", re.I | re.S)


def parse_detail(html_text: str) -> Dict[str, Any]:
    """Phân tích trang chi tiết ``/danh-ba-tin-nhiem/<slug>`` → dict."""
    html_text = html_text or ""
    detail: Dict[str, Any] = {
        "title": _clean(_first_group(r"<title>(.*?)</title>", html_text)),
        "fields": {},
        "criteria": [],
        "updated": None,
        "approved": None,
        "cert_expire": None,
        "domain": None,
        "medal_image": None,
        "email": None,
        "email_obfuscated": False,
    }

    block = _first_group(r'<ul class="org-info">(.*?)</ul>', html_text)
    fields: Dict[str, str] = {}
    if block:
        for li in _ORG_INFO_LI_RE.findall(block):
            label = _clean(_first_group(r'class="label">(.*?)</div>', li))
            info = _clean(_first_group(r'class="info[^"]*">(.*?)</div>', li))
            if label:
                fields[label] = info
    detail["fields"] = fields

    low = {k.lower(): v for k, v in fields.items()}
    detail["owner"] = low.get("tổ chức sở hữu") or None
    detail["phone"] = low.get("số điện thoại") or None
    detail["address"] = low.get("địa chỉ") or None
    if low.get("email"):
        if "email" in low["email"].lower() and "protected" in html_text.lower() and "@" not in low["email"]:
            detail["email_obfuscated"] = True
        else:
            detail["email"] = low["email"]
    detail["approved"] = parse_vn_date(low.get("ngày duyệt", ""))

    detail["updated"] = parse_vn_date(_first_group(r"Cập nhật ngày\s*([0-9]{1,2}/[0-9]{1,2}/[0-9]{4})", html_text))
    expire_raw = _clean(_first_group(r'class="expire_date[^"]*"[^>]*>(.*?)</div>', html_text))
    detail["cert_expire"] = parse_vn_date(expire_raw)

    detail["domain"] = normalize_domain(_first_group(r'<div class="obj">\s*<span>(.*?)</span>', html_text)) or None
    detail["medal_image"] = _first_group(r'<img[^>]*class="[^"]*medal[^"]*"[^>]*src="([^"]+)"', html_text) or None

    crit_idx = html_text.find("Các tiêu chí đạt được")
    if crit_idx >= 0:
        seg = html_text[crit_idx:crit_idx + 12000]
        for m in re.finditer(r'<h3[^>]*>(.*?)</h3>\s*<p[^>]*>(.*?)</p>', seg, re.S | re.I):
            title = _clean(m.group(1))
            desc = _clean(m.group(2))
            if title:
                detail["criteria"].append({"title": title, "description": desc})
    return detail


def parse_news_listing(html_text: str, feed_key: str = "noi_bat", base_url: str = BASE_URL) -> List[Dict[str, Any]]:
    """Phân tích HTML trang danh sách tin tức/cảnh báo tinnhiemmang.vn."""
    items: List[Dict[str, Any]] = []
    seen_urls = set()

    EXCLUDE_PATHS = (
        "/danh-cho-", "/to-chuc-tin-nhiem", "/website-tin-nhiem", "/thiet-bi-tin-nhiem",
        "/he-thong-tin-nhiem", "/ung-dung-tin-nhiem", "/website-lua-dao", "/canh-bao-lua-dao",
        "/noi-bat", "facebook.com", "zalo.me", "/filterObj", "/cdn-cgi/", "javascript:",
        "/gioi-thieu", "/lien-he", "/chinh-sach", "/dieu-khoan", "/faqs", "/hoi-dap", "/login",
    )

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text or "", "html.parser")
        # .post-vertical + .post-horizontal là 2 kiểu card thật của site (trước đây thiếu
        # .post-horizontal nên bỏ sót ~2/3 số bài trên trang).
        cards = soup.select(".post-vertical, .post-horizontal, article")
        if not cards:
            cards = soup.select(".item")
        for card in cards:
            # Chọn anchor mang tiêu đề (có chữ), không lấy nhầm anchor ảnh (không chữ).
            a, full_url = None, ""
            for cand in card.find_all("a", href=True):
                href = cand["href"].strip()
                cand_url = href if href.startswith("http") else urljoin(base_url + "/", href.lstrip("/"))
                if any(ex in cand_url for ex in EXCLUDE_PATHS):
                    continue
                if _node_text(cand):
                    a, full_url = cand, cand_url
                    break
                if not a:
                    a, full_url = cand, cand_url
            if not a or not full_url or full_url in seen_urls:
                continue
            if any(ex in full_url for ex in EXCLUDE_PATHS):
                continue

            title = _strip_site_prefix(_node_text(a)) or _node_text(
                card.find(["h2", "h3", "h4", "h5", "strong"])
            )
            if not title or len(title) < 10:
                continue

            img = card.find("img")
            cover = ""
            if img:
                cover = img.get("src") or img.get("data-src") or ""
                if cover and not cover.startswith("http"):
                    cover = urljoin(base_url + "/", cover.lstrip("/"))

            desc_el = card.find(["p", ".desc", ".summary", ".text"])
            summary = _strip_site_prefix(_node_text(desc_el)) if desc_el else ""
            if len(summary) > 280:
                summary = summary[:277] + "..."

            seen_urls.add(full_url)
            slug = full_url.rstrip("/").split("/")[-1]
            default_cat = NEWS_FEED_CONFIGS.get(feed_key, {}).get("category", "news")
            items.append({
                "title": title,
                "url": full_url,
                "slug": slug,
                "cover_image": cover or None,
                "summary": summary,
                "feed_key": feed_key,
                "category": default_cat,
            })
    except Exception as exc:
        logger.warning("parse_news_listing fallback error: %s", exc)

    return items


def parse_news_detail(html_text: str, article_url: str, feed_key: str = "noi_bat",
                      base_url: str = BASE_URL, fallback_meta: Optional[Dict[str, Any]] = None) -> Optional[TinnhiemArticle]:
    """Phân tích trang chi tiết bài viết tinnhiemmang.vn thành TinnhiemArticle.

    ``content`` trả về **HTML** (``<p>/<h3>/<ul>``) để hiển thị đúng định dạng qua
    MarkdownView; giữ nguyên đậm/nghiêng/liên kết, không dính chữ, sạch tiền tố tên site.
    """
    meta = fallback_meta or {}
    slug = article_url.rstrip("/").split("/")[-1]
    default_cat = NEWS_FEED_CONFIGS.get(feed_key, {}).get("category", "news")

    title = _strip_site_prefix(meta.get("title", ""))
    published_date = None
    cover_image = meta.get("cover_image")
    blocks: List[str] = []
    first_text = ""

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text or "", "html.parser")

        h1 = soup.find("h1")
        if h1:
            title = _node_text(h1) or title

        col = h1.find_parent("div", class_="col-md-9") if h1 else None
        if not col:
            col = (soup.find("div", class_="col-md-9") or soup.find("article")
                   or soup.find("div", class_="content"))

        if col:
            date_el = col.find("div", class_="date-create") or col.find(class_=re.compile(r"date", re.I))
            if date_el:
                published_date = parse_vn_date(_node_text(date_el))

            img = col.find("img")
            if img:
                img_src = img.get("src") or img.get("data-src") or ""
                if img_src and not img_src.startswith("http"):
                    img_src = urljoin(base_url + "/", img_src.lstrip("/"))
                if img_src:
                    cover_image = img_src

            blocks = _blocks_to_html(col, base_url, {"seen": set()})
            if blocks:
                first_text = _TAG_RE.sub(" ", blocks[0])
                first_text = _html.unescape(_WS_RE.sub(" ", first_text)).strip()
    except Exception as exc:
        logger.warning("parse_news_detail error on %s: %s", article_url, exc)

    title = _strip_site_prefix(title)
    if not title:
        return None

    content = "\n".join(blocks)
    if not content:
        fallback = _strip_site_prefix(meta.get("summary", ""))
        content = f"<p>{_html.escape(fallback)}</p>" if fallback else ""

    summary = _strip_site_prefix(meta.get("summary", "")) or first_text
    if len(summary) > 280:
        summary = summary[:277] + "..."

    return TinnhiemArticle(
        title=title,
        url=article_url,
        slug=slug,
        feed_key=feed_key,
        category=meta.get("category", default_cat),
        summary=summary,
        content=content,
        cover_image_url=cover_image,
        published_date=published_date,
        source_type="tinnhiemmang",
    )


# ---------------------------------------------------------------------------
# VnExpress (báo chí) — tag "Lừa đảo qua mạng"
# ---------------------------------------------------------------------------
_VNE_LISTING_SELECTOR = "article.item-news, .item-news"


def parse_vnexpress_listing(html_text: str, feed_key: str = "lua_dao_qua_mang",
                            base_url: str = VNEXPRESS_BASE_URL) -> List[Dict[str, Any]]:
    """Phân tích trang tag VnExpress thành danh sách bài viết."""
    items: List[Dict[str, Any]] = []
    seen = set()
    default_cat = VNEXPRESS_FEED_CONFIGS.get(feed_key, {}).get("category", "alert")
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text or "", "html.parser")
        for card in soup.select(_VNE_LISTING_SELECTOR):
            a = card.select_one("h2.title-news a, h3.title-news a, .title-news a")
            if not a or not a.get("href"):
                continue
            url = _abs_url(a["href"], base_url).split("#", 1)[0]
            if not url.endswith(".html") or url in seen:
                continue
            title = _node_text(a)
            if not title or len(title) < 10:
                continue
            seen.add(url)
            desc_el = card.select_one(".description")
            summary = _node_text(desc_el) if desc_el else ""
            if len(summary) > 280:
                summary = summary[:277] + "..."
            cover = _img_src(card.select_one(".thumb-art img, .thumb img, img"), base_url)
            items.append({
                "title": title,
                "url": url,
                "slug": url.rstrip("/").split("/")[-1].replace(".html", ""),
                "cover_image": cover or None,
                "summary": summary,
                "feed_key": feed_key,
                "category": default_cat,
            })
    except Exception as exc:
        logger.warning("parse_vnexpress_listing error: %s", exc)
    return items


def parse_vnexpress_detail(html_text: str, article_url: str, feed_key: str = "lua_dao_qua_mang",
                           base_url: str = VNEXPRESS_BASE_URL,
                           fallback_meta: Optional[Dict[str, Any]] = None) -> Optional[TinnhiemArticle]:
    """Phân tích bài viết VnExpress thành TinnhiemArticle (content HTML giữ ảnh/định dạng)."""
    meta = fallback_meta or {}
    default_cat = VNEXPRESS_FEED_CONFIGS.get(feed_key, {}).get("category", "alert")
    slug = article_url.rstrip("/").split("/")[-1].replace(".html", "")

    title = _strip_site_prefix(meta.get("title", ""))
    summary = _strip_site_prefix(meta.get("summary", ""))
    published_date = None
    cover_image = meta.get("cover_image")
    blocks: List[str] = []

    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(html_text or "", "html.parser")

        h1 = soup.find("h1", class_=re.compile(r"title-detail", re.I)) or soup.find("h1")
        if h1:
            title = _node_text(h1) or title
        desc = soup.find("p", class_="description")
        if desc:
            summary = _node_text(desc) or summary
        date_el = soup.find("span", class_=re.compile(r"\bdate\b", re.I))
        if date_el:
            published_date = parse_vn_date(_node_text(date_el))
        og = soup.find("meta", attrs={"property": "og:image"})
        if og and og.get("content"):
            cover_image = _abs_url(og["content"], base_url)

        page_title = _node_text(soup.find("title"))
        body = (soup.find("article", class_=re.compile(r"fck_detail", re.I))
                or soup.find("div", class_=re.compile(r"fck_detail", re.I)))
        if body is None or "nghe podcasts" in page_title.lower():
            # Podcast / trang không có thân bài → bỏ (tránh bài "sơ sài")
            logger.info("parse_vnexpress_detail: bỏ podcast/không có thân bài: %s", article_url)
            return None
        if not cover_image:
            cover_image = _img_src(body.find("img"), base_url) or cover_image
        blocks = _blocks_to_html(body, base_url)
    except Exception as exc:
        logger.warning("parse_vnexpress_detail error on %s: %s", article_url, exc)

    if not title:
        return None

    content = "\n".join(blocks)
    if not content and summary:
        content = f"<p>{_html.escape(summary)}</p>"
    if len(summary) > 280:
        summary = summary[:277] + "..."

    return TinnhiemArticle(
        title=title,
        url=article_url,
        slug=slug,
        feed_key=feed_key,
        category=meta.get("category", default_cat),
        summary=summary,
        content=content,
        cover_image_url=cover_image,
        published_date=published_date,
        source_type="press",
    )


def vnexpress_page_path(feed_key: str = "lua_dao_qua_mang", page: int = 1) -> str:
    """Đường dẫn trang tag VnExpress (trang 1 không hậu tố; trang N là ``…-pN``)."""
    cfg = VNEXPRESS_FEED_CONFIGS.get(feed_key)
    if not cfg:
        raise ValueError(f"Khóa feed VnExpress không hợp lệ: {feed_key!r}")
    base = cfg["path"].rstrip("/")
    return base if int(page) <= 1 else f"{base}-p{int(page)}"


def vnexpress_total_pages(html_text: str, feed_key: str = "lua_dao_qua_mang") -> int:
    """Số trang của tag VnExpress suy ra từ khối phân trang."""
    cfg = VNEXPRESS_FEED_CONFIGS.get(feed_key)
    if not cfg:
        return 1
    slug = cfg["path"].rstrip("/").split("/")[-1]
    nums = [int(x) for x in re.findall(re.escape(slug) + r"-p(\d+)", html_text or "")]
    return max(nums) if nums else 1


# ---------------------------------------------------------------------------
# robots.txt (tôn trọng điều khoản thu thập)
# ---------------------------------------------------------------------------
class RobotsDisallowed(RuntimeError):
    """URL bị ``robots.txt`` chặn và client đang bật chế độ tôn trọng robots."""


def _robots_pattern_to_regex(pattern: str) -> re.Pattern:
    """Dịch một dòng ``Allow/Disallow`` của robots.txt (hỗ trợ ``*`` và ``$``)."""
    pattern = (pattern or "").strip()
    anchor_end = pattern.endswith("$")
    if anchor_end:
        pattern = pattern[:-1]
    regex = re.escape(pattern).replace(r"\*", ".*")
    return re.compile("^" + regex + ("$" if anchor_end else ""))


class _RobotsRules:
    """Bộ luật robots.txt tối giản cho một User-Agent."""

    def __init__(self) -> None:
        self._rules: List[Tuple[bool, re.Pattern]] = []  # (allow?, regex)
        self.disallow_all = False

    def add(self, allowance: bool, pattern: str) -> None:
        self._rules.append((allowance, _robots_pattern_to_regex(pattern)))

    def allows(self, path_with_query: str) -> bool:
        if self.disallow_all:
            return False
        best_len, best_allow = -1, None
        for allowance, regex in self._rules:
            m = regex.match(path_with_query)
            if m and m.end() > best_len:
                best_len, best_allow = m.end(), allowance
        if best_allow is None:
            return True          # không khớp luật nào → mặc định cho phép
        return best_allow


def parse_robots(text: str, user_agent: str = "*") -> _RobotsRules:
    """Phân tích robots.txt, lấy luật cho ``*`` gộp với nhóm khớp User-Agent."""
    ua_token = (user_agent or "*").split("/")[0].strip().lower()
    rules = _RobotsRules()
    current_agents: List[str] = []
    # Luật dành riêng cho UA khớp; gộp cả nhóm '*'
    collected: List[Tuple[bool, str]] = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        field, _, value = line.partition(":")
        field = field.strip().lower()
        value = value.strip()
        if field == "user-agent":
            current_agents = [value.lower()]
            continue
        if field in ("allow", "disallow") and current_agents:
            relevant = any(a == "*" or a in ua_token or ua_token in a for a in current_agents)
            if relevant and value:
                collected.append((field == "allow", value))
    for allowance, pattern in collected:
        rules.add(allowance, pattern)
    return rules


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------
class TinnhiemClient:
    """Client lịch sự cho tinnhiemmang.vn (delay + retry + cache đĩa tuỳ chọn)."""

    def __init__(
        self,
        base_url: str = BASE_URL,
        delay: float = DEFAULT_DELAY,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        user_agent: str = DEFAULT_USER_AGENT,
        cache_dir: Optional[str] = None,
        respect_robots: bool = False,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.delay = max(0.0, float(delay))
        self.timeout = float(timeout)
        self.retries = max(0, int(retries))
        self.cache_dir = Path(cache_dir) if cache_dir else None
        if self.cache_dir:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.respect_robots = bool(respect_robots)
        self.user_agent = user_agent
        self._robots_rules: Optional[_RobotsRules] = None
        import socket
        try:
            import urllib3.util.connection as urllib3_cn
            urllib3_cn.allowed_gai_family = lambda: socket.AF_INET
        except Exception:
            pass
        self.session = requests.Session()
        try:
            from requests.adapters import HTTPAdapter
            from urllib3.util.retry import Retry
            adapter = HTTPAdapter(max_retries=Retry(total=self.retries, backoff_factor=1, status_forcelist=[500, 502, 503, 504]))
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)
        except Exception:
            pass
        self.session.headers.update({
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "vi,en-US;q=0.7,en;q=0.5",
        })
        self._last_request = 0.0

    # -- robots.txt ----------------------------------------------------------
    def _robots(self) -> _RobotsRules:
        """Tải và cache robots.txt (dùng UA của client, không dùng read() mặc định)."""
        if self._robots_rules is not None:
            return self._robots_rules
        rules = _RobotsRules()
        try:
            resp = self.session.get(urljoin(self.base_url + "/", "robots.txt"),
                                    timeout=self.timeout)
            if resp.status_code >= 500:
                rules.disallow_all = True          # lỗi máy chủ → thận trọng
            elif resp.status_code == 200:
                rules = parse_robots(resp.text, self.user_agent)
            # 4xx (404…) → coi như không có robots → cho phép
        except requests.RequestException:
            rules.disallow_all = True              # không xác minh được → thận trọng
        self._robots_rules = rules
        return rules

    def robots_allows(self, url: str) -> bool:
        """URL có được robots.txt cho phép không (bỏ qua nếu tắt respect_robots)."""
        if not self.respect_robots:
            return True
        parts = urlsplit(url)
        target = parts.path + (("?" + parts.query) if parts.query else "")
        return self._robots().allows(target)

    def _build_url(self, path: str, params: Optional[Dict[str, Any]] = None) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            url = path
        else:
            url = urljoin(self.base_url + "/", path.lstrip("/"))
        if params:
            url += ("&" if "?" in url else "?") + urlencode(params, doseq=True)
        return url

    def _cache_file(self, url: str) -> Optional[Path]:
        if not self.cache_dir:
            return None
        return self.cache_dir / (hashlib.sha1(url.encode("utf-8")).hexdigest() + ".html")

    def _throttle(self) -> None:
        if self.delay <= 0:
            return
        wait = self.delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)

    def get_html(self, path: str, params: Optional[Dict[str, Any]] = None,
                 use_cache: bool = True) -> str:
        """GET một trang, trả về HTML (dùng cache đĩa nếu bật)."""
        url = self._build_url(path, params)
        if not self.robots_allows(url):
            raise RobotsDisallowed(
                f"robots.txt không cho phép thu thập: {url} "
                f"(bỏ qua bằng cách đặt respect_robots=False nếu bạn có phép)"
            )
        cache_file = self._cache_file(url)
        if use_cache and cache_file and cache_file.exists():
            return cache_file.read_text(encoding="utf-8")

        last_exc: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            self._throttle()
            try:
                resp = self.session.get(url, timeout=self.timeout)
                self._last_request = time.monotonic()
                if resp.status_code >= 500:
                    raise requests.HTTPError(f"HTTP {resp.status_code} cho {url}")
                resp.raise_for_status()
                if "charset" not in resp.headers.get("Content-Type", "").lower():
                    resp.encoding = resp.apparent_encoding or "utf-8"
                text = resp.text
                if cache_file:
                    cache_file.write_text(text, encoding="utf-8")
                return text
            except requests.RequestException as exc:
                last_exc = exc
                if attempt < self.retries:
                    time.sleep(min(30.0, 2.0 ** attempt))
        raise last_exc if last_exc else RuntimeError(f"Không tải được {url}")

    # -- API công khai -------------------------------------------------------
    def listing(self, category: str, page: int = 1, use_cache: bool = True) -> str:
        """HTML danh bạ của một danh mục, trang ``page`` (1-based)."""
        meta = CATEGORIES.get(category)
        if not meta:
            raise ValueError(f"Danh mục không hợp lệ: {category!r}")
        params = {"page": int(page)} if int(page) > 1 else None
        return self.get_html(meta["path"], params, use_cache=use_cache)

    def iter_listing(self, category: str, pages: Optional[int] = None,
                     start_page: int = 1) -> Iterator[TinnhiemRecord]:
        """Duyệt ``pages`` trang danh bạ (``None`` = đến hết)."""
        page = max(1, int(start_page))
        total = None
        while True:
            html_text = self.listing(category, page)
            if total is None:
                total = listing_total_pages(html_text, category) or page
            records = parse_listing(html_text, category)
            if not records:
                break
            for rec in records:
                yield rec
            if pages is not None and page >= start_page + pages - 1:
                break
            if page >= total:
                break
            page += 1

    def search(self, category: str, keyword: str,
               use_cache: bool = True) -> List[TinnhiemRecord]:
        """Tra cứu theo tên/miền qua ``/filterObj`` (trả về tối đa 1 trang)."""
        meta = CATEGORIES.get(category)
        if not meta:
            raise ValueError(f"Danh mục không hợp lệ: {category!r}")
        html_text = self.get_html("filterObj", {"type": meta["type"], "name_obj": keyword},
                                  use_cache=use_cache)
        return parse_listing(html_text, category)

    def detail(self, slug_or_url: str, use_cache: bool = True) -> Dict[str, Any]:
        """Chi tiết một mục danh bạ (nhận ``slug`` hoặc URL đầy đủ)."""
        if slug_or_url.startswith("http"):
            path = slug_or_url
        else:
            slug = slug_or_url.strip().strip("/")
            path = slug if slug.startswith(DETAIL_PREFIX) else f"{DETAIL_PREFIX}/{slug}"
        return parse_detail(self.get_html(path, use_cache=use_cache))

    def lookup_domain(self, domain: str,
                      categories: Tuple[str, ...] = ("web", "fake"),
                      use_cache: bool = True) -> Dict[str, Any]:
        """Tra một tên miền trong danh bạ tín nhiệm & danh sách lừa đảo."""
        host = normalize_domain(domain)
        result: Dict[str, Any] = {"query": host, "trusted": [], "scam": []}
        if not host:
            return result
        for cat in categories:
            if cat not in CATEGORIES:
                continue
            try:
                hits = self.search(cat, host, use_cache=use_cache)
            except requests.RequestException as exc:
                logger.warning("lookup_domain(%s) lỗi danh mục %s: %s", host, cat, exc)
                continue
            bucket = "scam" if CATEGORIES[cat]["kind"] == "scam" else "trusted"
            for rec in hits:
                if rec.domain == host:
                    result[bucket].append(rec.to_dict())
        result["status"] = (
            "scam" if result["scam"] else
            ("trusted" if result["trusted"] else "unknown")
        )
        return result

    def get_news_listing(self, feed_key: str = "noi_bat", page: Optional[int] = None,
                         use_cache: bool = True) -> List[Dict[str, Any]]:
        """Lấy danh sách tóm tắt tin tức / cảnh báo theo khóa feed."""
        cfg = NEWS_FEED_CONFIGS.get(feed_key)
        if not cfg:
            raise ValueError(f"Khóa feed không hợp lệ: {feed_key!r} (hỗ trợ: {list(NEWS_FEED_CONFIGS.keys())})")
        path = cfg["path"]
        params = {"page": page} if page and page > 1 else None
        html_text = self.get_html(path, params=params, use_cache=use_cache)
        return parse_news_listing(html_text, feed_key=feed_key, base_url=self.base_url)

    def get_news_detail(self, article_url: str, feed_key: str = "noi_bat",
                        fallback_meta: Optional[Dict[str, Any]] = None,
                        use_cache: bool = True) -> Optional[TinnhiemArticle]:
        """Tải trang chi tiết và phân tích thành :class:`TinnhiemArticle`."""
        html_text = self.get_html(article_url, use_cache=use_cache)
        return parse_news_detail(html_text, article_url=article_url, feed_key=feed_key,
                                 base_url=self.base_url, fallback_meta=fallback_meta)

    def iter_news_articles(self, feed_keys: Sequence[str] = ("canh_bao_lua_dao", "noi_bat"),
                           max_per_feed: int = 15, use_cache: bool = True) -> Iterator[TinnhiemArticle]:
        """Duyệt bài viết đầy đủ (bao gồm nội dung) từ các feed chỉ định."""
        for key in feed_keys:
            items = self.get_news_listing(feed_key=key, use_cache=use_cache)
            for item in items[:max_per_feed]:
                try:
                    detail = self.get_news_detail(item["url"], feed_key=key, fallback_meta=item, use_cache=use_cache)
                    if detail:
                        yield detail
                except Exception as exc:
                    logger.warning("Lỗi tải chi tiết bài viết %s: %s", item.get("url"), exc)

    def iter_vnexpress_listing(self, feed_key: str = "lua_dao_qua_mang",
                               max_pages: Optional[int] = None,
                               use_cache: bool = True) -> Iterator[Dict[str, Any]]:
        """Duyệt toàn bộ bài trong tag VnExpress (hỗ trợ phân trang ``-p2``, ``-p3``…)."""
        page = 1
        total = None
        seen: set = set()
        while True:
            path = vnexpress_page_path(feed_key, page)
            html_text = self.get_html(path, use_cache=use_cache)
            if total is None:
                total = vnexpress_total_pages(html_text, feed_key)
            for item in parse_vnexpress_listing(html_text, feed_key=feed_key, base_url=self.base_url):
                if item["url"] in seen:
                    continue
                seen.add(item["url"])
                yield item
            if max_pages and page >= max_pages:
                break
            if page >= total:
                break
            page += 1


# ---------------------------------------------------------------------------
# Dataset cục bộ (JSONL) — tra cứu offline, không cần mạng
# ---------------------------------------------------------------------------
_INDEX_CACHE: Dict[str, Dict[str, TinnhiemRecord]] = {}


def dataset_path(category: str, base_dir: Optional[Path] = None) -> Path:
    base = Path(base_dir) if base_dir else DATA_DIR
    return base / f"{category}.jsonl"


def append_records(category: str, records: List[TinnhiemRecord],
                   base_dir: Optional[Path] = None) -> int:
    """Ghi nối các bản ghi vào JSONL (không lọc trùng). Trả về số dòng ghi."""
    if not records:
        return 0
    path = dataset_path(category, base_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with path.open("a", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec.to_dict(), ensure_ascii=False) + "\n")
            n += 1
    _INDEX_CACHE.pop(category, None)
    return n


def iter_records(category: str, base_dir: Optional[Path] = None) -> Iterator[Dict[str, Any]]:
    """Sinh (stream) từng bản ghi JSONL của một danh mục (bỏ dòng lỗi)."""
    path = dataset_path(category, base_dir)
    if not path.exists():
        return
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def load_records(category: str, base_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Đọc toàn bộ JSONL của một danh mục thành list (bỏ dòng lỗi)."""
    return list(iter_records(category, base_dir))


def build_index(category: str, base_dir: Optional[Path] = None,
                by: str = "slug") -> Dict[str, TinnhiemRecord]:
    """Dựng chỉ mục bản ghi theo ``slug`` (mặc định) hoặc ``domain``."""
    key_attr = "domain" if by == "domain" else "slug"
    index: Dict[str, TinnhiemRecord] = {}
    for row in load_records(category, base_dir):
        key = row.get(key_attr)
        if not key:
            continue
        try:
            index[key] = TinnhiemRecord(**{k: row.get(k) for k in TinnhiemRecord.__dataclass_fields__})
        except TypeError:
            continue
    return index


def domain_index(categories: Tuple[str, ...] = ("web", "fake"),
                 base_dir: Optional[Path] = None, refresh: bool = False) -> Dict[str, TinnhiemRecord]:
    """Chỉ mục ``domain → TinnhiemRecord`` gộp nhiều danh mục (có cache RAM)."""
    cache_key = "domains:" + ",".join(categories) + f"@{base_dir or DATA_DIR}"
    if not refresh and cache_key in _INDEX_CACHE:
        return _INDEX_CACHE[cache_key]
    merged: Dict[str, TinnhiemRecord] = {}
    for cat in categories:
        for key, rec in build_index(cat, base_dir, by="domain").items():
            merged.setdefault(key, rec)
    _INDEX_CACHE[cache_key] = merged
    return merged


# ---------------------------------------------------------------------------
# Chỉ mục SQLite — dò JSONL nhanh O(log n) thay vì quét toàn bộ file
# ---------------------------------------------------------------------------
# JSONL là nguồn chân lý; file ``<category>.sqlite`` chỉ là chỉ mục dẫn xuất,
# tự dựng/tự làm mới khi JSONL đổi (theo mtime+size). Nhờ vậy tra cứu 1 tên miền
# không phải đọc/parse hàng chục nghìn dòng.
_REC_FIELDS: Tuple[str, ...] = tuple(TinnhiemRecord.__dataclass_fields__)
_INDEX_META = "source"          # khoá lưu (mtime_ns, size) của JSONL nguồn
_BUILD_LOCK = threading.Lock()
_INDEX_STATE: Dict[str, Tuple[int, int]] = {}   # "cat@db" -> (mtime_ns, size)

_INSERT_SQL = (
    "INSERT OR REPLACE INTO records "
    "(key, category, kind, name, url, slug, ref_id, domain, date, owner, impersonated, badge, payload) "
    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


def _resolve_dir(base_dir: Optional[Path]) -> Path:
    return Path(base_dir) if base_dir else DATA_DIR


def index_path(category: str, base_dir: Optional[Path] = None) -> Path:
    """Đường dẫn file chỉ mục SQLite của một danh mục."""
    return _resolve_dir(base_dir) / f"{category}.sqlite"


def _source_stat(path: Path) -> Optional[Tuple[int, int]]:
    try:
        st = path.stat()
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


# Kết nối dùng lại theo luồng (tránh mở/đóng mỗi lần tra cứu — giảm từ ~0.5ms/call)
_POOL = threading.local()
# Hạn chế dựng lại chỉ mục quá dày khi JSONL vẫn đang được ghi thêm (giây)
_REFRESH_MIN_SECONDS = float(os.getenv("TINNHIEM_INDEX_REFRESH_SECONDS", "60"))
_LAST_BUILD: Dict[str, float] = {}


def _pooled_conn(db_path: Path) -> sqlite3.Connection:
    key = os.fspath(db_path)
    pool = getattr(_POOL, "conns", None)
    if pool is None:
        pool = _POOL.conns = {}
    conn = pool.get(key)
    if conn is None:
        conn = _connect(db_path)
        pool[key] = conn
    return conn


def _close_pooled(db_path: Path) -> None:
    pool = getattr(_POOL, "conns", None)
    if not pool:
        return
    conn = pool.pop(os.fspath(db_path), None)
    if conn is not None:
        try:
            conn.close()
        except sqlite3.Error:
            pass


def ensure_index(category: str, base_dir: Optional[Path] = None,
                 force: bool = False) -> Optional[Path]:
    """Bảo đảm chỉ mục SQLite khớp JSONL nguồn; trả về đường dẫn (None nếu chưa có dữ liệu)."""
    src = dataset_path(category, base_dir)
    if not src.exists():
        return None
    db = index_path(category, base_dir)
    stat = _source_stat(src)
    state_key = f"{category}@{db}"
    if not force and stat and _INDEX_STATE.get(state_key) == stat and db.exists():
        return db

    # Kiểm tra meta đã lưu (dùng chung giữa các tiến trình)
    if not force and stat and db.exists():
        try:
            row = _pooled_conn(db).execute(
                "SELECT v FROM meta WHERE k=?", (_INDEX_META,)
            ).fetchone()
            if row and tuple(json.loads(row[0])) == stat:
                _INDEX_STATE[state_key] = stat
                return db
        except (sqlite3.Error, ValueError):
            pass
        # JSONL vừa đổi do đang ghi thêm → dùng chỉ mục hiện có thay vì dựng lại liên tục
        if time.monotonic() - _LAST_BUILD.get(state_key, 0.0) < _REFRESH_MIN_SECONDS:
            return db

    with _BUILD_LOCK:
        # Kiểm tra lại trong lock (tránh 2 luồng cùng dựng)
        stat = _source_stat(src)
        if not force and stat and _INDEX_STATE.get(state_key) == stat and db.exists():
            return db
        tmp = db.with_name(db.name + ".tmp")
        if tmp.exists():
            tmp.unlink()
        conn = _connect(tmp)
        try:
            conn.execute("CREATE TABLE meta (k TEXT PRIMARY KEY, v TEXT)")
            conn.execute(
                "CREATE TABLE records ("
                "key TEXT PRIMARY KEY, category TEXT, kind TEXT, name TEXT, url TEXT, "
                "slug TEXT, ref_id TEXT, domain TEXT, date TEXT, owner TEXT, "
                "impersonated TEXT, badge TEXT, payload TEXT)"
            )
            conn.execute("CREATE INDEX idx_domain ON records(domain)")
            conn.execute("CREATE INDEX idx_name ON records(name)")
            batch: List[Tuple[Any, ...]] = []
            n = 0
            for row in iter_records(category, base_dir):
                key = row.get("domain") or row.get("slug")
                if not key:
                    continue
                batch.append((
                    key, row.get("category"), row.get("kind"), row.get("name"),
                    row.get("url"), row.get("slug"), row.get("ref_id"), row.get("domain"),
                    row.get("date"), row.get("owner"), row.get("impersonated"),
                    row.get("badge"), json.dumps(row, ensure_ascii=False),
                ))
                n += 1
                if len(batch) >= 5000:
                    conn.executemany(_INSERT_SQL, batch)
                    batch.clear()
            if batch:
                conn.executemany(_INSERT_SQL, batch)
            conn.execute("INSERT INTO meta(k, v) VALUES (?, ?)",
                         (_INDEX_META, json.dumps(list(stat or (0, 0)))))
            conn.execute("INSERT INTO meta(k, v) VALUES ('count', ?)", (str(n),))
            conn.execute("INSERT INTO meta(k, v) VALUES ('built_at', ?)",
                         (datetime.utcnow().isoformat(),))
            conn.commit()
        finally:
            conn.close()
        _close_pooled(db)
        os.replace(tmp, db)
        if stat:
            _INDEX_STATE[state_key] = stat
        _LAST_BUILD[state_key] = time.monotonic()
    return db


def reindex(category: str = "all", base_dir: Optional[Path] = None) -> Dict[str, int]:
    """Dựng lại chỉ mục (``category='all'`` để làm hết) và trả ``{category: số dòng}``."""
    cats = list(CATEGORIES) if category == "all" else [category]
    out: Dict[str, int] = {}
    for cat in cats:
        db = ensure_index(cat, base_dir, force=True)
        if db:
            row = _pooled_conn(db).execute("SELECT v FROM meta WHERE k='count'").fetchone()
            out[cat] = int(row[0]) if row else 0
    return out


def _fetch_one(db: Path, host: str) -> Optional[Dict[str, Any]]:
    """Tra 1 bản ghi theo ``domain`` (ưu tiên) rồi ``key`` trong một chỉ mục."""
    conn = _pooled_conn(db)
    row = conn.execute(
        "SELECT payload FROM records WHERE domain=? LIMIT 1", (host,)
    ).fetchone()
    if not row:
        row = conn.execute(
            "SELECT payload FROM records WHERE key=? LIMIT 1", (host,)
        ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (TypeError, ValueError):
        return None


def iter_keys(category: str, base_dir: Optional[Path] = None) -> Iterator[str]:
    """Sinh nhanh khoá duy nhất (``domain or slug``) — dùng cho resume/sync."""
    db = ensure_index(category, base_dir)
    if db:
        for (k,) in _pooled_conn(db).execute("SELECT key FROM records"):
            if k:
                yield k
        return
    for row in iter_records(category, base_dir):
        key = row.get("domain") or row.get("slug")
        if key:
            yield key


def iter_domain_records(categories: Tuple[str, ...] = ("web", "fake"),
                        base_dir: Optional[Path] = None) -> Iterator[Dict[str, Any]]:
    """Sinh gọn ``{domain, kind, name, owner, impersonated, category}`` từ chỉ mục.

    Nhanh và ít bộ nhớ hơn ``domain_index`` (không dựng dataclass, không parse JSON
    toàn bộ) — dùng để nạp danh sách tên miền tin cậy / lừa đảo.
    """
    for cat in categories:
        if not dataset_path(cat, base_dir).exists():
            continue
        db = ensure_index(cat, base_dir)
        if not db:
            continue
        for domain, kind, name, owner, impersonated in _pooled_conn(db).execute(
            "SELECT domain, kind, name, owner, impersonated FROM records "
            "WHERE domain IS NOT NULL AND domain <> ''"
        ):
            yield {
                "domain": domain,
                "kind": kind,
                "name": name,
                "owner": owner,
                "impersonated": impersonated,
                "category": cat,
            }


def _domain_candidates(host: str) -> Iterator[str]:
    """Sinh các tên miền ứng viên: chính nó → bỏ dần nhãn trái (dừng khi còn 1 nhãn).

    Ví dụ ``mail.capdo.bocongan.gov.vn`` → chính nó, ``capdo.bocongan.gov.vn``,
    ``bocongan.gov.vn``, ``gov.vn``.
    """
    parts = (host or "").split(".")
    for i in range(0, max(0, len(parts) - 1)):
        yield ".".join(parts[i:])


def lookup_local_domain(domain: str, base_dir: Optional[Path] = None,
                        categories: Tuple[str, ...] = ("web", "fake")) -> Dict[str, Any]:
    """Tra một tên miền trong dataset cục bộ (rất nhanh nhờ chỉ mục SQLite).

    Khớp chính xác trước; nếu không có, thử lần lượt tên miền cấp trên (subdomain →
    domain cha) nên ``mail.shopee.vn`` vẫn nhận ra ``shopee.vn`` là tín nhiệm.
    """
    host = normalize_domain(domain)
    if not host:
        return {"query": host, "status": "unknown", "record": None}
    dbs = []
    for cat in categories:
        if not dataset_path(cat, base_dir).exists():
            continue
        db = ensure_index(cat, base_dir)
        if db:
            dbs.append((cat, db))
    for cand in _domain_candidates(host):
        for cat, db in dbs:
            if cat == "fake" and is_major_platform_domain(cand):
                continue
            rec = _fetch_one(db, cand)
            if rec:
                out = {
                    "query": host,
                    "status": rec.get("kind") or "unknown",
                    "record": rec,
                    "category": cat,
                }
                if cand != host:
                    out["matched"] = cand
                    out["exact"] = False
                else:
                    out["exact"] = True
                return out
    return {"query": host, "status": "unknown", "record": None}


def search_local(query: str,
                 categories: Tuple[str, ...] = ("web", "org", "sys", "app", "iot", "fake"),
                 limit: int = 50,
                 base_dir: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Tìm cục bộ theo từ khoá (khớp một phần trên domain/tên/chủ sở/mạo danh)."""
    q = (query or "").strip().lower()
    if not q:
        return []
    like = f"%{q}%"
    out: List[Dict[str, Any]] = []
    for cat in categories:
        if not dataset_path(cat, base_dir).exists():
            continue
        db = ensure_index(cat, base_dir)
        if not db:
            continue
        rows = _pooled_conn(db).execute(
            "SELECT payload FROM records WHERE lower(domain) LIKE ? OR lower(name) LIKE ? "
            "OR lower(owner) LIKE ? OR lower(impersonated) LIKE ? LIMIT ?",
            (like, like, like, like, limit - len(out)),
        ).fetchall()
        for (payload,) in rows:
            try:
                out.append(json.loads(payload))
            except (TypeError, ValueError):
                continue
            if len(out) >= limit:
                break
        if len(out) >= limit:
            break
    return out


def available_datasets(base_dir: Optional[Path] = None) -> Dict[str, int]:
    """Số bản ghi hiện có cho mỗi danh mục (ưu tiên đọc từ chỉ mục)."""
    out: Dict[str, int] = {}
    for cat in CATEGORIES:
        src = dataset_path(cat, base_dir)
        if not src.exists():
            continue
        db = index_path(cat, base_dir)
        if db.exists():
            try:
                row = _pooled_conn(db).execute("SELECT v FROM meta WHERE k='count'").fetchone()
                if row:
                    out[cat] = int(row[0])
                    continue
            except (sqlite3.Error, ValueError):
                pass
        out[cat] = sum(1 for _ in src.open(encoding="utf-8"))
    return out


def index_status(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Trạng thái chỉ mục: số bản ghi, thời điểm dựng, JSONL đã đổi chưa."""
    out: Dict[str, Any] = {}
    for cat in CATEGORIES:
        src = dataset_path(cat, base_dir)
        db = index_path(cat, base_dir)
        info: Dict[str, Any] = {"dataset": src.exists(), "indexed": db.exists()}
        if db.exists():
            try:
                meta = dict(_pooled_conn(db).execute("SELECT k, v FROM meta").fetchall())
                info["count"] = int(meta.get("count", 0))
                info["built_at"] = meta.get("built_at")
                stored = meta.get(_INDEX_META)
                info["stale"] = bool(stored) and tuple(json.loads(stored)) != _source_stat(src)
            except (sqlite3.Error, ValueError):
                info["error"] = True
        out[cat] = info
    return out

