"""
ShieldCall VN — Định dạng lại nội dung tin tức thành **Markdown sạch**.

- ``html_to_markdown`` (trong ``api.utils.tinnhiemmang``) chuyển HTML đã trích sang Markdown.
- ``polish_markdown_with_llm`` dùng **LLM nhỏ** (SMALL_MODEL) để làm sạch/định dạng lại, với
  *prompt nghiêm ngặt* và **kiểm tra an toàn**: nếu LLM làm mất ảnh hoặc đổi độ dài quá nhiều
  thì **bỏ kết quả LLM**, giữ bản Markdown gốc (tránh bịa/đổi nội dung báo).
- ``reformat_news_markdown`` chạy hàng loạt cho các bài ``tinnhiemmang`` / ``press``.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, Optional, Sequence

import requests
from django.conf import settings

from api.core.models import Article, ArticleSourceType
from api.utils.tinnhiemmang import html_to_markdown

logger = logging.getLogger(__name__)

_STRICT_SYSTEM = (
    "Bạn là biên tập viên báo chí tiếng Việt. Nhiệm vụ: ĐỊNH DẠNG LẠI nội dung bài viết sang "
    "Markdown sạch, dễ đọc.\n"
    "QUY TẮC BẮT BUỘC:\n"
    "1. GIỮ NGUYÊN mọi thông tin, số liệu, tên riêng, câu chữ. KHÔNG thêm, bớt, tóm tắt hay suy diễn.\n"
    "2. GIỮ NGUYÊN tất cả các ảnh dưới dạng ![chú thích](URL) — đúng vị trí và đủ số lượng.\n"
    "3. Giữ tiêu đề phụ dạng ## / ###; danh sách dạng '- '; in đậm **...**; trích dẫn dạng '> '.\n"
    "4. KHÔNG thêm lời dẫn, tiêu đề mới, kết luận, hay ghi chú của bạn.\n"
    "5. Chỉ trả về Markdown thuần, không bọc trong ```."
)


def _ollama_chat(messages: Sequence[Dict[str, str]], model: str, timeout: int = 180) -> Optional[str]:
    base = getattr(settings, "OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    key = getattr(settings, "OLLAMA_API_KEY", None)
    headers = {"Content-Type": "application/json"}
    if key:
        headers["Authorization"] = f"Bearer {key}"
    try:
        resp = requests.post(
            f"{base}/api/chat",
            headers=headers,
            json={
                "model": model,
                "messages": list(messages),
                "stream": False,
                "options": {"temperature": 0.2, "num_ctx": 8192},
            },
            timeout=timeout,
        )
        resp.raise_for_status()
        return (resp.json().get("message", {}) or {}).get("content", "").strip()
    except Exception as exc:  # noqa: BLE001
        logger.warning("[ARTICLE-FORMAT] LLM lỗi (%s): %s", model, exc)
        return None


def _img_count(text: str) -> int:
    return len(re.findall(r"!\[[^\]]*\]\([^)]+\)", text or ""))


def _plain_len(text: str) -> int:
    return len(re.sub(r"[#*\->`\[\]\(\)!]", "", re.sub(r"!\[[^\]]*\]\([^)]+\)", "", text or "")).strip())


def polish_markdown_with_llm(markdown: str, model: Optional[str] = None, timeout: int = 180) -> Optional[str]:
    """Nhờ LLM nhỏ làm sạch Markdown. Trả ``None`` nếu LLM lỗi hoặc làm hỏng nội dung."""
    md = (markdown or "").strip()
    if len(md) < 40:
        return None
    model = model or getattr(settings, "SMALL_MODEL", "gemma4:latest")
    # Giới hạn độ dài để tránh quá tải ngữ cảnh
    src = md[:12000]
    out = _ollama_chat(
        [{"role": "system", "content": _STRICT_SYSTEM},
         {"role": "user", "content": f"Định dạng lại nội dung sau thành Markdown:\n\n{src}"}],
        model=model, timeout=timeout,
    )
    if not out:
        return None
    out = re.sub(r"^```(?:markdown)?\s*|\s*```$", "", out.strip(), flags=re.I).strip()
    # Kiểm tra an toàn: không mất ảnh, độ dài không lệch quá nhiều
    if _img_count(out) < _img_count(src):
        logger.info("[ARTICLE-FORMAT] Bỏ kết quả LLM: mất ảnh (%d<%d)", _img_count(out), _img_count(src))
        return None
    orig, new = _plain_len(src), _plain_len(out)
    if orig and not (0.7 * orig <= new <= 1.3 * orig):
        logger.info("[ARTICLE-FORMAT] Bỏ kết quả LLM: độ dài lệch (%d→%d)", orig, new)
        return None
    return out


def format_article_markdown(article: Article, use_llm: bool = False, model: Optional[str] = None) -> str:
    """Trả về nội dung Markdown của bài (tuỳ chọn qua LLM)."""
    raw = article.content or ""
    md = raw if _looks_like_markdown(raw) else html_to_markdown(raw)
    if use_llm and md:
        polished = polish_markdown_with_llm(md, model=model)
        if polished:
            return polished
    return md


def _looks_like_markdown(text: str) -> bool:
    t = (text or "").lstrip()
    if t.startswith("<"):
        return False
    return bool(re.search(r"^#{1,3}\s|\n- |\n\d+\. |!\[[^\]]*\]\(", text or "", re.M))


def reformat_news_markdown(
    use_llm: bool = False,
    model: Optional[str] = None,
    limit: Optional[int] = None,
    source_types: Sequence[str] = (ArticleSourceType.TINNHIEMMANG, ArticleSourceType.PRESS),
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Định dạng lại nội dung (Markdown) cho các bài tin tức; không tạo/xoá bài."""
    start = time.time()
    stats: Dict[str, Any] = {"total": 0, "updated": 0, "llm_used": 0, "errors": 0,
                             "skipped": 0, "duration_seconds": 0.0}
    qs = Article.objects.filter(source_type__in=list(source_types)).order_by("-updated_at")
    articles = list(qs[:limit] if limit else qs)
    stats["total"] = len(articles)

    for art in articles:
        try:
            md = format_article_markdown(art, use_llm=use_llm, model=model)
            if not md or md.strip() == (art.content or "").strip():
                stats["skipped"] += 1
                continue
            if use_llm:
                stats["llm_used"] += 1
            if not dry_run:
                art.content = md
                art.save(update_fields=["content", "updated_at"])
            stats["updated"] += 1
        except Exception as exc:  # noqa: BLE001
            stats["errors"] += 1
            logger.error("[ARTICLE-FORMAT] Lỗi bài #%s: %s", art.id, exc, exc_info=True)

    stats["duration_seconds"] = round(time.time() - start, 2)
    logger.info("[ARTICLE-FORMAT] Xong: %s", stats)
    return stats
