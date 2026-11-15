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
    """Gọi LLM qua ollama_client dùng chung (có retry + fallback provider)."""
    from api.utils.ollama_client import generate_response

    sys_parts = [m.get("content", "") for m in messages if m.get("role") == "system" and m.get("content")]
    usr_parts = [m.get("content", "") for m in messages if m.get("role") != "system" and m.get("content")]
    if not usr_parts:
        return None
    try:
        out = generate_response(
            prompt="\n\n".join(usr_parts),
            system_prompt="\n\n".join(sys_parts) if sys_parts else None,
            model=model,
            num_ctx=32768,
            max_tokens=16384,
            tools=[],
            skip_filter=True,
            allow_pii=True,
            think=False,
        )
        return out.strip() if out else None
    except Exception as exc:  # noqa: BLE001
        logger.warning("[ARTICLE-FORMAT] LLM lỗi (%s): %s", model, exc)
        return None


def _img_count(text: str) -> int:
    return len(re.findall(r"!\[[^\]]*\]\([^)]+\)", text or ""))


def _plain_len(text: str) -> int:
    return len(re.sub(r"[#*\->`\[\]\(\)!]", "", re.sub(r"!\[[^\]]*\]\([^)]+\)", "", text or "")).strip())


def _split_markdown_chunks(md: str, max_chars: int = 10000) -> list[str]:
    """Chia bài Markdown dài theo ranh giới đoạn/tiêu đề để không cắt mất phần cuối bài."""
    if len(md) <= max_chars:
        return [md]
    paragraphs = re.split(r"(\n{2,})", md)
    chunks: list[str] = []
    buf = ""
    for part in paragraphs:
        if buf and len(buf) + len(part) > max_chars:
            chunks.append(buf)
            buf = part.lstrip("\n")
        else:
            buf += part
    if buf:
        chunks.append(buf)
    return chunks or [md]


def _polish_chunk(chunk: str, model: str, timeout: int) -> str:
    """Chuẩn hoá một đoạn Markdown; trả lại ``chunk`` gốc nếu LLM làm hỏng hoặc mất ảnh."""
    out = _ollama_chat(
        [{"role": "system", "content": _STRICT_SYSTEM},
         {"role": "user", "content": f"Định dạng lại nội dung sau thành Markdown:\n\n{chunk}"}],
        model=model, timeout=timeout,
    )
    if not out:
        return chunk
    out = re.sub(r"^```(?:markdown)?\s*|\s*```$", "", out.strip(), flags=re.I).strip()
    if _img_count(out) < _img_count(chunk):
        logger.info("[ARTICLE-FORMAT] Giữ đoạn gốc: LLM làm mất ảnh (%d<%d)", _img_count(out), _img_count(chunk))
        return chunk
    orig, new = _plain_len(chunk), _plain_len(out)
    if orig and not (0.7 * orig <= new <= 1.3 * orig):
        logger.info("[ARTICLE-FORMAT] Giữ đoạn gốc: độ dài lệch (%d→%d)", orig, new)
        return chunk
    return out


def polish_markdown_with_llm(markdown: str, model: Optional[str] = None, timeout: int = 180) -> Optional[str]:
    """Nhờ LLM nhỏ làm sạch Markdown theo từng đoạn. Trả ``None`` nếu không cải thiện được hoặc mất nội dung."""
    md = (markdown or "").strip()
    if len(md) < 40:
        return None
    model = model or getattr(settings, "SMALL_MODEL", "gemma4:latest")
    chunks = _split_markdown_chunks(md, max_chars=10000)
    polished_chunks = [_polish_chunk(chunk, model=model, timeout=timeout) for chunk in chunks]
    out = "\n\n".join(c.strip() for c in polished_chunks if c.strip()).strip()
    if not out or out == md:
        return None
    if _img_count(out) < _img_count(md):
        logger.info("[ARTICLE-FORMAT] Bỏ kết quả LLM: mất ảnh toàn bài (%d<%d)", _img_count(out), _img_count(md))
        return None
    orig, new = _plain_len(md), _plain_len(out)
    if orig and not (0.7 * orig <= new <= 1.3 * orig):
        logger.info("[ARTICLE-FORMAT] Bỏ kết quả LLM: độ dài toàn bài lệch (%d→%d)", orig, new)
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
    article_ids: Optional[Sequence[int]] = None,
) -> Dict[str, Any]:
    """Định dạng lại nội dung (Markdown) cho các bài tin tức; không tạo/xoá bài."""
    start = time.time()
    stats: Dict[str, Any] = {"total": 0, "updated": 0, "llm_used": 0, "errors": 0,
                             "skipped": 0, "duration_seconds": 0.0}
    if article_ids is not None:
        id_list = [int(i) for i in article_ids if i]
        if not id_list:
            return stats
        qs = Article.objects.filter(id__in=id_list, source_type__in=list(source_types)).order_by("-updated_at")
    else:
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
