"""
ShieldCall VN — Lọc trùng tin tức khi đồng bộ.

Kết hợp:
- **Nhanh/tất định**: so khớp tiêu đề (chuẩn hoá) + độ tương đồng (difflib) + Jaccard tóm tắt,
  và trùng ``source_url``.
- **AI (LLM nhỏ)**: chỉ gọi cho các ca *nghi ngờ* (độ tương đồng trung bình) để quyết định
  "cùng một tin" hay không — tiết kiệm chi phí, tránh bỏ sót.

Dùng trong feed (``find_duplicate_article``) và dọn bài cũ (``dedup_news_articles``).
"""

from __future__ import annotations

import difflib
import logging
import re
import time
import unicodedata
from typing import Any, Dict, Optional

from django.conf import settings

from api.core.models import Article

logger = logging.getLogger(__name__)

# Chỉ so với các bài tin tức (không so với bài nội bộ/hướng dẫn)
_NEWS_SOURCE_TYPES = ("tinnhiemmang", "press")
_RECENT_WINDOW = 500          # số bài gần nhất để so


def _norm(text: str) -> str:
    t = unicodedata.normalize("NFC", str(text or "")).lower()
    t = re.sub(r"[^\w\s]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def _tokens(text: str) -> set:
    return {w for w in _norm(text).split() if len(w) > 2}


def _sim(a: str, b: str) -> float:
    a, b = _norm(a), _norm(b)
    if not a or not b:
        return 0.0
    return difflib.SequenceMatcher(None, a, b).ratio()


def _jaccard(a: str, b: str) -> float:
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


def _content_sim(text_a: str, text_b: str) -> float:
    """Độ giống nội dung (Jaccard trên token) — tránh nhầm bản tin cùng tên khác kỳ."""
    ta, tb = _tokens((text_a or "")[:4000]), _tokens((text_b or "")[:4000])
    if not ta or not tb:
        return 0.0
    return len(ta & tb) / len(ta | tb)


# Ngưỡng quyết định trùng
_TITLE_DUP_THRESHOLD = 0.90   # tiêu đề gần như giống hệt
_CONTENT_DUP_THRESHOLD = 0.55  # + nội dung phải giống đáng kể
_CONTENT_ONLY_THRESHOLD = 0.90  # hoặc nội dung gần như y hệt (khác tiêu đề)
_TITLE_LLM_LOW = 0.62         # ngưỡng dưới để nhờ LLM xác nhận


def llm_same_story(title_a: str, title_b: str,
                   summary_a: str = "", summary_b: str = "",
                   model: Optional[str] = None, timeout: int = 60) -> bool:
    """Nhờ LLM nhỏ xác nhận 2 tiêu đề có nói về cùng một tin không."""
    from api.maintenance.article_format import _ollama_chat
    model = model or getattr(settings, "SMALL_MODEL", "gemma4:latest")
    system = (
        "Bạn là trợ lý so khớp tin tức tiếng Việt. Trả lời DUY NHẤT một từ: "
        "'SAME' nếu hai tiêu đề nói về CÙNG một sự việc/tin, ngược lại 'DIFF'."
    )
    user = (
        f"Tiêu đề 1: {title_a}\nTóm tắt 1: {summary_a[:300]}\n"
        f"Tiêu đề 2: {title_b}\nTóm tắt 2: {summary_b[:300]}\n"
        "Trả lời SAME hoặc DIFF."
    )
    out = _ollama_chat([{"role": "system", "content": system},
                        {"role": "user", "content": user}], model=model, timeout=timeout)
    return bool(out) and out.strip().upper().startswith("SAME")


def find_duplicate_article(
    title: str,
    summary: str = "",
    url: str = "",
    content: str = "",
    *,
    exclude_id: Optional[int] = None,
    recent: int = _RECENT_WINDOW,
    use_llm: bool = False,
    model: Optional[str] = None,
) -> Optional[Article]:
    """Tìm bài tin tức đã tồn tại trùng với (title, summary, url, content).

    Trùng khi: cùng ``source_url``; hoặc **tiêu đề gần giống VÀ nội dung giống**; hoặc nội
    dung giống hệt dù tiêu đề khác. (Tránh nhầm các bản tin cùng tên nhưng khác kỳ.)
    """
    if not title:
        return None
    if url:
        same_url = Article.objects.filter(source_url=url)
        if exclude_id:
            same_url = same_url.exclude(id=exclude_id)
        hit = same_url.first()
        if hit:
            return hit

    qs = Article.objects.filter(source_type__in=_NEWS_SOURCE_TYPES).order_by("-created_at")
    if exclude_id:
        qs = qs.exclude(id=exclude_id)
    cands = list(qs[:recent])

    probe_content = (summary or "") + " " + (content or "")
    best_article, best_title, best_summary, best_score = None, "", "", 0.0
    for art in cands:
        ts = max(_sim(title, art.title), _jaccard(title, art.title))
        cs = _content_sim(probe_content, (art.summary or "") + " " + (art.content or ""))
        if ts >= _TITLE_DUP_THRESHOLD and cs >= _CONTENT_DUP_THRESHOLD:
            logger.info("[NEWS-DEDUP] Trùng (title=%.2f, content=%.2f) với #%s: %s",
                        ts, cs, art.id, art.title[:60])
            return art
        if cs >= _CONTENT_ONLY_THRESHOLD:
            logger.info("[NEWS-DEDUP] Trùng nội dung (%.2f) với #%s: %s", cs, art.id, art.title[:60])
            return art
        if ts > best_score:
            best_article, best_title, best_summary, best_score = art, art.title, art.summary or "", ts

    if use_llm and best_article and best_score >= _TITLE_LLM_LOW:
        try:
            if llm_same_story(title, best_title, summary, best_summary, model=model):
                logger.info("[NEWS-DEDUP] LLM xác nhận trùng (%.2f) với #%s", best_score, best_article.id)
                return best_article
        except Exception as exc:  # noqa: BLE001
            logger.warning("[NEWS-DEDUP] LLM lỗi: %s", exc)
    return None


def dedup_news_articles(
    use_llm: bool = False,
    threshold: float = _TITLE_DUP_THRESHOLD,
    apply: bool = False,
    model: Optional[str] = None,
) -> Dict[str, Any]:
    """Dọn bài tin tức trùng đã có. ``apply=True`` sẽ XOÁ bài trùng (giữ bài cũ hơn)."""
    start = time.time()
    stats: Dict[str, Any] = {"checked": 0, "duplicates": 0, "deleted": 0, "errors": 0,
                             "duration_seconds": 0.0}
    arts = list(Article.objects.filter(source_type__in=_NEWS_SOURCE_TYPES).order_by("created_at"))
    kept: list = []
    for art in arts:
        stats["checked"] += 1
        try:
            dup = None
            probe = (art.summary or "") + " " + (art.content or "")
            for k in kept:
                ts = max(_sim(art.title, k.title), _jaccard(art.title, k.title))
                cs = _content_sim(probe, (k.summary or "") + " " + (k.content or ""))
                if (ts >= threshold and cs >= _CONTENT_DUP_THRESHOLD) or cs >= _CONTENT_ONLY_THRESHOLD:
                    dup = k
                    break
                if use_llm and ts >= _TITLE_LLM_LOW and cs >= 0.3 and llm_same_story(
                        art.title, k.title, art.summary or "", k.summary or "", model=model):
                    dup = k
                    break
            if dup:
                stats["duplicates"] += 1
                if apply:
                    logger.info("[NEWS-DEDUP] Xoá #%s (trùng #%s)", art.id, dup.id)
                    art.delete()
                    stats["deleted"] += 1
                continue
            kept.append(art)
        except Exception as exc:  # noqa: BLE001
            stats["errors"] += 1
            logger.error("[NEWS-DEDUP] Lỗi bài #%s: %s", art.id, exc, exc_info=True)
    stats["duration_seconds"] = round(time.time() - start, 2)
    logger.info("[NEWS-DEDUP] Xong: %s", stats)
    return stats
