"""
ShieldCall VN — Tổng hợp tin tức lừa đảo từ **VnExpress** (tag "Lừa đảo qua mạng").

Nguồn: https://vnexpress.net/tag/lua-dao-qua-mang-27298 (báo chí chính thống).
Lưu vào model ``Article`` với ``source_type='press'``; nội dung giữ định dạng HTML
(đoạn văn, ảnh minh hoạ/figure + chú thích).

Hàm chính:
- ``sync_vnexpress_articles``: lấy danh sách tag + chi tiết, chống trùng theo source_url/slug.
- ``refresh_existing_vnexpress_articles``: ghi đè lại toàn bộ bài VnExpress đã có (không tạo mới).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional, Sequence

from api.core.models import Article, ArticleCategory, ArticleSourceType
from api.utils.tinnhiemmang import (
    VNEXPRESS_BASE_URL,
    VNEXPRESS_FEED_CONFIGS,
    TinnhiemArticle,
    TinnhiemClient,
    html_to_markdown,
    parse_vnexpress_detail,
)

# Dùng lại helper tạo slug/tải ảnh của feed tinnhiemmang để tránh trùng lặp logic.
from api.maintenance.tinnhiemmang_feed import (
    _download_and_attach_cover,
    _generate_unique_article_slug,
)
from api.maintenance.news_dedup import find_duplicate_article

logger = logging.getLogger(__name__)


def _client() -> TinnhiemClient:
    # VnExpress (và CDN vnecdn.net) chặn UA bot → dùng UA trình duyệt để tải được ảnh.
    return TinnhiemClient(
        base_url=VNEXPRESS_BASE_URL,
        delay=0.5,
        timeout=20.0,
        user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/122.0 Safari/537.36"
        ),
        respect_robots=False,
    )


def _fetch_detail(client: TinnhiemClient, url: str, feed_key: str, meta: Dict[str, Any]) -> Optional[TinnhiemArticle]:
    html_text = client.get_html(url, use_cache=False)
    return parse_vnexpress_detail(html_text, url, feed_key=feed_key,
                                  base_url=VNEXPRESS_BASE_URL, fallback_meta=meta)


def sync_vnexpress_articles(
    feed_keys: Optional[Sequence[str]] = None,
    limit_per_feed: int = 15,
    download_images: bool = True,
    force_update: bool = False,
    rebuild_rag: bool = False,
    create_new: bool = True,
    max_pages: Optional[int] = None,
    dedup: bool = True,
    dedup_llm: bool = False,
) -> Dict[str, Any]:
    """Thu thập tin VnExpress theo tag vào ``Article`` (nguồn báo chí)."""
    start_time = time.time()
    target_feeds = list(feed_keys) if feed_keys else list(VNEXPRESS_FEED_CONFIGS.keys())
    invalid = [f for f in target_feeds if f not in VNEXPRESS_FEED_CONFIGS]
    if invalid:
        raise ValueError(f"Khóa feed không hợp lệ: {invalid}. Hỗ trợ: {list(VNEXPRESS_FEED_CONFIGS.keys())}")

    client = _client()
    stats: Dict[str, Any] = {
        "status": "SUCCESS", "created": 0, "updated": 0, "skipped": 0, "errors": 0,
        "feed_stats": {}, "new_articles": [],
    }

    for feed_key in target_feeds:
        cfg = VNEXPRESS_FEED_CONFIGS[feed_key]
        feed_cat = ArticleCategory.ALERT if cfg.get("category") == "alert" else ArticleCategory.NEWS
        feed_stat = {"created": 0, "updated": 0, "skipped": 0, "errors": 0}
        try:
            # Duyệt hết các trang của tag (p1, p2, …) để lấy đủ bài
            items = list(client.iter_vnexpress_listing(feed_key=feed_key, max_pages=max_pages,
                                                       use_cache=False))
            logger.info(f"[VNEXPRESS-FEED] {feed_key}: {len(items)} bài trong tag")
        except Exception as exc:  # noqa: BLE001
            logger.error(f"[VNEXPRESS-FEED] Lỗi lấy danh sách {feed_key}: {exc}")
            stats["errors"] += 1
            feed_stat["errors"] += 1
            stats["feed_stats"][feed_key] = feed_stat
            continue

        for item in items[:limit_per_feed]:
            item_url = (item.get("url") or "").strip()
            if not item_url:
                continue
            try:
                existing = Article.objects.filter(source_url=item_url).first()
                if not existing:
                    cand = item.get("slug") or item.get("title", "")
                    existing = Article.objects.filter(slug=cand).first()

                if existing and not force_update:
                    stats["skipped"] += 1
                    feed_stat["skipped"] += 1
                    continue

                detail = _fetch_detail(client, item_url, feed_key, item)
                if detail is None:
                    # Podcast / trang không có thân bài → bỏ qua (không tính lỗi)
                    stats["skipped"] += 1
                    feed_stat["skipped"] += 1
                    continue
                if not detail.title:
                    stats["errors"] += 1
                    feed_stat["errors"] += 1
                    continue

                if existing:
                    existing.title = detail.title
                    existing.summary = detail.summary or existing.summary
                    existing.content = html_to_markdown(detail.content) if detail.content else existing.content
                    existing.category = feed_cat
                    existing.source_type = ArticleSourceType.PRESS
                    existing.source_url = detail.url
                    existing.is_published = True
                    if download_images and detail.cover_image_url and not existing.cover_image:
                        _download_and_attach_cover(existing, detail.cover_image_url, client)
                    existing.save()
                    stats["updated"] += 1
                    feed_stat["updated"] += 1
                    logger.info(f"[VNEXPRESS-FEED] Cập nhật #{existing.id}: {existing.title}")
                else:
                    if not create_new:
                        stats["skipped"] += 1
                        feed_stat["skipped"] += 1
                        continue
                    if dedup:
                        dup = find_duplicate_article(
                            detail.title, detail.summary or "", detail.url, detail.content or "",
                            use_llm=dedup_llm)
                        if dup:
                            stats["skipped"] += 1
                            feed_stat["skipped"] += 1
                            logger.info("[VNEXPRESS-FEED] Bỏ bài trùng với #%s: %s", dup.id, detail.title)
                            continue
                    article = Article(
                        title=detail.title,
                        slug=_generate_unique_article_slug(detail.slug or detail.title),
                        summary=detail.summary,
                        content=html_to_markdown(detail.content),
                        category=feed_cat,
                        source_type=ArticleSourceType.PRESS,
                        source_url=detail.url,
                        is_published=True,
                    )
                    if download_images and detail.cover_image_url:
                        _download_and_attach_cover(article, detail.cover_image_url, client)
                    article.save()
                    stats["created"] += 1
                    feed_stat["created"] += 1
                    stats["new_articles"].append({"id": article.id, "title": article.title, "slug": article.slug})
                    logger.info(f"[VNEXPRESS-FEED] Thêm mới #{article.id}: {article.title}")
            except Exception as exc:  # noqa: BLE001
                logger.error(f"[VNEXPRESS-FEED] Lỗi xử lý {item_url}: {exc}", exc_info=True)
                stats["errors"] += 1
                feed_stat["errors"] += 1

        stats["feed_stats"][feed_key] = feed_stat

    stats["duration_seconds"] = round(time.time() - start_time, 2)
    logger.info(
        f"[VNEXPRESS-FEED] Hoàn tất: {stats['created']} mới, {stats['updated']} cập nhật, "
        f"{stats['skipped']} bỏ qua, {stats['errors']} lỗi trong {stats['duration_seconds']}s"
    )

    if stats["created"] > 0 and rebuild_rag:
        try:
            from api.utils.vector_db import vector_db
            vector_db.rebuild_index(force_cpu=True)
        except Exception as rag_err:  # noqa: BLE001
            logger.warning(f"[VNEXPRESS-FEED] Không thể cập nhật RAG: {rag_err}")

    return stats


def refresh_existing_vnexpress_articles(
    download_images: bool = True,
    rebuild_rag: bool = False,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Ghi đè lại TẤT CẢ bài VnExpress hiện có (``source_type='press'``), không tạo mới."""
    start_time = time.time()
    client = _client()
    stats: Dict[str, Any] = {"status": "SUCCESS", "updated": 0, "skipped": 0, "errors": 0,
                             "duration_seconds": 0.0}

    qs = (Article.objects.filter(source_type=ArticleSourceType.PRESS)
          .exclude(source_url__isnull=True).exclude(source_url="").order_by("id"))
    articles = list(qs[:limit] if limit else qs)
    logger.info(f"[VNEXPRESS-FEED] Refresh {len(articles)} bài VnExpress hiện có (ghi đè, không tạo mới)")

    for article in articles:
        try:
            html_text = client.get_html(article.source_url, use_cache=False)
            detail = parse_vnexpress_detail(html_text, article.source_url, feed_key="lua_dao_qua_mang",
                                            base_url=VNEXPRESS_BASE_URL)
            if not detail or not detail.title:
                stats["skipped"] += 1
                continue
            article.title = detail.title
            if detail.summary:
                article.summary = detail.summary
            if detail.content:
                article.content = html_to_markdown(detail.content)
            if download_images and detail.cover_image_url and not article.cover_image:
                _download_and_attach_cover(article, detail.cover_image_url, client)
            article.save()
            stats["updated"] += 1
            logger.info(f"[VNEXPRESS-FEED] Ghi đè #{article.id}: {article.title}")
        except Exception as exc:  # noqa: BLE001
            stats["errors"] += 1
            logger.error(f"[VNEXPRESS-FEED] Lỗi refresh #{article.id}: {exc}", exc_info=True)

    stats["duration_seconds"] = round(time.time() - start_time, 2)
    logger.info(f"[VNEXPRESS-FEED] Refresh xong: {stats['updated']} ghi đè, "
                f"{stats['skipped']} bỏ qua, {stats['errors']} lỗi trong {stats['duration_seconds']}s")
    return stats
