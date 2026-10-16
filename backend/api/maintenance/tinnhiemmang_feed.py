"""
ShieldCall VN — Dịch vụ tổng hợp tin tức & cảnh báo lừa đảo từ tinnhiemmang.vn.

Chức năng:
- Thu thập tin tức nổi bật và cảnh báo lừa đảo từ:
    + https://tinnhiemmang.vn/noi-bat (chuyên mục Tin tức - news)
    + https://tinnhiemmang.vn/canh-bao-lua-dao (chuyên mục Cảnh báo - alert)
- Chuẩn hóa nội dung, loại bỏ thành phần thừa và tải ảnh bìa.
- Lưu trữ vào mô hình Article với kiểu nguồn tin `source_type='tinnhiemmang'`.
- Tự động phát hiện trùng lặp theo `source_url` hoặc `slug`.
- Cập nhật chỉ mục tìm kiếm / Vector DB RAG khi có bài viết mới.
"""

from __future__ import annotations

import logging
import re
import time
from typing import Any, Dict, List, Optional, Sequence
from urllib.parse import urlparse

from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone
from django.utils.text import slugify

from api.core.models import Article, ArticleCategory, ArticleSourceType
from api.utils.tinnhiemmang import (
    NEWS_FEED_CONFIGS,
    TinnhiemArticle,
    TinnhiemClient,
    html_to_markdown,
)
from api.maintenance.news_dedup import find_duplicate_article

logger = logging.getLogger(__name__)


def _generate_unique_article_slug(base_slug: str, existing_id: Optional[int] = None) -> str:
    """Đảm bảo slug là duy nhất trên toàn bảng Article."""
    clean_slug = slugify(base_slug, allow_unicode=False)[:240]
    if not clean_slug:
        clean_slug = f"tinnhiemmang-{int(time.time())}"

    candidate = clean_slug
    counter = 1
    while True:
        qs = Article.objects.filter(slug=candidate)
        if existing_id:
            qs = qs.exclude(id=existing_id)
        if not qs.exists():
            return candidate
        counter += 1
        candidate = f"{clean_slug[:230]}-{counter}"


def _download_and_attach_cover(article: Article, image_url: str, client: TinnhiemClient) -> bool:
    """Tải ảnh bài viết từ tinnhiemmang.vn và lưu vào trường cover_image."""
    if not image_url or not image_url.startswith("http"):
        return False
    try:
        resp = client.session.get(image_url, timeout=12)
        if resp.status_code == 200 and resp.content and len(resp.content) > 1000:
            parsed = urlparse(image_url)
            ext = "jpg"
            if "." in parsed.path:
                cand_ext = parsed.path.rsplit(".", 1)[-1].lower()
                if cand_ext in ("jpg", "jpeg", "png", "webp"):
                    ext = cand_ext
            safe_slug = re.sub(r"[^a-zA-Z0-9_-]", "", article.slug)[:40]
            filename = f"tnm_{safe_slug}.{ext}"
            article.cover_image.save(filename, ContentFile(resp.content), save=False)
            return True
    except Exception as exc:
        logger.warning(f"Không thể tải ảnh bìa {image_url}: {exc}")
    return False


def sync_tinnhiemmang_articles(
    feed_keys: Optional[Sequence[str]] = None,
    limit_per_feed: int = 15,
    download_images: bool = True,
    force_update: bool = False,
    rebuild_rag: bool = False,
    create_new: bool = True,
    dedup: bool = True,
    dedup_llm: bool = False,
) -> Dict[str, Any]:
    """
    Thu thập và cập nhật bài viết từ tinnhiemmang.vn vào ShieldCall VN.

    :param feed_keys: Danh sách khóa feed cần lấy ('canh_bao_lua_dao', 'noi_bat').
    :param limit_per_feed: Số bài tối đa thu thập cho mỗi feed.
    :param download_images: Có tải và đính kèm ảnh bìa về máy chủ hay không.
    :param force_update: Nếu bài viết đã tồn tại thì cập nhật đè lại nội dung.
    :param rebuild_rag: Có tự động xây dựng lại FAISS vector store khi có bài mới không.
    :return: Thống kê kết quả thu thập.
    """
    start_time = time.time()
    target_feeds = list(feed_keys) if feed_keys else ["canh_bao_lua_dao", "noi_bat"]
    invalid_feeds = [f for f in target_feeds if f not in NEWS_FEED_CONFIGS]
    if invalid_feeds:
        raise ValueError(f"Khóa feed không hợp lệ: {invalid_feeds}. Hỗ trợ: {list(NEWS_FEED_CONFIGS.keys())}")

    client = TinnhiemClient(delay=0.3, timeout=15.0, respect_robots=False)

    stats = {
        "status": "SUCCESS",
        "created": 0,
        "updated": 0,
        "skipped": 0,
        "errors": 0,
        "feed_stats": {},
        "new_articles": [],
    }

    for feed_key in target_feeds:
        feed_cfg = NEWS_FEED_CONFIGS[feed_key]
        feed_cat = ArticleCategory.ALERT if feed_cfg["category"] == "alert" else ArticleCategory.NEWS
        feed_stat = {"created": 0, "updated": 0, "skipped": 0, "errors": 0}

        try:
            items = client.get_news_listing(feed_key=feed_key, use_cache=False)
        except Exception as exc:
            logger.error(f"[TINNHIEMMANG-FEED] Lỗi khi lấy danh sách feed {feed_key}: {exc}")
            stats["errors"] += 1
            feed_stat["errors"] += 1
            stats["feed_stats"][feed_key] = feed_stat
            continue

        for item in items[:limit_per_feed]:
            item_url = item.get("url", "").strip()
            if not item_url:
                continue

            try:
                # Kiểm tra trùng lặp theo source_url hoặc slug
                existing = Article.objects.filter(source_url=item_url).first()
                if not existing:
                    cand_slug = item.get("slug") or slugify(item.get("title", ""))
                    existing = Article.objects.filter(slug=cand_slug).first()

                if existing and not force_update:
                    stats["skipped"] += 1
                    feed_stat["skipped"] += 1
                    continue

                # Tải chi tiết bài viết
                detail: Optional[TinnhiemArticle] = client.get_news_detail(
                    item_url, feed_key=feed_key, fallback_meta=item, use_cache=False
                )
                if not detail or not detail.title:
                    stats["errors"] += 1
                    feed_stat["errors"] += 1
                    continue

                if existing:
                    # Cập nhật bài viết có sẵn
                    existing.title = detail.title
                    existing.summary = detail.summary or existing.summary
                    existing.content = html_to_markdown(detail.content) if detail.content else existing.content
                    existing.category = feed_cat
                    existing.source_type = ArticleSourceType.TINNHIEMMANG
                    existing.source_url = detail.url
                    existing.is_published = True

                    if download_images and detail.cover_image_url and not existing.cover_image:
                        _download_and_attach_cover(existing, detail.cover_image_url, client)

                    existing.save()
                    stats["updated"] += 1
                    feed_stat["updated"] += 1
                    logger.info(f"[TINNHIEMMANG-FEED] Đã cập nhật bài viết #{existing.id}: {existing.title}")
                else:
                    if not create_new:
                        # Chế độ chỉ-ghi-đè: không tạo bài mới
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
                            logger.info("[TINNHIEMMANG-FEED] Bỏ bài trùng với #%s: %s", dup.id, detail.title)
                            continue
                    # Tạo bài viết mới
                    unique_slug = _generate_unique_article_slug(detail.slug or detail.title)
                    article = Article(
                        title=detail.title,
                        slug=unique_slug,
                        summary=detail.summary,
                        content=html_to_markdown(detail.content),
                        category=feed_cat,
                        source_type=ArticleSourceType.TINNHIEMMANG,
                        source_url=detail.url,
                        is_published=True,
                    )

                    if download_images and detail.cover_image_url:
                        _download_and_attach_cover(article, detail.cover_image_url, client)

                    article.save()
                    stats["created"] += 1
                    feed_stat["created"] += 1
                    stats["new_articles"].append({"id": article.id, "title": article.title, "slug": article.slug})
                    logger.info(f"[TINNHIEMMANG-FEED] Đã thêm bài viết mới #{article.id}: {article.title}")

            except Exception as item_err:
                logger.error(f"[TINNHIEMMANG-FEED] Lỗi xử lý bài viết {item_url}: {item_err}", exc_info=True)
                stats["errors"] += 1
                feed_stat["errors"] += 1

        stats["feed_stats"][feed_key] = feed_stat

    elapsed = time.time() - start_time
    stats["duration_seconds"] = round(elapsed, 2)
    logger.info(
        f"[TINNHIEMMANG-FEED] Hoàn tất: {stats['created']} bài tạo mới, {stats['updated']} cập nhật, "
        f"{stats['skipped']} bỏ qua trong {stats['duration_seconds']}s"
    )

    # Tự động cập nhật Vector DB cho RAG nếu có bài viết mới
    if stats["created"] > 0 and rebuild_rag:
        try:
            from api.utils.vector_db import vector_db
            logger.info("[TINNHIEMMANG-FEED] Xây dựng lại vector index RAG sau khi nhập dữ liệu...")
            vector_db.rebuild_index(force_cpu=True)
        except Exception as rag_err:
            logger.warning(f"[TINNHIEMMANG-FEED] Không thể cập nhật RAG: {rag_err}")

    return stats


def refresh_existing_tinnhiemmang_articles(
    download_images: bool = True,
    rebuild_rag: bool = False,
    limit: Optional[int] = None,
) -> Dict[str, Any]:
    """Ghi đè lại TẤT CẢ bài viết tinnhiemmang hiện có (KHÔNG tạo mới).

    Duyệt mọi ``Article`` nguồn ``tinnhiemmang`` có ``source_url``, tải lại trang gốc
    và ghi đè ``title``/``summary``/``content`` (định dạng HTML sạch). Dùng để sửa hàng
    loạt bài đã nhập bằng parser lỗi thời mà không sinh bài trùng.
    """
    start_time = time.time()
    client = TinnhiemClient(delay=0.3, timeout=15.0, respect_robots=False)

    stats: Dict[str, Any] = {
        "status": "SUCCESS", "updated": 0, "skipped": 0, "errors": 0,
        "duration_seconds": 0.0,
    }

    qs = (
        Article.objects.filter(source_type=ArticleSourceType.TINNHIEMMANG)
        .exclude(source_url__isnull=True)
        .exclude(source_url="")
        .order_by("id")
    )
    articles = list(qs[:limit] if limit else qs)
    logger.info(f"[TINNHIEMMANG-FEED] Refresh {len(articles)} bài viết hiện có (ghi đè, không tạo mới)")

    for article in articles:
        try:
            feed_key = "canh_bao_lua_dao" if article.category == ArticleCategory.ALERT else "noi_bat"
            detail = client.get_news_detail(article.source_url, feed_key=feed_key, use_cache=False)
            if not detail or not detail.title:
                stats["skipped"] += 1
                continue

            article.title = detail.title
            if detail.summary:
                article.summary = detail.summary
            if detail.content:
                article.content = html_to_markdown(detail.content)
            article.source_type = ArticleSourceType.TINNHIEMMANG
            article.is_published = True

            if download_images and detail.cover_image_url and not article.cover_image:
                _download_and_attach_cover(article, detail.cover_image_url, client)

            article.save()
            stats["updated"] += 1
            logger.info(f"[TINNHIEMMANG-FEED] Ghi đè bài viết #{article.id}: {article.title}")
        except Exception as exc:  # noqa: BLE001
            stats["errors"] += 1
            logger.error(f"[TINNHIEMMANG-FEED] Lỗi refresh #{article.id}: {exc}", exc_info=True)

    stats["duration_seconds"] = round(time.time() - start_time, 2)
    logger.info(
        f"[TINNHIEMMANG-FEED] Refresh xong: {stats['updated']} ghi đè, "
        f"{stats['skipped']} bỏ qua, {stats['errors']} lỗi trong {stats['duration_seconds']}s"
    )

    if stats["updated"] > 0 and rebuild_rag:
        try:
            from api.utils.vector_db import vector_db
            vector_db.rebuild_index(force_cpu=True)
        except Exception as rag_err:
            logger.warning(f"[TINNHIEMMANG-FEED] Không thể cập nhật RAG: {rag_err}")

    return stats

