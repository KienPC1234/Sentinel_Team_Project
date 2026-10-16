from celery import shared_task
from django.conf import settings
from django.utils import timezone
from .models import RAGIndexLog
import logging

logger = logging.getLogger(__name__)

@shared_task(name="api.maintenance.tasks.rebuild_vector_index", bind=True)
def rebuild_vector_index(self, trigger='MANUAL'):
    """
    Celery task to rebuild the FAISS vector index.
    """
    from datetime import timedelta
    stale_cutoff = timezone.now() - timedelta(minutes=15)
    RAGIndexLog.objects.filter(status='RUNNING', started_at__lt=stale_cutoff).update(
        status='FAILED',
        completed_at=timezone.now(),
        error_message='Hệ thống tự động hủy do worker khởi động lại hoặc timeout'
    )

    logger.info(f"[RAG-REBUILD] Task started (trigger={trigger}, task_id={self.request.id})")
    log = RAGIndexLog.objects.create(status='RUNNING', trigger=trigger)
    
    from api.utils.push_service import push_service
    push_service.send_rag_status_update('RUNNING', 'Bắt đầu xây dựng lại chỉ mục RAG...')
    
    try:
        from api.utils.vector_db import vector_db
        # Get count before rebuilding for the log
        from django.db.models import Q
        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario
        count = (
            Article.objects.filter(is_published=True).count() +
            LearnLesson.objects.filter(is_published=True).count() +
            LearnQuiz.objects.filter(Q(article__is_published=True) | Q(lesson__is_published=True)).distinct().count() +
            LearnScenario.objects.filter(Q(article__is_published=True) | Q(article__isnull=True)).count()
        )
        logger.info(f"[RAG-REBUILD] Found {count} documents to index")
        
        # Use force_cpu=True to avoid CUDA multiprocessing issues in Celery workers
        vector_db.rebuild_index(force_cpu=True)
        
        log.status = 'SUCCESS'
        log.documents_count = count
        log.completed_at = timezone.now()
        log.save()
        
        elapsed = (log.completed_at - log.started_at).total_seconds()
        logger.info(f"[RAG-REBUILD] SUCCESS — Indexed {count} documents in {elapsed:.1f}s")
        
        push_service.send_rag_status_update('SUCCESS', f'Hoàn tất! Đã lập chỉ mục {count} tài liệu.', count=count)
        return f"Index rebuild success: Indexed {count} documents in {elapsed:.1f}s"
        
    except Exception as e:
        logger.error(f"[RAG-REBUILD] FAILED — {e}", exc_info=True)
        log.status = 'FAILED'
        log.error_message = str(e)
        log.completed_at = timezone.now()
        log.save()
        
        push_service.send_rag_status_update('FAILED', f'Lỗi rebuild: {str(e)}', error=str(e))
        return f"Index rebuild failed: {str(e)}"


@shared_task(name="api.maintenance.tasks.sync_threat_intelligence", bind=True)
def sync_threat_intelligence(self, limit_per_feed=10000, sources=None, batch_size=2000):
    """
    Celery task to ingest and synchronize malicious domains and phishing feeds.
    Runs daily via Celery Beat or triggered on-demand.
    """
    logger.info(f"[ThreatIntel-TASK] Started (task_id={self.request.id})")
    try:
        from .threat_feeds import sync_threat_feeds
        stats = sync_threat_feeds(limit_per_feed=limit_per_feed, sources=sources, batch_size=batch_size)
        logger.info(
            f"[ThreatIntel-TASK] COMPLETED: {stats.get('total_saved', 0)} domains upserted in {stats.get('duration_seconds', 0)}s"
        )
        return stats
    except Exception as e:
        logger.error(f"[ThreatIntel-TASK] FAILED: {e}", exc_info=True)
        return {"status": "FAILED", "error": str(e)}



@shared_task(name="api.maintenance.tasks.sync_media_to_storage", bind=True)
def sync_media_to_storage(self, delete=False, prefix=''):
    """Đồng bộ media cục bộ lên S3 (chạy định kỳ để đảm bảo 100% media trên object storage)."""
    from django.conf import settings
    if not getattr(settings, 'AWS_S3_ENDPOINT_URL', ''):
        logger.info("[MEDIA-SYNC] Bỏ qua: chưa cấu hình S3.")
        return {'skipped': True}
    try:
        from api.utils.s3_sync import sync_media_to_s3
        stats = sync_media_to_s3(delete=delete, prefix=prefix)
        logger.info(f"[MEDIA-SYNC] {stats}")
        return stats
    except Exception as exc:
        logger.error(f"[MEDIA-SYNC] FAILED: {exc}", exc_info=True)
        return {'error': str(exc)}


@shared_task(name="api.maintenance.tasks.backup_vector_store")
def backup_vector_store_task():
    """Sao lưu chỉ mục vector (vector_store) lên object storage S3."""
    from django.conf import settings
    if not getattr(settings, 'AWS_S3_ENDPOINT_URL', ''):
        logger.info("[VECTOR-BACKUP] Bỏ qua: chưa cấu hình S3.")
        return {'skipped': True}
    try:
        from api.utils.s3_sync import backup_vector_store
        stats = backup_vector_store()
        logger.info(f"[VECTOR-BACKUP] {stats}")
        return stats
    except Exception as exc:
        logger.error(f"[VECTOR-BACKUP] FAILED: {exc}", exc_info=True)
        return {'error': str(exc)}


@shared_task(name="api.maintenance.tasks.sync_tinnhiemmang_news", bind=True)
def sync_tinnhiemmang_news(self, feed_keys=None, limit_per_feed=15, download_images=True, force_update=False, rebuild_rag=True):
    """
    Celery task để tự động tổng hợp tin tức nổi bật và cảnh báo lừa đảo từ tinnhiemmang.vn.
    Lưu vào Article với kiểu nguồn tin 'tinnhiemmang' phục vụ hệ sinh thái ShieldCall VN.
    """
    logger.info(f"[TINNHIEMMANG-TASK] Bắt đầu tổng hợp tin tức (task_id={getattr(self.request, 'id', 'sync')})")
    try:
        from .tinnhiemmang_feed import sync_tinnhiemmang_articles
        stats = sync_tinnhiemmang_articles(
            feed_keys=feed_keys,
            limit_per_feed=limit_per_feed,
            download_images=download_images,
            force_update=force_update,
            rebuild_rag=rebuild_rag,
            dedup=True,
            dedup_llm=getattr(settings, "NEWS_DEDUP_LLM", False),
        )
        if getattr(settings, "NEWS_LLM_FORMAT", False):
            try:
                from .article_format import reformat_news_markdown
                reformat_news_markdown(use_llm=True, limit=max(30, limit_per_feed * 2))
            except Exception as fmt_exc:  # noqa: BLE001
                logger.warning(f"[TINNHIEMMANG-TASK] Chuẩn hoá Markdown lỗi: {fmt_exc}")
        logger.info(
            f"[TINNHIEMMANG-TASK] Hoàn tất: {stats.get('created', 0)} bài mới, "
            f"{stats.get('updated', 0)} cập nhật trong {stats.get('duration_seconds', 0)}s"
        )
        return stats
    except Exception as exc:
        logger.error(f"[TINNHIEMMANG-TASK] Thất bại: {exc}", exc_info=True)
        return {"status": "FAILED", "error": str(exc)}


@shared_task(name="api.maintenance.tasks.sync_tinnhiem_directory", bind=True)
def sync_tinnhiem_directory(self, category="all", workers=None, stop_after_known=0,
                            ingest=True, respect_robots=False):
    """
    Celery task: đồng bộ **danh bạ** Tín nhiệm mạng (tinnhiemmang.vn) — chỉ thêm mục mới.

    Khác ``sync_tinnhiemmang_news`` (tin tức → Article), task này thu thập danh bạ
    website/tổ chức/hệ thống/ứng dụng tín nhiệm + website lừa đảo ra JSONL, rồi nạp
    danh sách lừa đảo vào model ``Domain``. Chạy hằng tuần qua Celery beat.
    """
    import io
    from django.core.management import call_command

    logger.info("[TINNHIEM-DIR-TASK] Bắt đầu đồng bộ danh bạ (task_id=%s)",
                getattr(self.request, "id", "sync"))
    buf = io.StringIO()
    try:
        call_command(
            "sync_tinnhiem_directory",
            category=category, workers=workers, stop_after_known=stop_after_known,
            ingest=ingest, respect_robots=respect_robots, stdout=buf,
        )
        tail = buf.getvalue()[-2000:]
        logger.info("[TINNHIEM-DIR-TASK] Hoàn tất đồng bộ danh bạ")
        return {"status": "SUCCESS", "category": category, "output_tail": tail}
    except Exception as exc:
        logger.error(f"[TINNHIEM-DIR-TASK] Thất bại: {exc}", exc_info=True)
        return {"status": "FAILED", "error": str(exc)}


@shared_task(name="api.maintenance.tasks.sync_vnexpress_news", bind=True)
def sync_vnexpress_news(self, feed_keys=None, limit_per_feed=15, download_images=True,
                        force_update=False, rebuild_rag=True, create_new=True):
    """
    Celery task: tổng hợp tin lừa đảo từ **VnExpress** (tag 'Lừa đảo qua mạng') vào Article
    với ``source_type='press'``. Chạy định kỳ qua Celery beat.
    """
    logger.info(f"[VNEXPRESS-TASK] Bắt đầu tổng hợp (task_id={getattr(self.request, 'id', 'sync')})")
    try:
        from .vnexpress_feed import sync_vnexpress_articles
        stats = sync_vnexpress_articles(
            feed_keys=feed_keys,
            limit_per_feed=limit_per_feed,
            download_images=download_images,
            force_update=force_update,
            rebuild_rag=rebuild_rag,
            create_new=create_new,
            dedup=True,
            dedup_llm=getattr(settings, "NEWS_DEDUP_LLM", False),
        )
        if getattr(settings, "NEWS_LLM_FORMAT", False):
            try:
                from .article_format import reformat_news_markdown
                reformat_news_markdown(use_llm=True, limit=max(30, limit_per_feed * 2))
            except Exception as fmt_exc:  # noqa: BLE001
                logger.warning(f"[VNEXPRESS-TASK] Chuẩn hoá Markdown lỗi: {fmt_exc}")
        logger.info(
            f"[VNEXPRESS-TASK] Hoàn tất: {stats.get('created', 0)} mới, "
            f"{stats.get('updated', 0)} cập nhật trong {stats.get('duration_seconds', 0)}s"
        )
        return stats
    except Exception as exc:
        logger.error(f"[VNEXPRESS-TASK] Thất bại: {exc}", exc_info=True)
        return {"status": "FAILED", "error": str(exc)}
