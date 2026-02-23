from celery import shared_task
from django.utils import timezone
from .models import RAGIndexLog
from api.utils.vector_db import vector_db
import logging

logger = logging.getLogger(__name__)

@shared_task(name="api.maintenance.tasks.rebuild_vector_index")
def rebuild_vector_index(trigger='MANUAL'):
    """
    Celery task to rebuild the FAISS vector index.
    """
    log = RAGIndexLog.objects.create(status='RUNNING', trigger=trigger)
    
    from api.utils.push_service import push_service
    push_service.send_rag_status_update('RUNNING', 'Bắt đầu xây dựng lại chỉ mục RAG...')
    
    try:
        # Get count before rebuilding for the log
        from django.db.models import Q
        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario
        count = (
            Article.objects.filter(is_published=True).count() +
            LearnLesson.objects.filter(is_published=True).count() +
            LearnQuiz.objects.filter(Q(article__is_published=True) | Q(lesson__is_published=True)).distinct().count() +
            LearnScenario.objects.filter(Q(article__is_published=True) | Q(article__isnull=True)).count()
        )
        
        # Use force_cpu=True to avoid CUDA multiprocessing issues in Celery workers
        vector_db.rebuild_index(force_cpu=True)
        
        log.status = 'SUCCESS'
        log.documents_count = count
        log.completed_at = timezone.now()
        log.save()
        
        push_service.send_rag_status_update('SUCCESS', f'Hoàn tất! Đã lập chỉ mục {count} tài liệu.', count=count)
        return f"Index rebuild success: Indexed {count} documents."
        
    except Exception as e:
        logger.error(f"Failed to rebuild vector index: {e}")
        log.status = 'FAILED'
        log.error_message = str(e)
        log.completed_at = timezone.now()
        log.save()
        
        push_service.send_rag_status_update('FAILED', f'Lỗi rebuild: {str(e)}', error=str(e))
        return f"Index rebuild failed: {str(e)}"
