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
    
    try:
        # Get count before rebuilding for the log
        from api.core.models import Article, LearnLesson, LearnQuiz, LearnScenario
        count = (
            Article.objects.filter(is_published=True).count() +
            LearnLesson.objects.filter(is_published=True).count() +
            LearnQuiz.objects.filter(article__is_published=True).count() +
            LearnQuiz.objects.filter(lesson__is_published=True).count() +
            LearnScenario.objects.filter(article__is_published=True).count()
        )
        
        vector_db.rebuild_index()
        
        log.status = 'SUCCESS'
        log.documents_count = count
        log.completed_at = timezone.now()
        log.save()
        return f"Index rebuild success: Indexed {count} documents."
        
    except Exception as e:
        logger.error(f"Failed to rebuild vector index: {e}")
        log.status = 'FAILED'
        log.error_message = str(e)
        log.completed_at = timezone.now()
        log.save()
        return f"Index rebuild failed: {str(e)}"
