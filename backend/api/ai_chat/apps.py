from django.apps import AppConfig


class AiChatConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api.ai_chat'
    label = 'ai_chat'

    def ready(self):
        import os
        # Prevent double loading (runserver reloader + main process)
        if os.environ.get('RUN_MAIN') != 'true':
            return

        # Pre-load VectorDB model and index on startup
        import threading
        def preload():
            import logging
            logger = logging.getLogger(__name__)
            try:
                from api.utils.vector_db import vector_db
                vector_db._load_model()
                logger.info("AI VectorDB and Model pre-loaded successfully.")
            except Exception as e:
                logger.warning("Error pre-loading VectorDB: %s", e)
        
        # Run in background to not block startup completely, but start early
        threading.Thread(target=preload, daemon=True).start()
