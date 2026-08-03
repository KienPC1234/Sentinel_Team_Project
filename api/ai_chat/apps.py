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
            try:
                from api.utils.vector_db import vector_db
                vector_db._load_model()
                print("DEBUG: AI VectorDB and Model pre-loaded successfully.")
            except Exception as e:
                print(f"DEBUG: Error pre-loading VectorDB: {e}")
        
        # Run in background to not block startup completely, but start early
        threading.Thread(target=preload, daemon=True).start()
