import os
import sys
import threading

from django.apps import AppConfig

_TRUTHY = ('true', '1', 'yes', 'on')
# Chỉ tiến trình PHỤC VỤ web mới preload (không làm chậm mọi lệnh manage.py/celery).
_SERVER_HINTS = ('runserver', 'daphne', 'uvicorn', 'gunicorn', 'asgi')


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api.core'
    verbose_name = 'ShieldCall Core'

    def ready(self):
        # Nạp sẵn giọng TTS trong luồng nền (best-effort) để giảm độ trễ lần
        # "Đọc to" đầu tiên. Bật bằng TTS_PRELOAD=true (mặc định tắt).
        try:
            from django.conf import settings

            from api.core import tts_service

            flag = str(getattr(settings, 'TTS_PRELOAD', os.getenv('TTS_PRELOAD', 'false'))).lower()
            if flag not in _TRUTHY or not tts_service.enabled():
                return
            argv = ' '.join(sys.argv)
            if not any(hint in argv for hint in _SERVER_HINTS):
                return
            # Làm nóng transformers ở LUỒNG CHÍNH trước khi spawn thread preload,
            # tránh đua import (module import dở → 'cannot import name ...').
            try:
                import transformers  # noqa: F401
            except Exception:
                pass
            threading.Thread(target=tts_service.preload, name='tts-preload', daemon=True).start()
        except Exception:
            # Không để lỗi preload làm chết quá trình khởi động ứng dụng.
            pass
