"""Tải model giọng đọc tiếng Việt (Piper) về ``backend/models/piper/``.

    python manage.py download_tts_voice

Idempotent: nếu model đã có thì bỏ qua. Dùng cho setup/CI (model không commit
vào git vì là file nhị phân ~63MB).
"""
from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from api.core import tts_service

# Ánh xạ voice_id → tên trên kho Piper (rhasspy/piper-voices).
_VOICE_REPO_NAMES = {
    'vi_VN-vais1000-medium': 'vi_VN/vais1000/medium/vi_VN-vais1000-medium',
}


class Command(BaseCommand):
    help = 'Tải model TTS tiếng Việt (Piper) nếu chưa có.'

    def handle(self, *args, **options):
        model = tts_service._model_path()
        if model.is_file():
            self.stdout.write(self.style.SUCCESS(f'Model đã có sẵn: {model}'))
            return

        voice = tts_service.voice_id()
        repo_name = _VOICE_REPO_NAMES.get(voice)
        if not repo_name:
            raise CommandError(f'Chưa biết cách tải voice "{voice}".')

        target_dir = model.parent
        target_dir.mkdir(parents=True, exist_ok=True)
        self.stdout.write(f'Đang tải {voice} → {target_dir} …')
        try:
            from piper.download_voices import download_voice
        except Exception as exc:  # pragma: no cover - phụ thuộc môi trường
            raise CommandError(f'Cần cài piper-tts trước (pip install piper-tts): {exc}') from exc

        # Piper ghi <data-dir>/<voice>.onnx — trùng tên file ta mong đợi.
        download_voice(repo_name, target_dir)

        if not model.is_file():
            # Một số phiên bản lưu tên khác → tìm file onnx vừa tải.
            candidates = sorted(target_dir.glob(f'{voice}*.onnx'))
            if candidates and candidates[0].name != model.name:
                candidates[0].replace(model)
        if not model.is_file():
            raise CommandError(f'Tải xong nhưng không thấy model tại {model}.')
        self.stdout.write(self.style.SUCCESS(f'Xong: {model}'))
