"""Build trước cache audio TTS cho các đoạn văn bản tiếng Việt.

Ví dụ:
    # 1 đoạn trực tiếp
    python manage.py build_tts_cache "Cháu chào bác, bác bấm vào ô lớn để chọn."

    # từ file JSON (mảng chuỗi, hoặc dict {k: text}, hoặc file .txt mỗi dòng 1 câu)
    python manage.py build_tts_cache --file corpus.json

Dùng để "tự động build ở backend" lúc deploy/CI. Frontend cũng có thể tự warm
qua endpoint ``POST /api/v1/tts/warm/`` khi mở trang Elder.
"""
from __future__ import annotations

import json
from pathlib import Path

from django.core.management.base import BaseCommand, CommandError

from api.core import tts_service


class Command(BaseCommand):
    help = 'Tổng hợp (cache) audio TTS tiếng Việt cho các đoạn văn bản chỉ định.'

    def add_arguments(self, parser):
        parser.add_argument('texts', nargs='*', help='Các đoạn văn bản cần build.')
        parser.add_argument('--file', dest='file', help='File JSON/.txt chứa danh sách văn bản.')

    def _load_file(self, path: str) -> list[str]:
        p = Path(path)
        if not p.is_file():
            raise CommandError(f'Không tìm thấy file: {path}')
        raw = p.read_text(encoding='utf-8')
        if p.suffix.lower() == '.json':
            data = json.loads(raw)
            if isinstance(data, list):
                return [str(x) for x in data]
            if isinstance(data, dict):
                return [str(v) for v in data.values()]
            raise CommandError('JSON phải là mảng chuỗi hoặc object giá trị-chuỗi.')
        return [line.strip() for line in raw.splitlines() if line.strip()]

    def handle(self, *args, **options):
        if not tts_service.enabled():
            raise CommandError('TTS đang tắt (TTS_ENABLED=False).')
        if not tts_service.is_available():
            raise CommandError(
                'TTS chưa sẵn sàng: thiếu piper-tts hoặc model '
                f'{tts_service._model_path()}.'
            )

        texts: list[str] = list(options.get('texts') or [])
        if options.get('file'):
            texts.extend(self._load_file(options['file']))

        # Khử trùng lặp (sau chuẩn hoá) để không build thừa.
        seen: set[str] = set()
        unique: list[str] = []
        for t in texts:
            norm = tts_service.normalize_text(t)
            if norm and norm not in seen:
                seen.add(norm)
                unique.append(t)

        if not unique:
            self.stdout.write('Không có văn bản nào để build.')
            return

        total = len(unique)
        built = 0
        cached = 0
        errors = 0
        for i, text in enumerate(unique, 1):
            try:
                _path, _key, generated = tts_service.ensure_audio(text)
                if generated:
                    built += 1
                    self.stdout.write(f'[{i}/{total}] build  {text[:60]}…')
                else:
                    cached += 1
            except Exception as exc:  # noqa: BLE001
                errors += 1
                self.stderr.write(f'[{i}/{total}] LỖI: {exc}')

        self.stdout.write(self.style.SUCCESS(
            f'Xong: {built} mới, {cached} đã có sẵn, {errors} lỗi '
            f'(cache: {tts_service.cache_dir()}).'
        ))
