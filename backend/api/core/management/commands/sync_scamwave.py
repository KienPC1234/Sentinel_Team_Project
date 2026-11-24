"""
Lệnh Django: đồng bộ danh bạ cảnh báo từ https://scamwave.com/scammers/.

Cách dùng:
    python manage.py sync_scamwave
"""

from __future__ import annotations

import json

from django.core.management.base import BaseCommand, CommandError

from api.utils.scamwave import sync_scamwave


class Command(BaseCommand):
    help = "Đồng bộ danh bạ website/thực thể cảnh báo từ https://scamwave.com/scammers/ vào snapshot cục bộ."

    def add_arguments(self, parser):
        parser.add_argument("--timeout", type=int, default=25, help="Timeout HTTP (giây)")
        parser.add_argument("--json", action="store_true", help="In thống kê dạng JSON")

    def handle(self, *args, **options):
        try:
            meta = sync_scamwave(timeout=int(options["timeout"]))
        except Exception as exc:
            raise CommandError(f"Đồng bộ ScamWave thất bại: {exc}") from exc

        if options["json"]:
            self.stdout.write(json.dumps(meta, ensure_ascii=False))
            return

        self.stdout.write(
            self.style.SUCCESS(
                f"Đã đồng bộ ScamWave: {meta.get('count', 0)} mục "
                f"(cập nhật {meta.get('updated_at')}) | trạng thái: {meta.get('status_counts')}"
            )
        )
