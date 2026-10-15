"""
Đồng bộ media cục bộ (backend/media) lên object storage S3.

Dùng để backfill media cũ lên S3 và/hoặc chạy định kỳ (Celery Beat) đảm bảo
100% media hiện diện trên S3 khi USE_S3_MEDIA=true.

Chạy:  python manage.py sync_media_to_s3 [--delete] [--prefix media]
Khi bật S3, có thể dùng luôn --delete để S3 phản chiếu đúng thư mục media.
"""
import mimetypes
import os

from django.conf import settings
from django.core.management.base import BaseCommand

try:
    from api.utils.s3_sync import sync_media_to_s3 as _sync
    _HAVE_SYNC = True
except Exception:  # pragma: no cover
    _HAVE_SYNC = False


class Command(BaseCommand):
    help = "Đồng bộ backend/media lên S3 (backfill + định kỳ)."

    def add_arguments(self, parser):
        parser.add_argument('--delete', action='store_true',
                            help="Xoá object trên S3 không còn tồn tại ở media cục bộ.")
        parser.add_argument('--dry-run', action='store_true', help="Chỉ liệt kê, không tải lên.")

    def handle(self, *args, **opts):
        if not _HAVE_SYNC:
            self.stderr.write(self.style.ERROR("Thiếu api.utils.s3_sync. Kiểm tra cài đặt."))
            return
        if getattr(settings, 'AWS_S3_ENDPOINT_URL', '') == '':
            self.stderr.write(self.style.ERROR("Chưa cấu hình S3 (AWS_S3_ENDPOINT_URL)."))
            return
        stats = _sync(
            media_root=str(settings.MEDIA_ROOT),
            bucket=settings.AWS_STORAGE_BUCKET_NAME,
            delete=opts['delete'],
            dry_run=opts['dry_run'],
            log=lambda m: self.stdout.write(m),
        )
        self.stdout.write(self.style.SUCCESS(
            f"Xong: {stats['uploaded']} tải lên, {stats['skipped']} bỏ qua, "
            f"{stats['deleted']} xoá, {stats['errors']} lỗi."
        ))
