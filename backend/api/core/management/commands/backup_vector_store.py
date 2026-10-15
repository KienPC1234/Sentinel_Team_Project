"""Sao lưu chỉ mục vector (vector_store) lên S3. Chạy tay: python manage.py backup_vector_store"""
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Sao lưu vector_store (FAISS + metadata + embedding cache) lên S3."

    def handle(self, *args, **opts):
        from api.utils.s3_sync import backup_vector_store
        stats = backup_vector_store()
        self.stdout.write(self.style.SUCCESS(f"Backup vector_store: {stats}"))
