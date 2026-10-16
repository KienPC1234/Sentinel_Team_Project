"""
Lệnh Django: dọn tin tức trùng đã có (tinnhiemmang/press).

Cách dùng::

    python manage.py dedup_news                 # chỉ báo cáo (không xoá)
    python manage.py dedup_news --llm           # dùng LLM cho ca nghi ngờ
    python manage.py dedup_news --apply         # XOÁ bài trùng (giữ bài cũ hơn)
    python manage.py dedup_news --apply --llm
"""

from django.conf import settings
from django.core.management.base import BaseCommand

from api.maintenance.news_dedup import dedup_news_articles


class Command(BaseCommand):
    help = "Dọn tin tức trùng (tinnhiemmang/press) — mặc định chỉ báo cáo, --apply để xoá."

    def add_arguments(self, parser):
        parser.add_argument("--llm", action="store_true",
                            help="Dùng LLM nhỏ cho các ca nghi ngờ (tiêu đề khác nhưng cùng tin).")
        parser.add_argument("--model", default=None, help="Model LLM (mặc định SMALL_MODEL).")
        parser.add_argument("--threshold", type=float, default=0.90, help="Ngưỡng tương đồng tiêu đề.")
        parser.add_argument("--apply", action="store_true", help="Thực sự XOÁ bài trùng.")

    def handle(self, *args, **options):
        use_llm = options.get("llm", False)
        model = options.get("model") or getattr(settings, "SMALL_MODEL", None)
        apply_ = options.get("apply", False)
        self.stdout.write(self.style.NOTICE(
            f"=== DEDUP NEWS ===\nLLM: {'CÓ (' + str(model) + ')' if use_llm else 'không'}"
            f" | threshold={options.get('threshold')} | apply={apply_}"
        ))
        stats = dedup_news_articles(
            use_llm=use_llm, threshold=options.get("threshold", 0.90), apply=apply_, model=model)
        self.stdout.write(self.style.SUCCESS(
            f"Kiểm {stats['checked']} bài | trùng: {stats['duplicates']} | "
            f"đã xoá: {stats['deleted']} | lỗi: {stats['errors']} | {stats['duration_seconds']}s"
        ))
        if not apply_ and stats["duplicates"]:
            self.stdout.write(self.style.WARNING("Chạy lại với --apply để xoá."))
