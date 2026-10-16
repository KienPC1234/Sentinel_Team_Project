"""
Lệnh Django: định dạng lại nội dung tin tức (tinnhiemmang / press) thành **Markdown sạch**.

Cách dùng::

    python manage.py format_news                    # chuyển HTML -> Markdown (nhanh, không LLM)
    python manage.py format_news --llm              # dùng LLM nhỏ (SMALL_MODEL) làm sạch
    python manage.py format_news --llm --model gemma4:latest --limit 20
    python manage.py format_news --dry-run          # chỉ xem, không ghi
"""

from django.conf import settings
from django.core.management.base import BaseCommand

from api.maintenance.article_format import reformat_news_markdown


class Command(BaseCommand):
    help = "Định dạng lại nội dung tin tức (tinnhiemmang/press) thành Markdown sạch (tuỳ chọn dùng LLM)."

    def add_arguments(self, parser):
        parser.add_argument("--llm", action="store_true",
                            help="Dùng LLM nhỏ để làm sạch/định dạng lại Markdown.")
        parser.add_argument("--model", default=None,
                            help="Tên model (mặc định: SMALL_MODEL trong settings).")
        parser.add_argument("--limit", type=int, default=None, help="Giới hạn số bài.")
        parser.add_argument("--dry-run", action="store_true", help="Không ghi DB, chỉ thống kê.")

    def handle(self, *args, **options):
        use_llm = options.get("llm", False)
        model = options.get("model") or getattr(settings, "SMALL_MODEL", None)
        self.stdout.write(self.style.NOTICE(
            f"=== FORMAT NEWS -> MARKDOWN ===\n"
            f"LLM: {'CÓ (' + str(model) + ')' if use_llm else 'không'}"
            f" | limit={options.get('limit')} | dry_run={options.get('dry_run')}"
        ))
        stats = reformat_news_markdown(
            use_llm=use_llm,
            model=model,
            limit=options.get("limit"),
            dry_run=options.get("dry_run", False),
        )
        self.stdout.write(self.style.SUCCESS(
            f"Xong: {stats['updated']}/{stats['total']} bài cập nhật, "
            f"LLM dùng cho {stats['llm_used']} bài, bỏ qua {stats['skipped']}, "
            f"lỗi {stats['errors']} trong {stats['duration_seconds']}s."
        ))
