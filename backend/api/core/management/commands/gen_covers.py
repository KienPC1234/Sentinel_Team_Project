"""
Lệnh Django: sinh ảnh bìa (cover) cho bài viết / bài học **thiếu ảnh** theo thương hiệu.

Cách dùng::

    python manage.py gen_covers                 # chỉ cấp cho mục đang thiếu ảnh
    python manage.py gen_covers --type lesson
    python manage.py gen_covers --overwrite     # ghi đè cả mục đã có ảnh
"""

from django.core.files.base import ContentFile
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils.text import slugify

from api.core.models import Article, LearnLesson
from api.utils.cover_gen import generate_cover


def _save_cover(obj, prefix: str, category: str, subtitle: str = "") -> None:
    data = generate_cover(obj.title, category, subtitle=subtitle)
    slug = (slugify(getattr(obj, "slug", "") or obj.title, allow_unicode=False) or f"item-{obj.id}")[:60]
    obj.cover_image.save(f"{prefix}_{slug}.jpg", ContentFile(data), save=True)


class Command(BaseCommand):
    help = "Sinh ảnh bìa cho bài viết/bài học thiếu ảnh."

    def add_arguments(self, parser):
        parser.add_argument("--type", choices=["article", "lesson", "all"], default="all")
        parser.add_argument("--overwrite", action="store_true", help="Ghi đè cả mục đã có ảnh.")

    def handle(self, *args, **options):
        kind = options.get("type", "all")
        overwrite = options.get("overwrite", False)

        def _qs(model):
            return model.objects.all() if overwrite else model.objects.filter(
                Q(cover_image="") | Q(cover_image__isnull=True))

        n_art = n_les = 0
        if kind in ("article", "all"):
            for a in _qs(Article):
                try:
                    _save_cover(a, "gen", a.category or "default",
                                subtitle=(a.summary or "")[:120])
                    n_art += 1
                except Exception as exc:  # noqa: BLE001
                    self.stderr.write(self.style.WARNING(f"Article #{a.id} lỗi: {exc}"))
        if kind in ("lesson", "all"):
            for l in _qs(LearnLesson):
                try:
                    _save_cover(l, "gen", l.category or "guide",
                                subtitle=(l.summary or "")[:120])
                    n_les += 1
                except Exception as exc:  # noqa: BLE001
                    self.stderr.write(self.style.WARNING(f"Lesson #{l.id} lỗi: {exc}"))

        self.stdout.write(self.style.SUCCESS(
            f"Đã sinh cover: {n_art} bài viết, {n_les} bài học."))
