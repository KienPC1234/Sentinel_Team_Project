"""
Lệnh Django: tổng hợp tin lừa đảo từ **VnExpress** (tag "Lừa đảo qua mạng") vào Article.

Cách dùng::

    python manage.py sync_vnexpress
    python manage.py sync_vnexpress --limit 20
    python manage.py sync_vnexpress --force
    python manage.py sync_vnexpress --update-only      # chỉ ghi đè bài đã có, không tạo mới
    python manage.py sync_vnexpress --refresh-existing # ghi đè lại toàn bộ bài VnExpress hiện có
    python manage.py sync_vnexpress --no-images
"""

from django.core.management.base import BaseCommand

from api.maintenance.vnexpress_feed import (
    refresh_existing_vnexpress_articles,
    sync_vnexpress_articles,
)
from api.utils.tinnhiemmang import VNEXPRESS_FEED_CONFIGS


class Command(BaseCommand):
    help = "Tổng hợp tin lừa đảo từ VnExpress (tag 'Lừa đảo qua mạng') vào ShieldCall VN (Article CMS)."

    def add_arguments(self, parser):
        parser.add_argument("--feed", choices=list(VNEXPRESS_FEED_CONFIGS.keys()),
                            help="Chỉ tổng hợp feed cụ thể.")
        parser.add_argument("--limit", type=int, default=15, help="Số bài tối đa mỗi feed (mặc định 15).")
        parser.add_argument("--max-pages", type=int, default=None,
                            help="Số trang tag tối đa cần duyệt (mặc định: tất cả các trang).")
        parser.add_argument("--dedup-llm", action="store_true",
                            help="Dùng LLM nhỏ để lọc tin trùng ở ca nghi ngờ.")
        parser.add_argument("--force", action="store_true", help="Ghi đè nếu bài đã tồn tại.")
        parser.add_argument("--no-images", action="store_true", help="Bỏ qua tải ảnh bìa.")
        parser.add_argument("--rebuild-rag", action="store_true", help="Cập nhật lại Vector DB RAG sau khi xong.")
        parser.add_argument("--update-only", action="store_true",
                            help="Chỉ ghi đè bài đã tồn tại, KHÔNG tạo bài mới.")
        parser.add_argument("--refresh-existing", action="store_true",
                            help="Ghi đè lại TOÀN BỘ bài VnExpress hiện có (không tạo bài mới).")

    def handle(self, *args, **options):
        feed_keys = [options["feed"]] if options.get("feed") else list(VNEXPRESS_FEED_CONFIGS.keys())
        limit = options.get("limit") or 15
        force = options.get("force", False)
        download_images = not options.get("no_images", False)
        rebuild_rag = options.get("rebuild_rag", False)
        update_only = options.get("update_only", False)
        refresh_existing = options.get("refresh_existing", False)

        self.stdout.write(self.style.NOTICE(
            f"=== TỔNG HỢP TIN VNEXPRESS (Lừa đảo qua mạng) ===\n"
            f"Feeds: {', '.join(feed_keys)} | Giới hạn: {limit} bài/feed | "
            f"Ảnh: {'Có' if download_images else 'Không'} | Ghi đè: {'Có' if force else 'Không'}\n"
            f"Chế độ: {'GHI ĐÈ TOÀN BỘ BÀI HIỆN CÓ' if refresh_existing else ('chỉ ghi đè (không tạo mới)' if update_only else 'bình thường')}"
        ))

        try:
            if refresh_existing:
                stats = refresh_existing_vnexpress_articles(
                    download_images=download_images, rebuild_rag=rebuild_rag, limit=limit or None)
                self.stdout.write(self.style.SUCCESS(
                    f"\n=== HOÀN TẤT (GHI ĐÈ) ===\nGhi đè: {stats['updated']} | "
                    f"Bỏ qua: {stats['skipped']} | Lỗi: {stats['errors']} | "
                    f"Thời gian: {stats['duration_seconds']}s"))
                return

            stats = sync_vnexpress_articles(
                feed_keys=feed_keys, limit_per_feed=limit, download_images=download_images,
                force_update=force, rebuild_rag=rebuild_rag, create_new=not update_only,
                max_pages=options.get("max_pages"),
                dedup_llm=options.get("dedup_llm", False),
            )
            self.stdout.write(self.style.SUCCESS(
                f"\n=== HOÀN TẤT ===\nTạo mới: {stats['created']} | Cập nhật: {stats['updated']} | "
                f"Bỏ qua: {stats['skipped']} | Lỗi: {stats['errors']} | "
                f"Thời gian: {stats['duration_seconds']}s"))
            for fk, fs in stats.get("feed_stats", {}).items():
                self.stdout.write(f" - [{fk}]: {fs.get('created',0)} mới, "
                                  f"{fs.get('updated',0)} cập nhật, {fs.get('skipped',0)} bỏ qua")
        except Exception as exc:  # noqa: BLE001
            self.stderr.write(self.style.ERROR(f"Tổng hợp VnExpress thất bại: {exc}"))
