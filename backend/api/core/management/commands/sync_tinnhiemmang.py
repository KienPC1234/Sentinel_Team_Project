"""
Lệnh Django: Tổng hợp tin tức & cảnh báo lừa đảo từ tinnhiemmang.vn vào ShieldCall VN.

Cách dùng:
    python manage.py sync_tinnhiemmang
    python manage.py sync_tinnhiemmang --limit 10
    python manage.py sync_tinnhiemmang --feed canh_bao_lua_dao
    python manage.py sync_tinnhiemmang --feed noi_bat
    python manage.py sync_tinnhiemmang --force
    python manage.py sync_tinnhiemmang --no-images
    python manage.py sync_tinnhiemmang --rebuild-rag
"""

from django.core.management.base import BaseCommand
from api.maintenance.tinnhiemmang_feed import (
    refresh_existing_tinnhiemmang_articles,
    sync_tinnhiemmang_articles,
)
from api.utils.tinnhiemmang import NEWS_FEED_CONFIGS


class Command(BaseCommand):
    help = "Tổng hợp tin tức & cảnh báo an toàn từ tinnhiemmang.vn vào ShieldCall VN (Article CMS)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--feed",
            choices=list(NEWS_FEED_CONFIGS.keys()),
            help="Chỉ tổng hợp feed cụ thể ('canh_bao_lua_dao' hoặc 'noi_bat').",
        )
        parser.add_argument(
            "--limit",
            type=int,
            default=15,
            help="Số bài viết tối đa cần lấy trên mỗi feed (mặc định: 15).",
        )
        parser.add_argument(
            "--force",
            action="store_true",
            help="Bắt buộc cập nhật lại nội dung nếu bài viết đã tồn tại.",
        )
        parser.add_argument(
            "--no-images",
            action="store_true",
            help="Bỏ qua việc tải ảnh bìa bài viết.",
        )
        parser.add_argument(
            "--rebuild-rag",
            action="store_true",
            help="Tự động cập nhật / xây dựng lại chỉ mục Vector DB RAG sau khi hoàn thành.",
        )
        parser.add_argument(
            "--update-only",
            action="store_true",
            help="Chỉ ghi đè bài đã tồn tại, KHÔNG tạo bài mới.",
        )
        parser.add_argument(
            "--refresh-existing",
            action="store_true",
            help="Ghi đè lại TOÀN BỘ bài tinnhiemmang hiện có (không tạo bài mới).",
        )
        parser.add_argument(
            "--dedup-llm",
            action="store_true",
            help="Dùng LLM nhỏ để lọc tin trùng ở ca nghi ngờ.",
        )

    def handle(self, *args, **options):
        feed_choice = options.get("feed")
        feed_keys = [feed_choice] if feed_choice else ["canh_bao_lua_dao", "noi_bat"]
        limit = options.get("limit") or 15
        force = options.get("force", False)
        download_images = not options.get("no_images", False)
        rebuild_rag = options.get("rebuild_rag", False)
        update_only = options.get("update_only", False)
        refresh_existing = options.get("refresh_existing", False)

        self.stdout.write(self.style.NOTICE(
            f"=== BẮT ĐẦU TỔNG HỢP TIN NHIỆM MẠNG ==="
            f"\nFeeds: {', '.join(feed_keys)}"
            f"\nGiới hạn: {limit} bài/feed"
            f"\nTải ảnh: {'Có' if download_images else 'Không'}"
            f"\nGhi đè: {'Có' if force else 'Không'}"
            f"\nChế độ: {'GHI ĐÈ TOÀN BỘ BÀI HIỆN CÓ' if refresh_existing else ('chỉ ghi đè (không tạo mới)' if update_only else 'bình thường')}"
        ))

        try:
            if refresh_existing:
                stats = refresh_existing_tinnhiemmang_articles(
                    download_images=download_images,
                    rebuild_rag=rebuild_rag,
                    limit=limit or None,
                )
                self.stdout.write(self.style.SUCCESS(
                    f"\n=== HOÀN TẤT (GHI ĐÈ BÀI HIỆN CÓ) ==="
                    f"\nGhi đè:   {stats['updated']} bài viết"
                    f"\nBỏ qua:   {stats['skipped']} bài"
                    f"\nLỗi:      {stats['errors']}"
                    f"\nThời gian:{stats['duration_seconds']} giây"
                ))
                return

            stats = sync_tinnhiemmang_articles(
                feed_keys=feed_keys,
                limit_per_feed=limit,
                download_images=download_images,
                force_update=force,
                rebuild_rag=rebuild_rag,
                create_new=not update_only,
                dedup_llm=options.get("dedup_llm", False),
            )

            self.stdout.write(self.style.SUCCESS(
                f"\n=== HOÀN TẤT THÀNH CÔNG ==="
                f"\nTạo mới:  {stats['created']} bài viết"
                f"\nCập nhật: {stats['updated']} bài viết"
                f"\nBỏ qua:   {stats['skipped']} bài (đã tồn tại/không tạo mới)"
                f"\nLỗi:      {stats['errors']}"
                f"\nThời gian:{stats['duration_seconds']} giây"
            ))

            for feed_k, feed_st in stats.get("feed_stats", {}).items():
                self.stdout.write(
                    f" - [{feed_k}]: {feed_st.get('created', 0)} mới, "
                    f"{feed_st.get('updated', 0)} cập nhật, {feed_st.get('skipped', 0)} bỏ qua"
                )

        except Exception as exc:
            self.stderr.write(self.style.ERROR(f"Quá trình tổng hợp thất bại: {exc}"))

