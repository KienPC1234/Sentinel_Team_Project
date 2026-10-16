"""
Lệnh Django: đồng bộ **danh bạ** Tín nhiệm mạng (tinnhiemmang.vn) — chỉ thêm mục mới.

Khác với ``sync_tinnhiemmang`` (tổng hợp *tin tức* thành Article), lệnh này thu thập
*danh bạ*: website/tổ chức/hệ thống/ứng dụng tín nhiệm và **website lừa đảo**, ghi ra
JSONL tại ``api/core/data/tinnhiemmang/<category>.jsonl`` rồi (tuỳ chọn) nạp danh sách
lừa đảo vào model ``Domain``.

Cách dùng::

    python manage.py sync_tinnhiem_directory                 # all, chỉ thêm mới, có ingest
    python manage.py sync_tinnhiem_directory --category fake
    python manage.py sync_tinnhiem_directory --workers 8 --stop-after-known 20
    python manage.py sync_tinnhiem_directory --no-ingest
    python manage.py sync_tinnhiem_directory --respect-robots

Lịch chạy hằng tuần (Celery beat): task ``api.maintenance.tasks.sync_tinnhiem_directory``.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError


class Command(BaseCommand):
    help = (
        "Đồng bộ danh bạ Tín nhiệm mạng (tinnhiemmang.vn): website/tổ chức/hệ thống/"
        "ứng dụng tín nhiệm + website lừa đảo; chỉ thêm mục mới (--resume)."
    )

    def add_arguments(self, parser):
        parser.add_argument("--category", default="all",
                            help="web|org|sys|app|iot|fake|all (mặc định: all)")
        parser.add_argument("--workers", type=int, default=None,
                            help="Số luồng tải song song (mặc định theo TINNHIEM_SYNC_WORKERS)")
        parser.add_argument("--delay", type=float, default=None,
                            help="Giây giữa 2 request (mặc định theo TINNHIEM_SYNC_DELAY)")
        parser.add_argument("--stop-after-known", type=int, default=0, metavar="N",
                            help="Dừng sau N trang liên tiếp không có mục mới (0 = quét hết)")
        parser.add_argument("--respect-robots", action="store_true",
                            help="Tôn trọng robots.txt (mặc định: bỏ qua — theo yêu cầu dữ liệu đầy đủ)")
        parser.add_argument("--no-ingest", action="store_true",
                            help="Không nạp danh sách lừa đảo vào model Domain sau khi thu thập")
        parser.add_argument("--json", action="store_true", help="In thống kê dạng JSON")

    def handle(self, *args, **options):
        base = Path(getattr(settings, "BASE_DIR", "."))
        script = base / "scripts" / "crawl_tinnhiemmang.py"
        if not script.exists():
            raise CommandError(f"Không tìm thấy crawler: {script}")

        workers = options["workers"] or int(getattr(settings, "TINNHIEM_SYNC_WORKERS", 8))
        delay = options["delay"] if options["delay"] is not None else float(
            getattr(settings, "TINNHIEM_SYNC_DELAY", 0.3)
        )
        # Mặc định: KHÔNG tôn trọng robots (site chặn /*?page=) — theo yêu cầu lấy đầy đủ.
        respect = bool(options["respect_robots"]) or bool(
            getattr(settings, "TINNHIEM_SYNC_RESPECT_ROBOTS", False)
        )

        cmd = [
            sys.executable, str(script),
            "--category", options["category"],
            "--all", "--resume",
            "--workers", str(workers),
            "--delay", str(delay),
        ]
        if options["stop_after_known"]:
            cmd += ["--stop-after-known", str(options["stop_after_known"])]
        if respect:
            cmd += ["--respect-robots"]
        if options["json"]:
            cmd += ["--json"]

        self.stdout.write(self.style.NOTICE(
            f"=== SYNC DANH BẠ TÍN NHIỆM MẠNG (tinnhiemmang.vn) ===\n"
            f"Danh mục: {options['category']} | workers={workers} | delay={delay}s | "
            f"robots={'tôn trọng' if respect else 'BỎ QUA (mặc định)'}"
        ))

        proc = subprocess.run(cmd, cwd=str(base))
        if proc.returncode != 0:
            raise CommandError(f"Crawler thoát với mã {proc.returncode}")

        # Làm mới chỉ mục SQLite để tra cứu tức thì (nhanh)
        try:
            from api.utils import tinnhiemmang as th
            th.reindex(options["category"])
        except Exception as exc:  # noqa: BLE001
            self.stderr.write(self.style.WARNING(f"reindex lỗi: {exc}"))

        if not options["no_ingest"]:
            try:
                from api.maintenance.threat_feeds import sync_threat_feeds
                stats = sync_threat_feeds(limit_per_feed=0, sources=["tinnhiem_fake"], batch_size=5000)
                self.stdout.write(self.style.SUCCESS(
                    f"Nạp vào Domain: {stats.get('total_saved', 0)} bản ghi "
                    f"({stats.get('total_fetched', 0)} đọc được)."
                ))
            except Exception as exc:  # noqa: BLE001
                self.stderr.write(self.style.ERROR(f"Ingest lỗi: {exc}"))

        # Tóm tắt số bản ghi hiện có
        try:
            from api.utils import tinnhiemmang as th
            avail = th.available_datasets()
            self.stdout.write("Dữ liệu hiện có: " + ", ".join(f"{k}={v}" for k, v in avail.items()))
        except Exception:  # noqa: BLE001
            pass

        self.stdout.write(self.style.SUCCESS("=== HOÀN TẤT SYNC DANH BẠ ==="))
