"""
Django Management Command to synchronize threat intelligence feeds into the Sentinel database.
Usage:
    python manage.py sync_threat_intel
    python manage.py sync_threat_intel --limit=1000 --sources=urlhaus,openphish
    python manage.py sync_threat_intel --limit=0 (unlimited)
"""
from django.core.management.base import BaseCommand
from api.maintenance.threat_feeds import sync_threat_feeds, FEED_CONFIGS


class Command(BaseCommand):
    help = "Synchronize malicious domains and phishing threat feeds into Domain database"

    def add_arguments(self, parser):
        parser.add_argument(
            "--limit",
            type=int,
            default=10000,
            help="Maximum items to ingest per feed (default: 10000, 0 for unlimited)",
        )
        parser.add_argument(
            "--sources",
            type=str,
            default="",
            help="Comma-separated list of feed keys to run (e.g. urlhaus,openphish,phishing_db). Defaults to all.",
        )
        parser.add_argument(
            "--batch-size",
            type=int,
            default=2000,
            help="Database bulk upsert batch size (default: 2000)",
        )

    def handle(self, *args, **options):
        limit = options.get("limit", 10000)
        sources_str = options.get("sources", "").strip()
        batch_size = options.get("batch_size", 2000)

        sources = [s.strip() for s in sources_str.split(",") if s.strip()] if sources_str else None

        self.stdout.write(self.style.NOTICE("Starting threat intelligence synchronization..."))
        self.stdout.write(f"Parameters: limit_per_feed={limit}, sources={sources or list(FEED_CONFIGS.keys())}, batch_size={batch_size}")

        stats = sync_threat_feeds(
            limit_per_feed=limit,
            sources=sources,
            batch_size=batch_size,
        )

        self.stdout.write("\n" + "=" * 60)
        self.stdout.write(f"{'Source':<25} | {'Fetched':<8} | {'Valid':<8} | {'Status':<10}")
        self.stdout.write("-" * 60)

        for src_key, s_data in stats.get("sources", {}).items():
            feed_name = FEED_CONFIGS.get(src_key, {}).get("name", src_key)
            fetched = s_data.get("fetched", 0)
            valid = s_data.get("valid_domains", 0)
            status_text = s_data.get("status", "UNKNOWN")
            self.stdout.write(f"{feed_name:<25} | {fetched:<8} | {valid:<8} | {status_text:<10}")

        self.stdout.write("=" * 60)
        self.stdout.write(f"Total Fetched:  {stats.get('total_fetched', 0)}")
        self.stdout.write(f"Total Upserted: {stats.get('total_saved', 0)}")
        self.stdout.write(f"Duration:       {stats.get('duration_seconds', 0)}s")

        if stats.get("errors"):
            self.stdout.write(self.style.ERROR(f"Errors encountered: {stats['errors']}"))

        if stats.get("status") == "SUCCESS":
            self.stdout.write(self.style.SUCCESS("\nThreat intelligence synchronization completed successfully."))
        else:
            self.stdout.write(self.style.WARNING("\nThreat intelligence synchronization completed with warnings/errors."))

