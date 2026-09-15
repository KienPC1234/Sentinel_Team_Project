"""
Threat Intelligence Feed Ingestion Service for Sentinel.
Fetches, normalizes, and ingests scam/phishing/malware indicators from
active public threat feeds into the Domain model.
"""
import csv
import io
import ipaddress
import logging
import re
import time
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlparse

import requests
from django.conf import settings
from django.core.cache import cache
from django.db import connection
from django.utils import timezone

from api.core.models import Domain, ScamType
from api.utils.normalization import normalize_domain

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT_SECONDS = getattr(settings, 'THREAT_FEED_TIMEOUT_SECONDS', 30)
DEFAULT_USER_AGENT = getattr(settings, 'THREAT_FEED_USER_AGENT', "Sentinel-ThreatIntel/1.0 (+https://sc.fptoj.com)")

FEED_CONFIGS = {
    "urlhaus": {
        "name": "URLhaus (abuse.ch)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_recent/",
        "type": "csv_urlhaus",
        "description": "Active malware and phishing distribution URLs curated by abuse.ch",
    },
    "openphish": {
        "name": "OpenPhish",
        "url": "https://openphish.com/feed.txt",
        "type": "plaintext_urls",
        "description": "Real-time verified zero-day phishing feeds",
    },
    "phishing_db": {
        "name": "Phishing.Database",
        "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
        "type": "plaintext_domains",
        "description": "Actively maintained community repository of malicious phishing domains",
    },
}

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)


def is_valid_public_domain_or_ip(host: str) -> bool:
    """
    Validate that a given hostname or IP is a valid public internet target.
    Rejects localhost, private IP ranges (RFC 1918), link-local, and reserved names.
    """
    if not host or len(host) > 253 or len(host) < 3:
        return False

    host = host.lower().strip().strip(".")

    # Reject localhost / test / example domains
    if host in ("localhost", "local", "invalid", "test"):
        return False
    if host.endswith((".localhost", ".test", ".example", ".invalid", ".local", ".internal")):
        return False

    # Check if host is an IP address
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
        return True
    except ValueError:
        pass

    # Host is a domain name
    return bool(DOMAIN_REGEX.match(host))


def clean_domain_target(target: str) -> Optional[str]:
    """
    Normalizes a URL or raw domain to a clean canonical hostname.
    Strips schemes, paths, queries, ports, and 'www.' prefixes.
    """
    if not target:
        return None

    raw = str(target).strip().strip("\"'").rstrip("/")
    if not raw:
        return None

    # Handle defanged URLs like hxxp:// or hxxps://
    raw = re.sub(r"^hxxp", "http", raw, flags=re.IGNORECASE)

    # Use standard normalization helper
    norm = normalize_domain(raw)
    if not norm:
        return None

    norm = norm.lower().strip()
    if norm.startswith("www."):
        norm = norm[4:]

    if is_valid_public_domain_or_ip(norm):
        return norm

    return None


def fetch_urlhaus_feed(limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """
    Stream and parse URLhaus recent CSV feed.
    """
    config = FEED_CONFIGS["urlhaus"]
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    response = requests.get(
        config["url"], headers=headers, stream=True, timeout=REQUEST_TIMEOUT_SECONDS
    )
    response.raise_for_status()

    yielded_count = 0
    lines = (line.decode("utf-8", errors="ignore") for line in response.iter_lines())
    for line in lines:
        if limit and yielded_count >= limit:
            break
        if not line or line.startswith("#"):
            continue

        try:
            row = next(csv.reader([line]))
            if len(row) < 8:
                continue

            raw_url = row[2]
            threat = row[5]
            tags = row[6]
            urlhaus_link = row[7]

            domain = clean_domain_target(raw_url)
            if not domain:
                continue

            yield {
                "domain": domain,
                "source": "URLhaus",
                "threat": threat or "malware_distribution",
                "tags": tags or "",
                "ref_url": urlhaus_link,
                "scam_type": ScamType.PHISHING,
            }
            yielded_count += 1
        except Exception as err:
            logger.debug(f"[URLhaus] Parsing error on line: {err}")
            continue


def fetch_openphish_feed(limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """
    Stream and parse OpenPhish active plain-text URL feed.
    """
    config = FEED_CONFIGS["openphish"]
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    response = requests.get(
        config["url"], headers=headers, stream=True, timeout=REQUEST_TIMEOUT_SECONDS
    )
    response.raise_for_status()

    yielded_count = 0
    for line in response.iter_lines():
        if limit and yielded_count >= limit:
            break
        url = line.decode("utf-8", errors="ignore").strip()
        if not url or url.startswith("#"):
            continue

        domain = clean_domain_target(url)
        if not domain:
            continue

        yield {
            "domain": domain,
            "source": "OpenPhish",
            "threat": "phishing",
            "tags": "verified_phishing",
            "ref_url": url,
            "scam_type": ScamType.PHISHING,
        }
        yielded_count += 1


def fetch_phishing_db_feed(limit: Optional[int] = None) -> Iterator[Dict[str, Any]]:
    """
    Stream and parse Phishing.Database active domain feed.
    """
    config = FEED_CONFIGS["phishing_db"]
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    response = requests.get(
        config["url"], headers=headers, stream=True, timeout=REQUEST_TIMEOUT_SECONDS
    )
    response.raise_for_status()

    yielded_count = 0
    for line in response.iter_lines():
        if limit and yielded_count >= limit:
            break
        raw_domain = line.decode("utf-8", errors="ignore").strip()
        if not raw_domain or raw_domain.startswith("#"):
            continue

        domain = clean_domain_target(raw_domain)
        if not domain:
            continue

        yield {
            "domain": domain,
            "source": "Phishing.Database",
            "threat": "phishing",
            "tags": "community_phishing",
            "ref_url": "",
            "scam_type": ScamType.PHISHING,
        }
        yielded_count += 1


FEED_FETCHERS = {
    "urlhaus": fetch_urlhaus_feed,
    "openphish": fetch_openphish_feed,
    "phishing_db": fetch_phishing_db_feed,
}


def _execute_bulk_upsert(domains_batch: List[Domain]) -> int:
    """
    Execute batch upsert on Domain model compatible with MySQL, SQLite, and PostgreSQL.
    """
    if not domains_batch:
        return 0

    engine = connection.settings_dict.get("ENGINE", "").lower()
    update_cols = ["risk_score", "whois_snapshot", "scam_type"]

    if "mysql" in engine:
        # MySQL ON DUPLICATE KEY UPDATE does not accept unique_fields
        Domain.objects.bulk_create(
            domains_batch,
            update_conflicts=True,
            update_fields=update_cols,
        )
    else:
        # SQLite and PostgreSQL require explicit unique_fields
        Domain.objects.bulk_create(
            domains_batch,
            update_conflicts=True,
            unique_fields=["domain_name"],
            update_fields=update_cols,
        )
    return len(domains_batch)


def sync_threat_feeds(
    limit_per_feed: Optional[int] = 10000,
    sources: Optional[List[str]] = None,
    batch_size: int = 2000,
) -> Dict[str, Any]:
    """
    Orchestrate ingestion from enabled threat feeds.

    Args:
        limit_per_feed: Max records to read per feed (None or 0 for unlimited).
        sources: Subset of feed keys to run (defaults to all configured feeds).
        batch_size: Number of records to upsert per database query.

    Returns:
        Structured statistics summary of the sync run.
    """
    start_time = time.time()
    effective_limit = None if (limit_per_feed is None or limit_per_feed <= 0) else limit_per_feed
    selected_sources = sources or list(FEED_CONFIGS.keys())

    stats: Dict[str, Any] = {
        "status": "RUNNING",
        "started_at": timezone.now().isoformat(),
        "sources": {},
        "total_fetched": 0,
        "total_distinct": 0,
        "total_saved": 0,
        "duration_seconds": 0.0,
        "errors": [],
    }

    # Consolidated domain mapping to ensure uniqueness within batch
    accumulated_domains: Dict[str, Domain] = {}
    now_iso = timezone.now().isoformat()

    for src_key in selected_sources:
        if src_key not in FEED_FETCHERS:
            stats["errors"].append(f"Unknown source: {src_key}")
            continue

        fetcher = FEED_FETCHERS[src_key]
        src_name = FEED_CONFIGS[src_key]["name"]
        src_stats = {"fetched": 0, "valid_domains": 0, "status": "PENDING", "error": None}
        stats["sources"][src_key] = src_stats

        logger.info(f"[ThreatIntel] Starting sync for {src_name} (limit={effective_limit})")
        src_start = time.time()

        try:
            for item in fetcher(limit=effective_limit):
                src_stats["fetched"] += 1
                dom = item["domain"]
                src_stats["valid_domains"] += 1

                # Build or update domain instance
                metadata = {
                    "source": item["source"],
                    "threat": item.get("threat", "phishing"),
                    "tags": item.get("tags", ""),
                    "ref_url": item.get("ref_url", ""),
                    "synced_at": now_iso,
                }

                accumulated_domains[dom] = Domain(
                    domain_name=dom,
                    risk_score=100,
                    scam_type=item.get("scam_type", ScamType.PHISHING),
                    whois_snapshot=metadata,
                )

                # Flush batch to database if threshold reached
                if len(accumulated_domains) >= batch_size:
                    batch_list = list(accumulated_domains.values())
                    saved_count = _execute_bulk_upsert(batch_list)
                    stats["total_saved"] += saved_count
                    accumulated_domains.clear()

            src_stats["status"] = "SUCCESS"
            src_stats["duration"] = round(time.time() - src_start, 2)
            logger.info(
                f"[ThreatIntel] Finished {src_name}: fetched {src_stats['fetched']} records in {src_stats['duration']}s"
            )

        except Exception as exc:
            logger.error(f"[ThreatIntel] Error syncing {src_name}: {exc}", exc_info=True)
            src_stats["status"] = "FAILED"
            src_stats["error"] = str(exc)
            stats["errors"].append(f"{src_name}: {str(exc)}")

    # Flush remaining accumulated records
    if accumulated_domains:
        batch_list = list(accumulated_domains.values())
        saved_count = _execute_bulk_upsert(batch_list)
        stats["total_saved"] += saved_count
        accumulated_domains.clear()

    total_fetched = sum(s.get("fetched", 0) for s in stats["sources"].values())
    stats["total_fetched"] = total_fetched
    stats["duration_seconds"] = round(time.time() - start_time, 2)
    stats["completed_at"] = timezone.now().isoformat()
    stats["status"] = "FAILED" if (stats["errors"] and stats["total_saved"] == 0) else "SUCCESS"

    # Cache sync summary for dashboard inspection (TTL: 7 days)
    cache.set("threat_intel_sync_summary", stats, timeout=86400 * 7)

    logger.info(
        f"[ThreatIntel] Pipeline completed in {stats['duration_seconds']}s. Total fetched: {stats['total_fetched']}, Upserted: {stats['total_saved']}"
    )
    return stats

