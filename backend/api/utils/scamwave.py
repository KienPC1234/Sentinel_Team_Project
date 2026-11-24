"""
ShieldCall VN — Tích hợp nguồn dữ liệu ScamWave (https://scamwave.com/).

Cung cấp:
- Đồng bộ danh bạ cảnh báo từ https://scamwave.com/scammers/ (script#tableData JSON)
  vào snapshot cục bộ (`api/core/data/scamwave/scammers.jsonl` + `meta.json`).
- Tra cứu nhanh (< 1ms từ chỉ mục bộ nhớ, fallback tải trực tiếp khi chưa có snapshot)
  cho tên miền (khớp chính xác host hoặc tên miền gốc apex, tránh trùng chuỗi con),
  số điện thoại, tài khoản hoặc thực thể.
- Tìm bài viết/cảnh báo liên quan trên https://scamwave.com/ qua WP REST API khi quét sâu.
"""

from __future__ import annotations

import json
import logging
import re
import threading
import time
from collections import Counter
from datetime import datetime, timezone as dt_timezone
from html import unescape
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from django.core.cache import cache

from api.utils.normalization import normalize_domain

logger = logging.getLogger(__name__)

SCAMWAVE_BASE_URL = "https://scamwave.com/"
SCAMWAVE_DIRECTORY_URL = "https://scamwave.com/scammers/"
SCAMWAVE_WP_POSTS_URL = "https://scamwave.com/wp-json/wp/v2/posts"

DATA_DIR = Path(__file__).resolve().parents[1] / "core" / "data" / "scamwave"
RECORDS_PATH = DATA_DIR / "scammers.jsonl"
META_PATH = DATA_DIR / "meta.json"

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/128.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    "Accept-Language": "vi-VN,vi;q=0.9,en-US;q=0.8,en;q=0.7",
}

_INDEX_LOCK = threading.Lock()
_INDEX_CACHE: Dict[str, Any] = {
    "loaded_at": 0.0,
    "file_mtime": 0.0,
    "exact_map": {},       # lower(name) -> [{"name": ..., "status": ...}]
    "rows": [],            # list of {"name": ..., "status": ...}
    "meta": {},
}

SCAMWAVE_RISK_STATUSES = {"scam", "ponzi", "illegal"}
SCAMWAVE_CAUTION_STATUSES = {"doubtful", "closed"}


def _clean_host_candidate(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return ""
    if "://" in text or "/" in text:
        parsed = urlparse(text if "://" in text else f"https://{text}")
        host = (parsed.netloc or parsed.path or "").split("@")[-1].split(":")[0]
    else:
        host = text.split(":")[0]
    host = normalize_domain(host) or host.lower().strip(".")
    if host.startswith("www."):
        host = host[4:]
    return host


def _looks_like_domain(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[a-z0-9-]+\.)+[a-z]{2,}", (value or "").lower()))


def _domain_lookup_candidates(host: str) -> List[str]:
    clean = _clean_host_candidate(host)
    if not clean:
        return []
    candidates = [clean]
    parts = [p for p in clean.split(".") if p]
    if len(parts) > 2:
        apex = ".".join(parts[-2:])
        if apex not in candidates:
            candidates.append(apex)
    return candidates


def fetch_scamwave_directory(timeout: int = 25) -> Dict[str, Any]:
    """Tải và phân tích dữ liệu bảng công khai từ https://scamwave.com/scammers/."""
    resp = requests.get(SCAMWAVE_DIRECTORY_URL, headers=_HEADERS, timeout=timeout)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text or "", "html.parser")
    script_tag = soup.find("script", id="tableData")
    if not script_tag or not script_tag.string:
        raise ValueError("Không tìm thấy script#tableData trên scamwave.com/scammers/")

    payload = json.loads(script_tag.string.strip())
    columns = [str(c).strip() for c in (payload.get("columns") or ["NAME", "STATUS"])]
    data_rows = payload.get("data") or []

    name_idx = columns.index("NAME") if "NAME" in columns else 0
    status_idx = columns.index("STATUS") if "STATUS" in columns else 1

    records: List[Dict[str, str]] = []
    seen = set()
    status_counts: Counter[str] = Counter()

    for row in data_rows:
        if not isinstance(row, list) or len(row) <= name_idx:
            continue
        raw_name = str(row[name_idx] or "").strip()
        if not raw_name:
            continue
        raw_status = str(row[status_idx] or "Scam").strip() if len(row) > status_idx else "Scam"
        norm_name = _clean_host_candidate(raw_name) if _looks_like_domain(_clean_host_candidate(raw_name)) else raw_name.lower()
        dedup_key = (norm_name, raw_status.lower())
        if dedup_key in seen:
            continue
        seen.add(dedup_key)
        status_counts[raw_status] += 1
        records.append({
            "name": raw_name,
            "normalized": norm_name,
            "status": raw_status,
            "source_url": SCAMWAVE_DIRECTORY_URL,
        })

    return {
        "columns": columns,
        "records": records,
        "status_counts": dict(status_counts),
        "updated_at": datetime.now(dt_timezone.utc).strftime("%Y-%m-%d"),
        "synced_at": datetime.now(dt_timezone.utc).isoformat(),
    }


def _invalidate_memory_index() -> None:
    with _INDEX_LOCK:
        _INDEX_CACHE["loaded_at"] = 0.0
        _INDEX_CACHE["file_mtime"] = 0.0
        _INDEX_CACHE["exact_map"] = {}
        _INDEX_CACHE["rows"] = []
        _INDEX_CACHE["meta"] = {}


def sync_scamwave(timeout: int = 25) -> Dict[str, Any]:
    """Tải mới danh bạ ScamWave và lưu JSONL/metadata ra đĩa + làm mới cache."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    fetched = fetch_scamwave_directory(timeout=timeout)
    records = fetched["records"]

    tmp_jsonl = RECORDS_PATH.with_suffix(".jsonl.tmp")
    with tmp_jsonl.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    tmp_jsonl.replace(RECORDS_PATH)

    meta = {
        "source": "scamwave",
        "source_name": "ScamWave (scamwave.com)",
        "source_url": SCAMWAVE_DIRECTORY_URL,
        "count": len(records),
        "status_counts": fetched["status_counts"],
        "updated_at": fetched["updated_at"],
        "synced_at": fetched["synced_at"],
    }
    tmp_meta = META_PATH.with_suffix(".json.tmp")
    tmp_meta.write_text(json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp_meta.replace(META_PATH)

    _invalidate_memory_index()
    try:
        cache.set("scamwave_dataset_stats", meta, timeout=86400)
    except Exception:
        pass
    return meta


def _load_index(refresh_if_empty: bool = False) -> Tuple[Dict[str, List[Dict[str, str]]], List[Dict[str, str]], Dict[str, Any]]:
    with _INDEX_LOCK:
        file_mtime = RECORDS_PATH.stat().st_mtime if RECORDS_PATH.exists() else 0.0
        now = time.time()
        if (
            _INDEX_CACHE["rows"]
            and _INDEX_CACHE["file_mtime"] == file_mtime
            and (now - _INDEX_CACHE["loaded_at"]) < 3600
        ):
            return _INDEX_CACHE["exact_map"], _INDEX_CACHE["rows"], _INDEX_CACHE["meta"]

    if not RECORDS_PATH.exists() and refresh_if_empty:
        try:
            sync_scamwave(timeout=20)
        except Exception as exc:
            logger.warning("scamwave live bootstrap failed: %s", exc)

    exact_map: Dict[str, List[Dict[str, str]]] = {}
    rows: List[Dict[str, str]] = []
    meta: Dict[str, Any] = {}

    if META_PATH.exists():
        try:
            meta = json.loads(META_PATH.read_text(encoding="utf-8"))
        except Exception:
            meta = {}

    if RECORDS_PATH.exists():
        try:
            with RECORDS_PATH.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        continue
                    norm = str(rec.get("normalized") or rec.get("name") or "").lower().strip()
                    if not norm:
                        continue
                    rows.append(rec)
                    exact_map.setdefault(norm, []).append(rec)
            file_mtime = RECORDS_PATH.stat().st_mtime
        except Exception as exc:
            logger.warning("Failed reading scamwave snapshot: %s", exc)
            file_mtime = 0.0
    else:
        file_mtime = 0.0

    with _INDEX_LOCK:
        _INDEX_CACHE["loaded_at"] = time.time()
        _INDEX_CACHE["file_mtime"] = file_mtime
        _INDEX_CACHE["exact_map"] = exact_map
        _INDEX_CACHE["rows"] = rows
        _INDEX_CACHE["meta"] = meta
        return exact_map, rows, meta


def scamwave_dataset_stats() -> Dict[str, Any]:
    """Trả thống kê snapshot ScamWave hiện có trên đĩa."""
    _, rows, meta = _load_index(refresh_if_empty=False)
    if meta:
        return {**meta, "count": meta.get("count", len(rows))}
    return {
        "source": "scamwave",
        "source_name": "ScamWave (scamwave.com)",
        "source_url": SCAMWAVE_DIRECTORY_URL,
        "count": len(rows),
        "status_counts": {},
        "updated_at": None,
    }


def search_scamwave_articles(query: str, max_results: int = 3, timeout: int = 5) -> List[Dict[str, str]]:
    """Tìm bài viết cảnh báo/đánh giá chuyên gia trên scamwave.com qua WP JSON API."""
    clean = (query or "").strip()
    if len(clean) < 3:
        return []
    cache_key = f"scamwave_wp_{clean.lower()[:80]}"
    try:
        cached = cache.get(cache_key)
        if cached is not None:
            return cached
    except Exception:
        pass

    articles: List[Dict[str, str]] = []
    try:
        resp = requests.get(
            SCAMWAVE_WP_POSTS_URL,
            params={"search": clean, "per_page": max_results},
            headers=_HEADERS,
            timeout=timeout,
        )
        if resp.status_code == 200:
            for item in (resp.json() or [])[:max_results]:
                raw_title = (item.get("title") or {}).get("rendered") or ""
                title = unescape(BeautifulSoup(raw_title, "html.parser").get_text(" ", strip=True))
                raw_excerpt = (item.get("excerpt") or {}).get("rendered") or ""
                excerpt = unescape(BeautifulSoup(raw_excerpt, "html.parser").get_text(" ", strip=True))[:240]
                link = str(item.get("link") or "").strip()
                if title and link:
                    articles.append({
                        "title": title,
                        "url": link,
                        "excerpt": excerpt,
                        "date": str(item.get("date") or "")[:10],
                    })
    except Exception as exc:
        logger.debug("search_scamwave_articles(%r) error: %s", clean, exc)

    try:
        cache.set(cache_key, articles, timeout=3600)
    except Exception:
        pass
    return articles


def lookup_scamwave(
    query: str,
    *,
    include_articles: bool = False,
    refresh_if_empty: bool = False,
) -> Optional[Dict[str, Any]]:
    """
    Tra cứu một tên miền/URL/SĐT/tài khoản trong danh bạ ScamWave (scamwave.com).

    Khớp tên miền chính xác theo host hoặc apex domain (tránh khớp chuỗi con sai lệch).
    """
    clean_query = (query or "").strip()
    if not clean_query:
        return None

    exact_map, rows, meta = _load_index(refresh_if_empty=refresh_if_empty)

    host_candidate = _clean_host_candidate(clean_query)
    is_domain = _looks_like_domain(host_candidate)
    matches: List[Dict[str, str]] = []

    if is_domain:
        seen_names = set()
        for cand in _domain_lookup_candidates(host_candidate):
            for rec in exact_map.get(cand, []):
                key = (rec.get("name", "").lower(), rec.get("status", "").lower())
                if key not in seen_names:
                    seen_names.add(key)
                    matches.append(rec)
    else:
        q_lower = clean_query.lower()
        q_compact = re.sub(r"[^a-z0-9]", "", q_lower)
        # Chỉ khớp token/giá trị đầy đủ, tránh query ngắn khớp bừa
        for rec in exact_map.get(q_lower, []):
            matches.append(rec)
        if not matches and len(q_compact) >= 6:
            for rec in rows:
                name_l = str(rec.get("name") or "").lower()
                name_compact = re.sub(r"[^a-z0-9]", "", name_l)
                if name_compact == q_compact or q_lower == name_l:
                    matches.append(rec)
                    if len(matches) >= 10:
                        break

    articles: List[Dict[str, str]] = []
    if include_articles:
        search_term = host_candidate if is_domain else clean_query
        articles = search_scamwave_articles(search_term, max_results=3)

    updated_at = meta.get("updated_at")
    total_count = meta.get("count") or len(rows)
    primary_status = matches[0].get("status") if matches else None

    if matches:
        summary_lines = [
            f"ScamWave ghi nhận {len(matches)} mục trùng khớp cho '{host_candidate if is_domain else clean_query}' "
            f"(trong {total_count} mục danh bạ, cập nhật {updated_at or 'gần đây'}):",
        ]
        for rec in matches[:10]:
            summary_lines.append(f"- NAME={rec['name']}; STATUS={rec['status']}")
        summary_lines.append(
            "Lưu ý độ tin cậy: ScamWave là danh mục cảnh báo cộng đồng chỉ gồm tên thực thể và nhãn trạng thái "
            "(Scam/Doubtful/Ponzi/Closed/Illegal), không có hồ sơ bằng chứng chi tiết — cần đối chiếu chéo với "
            "website nhà phát hành/cơ quan chính thức."
        )
    else:
        summary_lines = [
            f"Không tìm thấy '{host_candidate if is_domain else clean_query}' trong danh bạ {total_count} mục của ScamWave "
            f"(https://scamwave.com/scammers/)."
        ]

    if articles:
        summary_lines.append("")
        summary_lines.append("Bài viết liên quan trên ScamWave:")
        for art in articles:
            summary_lines.append(f"- {art['title']} ({art['url']})")

    links = [SCAMWAVE_DIRECTORY_URL] + [art["url"] for art in articles if art.get("url")]

    return {
        "source": "scamwave",
        "matched": bool(matches),
        "matches": matches,
        "primary_status": primary_status,
        "articles": articles,
        "updated_at": updated_at,
        "dataset_count": total_count,
        "query_url": SCAMWAVE_DIRECTORY_URL,
        "title": f"ScamWave lookup for {host_candidate if is_domain else clean_query}",
        "content": "\n".join(summary_lines),
        "links": links,
    }
