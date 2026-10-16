#!/usr/bin/env python
"""
ShieldCall VN — CLI thu thập danh bạ tinnhiemmang.vn → JSONL.

Ví dụ::

    # 1 trang đầu của mỗi danh mục (robots.txt VẪN cho phép trang 1)
    python backend/scripts/crawl_tinnhiemmang.py --category all --pages 1

    # xem hiện có bao nhiêu bản ghi
    python backend/scripts/crawl_tinnhiemmang.py --status

    # LẤY TOÀN BỘ (mặc định bỏ qua robots.txt để lấy được danh bạ).
    # Ghi tăng dần từng trang, chạy lại với --resume sẽ tiếp tục chỗ dừng.
    python backend/scripts/crawl_tinnhiemmang.py --category all --all --resume \
        --workers 8 --delay 0.3

    # Muốn tôn trọng robots.txt (site chặn /*?page= → sẽ dừng ở trang 2):
    python backend/scripts/crawl_tinnhiemmang.py --category web --all --respect-robots

Dữ liệu ghi vào ``backend/api/core/data/tinnhiemmang/<category>.jsonl`` (UTF-8,
mỗi dòng một JSON). Dùng ``--out`` khi muốn ghi nơi khác.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

_THIS = Path(__file__).resolve()
_BACKEND = _THIS.parents[1]
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from api.utils import tinnhiemmang as th  # noqa: E402


def _existing_keys(category: str, base_dir: Path) -> Set[str]:
    """Khoá duy nhất đã có: ưu tiên ``domain`` (mục lừa đảo), nếu không thì ``slug``.

    Lưu ý: với mục lừa đảo, ``slug`` là TRANG TỔ CHỨC BỊ MẠO DANH (dùng chung cho nhiều
    tên miền), nên chỉ ``domain`` mới định danh duy nhất.

    Dùng chỉ mục SQLite (nếu có) để nạp nhanh thay vì parse toàn bộ JSONL.
    """
    return set(th.iter_keys(category, base_dir))


def _dedup_key(rec) -> str:
    return rec.domain or rec.slug


def _to_rows(records, category: str, seen: Set[str], lock: Optional[threading.Lock]) -> List[Dict[str, Any]]:
    """Chuyển bản ghi → dict, đồng thời khử trùng theo khoá duy nhất (an toàn luồng)."""
    rows: List[Dict[str, Any]] = []
    if lock is None:
        for rec in records:
            key = _dedup_key(rec)
            if key in seen:
                continue
            seen.add(key)
            rows.append(rec.to_dict())
        return rows
    for rec in records:
        key = _dedup_key(rec)
        with lock:
            if key in seen:
                continue
            seen.add(key)
        rows.append(rec.to_dict())
    return rows


def _write_rows(out_path: Path, rows: List[Dict[str, Any]], lock: Optional[threading.Lock]) -> None:
    if not rows:
        return
    if lock is not None:
        lock.acquire()
    try:
        with out_path.open("a", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    finally:
        if lock is not None:
            lock.release()


def _with_details(client: th.TinnhiemClient, records, rows: List[Dict[str, Any]],
                  detail_scam: bool) -> int:
    """Gắn trang chi tiết cho các bản ghi trusted (tương ứng theo slug)."""
    by_slug = {r.get("slug"): r for r in rows}
    n = 0
    for rec in records:
        if rec.kind != "trusted" and not detail_scam:
            continue
        row = by_slug.get(rec.slug)
        if row is None:
            continue
        try:
            row["detail"] = client.detail(rec.slug)
            n += 1
        except Exception as exc:  # noqa: BLE001
            row["detail_error"] = str(exc)
    return n


def crawl_category_serial(
    client: th.TinnhiemClient,
    category: str,
    pages: Optional[int],
    start_page: int,
    out_dir: Path,
    with_detail: bool = False,
    detail_scam: bool = False,
    limit: Optional[int] = None,
    resume: bool = False,
    stop_after_known: int = 0,
) -> Dict[str, Any]:
    """Thu thập tuần tự một danh mục (ghi tăng dần từng trang)."""
    t0 = time.time()
    seen = _existing_keys(category, out_dir) if resume else set()
    out_path = th.dataset_path(category, out_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stats = _new_stats(category, start_page, pages)
    page = max(1, start_page)
    last_page = page + (pages - 1) if pages else None
    zero_streak = 0

    while True:
        try:
            html_text = client.listing(category, page)
        except th.RobotsDisallowed:
            _print_robots(category, page, stats)
            break
        except Exception as exc:  # noqa: BLE001
            print(f"  ! lỗi tải trang {page}: {exc}", file=sys.stderr)
            stats["errors"] += 1
            break
        records = th.parse_listing(html_text, category)
        if not records:
            break
        stats["scanned"] += len(records)
        rows = _to_rows(records, category, seen, None)
        if with_detail:
            stats["with_detail"] += _with_details(client, records, rows, detail_scam)
        _write_rows(out_path, rows, None)
        stats["written"] += len(rows)
        stats["new"] += len(rows)
        stats["last_page_done"] = page

        total = th.listing_total_pages(html_text, category) or None
        stats["total_pages"] = total
        _progress(stats, page, total, t0, start_page)

        # Sync tăng dần: danh bạ sắp xếp mới→cũ, gặp N trang liên tiếp không có gì mới thì dừng
        if stop_after_known:
            zero_streak = zero_streak + 1 if not rows else 0
            if zero_streak >= stop_after_known:
                stats["stopped_after_known"] = True
                break

        if limit and stats["new"] >= limit:
            break
        if last_page is not None and page >= last_page:
            break
        if total and page >= total:
            break
        page += 1

    stats["duration_seconds"] = round(time.time() - t0, 1)
    return stats


def crawl_category_parallel(
    client_factory: Callable[[], th.TinnhiemClient],
    category: str,
    pages: Optional[int],
    start_page: int,
    out_dir: Path,
    workers: int,
    detail_scam: bool = False,
    limit: Optional[int] = None,
    resume: bool = False,
    stop_after_known: int = 0,
) -> Dict[str, Any]:
    """Thu thập song song nhiều trang (mỗi luồng có client riêng)."""
    t0 = time.time()
    seen = _existing_keys(category, out_dir) if resume else set()
    out_path = th.dataset_path(category, out_dir)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()
    stats = _new_stats(category, start_page, pages)
    local = threading.local()

    def _client() -> th.TinnhiemClient:
        c = getattr(local, "client", None)
        if c is None:
            c = client_factory()
            local.client = c
        return c

    def _fetch(page: int):
        # Lỗi robots/khác trả về (page, None, error)
        try:
            html = _client().listing(category, page)
        except th.RobotsDisallowed:
            return page, None, "robots"
        except Exception as exc:  # noqa: BLE001
            return page, None, str(exc)
        return page, th.parse_listing(html, category), None

    # Bước 1: tải trang đầu để biết tổng số trang
    first = client_factory()
    try:
        html1 = first.listing(category, max(1, start_page))
    except th.RobotsDisallowed:
        _print_robots(category, max(1, start_page), stats)
        stats["duration_seconds"] = round(time.time() - t0, 1)
        return stats
    recs1 = th.parse_listing(html1, category)
    total = th.listing_total_pages(html1, category) or None
    stats["total_pages"] = total
    stats["scanned"] += len(recs1)
    rows1 = _to_rows(recs1, category, seen, lock)
    if detail_scam:
        stats["with_detail"] += _with_details(first, recs1, rows1, detail_scam)
    _write_rows(out_path, rows1, lock)
    stats["written"] += len(rows1)
    stats["new"] += len(rows1)
    stats["last_page_done"] = max(1, start_page)

    # Sync tăng dần (heuristic cho chế độ song song): đếm các trang liên tiếp không có mục mới.
    zero_streak = 0 if rows1 else 1

    range_start = max(1, start_page) + 1
    range_end = None
    if pages is not None:
        range_end = max(1, start_page) + pages - 1
    if total:
        range_end = total if range_end is None else min(range_end, total)

    if range_end is not None and range_end < range_start:
        stats["duration_seconds"] = round(time.time() - t0, 1)
        return stats

    stop = threading.Event()
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        pending: set = set()
        next_page = range_start
        inflight = max(1, workers) * 2

        def _can_submit() -> bool:
            if stop.is_set():
                return False
            return range_end is None or next_page <= range_end

        def _submit() -> None:
            nonlocal next_page
            pending.add(pool.submit(_fetch, next_page))
            next_page += 1

        for _ in range(inflight):
            if _can_submit():
                _submit()

        while pending and not stop.is_set():
            finished, pending = wait(pending, return_when=FIRST_COMPLETED)
            for fut in finished:
                p, recs, err = fut.result()
                if err == "robots":
                    _print_robots(category, p, stats)
                    stop.set()
                    break
                if err is not None:
                    stats["errors"] += 1
                    if stats["errors"] % 20 == 0:
                        print(f"  ! {stats['errors']} lỗi tải trang (mới nhất: trang {p}: {err})",
                              file=sys.stderr)
                    continue
                if not recs:
                    if range_end is None:
                        stop.set()      # hết danh bạ khi duyệt tới cuối
                    continue
                stats["scanned"] += len(recs)
                rows = _to_rows(recs, category, seen, lock)
                _write_rows(out_path, rows, lock)
                stats["written"] += len(rows)
                stats["new"] += len(rows)
                stats["last_page_done"] = p
                done += 1
                if stop_after_known:
                    zero_streak = zero_streak + 1 if not rows else 0
                    if zero_streak >= stop_after_known:
                        stats["stopped_after_known"] = True
                        stop.set()
                        break
                if done % 20 == 0:
                    _progress(stats, p, total, t0, range_start - 1)
                if limit and stats["new"] >= limit:
                    stop.set()
                    break
            while not stop.is_set() and len(pending) < inflight and _can_submit():
                _submit()

    stats["duration_seconds"] = round(time.time() - t0, 1)
    return stats


def _new_stats(category: str, start_page: int, pages: Optional[int]) -> Dict[str, Any]:
    return {
        "category": category,
        "start_page": start_page,
        "pages_requested": pages,
        "scanned": 0,
        "new": 0,
        "skipped_existing": 0,
        "written": 0,
        "with_detail": 0,
        "errors": 0,
        "robots_blocked": False,
        "stopped_after_known": False,
        "last_page_done": start_page - 1,
        "total_pages": None,
        "duration_seconds": 0.0,
    }


def _print_robots(category: str, page: int, stats: Dict[str, Any]) -> None:
    print(
        f"  ! robots.txt chặn trang {page} (danh mục {category}). "
        f"tinnhiemmang.vn không cho phân trang tự động (/*?page=). "
        f"Dùng --ignore-robots nếu bạn có phép.",
        file=sys.stderr,
    )
    stats["robots_blocked"] = True


def _progress(stats: Dict[str, Any], page: int, total: Optional[int],
              t0: float, first_page: int) -> None:
    elapsed = time.time() - t0
    per_page = elapsed / max(1, page - first_page + 1)
    eta = ""
    if total and page < total:
        eta = f" | ETA ~{(total - page) * per_page / 60:.0f} phút"
    print(
        f"  · trang {page}/{total or '?'}: tổng {stats['written']} bản ghi "
        f"({per_page:.1f}s/trang){eta}",
        file=sys.stderr,
    )


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Thu thập danh bạ tinnhiemmang.vn → JSONL")
    parser.add_argument("--category", default="web",
                        choices=[*th.CATEGORIES.keys(), "all"],
                        help="Danh mục cần thu thập (mặc định: web)")
    parser.add_argument("--pages", type=int, default=1, help="Số trang (mặc định 1)")
    parser.add_argument("--all", action="store_true", help="Thu thập toàn bộ số trang")
    parser.add_argument("--start-page", type=int, default=1, help="Trang bắt đầu (mặc định 1)")
    parser.add_argument("--delay", type=float, default=th.DEFAULT_DELAY,
                        help=f"Giây giữa 2 request (mặc định {th.DEFAULT_DELAY})")
    parser.add_argument("--timeout", type=float, default=th.DEFAULT_TIMEOUT)
    parser.add_argument("--workers", type=int, default=1,
                        help="Số luồng tải song song (mặc định 1; site khá chậm, 4–8 là hợp lý)")
    parser.add_argument("--cache-dir", default=None,
                        help="Thư mục cache HTML thô (bỏ qua để không cache)")
    parser.add_argument("--out", default=None, help="Thư mục ghi JSONL (mặc định DATA_DIR)")
    parser.add_argument("--detail", action="store_true", help="Lấy thêm trang chi tiết (trusted)")
    parser.add_argument("--detail-scam", action="store_true",
                        help="Lấy chi tiết cho cả mục lừa đảo (trỏ tới tổ chức bị mạo danh)")
    parser.add_argument("--limit", type=int, default=None, help="Giới hạn số bản ghi mới mỗi danh mục")
    parser.add_argument("--resume", action="store_true", help="Bỏ qua slug/domain đã có trong JSONL")
    parser.add_argument("--stop-after-known", type=int, default=0, metavar="N",
                        help="Dừng sau N trang liên tiếp không có mục mới (sync tăng dần; 0=tắt)")
    parser.add_argument("--respect-robots", action="store_true",
                        help="Tôn trọng robots.txt (mặc định: BỎ QUA để lấy được danh bạ)")
    parser.add_argument("--ignore-robots", action="store_true",
                        help=argparse.SUPPRESS)  # giữ tương thích; nay là mặc định
    parser.add_argument("--status", action="store_true", help="Chỉ in số bản ghi hiện có rồi thoát")
    parser.add_argument("--json", action="store_true", help="In thống kê dạng JSON")
    args = parser.parse_args(argv)

    out_dir = Path(args.out) if args.out else th.DATA_DIR

    if args.status:
        avail = th.available_datasets(out_dir)
        print(json.dumps({"data_dir": str(out_dir), "datasets": avail,
                          "total": sum(avail.values())}, ensure_ascii=False, indent=2))
        return 0

    categories = list(th.CATEGORIES.keys()) if args.category == "all" else [args.category]
    pages = None if args.all else max(1, args.pages)

    respect = bool(args.respect_robots)

    def client_factory() -> th.TinnhiemClient:
        return th.TinnhiemClient(
            delay=args.delay,
            timeout=args.timeout,
            cache_dir=args.cache_dir,
            respect_robots=respect,
        )

    if not respect:
        print("[crawl] Bỏ qua robots.txt của tinnhiemmang.vn (site chặn /*?page=). "
              "Dùng --respect-robots nếu muốn tôn trọng.", file=sys.stderr)

    all_stats = []
    for cat in categories:
        print(f"[crawl] {cat} ({th.CATEGORIES[cat]['label']}) — pages={pages or 'ALL'} "
              f"workers={args.workers}", file=sys.stderr)
        if args.workers > 1:
            stats = crawl_category_parallel(
                client_factory, cat, pages, max(1, args.start_page), out_dir,
                workers=args.workers, detail_scam=args.detail_scam,
                limit=args.limit, resume=args.resume,
                stop_after_known=args.stop_after_known,
            )
        else:
            stats = crawl_category_serial(
                client_factory(), cat, pages, max(1, args.start_page), out_dir,
                with_detail=args.detail, detail_scam=args.detail_scam,
                limit=args.limit, resume=args.resume,
                stop_after_known=args.stop_after_known,
            )
        all_stats.append(stats)
        print(f"[crawl] {cat}: ghi {stats['written']} bản ghi trong {stats['duration_seconds']}s "
              f"(lỗi {stats['errors']})", file=sys.stderr)

    summary = {
        "data_dir": str(out_dir),
        "categories": all_stats,
        "total_written": sum(s["written"] for s in all_stats),
        "available": th.available_datasets(out_dir),
    }
    if args.json:
        print(json.dumps(summary, ensure_ascii=False, indent=2))
    else:
        print(f"Đã ghi {summary['total_written']} bản ghi → {out_dir}")
        for cat, n in summary["available"].items():
            print(f"  {cat:5s}: {n} dòng")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
