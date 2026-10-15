from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from api.core.models import Report, ReportStatus

User = get_user_model()


def _trust_from_numbers(rank_points: int, total: int, approved: int,
                        rejected: int, recent_rejected: int) -> float:
    """Pure trust formula (0.0 - 1.0). Single source of truth for both paths."""
    base_trust = 0.3 + min(0.5, (rank_points / 5000) * 0.5)
    if total == 0:
        return base_trust

    accuracy_bonus = 0.0
    if total > 5:
        accuracy = approved / total
        if accuracy > 0.9:
            accuracy_bonus = 0.2
        elif accuracy > 0.7:
            accuracy_bonus = 0.1
        elif accuracy < 0.3:
            accuracy_bonus = -0.2

    penalty = 0.3 if recent_rejected >= 3 else 0.0
    return max(0.0, min(1.0, base_trust + accuracy_bonus - penalty))


def batch_reporter_trust(points_by_user: dict) -> dict:
    """
    Trust for many reporters in ~1 query (vs 4 queries per reporter).
    points_by_user: {user_id: rank_points}. Reporters with no history get base trust.
    Returns {user_id: trust}. Anonymous/None ids map to 0.1 via caller default.
    """
    ids = [i for i in points_by_user.keys() if i]
    if not ids:
        return {}
    agg = Report.objects.filter(reporter_id__in=ids).values('reporter_id').annotate(
        total=Count('id'),
        approved=Count('id', filter=Q(status=ReportStatus.APPROVED)),
        rejected=Count('id', filter=Q(status=ReportStatus.REJECTED)),
    )
    stats = {row['reporter_id']: row for row in agg}
    out = {}
    for uid, pts in points_by_user.items():
        if not uid:
            continue
        s = stats.get(uid, {})
        total = s.get('total', 0)
        rejected = s.get('rejected', 0)
        # Recent-5 slice only matters when the reporter has rejections (exact, cheap).
        recent_rejected = 0
        if rejected:
            recent = Report.objects.filter(reporter_id=uid).order_by('-id').values_list('status', flat=True)[:5]
            recent_rejected = sum(1 for st in recent if st == ReportStatus.REJECTED)
        out[uid] = _trust_from_numbers(pts or 0, total, s.get('approved', 0), rejected, recent_rejected)
    return out

def calculate_reporter_trust(user) -> float:
    """
    Calculate a trust score (0.0 - 1.0) for a reporter based on:
    - Historical report accuracy
    - User Rank Points
    """
    if not user or not user.is_authenticated:
        return 0.1 # Anonymous report trust

    # 1. Base trust from Rank Points
    # 0 points -> 0.3
    # 1000 points -> 0.5
    # 5000 points -> 0.8
    try:
        rank_points = user.profile.rank_points
    except:
        rank_points = 0

    # 2. Historical Accuracy
    reports = Report.objects.filter(reporter=user)
    total = reports.count()
    if total == 0:
        return 0.3 + min(0.5, (rank_points / 5000) * 0.5)

    approved = reports.filter(status=ReportStatus.APPROVED).count()
    rejected = reports.filter(status=ReportStatus.REJECTED).count()

    # 3. Penalty for recent rejections (Spam behavior)
    # Check last 5 reports
    recent_reports = list(reports.order_by('-id')[:5])
    recent_rejected = sum(1 for r in recent_reports if r.status == ReportStatus.REJECTED)

    return _trust_from_numbers(rank_points, total, approved, rejected, recent_rejected)
