from django.contrib.auth import get_user_model
from api.core.models import Report, ReportStatus

User = get_user_model()

def calculate_reporter_trust(user) -> float:
    """
    Calculate a trust score (0.0 - 1.0) for a reporter based on:
    - Account age (TODO)
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
        
    base_trust = 0.3 + min(0.5, (rank_points / 5000) * 0.5)

    # 2. Historical Accuracy
    reports = Report.objects.filter(reporter=user)
    total = reports.count()
    if total == 0:
        return base_trust

    approved = reports.filter(status=ReportStatus.APPROVED).count()
    rejected = reports.filter(status=ReportStatus.REJECTED).count()
    
    # Simple accuracy ratio
    # If 10 reports, 9 approved -> high trust
    # If 10 reports, 5 rejected -> low trust
    
    accuracy_bonus = 0.0
    if total > 5:
        accuracy = approved / total
        if accuracy > 0.9: accuracy_bonus = 0.2
        elif accuracy > 0.7: accuracy_bonus = 0.1
        elif accuracy < 0.3: accuracy_bonus = -0.2
    
    # 3. Penalty for recent rejections (Spam behavior)
    # Check last 5 reports
    recent_rejected = reports.order_by('-id')[:5].filter(status=ReportStatus.REJECTED).count()
    penalty = 0.0
    if recent_rejected >= 3:
        penalty = 0.3

    final_trust = base_trust + accuracy_bonus - penalty
    return max(0.0, min(1.0, final_trust))
