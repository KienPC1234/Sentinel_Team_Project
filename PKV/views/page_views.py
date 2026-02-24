import json
import logging
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash, logout
from django.contrib import messages
from django.db.models import Count, Q, Sum
from django.db.models.functions import TruncDate
from django.utils import timezone
from datetime import timedelta

from api.core.models import (
    ScanEvent, Report, Domain, TrendDaily,
    UserAlert, ForumPost, ForumComment, ScamType, RiskLevel,
    Article, ArticleCategory,
)
from api.phone_security.models import PhoneNumber

logger = logging.getLogger(__name__)


def home_view(request):
    """Home page with real stats from DB."""
    try:
        total_scans = ScanEvent.objects.count()
        scam_detected = ScanEvent.objects.filter(
            risk_level__in=[RiskLevel.RED, RiskLevel.YELLOW]
        ).count()

        # Top scam types in last 7 days
        week_ago = timezone.now() - timedelta(days=7)
        top_scam_types = (
            Report.objects.filter(created_at__gte=week_ago)
            .values('scam_type')
            .annotate(count=Count('id'))
            .order_by('-count')[:4]
        )
        # Map scam type codes to labels + colors
        scam_labels = dict(ScamType.choices)
        scam_icons = {
            'police_impersonation': 'bi-shield-slash-fill',
            'bank_impersonation': 'bi-bank2',
            'recruitment_scam': 'bi-briefcase-fill',
            'investment_scam': 'bi-graph-up-arrow',
            'phishing': 'bi-bug-fill',
            'otp_steal': 'bi-key-fill',
            'loan_scam': 'bi-cash-coin',
            'other': 'bi-question-circle-fill',
        }
        for st in top_scam_types:
            code = st['scam_type']
            st['label'] = scam_labels.get(code, code)
            st['icon'] = scam_icons.get(code, '🔍')
            max_count = top_scam_types[0]['count'] if top_scam_types else 1
            st['pct'] = int((st['count'] / max(max_count, 1)) * 100)
            st['color'] = 'var(--risk-red)' if st['pct'] > 60 else 'var(--risk-yellow)'

        # Latest alert
        latest_report = Report.objects.order_by('-created_at').first()

    except Exception as e:
        logger.error(f"Error loading home stats: {e}")
        total_scans = 0
        scam_detected = 0
        top_scam_types = []
        latest_report = None

    return render(request, "Home/home.html", {
        "title": "Trang chủ",
        "total_scans": _format_number(total_scans),
        "scam_detected": _format_number(scam_detected),
        "top_scam_types": top_scam_types,
        "latest_report": latest_report,
    })


def _format_number(n: int) -> str:
    """Format large numbers: 15200 -> 15.2K"""
    if n >= 1000:
        return f"{n/1000:.1f}K"
    return str(n)


def scan_phone_view(request):
    return render(request, "Scan/scan_phone.html", {"title": "Scan Số điện thoại"})


def scan_message_view(request):
    return render(request, "Scan/scan_message.html", {"title": "Scan Tin nhắn"})


def scan_website_view(request):
    return render(request, "Scan/scan_website.html", {"title": "Scan Website"})


def scan_email_view(request):
    return render(request, "Scan/scan_email.html", {"title": "Scan Email"})


def scan_bank_view(request):
    return render(request, "Scan/scan_bank.html", {"title": "Scan Tài khoản ngân hàng"})


def scan_qr_view(request):
    return render(request, "Scan/scan_qr.html", {"title": "Scan QR / Ảnh"})


def report_view(request):
    return render(request, "Report/report.html", {"title": "Báo cáo lừa đảo"})


def scam_radar_view(request):
    """Scam Radar page with real stats and chart data."""
    try:
        week_ago = timezone.now() - timedelta(days=7)
        prev_week = week_ago - timedelta(days=7)

        reports_this_week = Report.objects.filter(created_at__gte=week_ago).count()
        reports_prev_week = Report.objects.filter(
            created_at__gte=prev_week, created_at__lt=week_ago
        ).count()
        pct_change = 0
        if reports_prev_week > 0:
            pct_change = int(((reports_this_week - reports_prev_week) / reports_prev_week) * 100)

        new_phones = PhoneNumber.objects.filter(created_at__gte=week_ago).count() if hasattr(PhoneNumber, 'created_at') else 0
        phishing_domains = Domain.objects.filter(created_at__gte=week_ago).count()

        # Hot phone numbers
        hot_phones = (
            Report.objects.filter(created_at__gte=week_ago, target_type='phone')
            .values('target_value', 'scam_type')
            .annotate(count=Count('id'))
            .order_by('-count')[:5]
        )
        scam_labels = dict(ScamType.choices)
        for hp in hot_phones:
            hp['label'] = scam_labels.get(hp['scam_type'], hp['scam_type'])
            # Mask phone
            v = hp['target_value']
            hp['masked'] = v[:4] + '****' + v[-2:] if len(v) > 6 else v

        # Recent reports
        recent_reports = Report.objects.select_related('reporter').order_by('-created_at')[:5]

        # Trend chart data (7 days)
        trend_data = _build_trend_data(week_ago)
        type_data = _build_type_distribution(week_ago)

    except Exception as e:
        logger.error(f"Error loading scam radar: {e}")
        reports_this_week = 0
        pct_change = 0
        new_phones = 0
        phishing_domains = 0
        hot_phones = []
        recent_reports = []
        trend_data = {'labels': [], 'datasets': []}
        type_data = {'labels': [], 'data': []}

    return render(request, "ScamRadar/scam_radar.html", {
        "title": "Scam Radar",
        "reports_this_week": _format_number(reports_this_week),
        "pct_change": f"+{pct_change}%" if pct_change >= 0 else f"{pct_change}%",
        "new_phones": _format_number(new_phones),
        "phishing_domains": phishing_domains,
        "hot_phones": hot_phones,
        "recent_reports": recent_reports,
        "trend_data_json": json.dumps(trend_data),
        "type_data_json": json.dumps(type_data),
    })


def _build_trend_data(since):
    """Build 7-day trend chart data grouped by scam type."""
    days = [(since + timedelta(days=i)).date() for i in range(7)]
    day_labels = ['T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'CN']

    # Get top 3 scam types
    top_types = (
        Report.objects.filter(created_at__gte=since)
        .values('scam_type')
        .annotate(c=Count('id'))
        .order_by('-c')[:3]
    )
    colors = ['#ff1744', '#ffea00', '#00e5ff']
    scam_labels = dict(ScamType.choices)

    datasets = []
    for i, tt in enumerate(top_types):
        st = tt['scam_type']
        daily = (
            Report.objects.filter(created_at__gte=since, scam_type=st)
            .annotate(day=TruncDate('created_at'))
            .values('day')
            .annotate(c=Count('id'))
        )
        day_map = {d['day']: d['c'] for d in daily}
        datasets.append({
            'label': scam_labels.get(st, st),
            'data': [day_map.get(d, 0) for d in days],
            'borderColor': colors[i],
            'backgroundColor': colors[i].replace('#', 'rgba(') + ',0.1)' if i == 0 else f'rgba({int(colors[i][1:3],16)},{int(colors[i][3:5],16)},{int(colors[i][5:7],16)},0.1)',
            'fill': True,
            'tension': 0.4,
        })

    return {'labels': day_labels[:len(days)], 'datasets': datasets}


def _build_type_distribution(since):
    """Build scam type pie chart data."""
    dist = (
        Report.objects.filter(created_at__gte=since)
        .values('scam_type')
        .annotate(count=Count('id'))
        .order_by('-count')[:6]
    )
    scam_labels = dict(ScamType.choices)
    colors = [
        'rgba(255,23,68,0.8)', 'rgba(255,234,0,0.8)', 'rgba(0,229,255,0.8)',
        'rgba(179,136,255,0.8)', 'rgba(0,230,118,0.8)', 'rgba(255,255,255,0.3)',
    ]
    return {
        'labels': [scam_labels.get(d['scam_type'], d['scam_type']) for d in dist],
        'data': [d['count'] for d in dist],
        'colors': colors[:len(dist)],
    }


def learn_hub_view(request):
    """Learn Hub with real articles."""
    articles = Article.objects.filter(is_published=True).order_by('-created_at')
    
    # Categorize for the template if needed, or just send all
    news_articles = articles.filter(category=ArticleCategory.NEWS)[:6]
    guide_articles = articles.filter(category=ArticleCategory.GUIDE)[:6]
    alert_articles = articles.filter(category=ArticleCategory.ALERT)[:6]
    story_articles = articles.filter(category=ArticleCategory.STORY)[:6]

    return render(request, "LearnHub/learn_hub.html", {
        "title": "Kiến thức phòng tránh",
        "articles": articles[:12],
        "news": news_articles,
        "guides": guide_articles,
        "alerts": alert_articles,
        "stories": story_articles,
    })


def emergency_view(request):
    return render(request, "Emergency/emergency.html", {"title": "Hỗ trợ khẩn cấp"})


def login_view(request):
    return render(request, "Auth/login.html", {"title": "Đăng nhập"})


def register_view(request):
    return render(request, "Auth/register.html", {"title": "Đăng ký"})


def logout_view(request):
    if request.method == "POST":
        logout(request)
    return redirect('home')


@login_required
def dashboard_view(request):
    """Dashboard with real user data."""
    user = request.user
    try:
        total_scans = ScanEvent.objects.filter(user=user).count()
        danger_scans = ScanEvent.objects.filter(
            user=user, risk_level__in=[RiskLevel.RED, RiskLevel.YELLOW]
        ).count()
        total_reports = Report.objects.filter(reporter=user).count()

        # Protection score
        safe_scans = ScanEvent.objects.filter(user=user, risk_level__in=[RiskLevel.SAFE, RiskLevel.GREEN]).count()
        protection_score = int((safe_scans / max(total_scans, 1)) * 100) if total_scans > 0 else 100

        # Recent scans
        recent_scans = ScanEvent.objects.filter(user=user).order_by('-created_at')[:10]

        # User reports
        user_reports = Report.objects.filter(reporter=user).order_by('-created_at')[:10]

        # User alerts
        user_alerts = UserAlert.objects.filter(user=user).order_by('-created_at')[:10]

        # Chart data (7 days)
        week_ago = timezone.now() - timedelta(days=7)
        daily_scans = (
            ScanEvent.objects.filter(user=user, created_at__gte=week_ago)
            .annotate(day=TruncDate('created_at'))
            .values('day')
            .annotate(count=Count('id'))
            .order_by('day')
        )
        days = [(week_ago + timedelta(days=i)).date() for i in range(7)]
        day_labels = ['T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'CN']
        day_map = {d['day']: d['count'] for d in daily_scans}
        chart_data = [day_map.get(d, 0) for d in days]

        # Recent alerts from scans
        recent_alerts = ScanEvent.objects.filter(
            user=user,
            risk_level__in=[RiskLevel.RED, RiskLevel.YELLOW]
        ).order_by('-created_at')[:3]

        # Latest articles for the dashboard
        latest_articles = Article.objects.filter(is_published=True).order_by('-created_at')[:3]

    except Exception as e:
        logger.error(f"Error loading dashboard: {e}")
        total_scans = danger_scans = total_reports = protection_score = 0
        recent_scans = user_reports = user_alerts = recent_alerts = []
        chart_data = [0] * 7
        day_labels = ['T2', 'T3', 'T4', 'T5', 'T6', 'T7', 'CN']

    return render(request, "Dashboard/dashboard.html", {
        "title": "Dashboard",
        "total_scans": total_scans,
        "danger_scans": danger_scans,
        "total_reports": total_reports,
        "protection_score": protection_score,
        "recent_scans": recent_scans,
        "user_reports": user_reports,
        "user_alerts": user_alerts,
        "recent_alerts": recent_alerts,
        "latest_articles": latest_articles,
        "chart_labels_json": json.dumps(day_labels),
        "chart_data_json": json.dumps(chart_data),
    })


def admin_panel_view(request):
    return render(request, "Admin/admin_panel.html", {"title": "Admin Panel"})


# ─── Profile & Password ────────────────────────────────────────────────────

@login_required
def profile_view(request):
    """User profile page."""
    user = request.user
    if request.method == 'POST':
        user.first_name = request.POST.get('first_name', '').strip()
        user.last_name = request.POST.get('last_name', '').strip()
        user.save(update_fields=['first_name', 'last_name'])
        messages.success(request, 'Cập nhật thông tin thành công!')
        return redirect('profile')

    total_scans = ScanEvent.objects.filter(user=user).count()
    total_reports = Report.objects.filter(reporter=user).count()
    total_posts = ForumPost.objects.filter(author=user).count()

    return render(request, "Auth/profile.html", {
        "title": "Hồ sơ cá nhân",
        "total_scans": total_scans,
        "total_reports": total_reports,
        "total_posts": total_posts,
    })


@login_required
def change_password_view(request):
    """Change password page."""
    if request.method == 'POST':
        old_pw = request.POST.get('old_password', '')
        new_pw1 = request.POST.get('new_password1', '')
        new_pw2 = request.POST.get('new_password2', '')

        if not request.user.check_password(old_pw):
            return render(request, "Auth/change_password.html", {
                "title": "Đổi mật khẩu",
                "error": "Mật khẩu hiện tại không đúng.",
            })
        if new_pw1 != new_pw2:
            return render(request, "Auth/change_password.html", {
                "title": "Đổi mật khẩu",
                "error": "Mật khẩu mới không khớp.",
            })
        if len(new_pw1) < 8:
            return render(request, "Auth/change_password.html", {
                "title": "Đổi mật khẩu",
                "error": "Mật khẩu mới cần ít nhất 8 ký tự.",
            })

        request.user.set_password(new_pw1)
        request.user.save()
        update_session_auth_hash(request, request.user)
        messages.success(request, 'Đổi mật khẩu thành công!')
        return redirect('profile')

    return render(request, "Auth/change_password.html", {"title": "Đổi mật khẩu"})


# ─── Forum Page Views ──────────────────────────────────────────────────────

def forum_view(request):
    """Forum listing page."""
    posts = ForumPost.objects.select_related('author').order_by('-is_pinned', '-created_at')[:50]
    posts_list = []
    for p in posts:
        posts_list.append({
            'id': p.id,
            'title': p.title,
            'content': p.content[:300],
            'category': p.category,
            'image': p.image.url if p.image else None,
            'views_count': p.views_count,
            'author_name': p.author.first_name or p.author.username,
            'likes_count': p.likes_count,
            'comments_count': p.comments_count,
            'is_pinned': p.is_pinned,
            'created_at': p.created_at.isoformat(),
            'user_liked': p.likes.filter(user=request.user).exists() if request.user.is_authenticated else False,
        })

    return render(request, "Forum/forum.html", {
        "title": "Diễn đàn",
        "posts_json": json.dumps(posts_list),
    })


def forum_post_view(request, post_id):
    """Forum post detail page."""
    post = get_object_or_404(ForumPost.objects.select_related('author'), id=post_id)
    comments = ForumComment.objects.filter(post=post).select_related('author')
    comments_list = [{
        'id': c.id,
        'author_name': c.author.first_name or c.author.username,
        'content': c.content,
        'parent': c.parent_id,
        'created_at': c.created_at.isoformat(),
    } for c in comments]

    return render(request, "Forum/forum_detail.html", {
        "title": post.title,
        "post": post,
        "comments_json": json.dumps(comments_list),
    })


def error_404_view(request, exception):
    return render(request, "Errors/404.html", status=404)


def error_500_view(request):
    return render(request, "Errors/500.html", status=500)
