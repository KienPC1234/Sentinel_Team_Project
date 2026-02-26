from django.conf import settings
import json
import logging
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib.auth import update_session_auth_hash, logout, get_user_model
from django.contrib import messages

User = get_user_model()
from django.db.models import Count, Q, Sum, F
from django.db.models.functions import TruncDate, TruncHour, TruncMonth
from django.utils import timezone
from datetime import timedelta

from api.core.models import (
    ScanEvent, Report, Domain, TrendDaily,
    UserAlert, ForumPost, ForumComment, ScamType, RiskLevel,
    Article, ArticleCategory, ReportStatus,
    LearnLesson, LearnQuiz, LearnScenario,
)
from api.core.serializers import ForumPostSerializer, ForumCommentSerializer
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
        "DEMO_VIDEO_EMBED": getattr(settings, 'DEMO_VIDEO_EMBED', ''),
    })


def demo_video_view(request):
    """Redirect to YouTube demo video."""
    video_url = getattr(settings, 'DEMO_VIDEO_URL', 'https://www.youtube.com/')
    return redirect(video_url)


def _format_number(n: int) -> str:
    """Format large numbers: 15200 -> 15.2K"""
    if n >= 1000:
        return f"{n/1000:.1f}K"
    return str(n)


def scan_phone_view(request):
    return render(request, "Scan/scan_phone.html", {
        "title": "Scan Số điện thoại",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scan_message_view(request):
    return render(request, "Scan/scan_message.html", {
        "title": "Scan Tin nhắn",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scan_website_view(request):
    return render(request, "Scan/scan_website.html", {
        "title": "Scan Website",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scan_email_view(request):
    return render(request, "Scan/scan_email.html", {
        "title": "Scan Email",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scan_bank_view(request):
    return render(request, "Scan/scan_bank.html", {
        "title": "Scan Tài khoản ngân hàng",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scan_qr_view(request):
    return render(request, "Scan/scan_qr.html", {
        "title": "Scan QR / Ảnh",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scan_lookup_view(request):
    """Unified scan lookup / search page."""
    return render(request, "Scan/scan_lookup.html", {
        "title": "Tra cứu hệ thống",
    })


def scan_status_view(request, scan_id):
    """Display scan result page for /scan/status/<id>/."""
    scan = get_object_or_404(ScanEvent, id=scan_id)
    scan_json = json.dumps({
        'result': scan.result_json or {},
        'risk_score': scan.risk_score,
        'risk_level': scan.risk_level,
    }, ensure_ascii=False)
    return render(request, "Scan/scan_status.html", {
        "title": f"Kết quả quét #{scan.id}",
        "scan": scan,
        "scan_json": scan_json,
    })


def report_view(request):
    return render(request, "Report/report.html", {
        "title": "Báo cáo lừa đảo",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


@login_required
def my_reports_view(request):
    """User's own reports tracking page"""
    reports = Report.objects.filter(reporter=request.user).select_related('scan_event').prefetch_related('evidence_images').order_by('-created_at')
    status_filter = request.GET.get('status', '')
    if status_filter:
        reports = reports.filter(status=status_filter)

    stats = {
        'total': reports.count(),
        'pending': Report.objects.filter(reporter=request.user, status='pending').count(),
        'approved': Report.objects.filter(reporter=request.user, status='approved').count(),
        'rejected': Report.objects.filter(reporter=request.user, status='rejected').count(),
    }
    return render(request, "Report/my_reports.html", {
        "reports": reports,
        "stats": stats,
        "status_filter": status_filter,
    })


def scam_radar_view(request):
    """Scam Radar page with real stats and chart data."""
    try:
        range_key = request.GET.get('range', '7d')
        now = timezone.now()
        
        # 1. Calculate time range
        if range_key == '24h':
            delta = timedelta(hours=24)
            start_date = now - delta
            prev_start = now - timedelta(hours=48)
            trunc_func = TruncHour
            date_fmt = '%H:%M'
            chart_range_steps = 24
        elif range_key == '30d':
            delta = timedelta(days=30)
            start_date = now - delta
            prev_start = now - timedelta(days=60)
            trunc_func = TruncDate
            date_fmt = '%d/%m'
            chart_range_steps = 30
        elif range_key == '1y':
            delta = timedelta(days=365)
            start_date = now - delta
            prev_start = now - timedelta(days=730)
            trunc_func = TruncMonth
            date_fmt = '%m/%Y'
            chart_range_steps = 12
        else: # default 7d
            range_key = '7d'
            delta = timedelta(days=7)
            start_date = now - delta
            prev_start = now - timedelta(days=14)
            trunc_func = TruncDate
            date_fmt = '%d/%m'
            chart_range_steps = 7

        # 2. Key Metrics (match API: only approved reports + risky scans)
        reports_this_period = (
            Report.objects.filter(created_at__gte=start_date, status=ReportStatus.APPROVED).count() +
            ScanEvent.objects.filter(
                created_at__gte=start_date, status='completed',
                risk_level__in=[RiskLevel.RED, RiskLevel.YELLOW]
            ).count()
        )
        reports_prev_period = (
            Report.objects.filter(
                created_at__gte=prev_start, created_at__lt=start_date, status=ReportStatus.APPROVED
            ).count() +
            ScanEvent.objects.filter(
                created_at__gte=prev_start, created_at__lt=start_date, status='completed',
                risk_level__in=[RiskLevel.RED, RiskLevel.YELLOW]
            ).count()
        )
        
        pct_change = 0
        if reports_prev_period > 0:
            pct_change = int(((reports_this_period - reports_prev_period) / reports_prev_period) * 100)

        new_phones = PhoneNumber.objects.filter(created_at__gte=start_date).count() if hasattr(PhoneNumber, 'created_at') else 0
        phishing_domains = Domain.objects.filter(created_at__gte=start_date).count()

        # 3. Hot phone numbers (only approved reports)
        hot_phones = (
            Report.objects.filter(created_at__gte=start_date, target_type='phone', status=ReportStatus.APPROVED)
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

        # 4. Recent reports (only approved)
        recent_reports = Report.objects.filter(status=ReportStatus.APPROVED).select_related('reporter').order_by('-created_at')[:5]

        # 5. Trend chart data
        trend_data = _build_dynamic_trend_data(start_date, range_key, trunc_func, date_fmt, chart_range_steps)
        type_data = _build_type_distribution(start_date)

    except Exception as e:
        logger.error(f"Error loading scam radar: {e}")
        reports_this_period = 0
        pct_change = 0
        new_phones = 0
        phishing_domains = 0
        hot_phones = []
        recent_reports = []
        trend_data = {'labels': [], 'datasets': []}
        type_data = {'labels': [], 'data': []}
        range_key = '7d'

    return render(request, "ScamRadar/scam_radar.html", {
        "title": "Radar Lừa Đảo",
        "current_range": range_key,
        "reports_count": _format_number(reports_this_period),
        "pct_change": f"+{pct_change}%" if pct_change >= 0 else f"{pct_change}%",
        "pct_color": "text-green-400" if pct_change >= 0 else "text-red-400",
        "new_phones": _format_number(new_phones),
        "phishing_domains": phishing_domains,
        "hot_phones": hot_phones,
        "recent_reports": recent_reports,
        "trend_data_json": json.dumps(trend_data),
        "type_data_json": json.dumps(type_data),
    })


def _build_dynamic_trend_data(since, range_key, trunc_func, date_fmt, steps):
    """Build dynamic trend chart data."""
    now = timezone.now()
    expected_keys = []
    
    if range_key == '24h':
        # Last 24 hours
        expected_keys = [(now - timedelta(hours=i)).strftime(date_fmt) for i in range(steps)][::-1]
    elif range_key == '30d':
        # Last 30 days
        expected_keys = [(now - timedelta(days=i)).strftime(date_fmt) for i in range(steps)][::-1]
    elif range_key == '1y':
        # Last 12 months (approx)
        expected_keys = []
        # Go back 12 months.
        # We start from current month and go back.
        curr_m = now.month
        curr_y = now.year
        for i in range(steps):
             # Calculate month/year
             m = curr_m - i
             y = curr_y
             while m <= 0:
                 m += 12
                 y -= 1
             # Create date object for 1st of that month
             d = now.replace(year=y, month=m, day=1)
             expected_keys.append(d.strftime(date_fmt))
        expected_keys = expected_keys[::-1] 
    else: # 7d
        expected_keys = [(now - timedelta(days=i)).strftime(date_fmt) for i in range(steps)][::-1]

    # Get top 3 scam types (only approved reports)
    top_types = (
        Report.objects.filter(created_at__gte=since, status=ReportStatus.APPROVED)
        .values('scam_type')
        .annotate(c=Count('id'))
        .order_by('-c')[:3]
    )
    colors = ['#ff1744', '#ffea00', '#00e5ff']
    scam_labels = dict(ScamType.choices)

    datasets = []
    
    # Helper to format db result key
    def fmt_key(dt_obj):
        if not dt_obj: return ""
        return dt_obj.strftime(date_fmt)

    for i, tt in enumerate(top_types):
        st = tt['scam_type']
        
        # Query (only approved reports)
        qs = (
            Report.objects.filter(created_at__gte=since, scam_type=st, status=ReportStatus.APPROVED)
            .annotate(period=trunc_func('created_at'))
            .values('period')
            .annotate(c=Count('id'))
            .order_by('period')
        )
        
        data_map = {fmt_key(item['period']): item['c'] for item in qs}
        
        # Fill zero for missing points
        data_points = [data_map.get(k, 0) for k in expected_keys]
        
        datasets.append({
            'label': scam_labels.get(st, st),
            'data': data_points,
            'borderColor': colors[i],
            'backgroundColor': colors[i].replace('#', 'rgba(') + ',0.1)' if i == 0 else f'rgba({int(colors[i][1:3],16)},{int(colors[i][3:5],16)},{int(colors[i][5:7],16)},0.1)',
            'fill': True,
            'tension': 0.4,
        })

    return {'labels': expected_keys, 'datasets': datasets}


def _build_type_distribution(since):
    """Build scam type pie chart data."""
    dist = (
        Report.objects.filter(created_at__gte=since, status=ReportStatus.APPROVED)
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
    """Learn Hub with real articles and lessons."""
    articles = Article.objects.filter(is_published=True).order_by('-created_at')
    lessons = LearnLesson.objects.filter(is_published=True).order_by('-created_at')

    # All quizzes (from both lessons and articles)
    all_quizzes = LearnQuiz.objects.select_related('lesson', 'article').order_by('-id')
    # All scenarios
    all_scenarios = LearnScenario.objects.order_by('-created_at')

    # Categorize articles
    news_articles = articles.filter(category=ArticleCategory.NEWS)[:6]
    guide_articles = articles.filter(category=ArticleCategory.GUIDE)[:6]
    alert_articles = articles.filter(category=ArticleCategory.ALERT)[:6]
    story_articles = articles.filter(category=ArticleCategory.STORY)[:6]

    return render(request, "LearnHub/learn_hub.html", {
        "title": "Kiến thức phòng tránh",
        "articles": articles,
        "lessons": lessons,
        "news": news_articles,
        "guides": guide_articles,
        "alerts": alert_articles,
        "stories": story_articles,
        "quizzes": all_quizzes,
        "scenarios": all_scenarios,
    })


def article_detail_view(request, slug):
    """Article detail page by slug."""
    article = get_object_or_404(Article, slug=slug, is_published=True)
    return render(request, "Learning/article_detail.html", {
        "title": article.title,
        "article": article,
    })


def lesson_detail_view(request, slug):
    """Lesson detail page with quizzes and scenario."""
    lesson = get_object_or_404(LearnLesson, slug=slug, is_published=True)
    quizzes = list(lesson.quizzes.all().values('id', 'question', 'options', 'correct_answer', 'explanation'))
    scenario = lesson.scenarios.first()
    scenario_steps = []
    if scenario:
        scenario_steps = scenario.content.get('steps', []) if isinstance(scenario.content, dict) else []
    return render(request, "Learning/lesson_detail.html", {
        "title": lesson.title,
        "lesson": lesson,
        "quizzes": quizzes,
        "scenario": scenario,
        "scenario_steps": scenario_steps,
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
    return redirect('admin-dashboard')


# ─── Profile & Password ────────────────────────────────────────────────────

@login_required
def profile_view(request):
    """User profile page."""
    user = request.user
    if request.method == 'POST':
        user.first_name = request.POST.get('first_name', '').strip()
        user.last_name = request.POST.get('last_name', '').strip()
        user.save(update_fields=['first_name', 'last_name'])
        
        bio = request.POST.get('bio', '').strip()
        if user.profile.bio != bio:
            user.profile.bio = bio
            user.profile.save(update_fields=['bio'])

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


def public_profile_view(request, username):
    """Public profile page."""
    user = get_object_or_404(User.objects.select_related('profile'), username=username)
    posts = ForumPost.objects.filter(author=user).order_by('-created_at')[:10]
    serializer = ForumPostSerializer(posts, many=True, context={'request': request})
    
    return render(request, "Auth/public_profile.html", {
        "title": f"Hồ sơ của {user.username}",
        "profile_user": user,
        "posts_data": serializer.data,
        "total_posts": ForumPost.objects.filter(author=user).count(),
        "total_reports": Report.objects.filter(reporter=user).count(),
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
    """Forum listing page — VOZ-style category layout."""
    from django.db.models import Count, Max, Q, Subquery, OuterRef
    from api.core.models import ForumCategory, ForumComment

    posts = ForumPost.objects.select_related('author', 'author__profile').order_by('-is_pinned', '-created_at')[:100]
    serializer = ForumPostSerializer(posts, many=True, context={'request': request})

    # Build category stats for VOZ-style home
    category_stats = []
    for cat_value, cat_label in ForumCategory.choices:
        cat_posts = ForumPost.objects.filter(category=cat_value)
        threads_count = cat_posts.count()
        messages_count = ForumComment.objects.filter(post__category=cat_value).count()
        latest_post = cat_posts.order_by('-created_at').select_related('author', 'author__profile').first()

        cat_info = {
            'value': cat_value,
            'label': cat_label,
            'threads_count': threads_count,
            'messages_count': messages_count,
            'latest_post': None,
        }
        if latest_post:
            cat_info['latest_post'] = {
                'id': latest_post.id,
                'title': latest_post.title,
                'created_at': latest_post.created_at.isoformat(),
                'author_name': latest_post.author.profile.display_name or latest_post.author.username,
                'author_username': latest_post.author.username,
                'author_avatar': latest_post.author.profile.avatar.url if latest_post.author.profile.avatar else None,
            }
        category_stats.append(cat_info)

    return render(request, "Forum/forum.html", {
        "title": "Diễn đàn",
        "posts_data": serializer.data,
        "category_stats": category_stats,
    })

def forum_post_view(request, post_id):
    """Forum post detail page."""
    post = get_object_or_404(ForumPost.objects.select_related('author', 'author__profile'), id=post_id)

    # Block locked posts for non-staff users
    if post.is_locked and not (request.user.is_authenticated and request.user.is_staff):
        from django.contrib import messages as django_messages
        django_messages.warning(request, 'Bài viết này đã bị khóa bởi quản trị viên.')
        return redirect('forum')

    # Increment views
    ForumPost.objects.filter(id=post_id).update(views_count=F('views_count') + 1)
    post.refresh_from_db()

    serializer = ForumPostSerializer(post, context={'request': request})
    
    return render(request, "Forum/forum_detail.html", {
        "title": post.title,
        "post": post,
        "post_data": serializer.data,
        "comments_data": serializer.data.get('comments', []),
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })

@login_required
def forum_create_view(request):
    """Page to create a new forum thread."""
    return render(request, "Forum/forum_create.html", {
        "title": "Tạo chủ đề mới",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


@login_required
def forum_edit_view(request, post_id):
    """Page to edit an existing forum post (author only)."""
    post = get_object_or_404(ForumPost.objects.select_related('author'), id=post_id)
    if post.author != request.user and not request.user.is_staff:
        from django.contrib import messages as django_messages
        django_messages.error(request, 'Bạn không có quyền chỉnh sửa bài viết này.')
        return redirect('forum-post', post_id=post_id)
    if post.is_locked and not request.user.is_staff:
        from django.contrib import messages as django_messages
        django_messages.warning(request, 'Bài viết đã bị khóa, không thể chỉnh sửa.')
        return redirect('forum-post', post_id=post_id)

    serializer = ForumPostSerializer(post, context={'request': request})
    return render(request, "Forum/forum_edit.html", {
        "title": f"Chỉnh sửa: {post.title}",
        "post": post,
        "post_data": serializer.data,
    })


def error_404_view(request, exception):
    return render(request, "Errors/404.html", status=404)


def error_500_view(request):
    return render(request, "Errors/500.html", status=500)

def scan_file_view(request):
    """Scan file page."""
    return render(request, "Scan/scan_file.html", {
        "title": "Scan File",
        "active_page": "scan_file",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scan_audio_view(request):
    """Audio scan page — upload or record audio for AI scam analysis."""
    return render(request, "Scan/scan_audio.html", {
        "title": "Quét Âm Thanh",
        "active_page": "scan_audio",
        "TURNSTILE_SITEKEY": getattr(settings, 'TURNSTILE_SITEKEY', ''),
    })


def scam_radar_list_view(request, list_type):
    """View detailed list of scams (phones, accounts, domains, emails)"""
    mapping = {
        'phones': ('phone', 'Danh sách SĐT lừa đảo'),
        'accounts': ('account', 'Danh sách TK ngân hàng lừa đảo'),
        'domains': ('domain', 'Danh sách Website/Link lừa đảo'),
        'emails': ('email', 'Danh sách Email lừa đảo'),
    }

    if list_type not in mapping:
        return redirect('scam-radar')

    mapped_type, title = mapping[list_type]

    # Get approved reports only
    reports = Report.objects.filter(
        target_type=mapped_type,
        status=ReportStatus.APPROVED
    ).select_related('reporter').order_by('-created_at')[:200]

    return render(request, "ScamRadar/list.html", {
        "title": title,
        "list_type": list_type,
        "reports": reports,
    })
