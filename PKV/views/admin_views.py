"""ShieldCall VN – Admin Dashboard Views"""
import logging
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.db.models import Count, F
from django.http import HttpResponseForbidden
from api.core.models import (
    LearnLesson, ForumPost, Article, LearnQuiz, LearnScenario, BankAccount, Domain,
    Report, ScanEvent, ForumPostReport, ForumCommentReport, ScamType, ArticleCategory
)
from django.db.models import Q
from api.core.forms import LearnLessonForm, ArticleForm, LearnScenarioForm
from django.http import HttpResponseForbidden, JsonResponse
from django.db import transaction
from django.utils import timezone
from datetime import timedelta
# The instruction implies these are from a local file, but the original code doesn't have a .page_views.
# Assuming the user wants to add these imports, but the functions admin_required and super_admin_required are defined in this file.
# If they were meant to be imported from .page_views, the local definitions would be redundant or cause issues.
# For now, I will add the import as requested, but comment out the specific functions if they are defined locally.
# from .page_views import admin_required, super_admin_required, _format_number # These functions are defined in this file.

User = get_user_model()
logger = logging.getLogger(__name__)

def super_admin_required(view_func):
    """Decorator to require super admin role"""
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if hasattr(request.user, 'profile') and request.user.profile.is_super_admin:
            return view_func(request, *args, **kwargs)
        return HttpResponseForbidden("Bạn không có quyền truy cập trang này. Chỉ Super Admin mới có quyền.")
    return _wrapped_view

def admin_required(view_func):
    """Decorator to require staff (Admin) or super admin"""
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_staff or (hasattr(request.user, 'profile') and request.user.profile.is_super_admin):
            return view_func(request, *args, **kwargs)
        return HttpResponseForbidden("Bạn không có quyền truy cập trang này.")
    return _wrapped_view

@admin_required
def admin_dashboard(request):
    """Enhanced admin overview with detailed stats"""
    stats = {
        'total_users': User.objects.count(),
        'pending_reports': Report.objects.filter(status='pending').count(),
        'approved_reports': Report.objects.filter(status='approved').count(),
        'rejected_reports': Report.objects.filter(status='rejected').count(),
        'pending_forum_reports': ForumPostReport.objects.filter(status='pending').count() + ForumCommentReport.objects.filter(status='pending').count(),
        'total_scans': ScanEvent.objects.count(),
        'total_lessons': LearnLesson.objects.count(),
        'total_posts': ForumPost.objects.count(),
        'total_bank_accounts': BankAccount.objects.count(),
        'total_domains': Domain.objects.count(),
    }
    return render(request, "Admin/dashboard.html", {
        "title": "Admin Dashboard",
        "stats": stats
    })

@admin_required
def admin_stats_api(request):
    """API for real-time dashboard stats and charts"""
    now = timezone.now()
    seven_days_ago = now - timedelta(days=7)
    
    try:
        # Simple count-up stats
        stats = {
            'users': User.objects.count(),
            'reports': Report.objects.filter(status='pending').count(),
            'scans': ScanEvent.objects.count(),
            'forum_reports': ForumPostReport.objects.filter(status='pending').count() + ForumCommentReport.objects.filter(status='pending').count(),
        }
        
        # Chart data (last 7 days)
        chart_data = {
            'labels': [(seven_days_ago + timedelta(days=i)).strftime('%d/%m') for i in range(8)],
            'reports': [],
            'scans': []
        }
        
        for i in range(8):
            day = (seven_days_ago + timedelta(days=i)).date()
            report_count = Report.objects.filter(created_at__date=day).count()
            scan_count = ScanEvent.objects.filter(created_at__date=day).count()
            chart_data['reports'].append(report_count)
            chart_data['scans'].append(scan_count)
            
        return JsonResponse({
            'status': 'success',
            'stats': stats,
            'charts': chart_data
        })
    except Exception as e:
        logger.error(f"Error in admin_stats_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@admin_required
def manage_reports(request):
    """List and manage community reports with filtering and search"""
    sort_by = request.GET.get('sort', '-created_at')
    status_filter = request.GET.get('status', '')
    type_filter = request.GET.get('type', '')
    query = request.GET.get('q', '').strip()
    
    allowed_sorts = [
        'created_at', '-created_at', 'status', '-status', 
        'target_type', '-target_type', 'reporter__username', '-reporter__username'
    ]
    if sort_by not in allowed_sorts:
        sort_by = '-created_at'
        
    reports = Report.objects.select_related('reporter').all()
    
    if status_filter:
        reports = reports.filter(status=status_filter)
    if type_filter:
        reports = reports.filter(target_type=type_filter)
    if query:
        reports = reports.filter(
            Q(target_value__icontains=query) |
            Q(description__icontains=query) |
            Q(scammer_name__icontains=query) |
            Q(scammer_phone__icontains=query) |
            Q(scammer_bank_account__icontains=query)
        )
        
    reports = reports.order_by(sort_by)
    
    context = {
        "reports": reports,
        "current_sort": sort_by,
        "status_filter": status_filter,
        "type_filter": type_filter,
        "query": query,
    }
    return render(request, "Admin/reports.html", context)

@admin_required
def manage_forum(request):
    """Manage forum posts and reports"""
    posts = ForumPost.objects.select_related('author').order_by('-is_pinned', '-created_at')[:100]
    post_reports = ForumPostReport.objects.select_related('reporter', 'post', 'post__author').order_by('-created_at')
    comment_reports = ForumCommentReport.objects.select_related('reporter', 'comment', 'comment__author').order_by('-created_at')

    from django.utils.timesince import timesince
    posts_json = [
        {
            'id': p.id,
            'title': p.title,
            'author_name': p.author.get_full_name() or p.author.username,
            'category': p.category,
            'likes_count': p.likes_count,
            'comments_count': p.comments_count,
            'views_count': p.views_count,
            'is_pinned': p.is_pinned,
            'is_locked': p.is_locked,
            'created_at_display': timesince(p.created_at) + ' trước',
        }
        for p in posts
    ]

    def _report_ai_status(report):
        ai = report.ai_analysis or {}
        if ai.get('violation') is True:
            return {'ai_status': 'done', 'ai_violation': True, 'ai_confidence': ai.get('confidence', '—')}
        if ai.get('violation') is False:
            return {'ai_status': 'done', 'ai_violation': False, 'ai_confidence': ai.get('confidence', '—')}
        return {'ai_status': 'none', 'ai_violation': None, 'ai_confidence': None}

    post_reports_json = [
        {
            'id': r.id,
            'reporter_name': r.reporter.get_full_name() or r.reporter.username,
            'post_title': r.post.title if r.post else '—',
            'reason': r.reason,
            'status': r.status,
            'created_at_display': timesince(r.created_at) + ' trước',
            **_report_ai_status(r),
        }
        for r in post_reports
    ]
    comment_reports_json = [
        {
            'id': r.id,
            'reporter_name': r.reporter.get_full_name() or r.reporter.username,
            'comment_content': (r.comment.content[:120] + '…') if r.comment and len(r.comment.content) > 120 else (r.comment.content if r.comment else '—'),
            'reason': r.reason,
            'status': r.status,
            'created_at_display': timesince(r.created_at) + ' trước',
        }
        for r in comment_reports
    ]

    return render(request, "Admin/forum_management.html", {
        "posts": posts,
        "post_reports": post_reports,
        "comment_reports": comment_reports,
        "posts_json": posts_json,
        "post_reports_json": post_reports_json,
        "comment_reports_json": comment_reports_json,
    })


@admin_required
def forum_report_action(request, report_type, report_id):
    """Approve/reject/analyze forum reports. Returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    action = request.POST.get('action') or json.loads(request.body).get('action') if request.body else None
    if not action:
        return JsonResponse({'error': 'Missing action'}, status=400)

    try:
        if report_type == 'post':
            report = ForumPostReport.objects.select_related('post', 'post__author', 'reporter').get(id=report_id)
        else:
            report = ForumCommentReport.objects.select_related('comment', 'comment__author', 'reporter').get(id=report_id)

        if action == 'approve':
            report.status = 'approved'
            report.is_resolved = True
            report.save()
            if report_type == 'post' and hasattr(report, 'post'):
                report.post.is_locked = True
                report.post.save(update_fields=['is_locked'])
            return JsonResponse({'status': 'ok', 'message': f'Đã chấp thuận báo cáo #{report_id}'})

        elif action == 'reject':
            report.status = 'rejected'
            report.is_resolved = True
            report.save()
            return JsonResponse({'status': 'ok', 'message': f'Đã từ chối báo cáo #{report_id}'})

        elif action == 'analyze':
            if report_type == 'post':
                from api.core.tasks import process_forum_report
                process_forum_report.delay(report_id)
            else:
                from api.core.tasks import process_forum_comment_report
                process_forum_comment_report.delay(report_id)
            return JsonResponse({'status': 'ok', 'message': f'Đã gửi phân tích AI cho báo cáo #{report_id}'})

        else:
            return JsonResponse({'error': 'Unknown action'}, status=400)

    except (ForumPostReport.DoesNotExist, ForumCommentReport.DoesNotExist):
        return JsonResponse({'error': 'Báo cáo không tồn tại'}, status=404)
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@admin_required
def forum_post_admin_action(request, post_id):
    """Admin actions on forum posts: delete, pin/unpin. Returns JSON."""
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)

    action = request.POST.get('action') or json.loads(request.body).get('action') if request.body else None
    try:
        post = ForumPost.objects.get(id=post_id)

        if action == 'delete':
            title = post.title
            post.delete()
            return JsonResponse({'status': 'ok', 'message': f'Đã xóa bài viết: {title}'})

        elif action == 'pin':
            post.is_pinned = not post.is_pinned
            post.save(update_fields=['is_pinned'])
            state = 'ghim' if post.is_pinned else 'bỏ ghim'
            return JsonResponse({'status': 'ok', 'message': f'Đã {state} bài viết', 'is_pinned': post.is_pinned})

        elif action == 'lock':
            post.is_locked = not post.is_locked
            post.save(update_fields=['is_locked'])
            state = 'khóa' if post.is_locked else 'mở khóa'
            return JsonResponse({'status': 'ok', 'message': f'Đã {state} bài viết', 'is_locked': post.is_locked})

        else:
            return JsonResponse({'error': 'Unknown action'}, status=400)

    except ForumPost.DoesNotExist:
        return JsonResponse({'error': 'Bài viết không tồn tại'}, status=404)

@super_admin_required
def manage_users(request):
    """Super Admin only: manage users and roles"""
    users = User.objects.select_related('profile').all()
    return render(request, "Admin/users.html", {"users": users})

@super_admin_required
def toggle_admin_role(request, user_id):
    """Promote/Demote a user to Admin (Staff)"""
    target_user = get_object_or_404(User, id=user_id)
    if target_user == request.user:
        messages.error(request, "Bạn không thể tự thay đổi quyền của mình.")
    else:
        target_user.is_staff = not target_user.is_staff
        target_user.save()
        role = "Admin" if target_user.is_staff else "User"
        messages.success(request, f"Đã cập nhật vai trò cho {target_user.username} thành {role}.")
    return redirect('admin_manage_users')

@admin_required
def manage_learn(request):
    """Management interface for /learn/ articles and lessons"""
    lessons = LearnLesson.objects.all().order_by('-created_at')
    return render(request, "Admin/learn_management.html", {"lessons": lessons})

@admin_required
def approve_report(request, report_id):
    """Approve a community report"""
    report = get_object_or_404(Report, id=report_id)
    report.status = 'approved'
    report.is_resolved = True
    report.save()
    
    # Notify user via email
    from api.utils.email_utils import send_report_outcome_email
    send_report_outcome_email(report.reporter, "website/tài khoản", report.target_value, 'approved')
    
    messages.success(request, f"Đã chấp thuận báo cáo #{report_id}.")
    return redirect('admin-manage-reports')

@admin_required
def reject_report(request, report_id):
    """Reject a community report"""
    report = get_object_or_404(Report, id=report_id)
    report.status = 'rejected'
    report.is_resolved = True
    report.save()
    
    # Notify user via email
    from api.utils.email_utils import send_report_outcome_email
    send_report_outcome_email(report.reporter, "website/tài khoản", report.target_value, 'rejected')
    
    messages.info(request, f"Đã từ chối báo cáo #{report_id}.")
    return redirect('admin-manage-reports')

@admin_required
def edit_lesson(request, lesson_id=None):
    """View to create or edit a Learn Lesson with quiz and scenario"""
    lesson = None
    scenario = None
    if lesson_id:
        lesson = get_object_or_404(LearnLesson, id=lesson_id)
        scenario = LearnScenario.objects.filter(
            title__icontains=lesson.title[:30]
        ).first() if lesson else None
        # Also check scenarios linked to lesson via a naming convention
        if not scenario:
            # Try matching by recent scenarios created around same time
            scenario = LearnScenario.objects.filter(
                created_at__gte=lesson.created_at - timedelta(minutes=5),
                created_at__lte=lesson.created_at + timedelta(minutes=5),
            ).first() if lesson else None
    
    if request.method == 'POST':
        form = LearnLessonForm(request.POST, request.FILES, instance=lesson)
        if form.is_valid():
            lesson = form.save()
            
            # Handle multiple quizzes from JSON
            quizzes_raw = request.POST.get('quizzes_json', '').strip()
            if quizzes_raw:
                try:
                    quizzes_data = json.loads(quizzes_raw)
                    # Delete existing quizzes and recreate
                    lesson.quizzes.all().delete()
                    for qd in quizzes_data:
                        if qd.get('question') and qd.get('options'):
                            correct_answers = qd.get('correct_answers') or []
                            if not isinstance(correct_answers, list):
                                correct_answers = []
                            if not correct_answers and qd.get('correct_answer'):
                                correct_answers = [qd.get('correct_answer')]
                            LearnQuiz.objects.create(
                                lesson=lesson,
                                question=qd['question'],
                                question_type=qd.get('question_type') or 'single_choice',
                                options=qd['options'],
                                correct_answer=qd.get('correct_answer', ''),
                                correct_answers=correct_answers,
                                explanation=qd.get('explanation', ''),
                            )
                except (json.JSONDecodeError, TypeError) as e:
                    logger.error(f"Failed to parse quizzes JSON in edit_lesson: {e}")
            
            # Handle scenario data
            scenario_title = request.POST.get('scenario_title', '').strip()
            if scenario_title:
                scenario_desc = request.POST.get('scenario_description', '').strip()
                scenario_steps_raw = request.POST.get('scenario_steps', '').strip()
                try:
                    scenario_steps = json.loads(scenario_steps_raw) if scenario_steps_raw else []
                except json.JSONDecodeError:
                    scenario_steps = []
                
                scenario_content = {'steps': scenario_steps}
                scenario_id_form = request.POST.get('scenario_id', '')
                
                if scenario_id_form:
                    try:
                        sc = LearnScenario.objects.get(id=int(scenario_id_form))
                        sc.title = scenario_title
                        sc.description = scenario_desc
                        sc.content = scenario_content
                        sc.save()
                    except LearnScenario.DoesNotExist:
                        LearnScenario.objects.create(
                            lesson=lesson,
                            title=scenario_title,
                            description=scenario_desc,
                            content=scenario_content,
                        )
                elif scenario:
                    scenario.title = scenario_title
                    scenario.description = scenario_desc
                    scenario.content = scenario_content
                    scenario.save()
                else:
                    LearnScenario.objects.create(
                        lesson=lesson,
                        title=scenario_title,
                        description=scenario_desc,
                        content=scenario_content,
                    )
            
            messages.success(request, "Bài học đã được lưu thành công.")
            return redirect('admin-manage-learn')
    else:
        form = LearnLessonForm(instance=lesson)
    
    # Prepare scenario steps as JSON for the template
    scenario_steps_json = '[]'
    if scenario and scenario.content:
        steps = scenario.content.get('steps', []) if isinstance(scenario.content, dict) else []
        scenario_steps_json = json.dumps(steps, ensure_ascii=False)
    
    # Prepare all quizzes as JSON for the template
    quizzes_json = '[]'
    if lesson:
        qs = list(lesson.quizzes.all().values('id', 'question', 'question_type', 'options', 'correct_answer', 'correct_answers', 'explanation'))
        quizzes_json = json.dumps([{
            'question': q['question'] or '',
            'question_type': q.get('question_type') or 'single_choice',
            'options': q['options'] if isinstance(q['options'], list) else [],
            'correct_answer': q['correct_answer'] or '',
            'correct_answers': q['correct_answers'] if isinstance(q.get('correct_answers'), list) else ([q['correct_answer']] if q['correct_answer'] else []),
            'explanation': q['explanation'] or '',
        } for q in qs], ensure_ascii=False)
    
    return render(request, "Admin/edit_lesson.html", {
        "form": form,
        "lesson": lesson,
        "quizzes_json": quizzes_json,
        "scenario": scenario,
        "scenario_steps_json": scenario_steps_json,
        "title": "Chỉnh sửa bài học" if lesson else "Thêm bài học mới"
    })

@admin_required
def delete_lesson(request, lesson_id):
    """Delete a Learn Lesson"""
    lesson = get_object_or_404(LearnLesson, id=lesson_id)
    lesson.delete()
    messages.success(request, f"Đã xóa bài học '{lesson.title}'.")
    return redirect('admin-manage-learn')

@admin_required
def delete_article(request, article_id):
    """Delete an Article"""
    article = get_object_or_404(Article, id=article_id)
    article.delete()
    messages.success(request, f"Đã xóa tin tức '{article.title}'.")
    return redirect('admin-manage-articles')

@admin_required
def notify_lesson_email(request, lesson_id):
    """Send email and push notifications to users about a new lesson"""
    lesson = get_object_or_404(LearnLesson, id=lesson_id)
    
    # Get all user emails (excluding admins/staff who might already know)
    user_emails = list(User.objects.filter(is_active=True, is_staff=False).values_list('email', flat=True))
    user_emails = [email for email in user_emails if email] # filter empty
    
    if not user_emails:
        messages.warning(request, "Không có người dùng nào để gửi thông báo.")
        return redirect('admin-manage-learn')
        
    from api.utils.email_utils import send_new_lesson_email
    lesson_url = request.build_absolute_uri(f"/learn/{lesson.slug}/")
    
    # Send email notifications
    send_new_lesson_email(user_emails, lesson.title, lesson_url)
    
    # Send push notifications to all active users
    try:
        from api.utils.push_service import PushNotificationService
        active_users = User.objects.filter(is_active=True, is_staff=False)
        push_count = 0
        for user in active_users:
            try:
                PushNotificationService.send_push(
                    user_id=user.id,
                    title='📚 Bài học mới trên ShieldCall',
                    message=f'{lesson.title}',
                    url=f'/learn/{lesson.slug}/',
                    notification_type='info'
                )
                push_count += 1
            except Exception:
                pass
        logger.info(f"Sent push notifications to {push_count} users for lesson '{lesson.title}'")
    except Exception as e:
        logger.error(f"Error sending push notifications for lesson: {e}")
    
    messages.success(request, f"Đã gửi email cho {len(user_emails)} & push thông báo cho người dùng.")
    return redirect('admin-manage-learn')

@admin_required
def magic_create_lesson_page(request):
    """Dedicated Magic Create page with real-time streaming."""
    return render(request, "Admin/magic_create.html")


@admin_required
def magic_create_lesson_api(request):
    """AI API to generate lesson structure — dispatched to Celery with WS progress."""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
        
    try:
        data = json.loads(request.body)
        raw_text = data.get('text', '').strip()
        
        if not raw_text:
            return JsonResponse({'status': 'error', 'message': 'Empty text'}, status=400)
        
        import uuid
        task_id = uuid.uuid4().hex[:12]
        
        from api.core.tasks import magic_create_lesson_task
        magic_create_lesson_task.delay(task_id, raw_text)
        
        return JsonResponse({'status': 'pending', 'task_id': task_id})
        
    except Exception as e:
        logger.error(f"Error in magic_create_lesson_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@admin_required
def magic_save_lesson_api(request):
    """API to save the AI-generated lesson, multiple quizzes and scenario"""
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST allowed'}, status=405)
        
    try:
        data = json.loads(request.body)
        
        with transaction.atomic():
            # 1. Create Lesson
            lesson = LearnLesson.objects.create(
                title=data.get('title'),
                content=data.get('content'),
                category=data.get('category', 'guide'),
                is_published=False # Start as draft
            )
            
            # 2. Create Quizzes (multiple)
            quizzes_data = data.get('quizzes', [])
            # Backward compat: single quiz
            if not quizzes_data and data.get('quiz'):
                quizzes_data = [data['quiz']]
            
            for quiz_data in quizzes_data:
                if quiz_data and quiz_data.get('question'):
                    LearnQuiz.objects.create(
                        lesson=lesson,
                        question=quiz_data.get('question'),
                        options=quiz_data.get('options', []),
                        correct_answer=quiz_data.get('correct_answer'),
                        explanation=quiz_data.get('explanation', '')
                    )
            
            # 3. Create Scenario
            scenario_data = data.get('scenario')
            if scenario_data:
                LearnScenario.objects.create(
                    lesson=lesson,
                    title=scenario_data.get('title'),
                    description=scenario_data.get('description'),
                    content=scenario_data.get('content_json'),
                )
                
        return JsonResponse({'status': 'success', 'lesson_id': lesson.id})
        
    except Exception as e:
        logger.error(f"Error in magic_save_lesson_api: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@admin_required
def manage_articles(request):
    """List and manage Articles"""
    articles = Article.objects.all().order_by('-created_at')
    return render(request, "Admin/article_management.html", {"articles": articles})

@admin_required
def manage_scenarios(request):
    """List and manage Scenarios stand-alone"""
    scenarios = LearnScenario.objects.select_related('article').all().order_by('-created_at')
    return render(request, "Admin/scenario_management.html", {
        "scenarios": scenarios,
        "articles_exist": Article.objects.exists()
    })

@admin_required
def edit_article(request, article_id=None):
    """View to create or edit an Article"""
    article = None
    if article_id:
        article = get_object_or_404(Article, id=article_id)
    
    if request.method == 'POST':
        form = ArticleForm(request.POST, request.FILES, instance=article)
        if form.is_valid():
            article = form.save()
            
            # Handle Quizzes (Keep inline for now as requested or until simplified)
            quizzes_data = request.POST.get('quizzes_json')
            if quizzes_data:
                try:
                    quizzes = json.loads(quizzes_data)
                    article.quizzes.all().delete()
                    for q in quizzes:
                        correct_answers = q.get('correct_answers') or []
                        if not isinstance(correct_answers, list):
                            correct_answers = []
                        if not correct_answers and q.get('correct_answer'):
                            correct_answers = [q.get('correct_answer')]
                        LearnQuiz.objects.create(
                            article=article,
                            question=q.get('question'),
                            question_type=q.get('question_type') or 'single_choice',
                            options=q.get('options', []),
                            correct_answer=q.get('correct_answer'),
                            correct_answers=correct_answers,
                            explanation=q.get('explanation', '')
                        )
                except Exception as e:
                    logger.error(f"Error saving quizzes: {e}")

            messages.success(request, "Bài viết đã được lưu thành công.")
            return redirect('admin-manage-articles')
    else:
        form = ArticleForm(instance=article)
    
    existing_quizzes = []
    if article:
        for q in article.quizzes.all():
            existing_quizzes.append({
                'question': q.question,
                'question_type': getattr(q, 'question_type', 'single_choice') or 'single_choice',
                'options': q.options,
                'correct_answer': q.correct_answer,
                'correct_answers': getattr(q, 'correct_answers', []) or ([q.correct_answer] if q.correct_answer else []),
                'explanation': q.explanation
            })

    return render(request, "Admin/edit_article.html", {
        "form": form,
        "article": article,
        "title": "Chỉnh sửa tin tức" if article else "Thêm tin tức mới",
        "existing_quizzes_json": json.dumps(existing_quizzes),
    })

@admin_required
def edit_scenario(request, scenario_id=None, article_id=None):
    """Dedicated view to edit or add a Scenario"""
    scenario = None
    article = None
    if scenario_id:
        scenario = get_object_or_404(LearnScenario, id=scenario_id)
        article = scenario.article
    elif article_id:
        article = get_object_or_404(Article, id=article_id)

    if request.method == 'POST':
        form = LearnScenarioForm(request.POST, instance=scenario)
        if form.is_valid():
            scenario = form.save()
            # If created from an article edit page, and it wasn't linked yet
            if article and not scenario.article:
                scenario.article = article
                scenario.save()
            
            messages.success(request, "Kịch bản đã được lưu.")
            if article_id:
                return redirect('admin-edit-article', article_id=article.id)
            return redirect('admin-manage-scenarios')
    else:
        form = LearnScenarioForm(instance=scenario)

    return render(request, "Admin/edit_scenario.html", {
        "form": form,
        "scenario": scenario,
        "article": article,
        "title": "Chỉnh sửa kịch bản" if scenario else "Thêm kịch bản mới"
    })

@admin_required
def delete_scenario(request, scenario_id):
    """Delete a scenario"""
    scenario = get_object_or_404(LearnScenario, id=scenario_id)
    article_id = scenario.article.id if scenario.article else None
    scenario.delete()
    messages.success(request, "Kịch bản đã được xóa.")
    
    next_page = request.GET.get('next')
    if next_page == 'admin-manage-scenarios':
        return redirect('admin-manage-scenarios')
    if article_id:
        return redirect('admin-edit-article', article_id=article_id)
    return redirect('admin-manage-scenarios')

