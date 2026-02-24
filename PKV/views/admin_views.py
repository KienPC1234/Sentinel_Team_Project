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
    Report, ForumPostReport, ForumCommentReport, ScanEvent, 
    LearnLesson, ForumPost, Article, LearnQuiz, LearnScenario
)
from api.core.forms import LearnLessonForm, ArticleForm, LearnScenarioForm
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
    }
    return render(request, "Admin/dashboard.html", {
        "title": "Admin Dashboard",
        "stats": stats
    })

@admin_required
def manage_reports(request):
    """List and manage community reports"""
    reports = Report.objects.select_related('reporter').all().order_by('-created_at')
    return render(request, "Admin/reports.html", {"reports": reports})

@admin_required
def manage_forum(request):
    """Manage forum posts and reports"""
    post_reports = ForumPostReport.objects.select_related('reporter', 'post').all()
    comment_reports = ForumCommentReport.objects.select_related('reporter', 'comment').all()
    return render(request, "Admin/forum_management.html", {
        "post_reports": post_reports,
        "comment_reports": comment_reports
    })

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
    """View to create or edit a Learn Lesson"""
    lesson = None
    if lesson_id:
        lesson = get_object_or_404(LearnLesson, id=lesson_id)
    
    if request.method == 'POST':
        form = LearnLessonForm(request.POST, request.FILES, instance=lesson)
        if form.is_valid():
            lesson = form.save()
            messages.success(request, "Bài học đã được lưu thành công.")
            return redirect('admin-manage-learn')
    else:
        form = LearnLessonForm(instance=lesson)
    
    return render(request, "Admin/edit_lesson.html", {
        "form": form,
        "lesson": lesson,
        "title": "Chỉnh sửa bài học" if lesson else "Thêm bài học mới"
    })

@admin_required
def manage_articles(request):
    """List and manage Articles"""
    articles = Article.objects.all().order_by('-created_at')
    return render(request, "Admin/article_management.html", {"articles": articles})

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
                        LearnQuiz.objects.create(
                            article=article,
                            question=q.get('question'),
                            options=q.get('options', []),
                            correct_answer=q.get('correct_answer'),
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
                'options': q.options,
                'correct_answer': q.correct_answer,
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
            scenario = form.save(commit=False)
            scenario.article = article
            scenario.save()
            messages.success(request, "Kịch bản đã được lưu.")
            return redirect('admin-edit-article', article_id=article.id)
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
    article_id = scenario.article.id
    scenario.delete()
    messages.success(request, "Kịch bản đã được xóa.")
    return redirect('admin-edit-article', article_id=article_id)

