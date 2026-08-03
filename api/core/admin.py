"""
ShieldCall VN – Core Admin Registration
"""
from django.contrib import admin
from .models import (
    Domain, BankAccount, Report, ScanEvent, TrendDaily, EntityLink, UserAlert,
    Article, LearnLesson, LearnQuiz, LearnScenario, ForumPost, ForumComment,
    ForumPostReport, UserProfile
)


@admin.register(Domain)
class DomainAdmin(admin.ModelAdmin):
    list_display = ['domain_name', 'risk_score', 'ssl_valid', 'domain_age_days',
                    'report_count', 'scam_type', 'created_at']
    list_filter = ['scam_type', 'ssl_valid']
    search_fields = ['domain_name']
    ordering = ['-risk_score']


@admin.register(BankAccount)
class BankAccountAdmin(admin.ModelAdmin):
    list_display = ['bank_name', 'account_number_masked', 'risk_score',
                    'report_count', 'scam_type', 'created_at']
    list_filter = ['bank_name', 'scam_type']
    search_fields = ['account_number_masked']
    ordering = ['-risk_score']


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ['id', 'target_type', 'target_value', 'scam_type',
                    'severity', 'status', 'reporter', 'created_at']
    list_filter = ['status', 'target_type', 'scam_type', 'severity']
    search_fields = ['target_value', 'description']
    ordering = ['-created_at']
    raw_id_fields = ['reporter', 'moderator']
    actions = ['approve_reports', 'reject_reports']

    @admin.action(description='Approve selected reports')
    def approve_reports(self, request, queryset):
        queryset.update(status='approved', moderator=request.user)

    @admin.action(description='Reject selected reports')
    def reject_reports(self, request, queryset):
        queryset.update(status='rejected', moderator=request.user)


@admin.register(ScanEvent)
class ScanEventAdmin(admin.ModelAdmin):
    list_display = ['id', 'scan_type', 'normalized_input', 'risk_score',
                    'risk_level', 'user', 'created_at']
    list_filter = ['scan_type', 'risk_level']
    search_fields = ['normalized_input', 'raw_input']
    ordering = ['-created_at']


@admin.register(TrendDaily)
class TrendDailyAdmin(admin.ModelAdmin):
    list_display = ['date', 'scam_type', 'region', 'count']
    list_filter = ['scam_type', 'region']
    ordering = ['-date']


@admin.register(EntityLink)
class EntityLinkAdmin(admin.ModelAdmin):
    list_display = ['from_type', 'from_entity_id', 'to_type', 'to_entity_id',
                    'link_reason', 'confidence', 'created_at']
    list_filter = ['link_reason', 'from_type', 'to_type']


@admin.register(UserAlert)
class UserAlertAdmin(admin.ModelAdmin):
    list_display = ['user', 'target_type', 'target_value', 'risk_level', 'created_at']
    list_filter = ['target_type', 'risk_level']
    search_fields = ['target_value']
@admin.register(Article)
class ArticleAdmin(admin.ModelAdmin):
    list_display = ['title', 'category', 'author', 'is_published', 'created_at']
    list_filter = ['category', 'is_published', 'author']
    search_fields = ['title', 'content']
    prepopulated_fields = {'slug': ('title',)}
    ordering = ['-created_at']

@admin.register(LearnLesson)
class LearnLessonAdmin(admin.ModelAdmin):
    list_display = ['title', 'category', 'is_published', 'created_at']
    list_filter = ['category', 'is_published']
    search_fields = ['title', 'content']
    prepopulated_fields = {'slug': ('title',)}

@admin.register(ForumPost)
class ForumPostAdmin(admin.ModelAdmin):
    list_display = ['title', 'author', 'category', 'is_locked', 'created_at']
    list_filter = ['category', 'is_locked', 'is_pinned']
    search_fields = ['title', 'content']

@admin.register(ForumComment)
class ForumCommentAdmin(admin.ModelAdmin):
    list_display = ['author', 'post', 'created_at']
    search_fields = ['content']

@admin.register(ForumPostReport)
class ForumPostReportAdmin(admin.ModelAdmin):
    list_display = ['reporter', 'post', 'status', 'created_at']
    list_filter = ['status']
    raw_id_fields = ['reporter', 'post']

@admin.register(UserProfile)
class UserProfileAdmin(admin.ModelAdmin):
    list_display = ['user', 'display_name', 'rank_points', 'is_super_admin', 'created_at']
    search_fields = ['user__username', 'display_name']
    list_filter = ['is_super_admin']
