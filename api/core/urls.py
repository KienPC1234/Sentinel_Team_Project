"""
ShieldCall VN – Core URL Configuration
MVP spec Section 8: All API endpoints
"""
from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    # Auth
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('auth/me/', views.MeView.as_view(), name='me'),
    path('chat/stream/', views.ChatStreamView.as_view(), name='chat-stream'),

    # MFA
    path('auth/mfa/status/', views.MFAStatusView.as_view(), name='mfa-status'),
    path('auth/mfa/setup/totp/', views.MFASetupTOTPView.as_view(), name='mfa-setup-totp'),
    path('auth/mfa/setup/email/', views.MFASetupEmailView.as_view(), name='mfa-setup-email'),
    path('auth/mfa/verify/', views.MFAVerifyView.as_view(), name='mfa-verify'),
    path('auth/mfa/deactivate/', views.MFADeactivateView.as_view(), name='mfa-deactivate'),
    path('auth/password/change/', views.PasswordChangeView.as_view(), name='api-password-change'),

    # Scan
    path('scan/analyze-sse/', views.ScanAnalyzeSSEView.as_view(), name='scan-analyze-sse'),
    path('scan/phone/', views.ScanPhoneView.as_view(), name='scan-phone'),
    path('scan/message/', views.ScanMessageView.as_view(), name='scan-message'),
    path('scan/domain/', views.ScanDomainView.as_view(), name='api-scan-domain'),
    path('scan/account/', views.ScanAccountView.as_view(), name='api-scan-account'),
    path('scan/image/', views.ScanImageView.as_view(), name='api-scan-image'),
    path('scan/status/<int:scan_id>/', views.ScanStatusView.as_view(), name='api-scan-status'),
    path('scan/email/', views.ScanEmailView.as_view(), name='api-scan-email'),
    path('scan/banks/', views.ScanBanksView.as_view(), name='api-scan-banks'),
    path('scan/file/', views.ScanFileView.as_view(), name='api-scan-file'),

    # Report
    path('report/', views.ReportCreateView.as_view(), name='report'),

    # Trends
    path('trends/daily/', views.TrendDailyView.as_view(), name='trends-daily'),
    path('trends/hot/', views.TrendHotView.as_view(), name='trends-hot'),

    # User
    path('user/scans/', views.UserScansView.as_view(), name='user-scans'),
    path('user/reports/', views.UserReportsView.as_view(), name='user-reports'),
    path('user/alerts/', views.UserAlertsView.as_view(), name='user-alerts'),
    path('user/profile/<str:username>/', views.PublicProfileView.as_view(), name='public-profile'),

    # Admin
    path('admin/reports/', views.AdminReportsView.as_view(), name='admin-reports'),
    path('admin/reports/<int:report_id>/action/', views.AdminReportActionView.as_view(), name='admin-report-action'),
    path('admin/stats/', views.AdminStatsView.as_view(), name='admin-stats'),
    path('admin/rag/', views.AdminRAGManagementView.as_view(), name='admin-rag'),
    path('admin/rag/rebuild/', views.AdminRAGRebuildView.as_view(), name='admin-rag-rebuild'),

    # Forum
    path('forum/posts/', views.ForumPostListCreateView.as_view(), name='forum-posts'),
    path('forum/posts/<int:post_id>/', views.ForumPostDetailView.as_view(), name='forum-detail'),
    path('forum/posts/<int:post_id>/comment/', views.ForumPostCommentView.as_view(), name='forum-comment'),
    path('forum/posts/<int:post_id>/like/', views.ForumPostLikeView.as_view(), name='forum-like'),
    path('forum/posts/<int:post_id>/reaction/', views.ForumPostReactionView.as_view(), name='forum-reaction'),
    path('forum/posts/<int:post_id>/report/', views.ForumPostReportView.as_view(), name='forum-report'),
    path('forum/comments/<int:comment_id>/like/', views.ForumCommentLikeView.as_view(), name='forum-comment-like'),
    
    # Articles
    path('articles/', views.ArticleListView.as_view(), name='article-list'),
    path('articles/<slug:slug>/', views.ArticleDetailView.as_view(), name='article-detail'),

    # Utils
    path('utils/upload-image/', views.EditorImageUploadView.as_view(), name='editor-upload-image'),
    path('utils/fetch-url/', views.EditorFetchUrlView.as_view(), name='editor-fetch-url'),
    path('utils/mentions/', views.MentionUserListView.as_view(), name='mentions'),
]
