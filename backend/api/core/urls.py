"""
ShieldCall VN – Core URL Configuration
MVP spec Section 8: All API endpoints
"""
from django.urls import path
from . import views
from .views.debug_views import DebugSystemView

app_name = 'core'

urlpatterns = [
    # Auth
    path('auth/register/request-otp/', views.RegisterRequestOTPView.as_view(), name='register-request-otp'),
    path('auth/register/', views.RegisterView.as_view(), name='register'),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/logout/', views.LogoutView.as_view(), name='logout'),
    path('auth/me/', views.MeView.as_view(), name='me'),

    # MFA
    path('auth/mfa/status/', views.MFAStatusView.as_view(), name='mfa-status'),
    path('auth/mfa/setup/totp/', views.MFASetupTOTPView.as_view(), name='mfa-setup-totp'),
    path('auth/mfa/setup/email/', views.MFASetupEmailView.as_view(), name='mfa-setup-email'),
    path('auth/mfa/verify/', views.MFAVerifyView.as_view(), name='mfa-verify'),
    path('auth/mfa/deactivate/', views.MFADeactivateView.as_view(), name='mfa-deactivate'),
    path('auth/mfa/recovery/', views.MFARecoveryCodesView.as_view(), name='mfa-recovery'),
    path('auth/password/change/', views.PasswordChangeView.as_view(), name='api-password-change'),
    path('auth/password/reset/', views.PasswordResetRequestView.as_view(), name='api-password-reset'),
    path('auth/password/reset/confirm/', views.PasswordResetConfirmView.as_view(), name='api-password-reset-confirm'),
    path('auth/account/delete/', views.DeleteAccountView.as_view(), name='api-account-delete'),
    path('auth/email-change/request/', views.EmailChangeRequestOTPView.as_view(), name='api-email-change-request'),
    path('auth/email-change/verify/', views.EmailChangeVerifyOTPView.as_view(), name='api-email-change-verify'),

    # Scan
    path('scan/analyze-sse/', views.ScanAnalyzeSSEView.as_view(), name='scan-analyze-sse'),
    path('scan/analyze/stream/', views.ScanAnalyzeSSEView.as_view(), name='scan-analyze-stream'),
    path('scan/analyze/', views.ScanAnalyzeSSEView.as_view(), name='scan-analyze'),
    path('scan/phone/', views.ScanPhoneView.as_view(), name='scan-phone'),
    path('scan/message/', views.ScanMessageView.as_view(), name='scan-message'),
    path('scan/domain/', views.ScanDomainView.as_view(), name='api-scan-domain'),
    path('scan/account/', views.ScanAccountView.as_view(), name='api-scan-account'),
    path('scan/image/', views.ScanImageView.as_view(), name='api-scan-image'),
    path('scan/status/<int:scan_id>/', views.ScanStatusView.as_view(), name='api-scan-status'),
    path('scan/email/', views.ScanEmailView.as_view(), name='api-scan-email'),
    path('scan/banks/', views.ScanBanksView.as_view(), name='api-scan-banks'),
    path('scan/file/', views.ScanFileView.as_view(), name='api-scan-file'),
    path('scan/audio/', views.ScanAudioView.as_view(), name='api-scan-audio'),
    path('scan/<int:scan_id>/report-admin/', views.ScanReportAdminView.as_view(), name='api-scan-report-admin'),

    # Report
    path('report/', views.ReportCreateView.as_view(), name='report'),
    path('report/<int:pk>/', views.ReportDetailView.as_view(), name='report-detail'),
    path('reports/stats/', views.CommunityReportStatsView.as_view(), name='reports-stats'),
    path('stats/public/', views.PublicStatsView.as_view(), name='public-stats'),

    # Trends
    path('trends/daily/', views.TrendDailyView.as_view(), name='trends-daily'),
    path('trends/hot/', views.TrendHotView.as_view(), name='trends-hot'),
    path('trends/radar-stats/', views.ScamRadarStatsView.as_view(), name='trends-radar-stats'),
    path('scan/lookup/', views.ScanLookupView.as_view(), name='scan-lookup-api'),

    # User
    path('user/scans/', views.UserScansView.as_view(), name='user-scans'),
    path('user/scan-picker/', views.UserScanPickerView.as_view(), name='user-scan-picker'),
    path('user/reports/', views.UserReportsView.as_view(), name='user-reports'),
    path('user/alerts/', views.UserAlertsView.as_view(), name='user-alerts'),
    path('user/profile/<str:username>/', views.PublicProfileView.as_view(), name='public-profile'),
    path('user/api-keys/', views.UserAPIKeyListCreateView.as_view(), name='user-api-keys'),
    path('user/api-keys/<int:pk>/', views.UserAPIKeyDetailView.as_view(), name='user-api-key-detail'),
    path('user/api-keys/<int:pk>/toggle/', views.UserAPIKeyToggleView.as_view(), name='user-api-key-toggle'),
    path('user/api-keys/<int:pk>/regenerate/', views.UserAPIKeyRegenerateView.as_view(), name='user-api-key-regenerate'),

    # Remote Model Context Protocol (MCP) Server for Claude Chat, Claude Desktop & Chatbots
    path('mcp/sse/', views.MCPConnectSSEView.as_view(), name='mcp-sse'),
    path('mcp/messages/', views.MCPMessagesView.as_view(), name='mcp-messages'),
    path('mcp/', views.MCPDiscoveryView.as_view(), name='mcp-discovery'),


    # Admin
    path('admin/reports/', views.AdminReportsView.as_view(), name='admin-reports'),
    path('admin/reports/<int:report_id>/action/', views.AdminReportActionView.as_view(), name='admin-report-action'),
    path('admin/stats/', views.AdminStatsView.as_view(), name='admin-stats'),
    path('admin/rag/', views.AdminRAGManagementView.as_view(), name='admin-rag'),
    path('admin/rag/rebuild/', views.AdminRAGRebuildView.as_view(), name='admin-rag-rebuild'),
    path('admin/rag/clear-logs/', views.AdminRAGClearLogsView.as_view(), name='admin-rag-clear-logs'),
    path('admin/users/', views.AdminUsersView.as_view(), name='admin-users'),
    path('admin/users/<int:user_id>/action/', views.AdminUserActionView.as_view(), name='admin-user-action'),
    path('admin/scenarios/', views.AdminScenariosView.as_view(), name='admin-scenarios'),
    path('admin/scenarios/<int:scenario_id>/', views.AdminScenarioDetailView.as_view(), name='admin-scenario-detail'),
    path('admin/learn/', views.AdminLearnView.as_view(), name='admin-learn'),
    path('admin/learn/<int:lesson_id>/', views.AdminLearnDetailView.as_view(), name='admin-learn-detail'),
    path('admin/learn/<int:lesson_id>/notify/', views.AdminLearnNotifyView.as_view(), name='admin-learn-notify'),
    path('admin/articles/', views.AdminArticlesView.as_view(), name='admin-articles'),
    path('admin/articles/<int:article_id>/', views.AdminArticleDetailView.as_view(), name='admin-article-detail'),

    # Forum
    path('forum/stats/', views.ForumStatsView.as_view(), name='forum-stats'),
    path('forum/posts/', views.ForumPostListCreateView.as_view(), name='forum-posts'),
    path('forum/posts/<int:post_id>/', views.ForumPostDetailView.as_view(), name='forum-detail'),
    path('forum/posts/<int:post_id>/comment/', views.ForumPostCommentView.as_view(), name='forum-comment'),
    path('forum/posts/<int:post_id>/like/', views.ForumPostLikeView.as_view(), name='forum-like'),
    path('forum/posts/<int:post_id>/like/mutual/', views.ForumPostLikeMutualView.as_view(), name='forum-like-mutual'),
    path('forum/posts/<int:post_id>/reaction/', views.ForumPostReactionView.as_view(), name='forum-reaction'),
    path('forum/posts/<int:post_id>/reaction/mutual/', views.ForumPostReactionMutualView.as_view(), name='forum-reaction-mutual'),
    path('forum/posts/<int:post_id>/report/', views.ForumPostReportView.as_view(), name='forum-report'),
    path('forum/comments/<int:comment_id>/like/', views.ForumCommentLikeView.as_view(), name='forum-comment-like'),
    path('forum/comments/<int:comment_id>/reaction/', views.ForumCommentReactionView.as_view(), name='forum-comment-reaction'),
    path('forum/comments/<int:comment_id>/report/', views.ForumCommentReportView.as_view(), name='forum-comment-report'),

    # Admin Forum moderation
    path('admin/forum/reports/', views.AdminForumReportsView.as_view(), name='admin-forum-reports'),
    path('admin/forum/reports/<int:report_id>/action/', views.AdminForumReportActionView.as_view(), name='admin-forum-report-action'),
    path('admin/forum/comment-reports/', views.AdminForumCommentReportsView.as_view(), name='admin-forum-comment-reports'),
    path('admin/forum/comment-reports/<int:report_id>/action/', views.AdminForumCommentReportActionView.as_view(), name='admin-forum-comment-report-action'),
    path('admin/forum/bans/', views.AdminForumBansView.as_view(), name='admin-forum-bans'),
    path('admin/forum/ban/', views.AdminForumBanActionView.as_view(), name='admin-forum-ban'),
    path('admin/forum/moderator/', views.AdminForumModeratorView.as_view(), name='admin-forum-moderator'),
    
    # Articles
    path('articles/', views.ArticleListView.as_view(), name='article-list'),
    path('articles/<slug:slug>/', views.ArticleDetailView.as_view(), name='article-detail'),
    path('learn/lessons/', views.LearnLessonListView.as_view(), name='learn-lessons'),
    path('learn/scenarios/', views.LearnScenarioListView.as_view(), name='learn-scenarios'),
    path('learn/quizzes/', views.LearnQuizListView.as_view(), name='learn-quizzes'),
    path('learn/quizzes/<int:quiz_id>/check/', views.LearnQuizCheckView.as_view(), name='learn-quiz-check'),
    path('learn/lessons/<slug:slug>/reaction/', views.LessonReactionView.as_view(), name='learn-lesson-reaction'),
    path('learn/lessons/<slug:slug>/', views.LearnLessonDetailView.as_view(), name='learn-lesson-detail'),
    path('learn/articles/<slug:slug>/reaction/', views.ArticleReactionView.as_view(), name='learn-article-reaction'),
    path('learn/articles/<slug:slug>/comments/', views.ArticleCommentListCreateView.as_view(), name='learn-article-comments'),
    path('learn/articles/<slug:slug>/comments/<int:comment_id>/reaction/', views.ArticleCommentReactionView.as_view(), name='learn-article-comment-reaction'),

    # Utils
    path('utils/upload-image/', views.EditorImageUploadView.as_view(), name='editor-upload-image'),
    path('utils/editor-media/', views.EditorMediaLibraryView.as_view(), name='editor-media-library'),
    path('utils/fetch-url/', views.EditorFetchUrlView.as_view(), name='editor-fetch-url'),
    path('utils/mentions/', views.MentionUserListView.as_view(), name='mentions'),
    path('notifications/test-push/', views.TestPushView.as_view(), name='test-push'),
    path('push/public-key/', views.PushPublicKeyView.as_view(), name='push-public-key'),
    path('push/subscribe/', views.WebPushSubscribeView.as_view(), name='push-subscribe'),
    path('push/unsubscribe/', views.WebPushUnsubscribeView.as_view(), name='push-unsubscribe'),
    # Backward-compatible aliases
    path('notifications/webpush/subscribe/', views.WebPushSubscribeView.as_view(), name='webpush-subscribe'),
    path('notifications/webpush/unsubscribe/', views.WebPushUnsubscribeView.as_view(), name='webpush-unsubscribe'),
    path('notifications/', views.NotificationListView.as_view(), name='notification-list'),
    path('notifications/unread-count/', views.NotificationUnreadCountView.as_view(), name='notification-unread-count'),
    path('notifications/<int:notification_id>/read/', views.NotificationMarkReadView.as_view(), name='notification-mark-read'),
    path('notifications/read-all/', views.NotificationMarkAllReadView.as_view(), name='notification-read-all'),
    path('admin/notifications/broadcast/', views.AdminNotificationBroadcastView.as_view(), name='admin-notification-broadcast'),
    path('admin/rag/reset/', views.ResetRAGView.as_view(), name='rag-reset'),
    
    # Announcements
    path('announcements/', views.AnnouncementListCreateView.as_view(), name='announcements'),
    path('announcements/<int:announcement_id>/reaction/', views.AnnouncementReactionView.as_view(), name='announcement-reaction'),

    # Direct Messages
    path('dm/inbox/', views.DirectMessageInboxView.as_view(), name='dm-inbox'),
    path('dm/thread/<str:username>/', views.DirectMessageThreadView.as_view(), name='dm-thread'),

    # Support Tickets
    path('tickets/', views.TicketListCreateView.as_view(), name='tickets'),
    path('admin/tickets/', views.AdminTicketListView.as_view(), name='admin-tickets'),

    # User Card
    path('user/card/<str:username>/', views.UserCardView.as_view(), name='user-card'),

    # Helps Center API
    path('helps/', views.HelpsDetailAPIView.as_view(), name='api-helps-index'),
    path('helps/<slug:slug>/', views.HelpsDetailAPIView.as_view(), name='api-helps-detail'),

    # Debug
    path('debug/system/', DebugSystemView.as_view(), name='debug-system'),

    # Scam IQ Exam
    path('scam-iq/start/', views.ScamIQStartView.as_view(), name='scam-iq-start'),
    path('scam-iq/status/<str:task_id>/', views.ScamIQStatusView.as_view(), name='scam-iq-status'),
    path('scam-iq/submit/', views.ScamIQSubmitView.as_view(), name='scam-iq-submit'),
    path('scam-iq/history/', views.ScamIQHistoryView.as_view(), name='scam-iq-history'),

    # Trust / Guardrail / Source reliability / Privacy (cải tiến theo hội đồng)
    path('trust/sources/', views.SourceCatalogView.as_view(), name='trust-sources'),
    path('trust/policy/', views.TrustPolicyView.as_view(), name='trust-policy'),
    path('trust/channels/', views.VNOfficialChannelsView.as_view(), name='trust-channels'),
    path('trust/privacy/', views.PrivacyNoticeView.as_view(), name='trust-privacy'),
    path('trust/redact/', views.RedactPreviewView.as_view(), name='trust-redact'),
    path('trust/storage/', views.StorageStatusView.as_view(), name='trust-storage'),
]
