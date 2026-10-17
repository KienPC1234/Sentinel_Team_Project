"""
ShieldCall VN – Views Package
Re-exports all views so urls.py continues to work unchanged.
"""
from .stream_views import ScanAnalyzeSSEView
from .auth_views import RegisterRequestOTPView, RegisterView, LoginView, LogoutView, MeView, PasswordChangeView, DeleteAccountView, EmailChangeRequestOTPView, EmailChangeVerifyOTPView
from .mfa_views import MFAStatusView, MFASetupTOTPView, MFASetupEmailView, MFAVerifyView, MFADeactivateView, MFARecoveryCodesView
from .scan_views import (
    ScanPhoneView, ScanMessageView, ScanDomainView,
    ScanAccountView, ScanImageView, ScanEmailView, ScanBanksView,
    ScanAudioView, ScanStatusView, ScanReportAdminView,
)
from .article_views import ArticleListView, ArticleDetailView
from .report_views import ReportCreateView, ReportDetailView, CommunityReportStatsView
from .trend_views import TrendDailyView, TrendHotView, ScamRadarStatsView, ScanLookupView, PublicStatsView
from .user_views import UserScansView, UserScanPickerView, UserReportsView, UserAlertsView, PublicProfileView
from .scan_views import ScanFileView, ScanAudioView as _ScanAudioView  # noqa: already imported above
from .admin_views import (
    AdminReportsView, AdminReportActionView, AdminStatsView,
    AdminRAGManagementView, AdminRAGRebuildView, AdminRAGClearLogsView,
    AdminUsersView, AdminUserActionView,
    AdminScenariosView, AdminScenarioDetailView,
    AdminLearnView, AdminLearnDetailView, AdminLearnNotifyView,
    AdminArticlesView, AdminArticleDetailView,
)

from .forum_views import (ForumPostListCreateView, ForumPostCommentView, ForumPostLikeView, ForumPostReactionView, 
                          ForumPostReportView, ForumPostDetailView, ForumCommentLikeView, ForumCommentReportView,
                          ForumCommentReactionView, ForumPostReactionMutualView, ForumPostLikeMutualView, ForumStatsView)
from .utils_views import EditorImageUploadView, EditorFetchUrlView, MentionUserListView, EditorMediaLibraryView, HealthCheckView
from .tts_views import TtsView, TtsWarmView
from .notification_views import (TestPushView, ResetRAGView, PushPublicKeyView,
                                NotificationListView, NotificationUnreadCountView,
                                NotificationMarkReadView, NotificationMarkAllReadView,
                                AdminNotificationBroadcastView, WebPushSubscribeView,
                                WebPushUnsubscribeView)
from .community_views import (
    AnnouncementListCreateView, AnnouncementReactionView,
    DirectMessageInboxView, DirectMessageThreadView,
    TicketListCreateView, AdminTicketListView,
    UserCardView,
)
from .learn_views import (
    LessonReactionView,
    ArticleReactionView,
    ArticleCommentListCreateView,
    ArticleCommentReactionView,
    LearnLessonDetailView,
    LearnLessonListView,
    LearnScenarioListView,
    LearnQuizListView,
    LearnQuizCheckView,
)
from .admin_forum_views import (
    AdminForumReportsView,
    AdminForumReportActionView,
    AdminForumCommentReportsView,
    AdminForumCommentReportActionView,
    AdminForumBansView,
    AdminForumBanActionView,
    AdminForumModeratorView,
)
from .scam_iq_views import ScamIQStartView, ScamIQStatusView, ScamIQSubmitView, ScamIQAttemptView, ScamIQHistoryView
from .api_key_views import (
    UserAPIKeyListCreateView, UserAPIKeyDetailView,
    UserAPIKeyToggleView, UserAPIKeyRegenerateView,
)
from .mcp_remote_views import (
    MCPConnectSSEView, MCPMessagesView, MCPDiscoveryView,
    mcp_download_script_view,
)
from .helps_views import HelpsDetailAPIView
from .trust_views import (
    SourceCatalogView, TrustPolicyView, VNOfficialChannelsView,
    PrivacyNoticeView, RedactPreviewView, StorageStatusView,
)
from .password_reset_views import PasswordResetRequestView, PasswordResetConfirmView


__all__ = [
    'ScanAnalyzeSSEView',
    'RegisterRequestOTPView', 'RegisterView', 'LoginView', 'LogoutView', 'MeView', 'DeleteAccountView', 'EmailChangeRequestOTPView', 'EmailChangeVerifyOTPView',
    'MFAStatusView', 'MFASetupTOTPView', 'MFASetupEmailView', 'MFAVerifyView', 'MFADeactivateView', 'MFARecoveryCodesView',
    'PasswordChangeView',
    'ScanPhoneView', 'ScanMessageView', 'ScanDomainView',
    'ScanAccountView', 'ScanImageView', 'ScanEmailView', 'ScanBanksView', 'ScanFileView',
    'ScanAudioView', 'ScanStatusView', 'ScanReportAdminView',
    'ReportCreateView', 'ReportDetailView', 'CommunityReportStatsView',
    'TrendDailyView', 'TrendHotView', 'ScamRadarStatsView', 'ScanLookupView', 'PublicStatsView',
    'UserScansView', 'UserScanPickerView', 'UserReportsView', 'UserAlertsView', 'PublicProfileView',
    'AdminReportsView', 'AdminReportActionView', 'AdminStatsView',
    'AdminRAGManagementView', 'AdminRAGRebuildView', 'AdminRAGClearLogsView',
    'AdminUsersView', 'AdminUserActionView',
    'AdminScenariosView', 'AdminScenarioDetailView',
    'AdminLearnView', 'AdminLearnDetailView', 'AdminLearnNotifyView',
    'AdminArticlesView', 'AdminArticleDetailView',
    'ForumPostListCreateView', 'ForumPostCommentView', 'ForumPostLikeView',
    'ForumPostReactionView', 'ForumPostReportView', 'ForumPostDetailView', 'ForumCommentLikeView',
    'ForumCommentReportView', 'ForumCommentReactionView', 'ForumPostReactionMutualView', 'ForumPostLikeMutualView', 'ForumStatsView',
    'ArticleListView', 'ArticleDetailView',
    'EditorImageUploadView', 'EditorFetchUrlView', 'MentionUserListView', 'EditorMediaLibraryView',
    'TestPushView', 'ResetRAGView', 'PushPublicKeyView',
    'NotificationListView', 'NotificationUnreadCountView',
    'NotificationMarkReadView', 'NotificationMarkAllReadView',
    'AdminNotificationBroadcastView', 'WebPushSubscribeView', 'WebPushUnsubscribeView',
    'AnnouncementListCreateView', 'AnnouncementReactionView',
    'DirectMessageInboxView', 'DirectMessageThreadView',
    'TicketListCreateView', 'AdminTicketListView',
    'UserCardView',
    'LessonReactionView', 'ArticleReactionView', 'ArticleCommentListCreateView', 'ArticleCommentReactionView',
    'LearnLessonDetailView',
    'LearnLessonListView', 'LearnScenarioListView', 'LearnQuizListView', 'LearnQuizCheckView',
    'AdminForumReportsView', 'AdminForumReportActionView',
    'AdminForumCommentReportsView', 'AdminForumCommentReportActionView',
    'AdminForumBansView', 'AdminForumBanActionView', 'AdminForumModeratorView',
    'ScamIQStartView', 'ScamIQStatusView', 'ScamIQSubmitView', 'ScamIQAttemptView', 'ScamIQHistoryView',
    'UserAPIKeyListCreateView', 'UserAPIKeyDetailView', 'UserAPIKeyToggleView', 'UserAPIKeyRegenerateView',
    'MCPConnectSSEView', 'MCPMessagesView', 'MCPDiscoveryView',
    'HelpsDetailAPIView',
    'SourceCatalogView', 'TrustPolicyView', 'VNOfficialChannelsView',
    'PrivacyNoticeView', 'RedactPreviewView', 'StorageStatusView',
    'PasswordResetRequestView', 'PasswordResetConfirmView',
    'TtsView', 'TtsWarmView',
]


