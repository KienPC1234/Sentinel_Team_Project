"""
ShieldCall VN – Views Package
Re-exports all views so urls.py continues to work unchanged.
"""
from .stream_views import ChatStreamView, ScanAnalyzeSSEView
from .auth_views import RegisterView, LoginView, LogoutView, MeView, PasswordChangeView
from .mfa_views import MFAStatusView, MFASetupTOTPView, MFASetupEmailView, MFAVerifyView, MFADeactivateView
from .scan_views import (
    ScanPhoneView, ScanMessageView, ScanDomainView,
    ScanAccountView, ScanImageView, ScanEmailView, ScanBanksView,
    ScanStatusView,
)
from .article_views import ArticleListView, ArticleDetailView
from .report_views import ReportCreateView
from .trend_views import TrendDailyView, TrendHotView
from .user_views import UserScansView, UserReportsView, UserAlertsView
from .admin_views import AdminReportsView, AdminReportActionView, AdminStatsView
from .forum_views import ForumPostListCreateView, ForumPostCommentView, ForumPostLikeView

__all__ = [
    'ChatStreamView', 'ScanAnalyzeSSEView',
    'RegisterView', 'LoginView', 'LogoutView', 'MeView',
    'MFAStatusView', 'MFASetupTOTPView', 'MFASetupEmailView', 'MFAVerifyView', 'MFADeactivateView',
    'PasswordChangeView',
    'ScanPhoneView', 'ScanMessageView', 'ScanDomainView',
    'ScanAccountView', 'ScanImageView', 'ScanEmailView', 'ScanBanksView',
    'ScanStatusView',
    'ReportCreateView',
    'TrendDailyView', 'TrendHotView',
    'UserScansView', 'UserReportsView', 'UserAlertsView',
    'AdminReportsView', 'AdminReportActionView', 'AdminStatsView',
    'ForumPostListCreateView', 'ForumPostCommentView', 'ForumPostLikeView',
    'ArticleListView', 'ArticleDetailView',
]
