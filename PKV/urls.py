"""
URL configuration for PKV project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from .views import (
    home_view,
    scan_phone_view,
    scan_message_view,
    scan_website_view,
    scan_email_view,
    scan_bank_view,
    scan_qr_view,
    report_view,
    scam_radar_view,
    learn_hub_view,
    emergency_view,
    login_view,
    register_view,
    logout_view,
    dashboard_view,
    admin_panel_view,
    profile_view,
    change_password_view,
    forum_view,
    forum_post_view,
)

urlpatterns = [
    # Pages
    path("", home_view, name="root"), 
    path('admin/', admin.site.urls),
    path("home/", home_view, name="home"),
    
    # Scan pages
    path("scan/phone/", scan_phone_view, name="scan-phone"),
    path("scan/message/", scan_message_view, name="scan-message"),
    path("scan/website/", scan_website_view, name="scan-website"),
    path("scan/bank/", scan_bank_view, name="scan-bank"),
    path("scan/email/", scan_email_view, name="scan-email"),
    path("scan/qr/", scan_qr_view, name="scan-qr"),
    
    # Community pages
    path("report/", report_view, name="report"),
    path("scam-radar/", scam_radar_view, name="scam-radar"),
    path("learn/", learn_hub_view, name="learn-hub"),
    path("emergency/", emergency_view, name="emergency"),
    
    # Auth pages
    path("login/", login_view, name="login"),
    path("register/", register_view, name="register"),
    path("logout/", logout_view, name="logout"),
    
    # User pages
    path("dashboard/", dashboard_view, name="dashboard"),
    path("admin-panel/", admin_panel_view, name="admin-panel"),
    path("profile/", profile_view, name="profile"),
    path("change-password/", change_password_view, name="change-password"),

    # Forum pages
    path("forum/", forum_view, name="forum"),
    path("forum/<int:post_id>/", forum_post_view, name="forum-post"),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # API endpoints v1
    path('api/v1/', include([
        path('', include('api.sessions_api.urls')),
        path('', include('api.phone_security.urls')),
        path('', include('api.ai_chat.urls')),
        path('', include('api.media_analysis.urls')),
        path('', include('api.maintenance.urls')),
        path('', include('api.core.urls')),
    ])),

# Allauth (Google OAuth)
    path('accounts/', include('allauth.urls')),
]

handler404 = 'PKV.views.page_views.error_404_view'
handler500 = 'PKV.views.page_views.error_500_view'

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
