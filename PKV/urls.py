"""
URL configuration for PKV project.
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from api.ai_chat.views import AssistantPageView
from django.http import HttpResponse
import os
from .views import (
    home_view, scan_phone_view, scan_message_view, scan_website_view,
    scan_email_view, scan_bank_view, scan_qr_view, scan_status_view,
    report_view,
    scam_radar_view, learn_hub_view, emergency_view, login_view,
    register_view, logout_view, dashboard_view, admin_panel_view,
    profile_view, change_password_view, forum_view, forum_post_view,
    forum_create_view, public_profile_view, scan_file_view, scan_audio_view,
    article_detail_view, scam_radar_list_view, demo_video_view,
    lesson_detail_view, scan_lookup_view,
)
from .views.admin_views import (
    admin_dashboard, 
    admin_stats_api,
    manage_reports, 
    manage_forum, 
    manage_users, 
    toggle_admin_role, 
    manage_learn,
    edit_lesson,
    manage_articles,
    edit_article,
    edit_scenario,
    manage_scenarios,
    delete_scenario,
    approve_report,
    reject_report,
    delete_lesson,
    delete_article,
    notify_lesson_email,
    magic_create_lesson_api,
    magic_save_lesson_api,
    magic_create_lesson_page,
    forum_report_action,
    forum_post_admin_action,
)

def service_worker(request):
    # OneSignal expects these at root
    filename = request.path.lstrip('/')
    worker_path = os.path.join(settings.BASE_DIR, filename)
    if os.path.exists(worker_path) and filename.endswith('.js'):
        with open(worker_path, 'r') as f:
            return HttpResponse(f.read(), content_type="application/javascript")
    return HttpResponse("/* Service Worker Not Found */", status=404)

urlpatterns = [
    # OneSignal Service Workers (OneSignalSDKWorker.js and OneSignalSDK.sw.js)
    path('OneSignalSDKWorker.js', service_worker),
    path('OneSignalSDK.sw.js', service_worker),

    # Pages
    path("", home_view, name="root"), 
    path('admin/', admin.site.urls),
    path("home/", home_view, name="home"),
    path("demo_video/", demo_video_view, name="demo-video"),
    
    # Scan pages
    path("scan/phone/", scan_phone_view, name="scan-phone"),
    path("scan/message/", scan_message_view, name="scan-message"),
    path("scan/website/", scan_website_view, name="scan-website"),
    path("scan/bank/", scan_bank_view, name="scan-bank"),
    path("scan/email/", scan_email_view, name="scan-email"),
    path("scan/qr/", scan_qr_view, name="scan-qr"),
    path('scan/file/', scan_file_view, name='scan-file'),
    path('scan/audio/', scan_audio_view, name='scan-audio'),
    path('scan/status/<int:scan_id>/', scan_status_view, name='scan-status'),
    path('scan/lookup/', scan_lookup_view, name='scan-lookup'),
    
    # Community pages
    path("report/", report_view, name="report"),
    path("scam-radar/", scam_radar_view, name="scam-radar"),
    path("scam-radar/list/<str:list_type>/", scam_radar_list_view, name="scam-radar-list"),
    path("learn/", learn_hub_view, name="learn-hub"),
    path("learn/lesson/<slug:slug>/", lesson_detail_view, name="lesson-detail"),
    path("learn/<slug:slug>/", article_detail_view, name="article-detail"),
    path("emergency/", emergency_view, name="emergency"),
    path("ai-assistant/", AssistantPageView.as_view(), name="ai-assistant"),
    path("ai-assistant/<uuid:session_id>/", AssistantPageView.as_view(), name="ai-assistant-session"),
    
    # Auth pages
    path("login/", login_view, name="login"),
    path("register/", register_view, name="register"),
    path("logout/", logout_view, name="logout"),
    
    # User pages
    path("dashboard/", dashboard_view, name="dashboard"),
    
    # Custom Admin Control Panel
    path("admin-cp/", admin_dashboard, name="admin-dashboard"),
    path("admin-cp/api/stats/", admin_stats_api, name="admin-dashboard-stats"),
    path("admin-cp/reports/", manage_reports, name="admin-manage-reports"),
    path("admin-cp/reports/<int:report_id>/approve/", approve_report, name="admin-approve-report"),
    path("admin-cp/reports/<int:report_id>/reject/", reject_report, name="admin-reject-report"),
    path("admin-cp/forum/", manage_forum, name="admin-manage-forum"),
    path("admin-cp/forum/report/<str:report_type>/<int:report_id>/action/", forum_report_action, name="admin-forum-report-action"),
    path("admin-cp/forum/post/<int:post_id>/action/", forum_post_admin_action, name="admin-forum-post-action"),
    path("admin-cp/users/", manage_users, name="admin-manage-users"),
    path("admin-cp/users/<int:user_id>/toggle-admin/", toggle_admin_role, name="admin-toggle-role"),
    path("admin-cp/learn/", manage_learn, name="admin-manage-learn"),
    path("admin-cp/learn/add/", edit_lesson, name="admin-add-lesson"),
    path("admin-cp/learn/<int:lesson_id>/edit/", edit_lesson, name="admin-edit-lesson"),
    path("admin-cp/learn/<int:lesson_id>/delete/", delete_lesson, name="admin-delete-lesson"),
    path("admin-cp/learn/magic-create/", magic_create_lesson_page, name="admin-magic-create"),
    path("admin-cp/learn/<int:lesson_id>/notify/", notify_lesson_email, name="admin-notify-lesson"),
    path("admin-cp/articles/", manage_articles, name="admin-manage-articles"),
    path("admin-cp/articles/add/", edit_article, name="admin-add-article"),
    path("admin-cp/articles/<int:article_id>/edit/", edit_article, name="admin-edit-article"),
    path("admin-cp/articles/<int:article_id>/delete/", delete_article, name="admin-delete-article"),
    path("admin-cp/scenarios/", manage_scenarios, name="admin-manage-scenarios"),
    path("admin-cp/scenarios/add/", edit_scenario, name="admin-add-scenario-standalone"),
    path("admin-cp/articles/<int:article_id>/scenarios/add/", edit_scenario, name="admin-add-scenario"),
    path("admin-cp/scenarios/<int:scenario_id>/edit/", edit_scenario, name="admin-edit-scenario"),
    path("admin-cp/scenarios/<int:scenario_id>/delete/", delete_scenario, name="admin-delete-scenario"),
    
    path("admin-panel/", admin_panel_view, name="admin-panel"),
    path("profile/", profile_view, name="profile"),
    path("profile/@<str:username>/", public_profile_view, name="public-profile"),
    path("change-password/", change_password_view, name="change-password"),

    # Forum pages
    path("forum/", forum_view, name="forum"),
    path("forum/create/", forum_create_view, name="forum-create"),
    path("forum/<int:post_id>/", forum_post_view, name="forum-post"),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # API endpoints v1
    path('api/v1/', include([
        path('', include('api.sessions_api.urls')),
        path('', include('api.phone_security.urls')),
        path('chat/', include('api.ai_chat.urls')),
        path('admin/learn/ai-generate/', magic_create_lesson_api, name='admin-ai-generate-lesson'),
        path('admin/learn/magic-save/', magic_save_lesson_api, name='admin-magic-save-lesson'),
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
