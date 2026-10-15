"""
URL configuration for PKV project.
Backend is API-first: provides REST APIs, OpenAPI docs, Allauth OAuth,
Media, WebSockets, and reverse-proxies non-API frontend traffic to Next.js.
"""
import os
from django.contrib import admin
from django.urls import path, include, re_path
from django.conf import settings
from django.conf.urls.static import static
from django.views.static import serve
from django.views.generic import RedirectView
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView
from django.http import HttpResponse

from .views.auth_overrides import TurnstilePasswordResetView
from .views.proxy_views import frontend_proxy_view
from api.core.views import MCPConnectSSEView, MCPMessagesView, MCPDiscoveryView
from api.core import views as core_api_views
from .views.admin_views import (
    approve_report,
    reject_report,
    analyze_report_ai,
    update_report_note,
    magic_create_lesson_api,
    generate_summary_api,
    magic_save_lesson_api,
    magic_create_article_api,
    magic_save_article_api,
)

def pwa_assets(request):
    allowed = {
        'sw.js': ('sw.js', 'application/javascript'),
        'manifest.json': ('PKV/static/site.webmanifest', 'application/manifest+json'),
        'site.webmanifest': ('PKV/static/site.webmanifest', 'application/manifest+json'),
    }
    filename = request.path.lstrip('/')
    entry = allowed.get(filename)
    if not entry:
        return HttpResponse("/* Asset Not Found */", status=404)
    asset_path = os.path.join(settings.BASE_DIR, entry[0])
    if os.path.exists(asset_path):
        with open(asset_path, 'r') as f:
            response = HttpResponse(f.read(), content_type=entry[1])
            response['Cache-Control'] = 'no-cache, no-store, must-revalidate'
            response['Pragma'] = 'no-cache'
            response['Expires'] = '0'
            return response
    return HttpResponse(f"/* Asset {filename} Not Found */", status=404)


def auth_page_redirect(request, to, **kwargs):
    """Chuyển trang HTML của allauth (GET/HEAD) về trang Next native có đầy đủ CSS.

    Chỉ redirect GET/HEAD; POST (form allauth, OAuth callback) vẫn tới allauth.
    Hỗ trợ placeholder {key}, {provider} từ URL params.
    """
    from django.shortcuts import redirect as dj_redirect
    if request.method not in ('GET', 'HEAD'):
        from django.http import Http404
        raise Http404()
    try:
        dest = to.format(**kwargs)
    except (KeyError, IndexError):
        dest = to
    return dj_redirect(dest)


urlpatterns = [
    # App service worker & manifest
    path('sw.js', pwa_assets),
    path('manifest.json', pwa_assets),
    path('site.webmanifest', pwa_assets),

    # Django Standard Admin
    path('admin/', admin.site.urls),

    # MCP Server & Download
    path("mcp/sse/", MCPConnectSSEView.as_view(), name="root-mcp-sse"),
    path("mcp/messages/", MCPMessagesView.as_view(), name="root-mcp-messages"),
    path("mcp/download/", core_api_views.mcp_download_script_view, name="mcp-download-script"),
    path("api/v1/mcp/download/", core_api_views.mcp_download_script_view, name="api-mcp-download-script"),

    # Report moderation actions (invoked via Next.js BFF proxy)
    path("admin-cp/reports/<int:report_id>/approve/", approve_report, name="admin-approve-report"),
    path("admin-cp/reports/<int:report_id>/reject/", reject_report, name="admin-reject-report"),
    path("admin-cp/reports/<int:report_id>/analyze/", analyze_report_ai, name="admin-analyze-report"),
    path("admin-cp/reports/<int:report_id>/note/", update_report_note, name="admin-report-note"),

    # API Documentation (OpenAPI / Swagger / ReDoc)
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),

    # API endpoints v1
    path('api/v1/', include([
        path('chat/', include('api.ai_chat.urls')),
        path('admin/learn/ai-generate/', magic_create_lesson_api, name='admin-ai-generate-lesson'),
        path('admin/content/generate-summary/', generate_summary_api, name='admin-generate-summary'),
        path('admin/learn/magic-save/', magic_save_lesson_api, name='admin-magic-save-lesson'),
        path('admin/articles/ai-generate/', magic_create_article_api, name='admin-ai-generate-article'),
        path('admin/articles/magic-save/', magic_save_article_api, name='admin-magic-save-article'),
        path('', include('api.core.urls')),
    ])),

    # API Root Aliases (direct fallback endpoints to prevent 404s)
    path('api/auth/logout/', core_api_views.LogoutView.as_view(), name='root-api-auth-logout'),
    path('api/auth/me/', core_api_views.MeView.as_view(), name='root-api-auth-me'),
    path('api/me/', core_api_views.MeView.as_view(), name='root-api-me'),
    path('api/scan/file/', core_api_views.ScanFileView.as_view(), name='root-api-scan-file'),
    path('api/scan/status/<int:scan_id>/', core_api_views.ScanStatusView.as_view(), name='root-api-scan-status'),
    path('api/scan/analyze/stream/', core_api_views.ScanAnalyzeSSEView.as_view(), name='root-api-scan-analyze-stream'),
    path('api/scan/analyze-sse/', core_api_views.ScanAnalyzeSSEView.as_view(), name='root-api-scan-analyze-sse'),
    path('api/scan/analyze/', core_api_views.ScanAnalyzeSSEView.as_view(), name='root-api-scan-analyze'),

    # Allauth (Google OAuth & Password Reset)
    path('accounts/password/reset/', TurnstilePasswordResetView.as_view(), name='account_reset_password'),
    path('accounts/profile/', RedirectView.as_view(url='/profile/', permanent=False), name='account_profile_redirect'),
    # Các trang HTML của allauth (login/signup/error/confirm) do Next.js phục vụ
    # native để có đầy đủ CSS — Django chỉ giữ lại endpoint xử lý (POST/callback).
    # Chuyển hướng GET/HEAD; các method khác (POST callback/form) vẫn tới allauth.
    path('accounts/login/', auth_page_redirect, {'to': '/login/'}, name='account_login_page'),
    path('accounts/logout/', auth_page_redirect, {'to': '/logout/'}, name='account_logout_page'),
    path('accounts/signup/', auth_page_redirect, {'to': '/register/'}, name='account_signup_page'),
    path('accounts/password/change/', auth_page_redirect, {'to': '/change-password/'}, name='account_change_password_page'),
    path('accounts/confirm-email/<str:key>/', auth_page_redirect, {'to': '/email-confirm/{key}/'}, name='account_confirm_email_page'),
    path('accounts/confirm-email/', auth_page_redirect, {'to': '/email-confirm/'}, name='account_email_verification_sent_page'),
    path('accounts/3rdparty/signup/', auth_page_redirect, {'to': '/login/?error=social_signup'}, name='socialaccount_signup_page'),
    path('accounts/3rdparty/login/cancelled/', auth_page_redirect, {'to': '/login/?error=cancelled'}, name='socialaccount_login_cancelled_page'),
    path('accounts/3rdparty/login/error/', auth_page_redirect, {'to': '/login/?error=social'}, name='socialaccount_login_error_page'),
    path('accounts/3rdparty/', auth_page_redirect, {'to': '/profile/'}, name='socialaccount_connections_page'),
    path('accounts/email/', auth_page_redirect, {'to': '/profile/'}, name='account_email_page'),
    path('accounts/', include('allauth.urls')),

    # Media files serving (avatars, reports, forum uploads, covers, etc.)
    re_path(r'^media/(?P<path>.*)$', serve, {'document_root': settings.MEDIA_ROOT}),

    # Reverse proxy all frontend routes and Next.js assets to Next.js production server (port 3000)
    re_path(r'^(?P<path>.*)$', frontend_proxy_view, name='frontend-proxy'),
]

handler404 = 'PKV.views.error_views.error_404_view'
handler400 = 'PKV.views.error_views.error_400_view'
handler403 = 'PKV.views.error_views.error_403_view'
handler500 = 'PKV.views.error_views.error_500_view'
