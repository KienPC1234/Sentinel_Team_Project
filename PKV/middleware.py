import logging
import re
import json
import os
from django.conf import settings
from django.http import HttpResponse, JsonResponse, Http404
from django.shortcuts import render
from PKV.utils.site_url import set_current_site_url

logger = logging.getLogger(__name__)


class SafeErrorPageMiddleware:
    """Last-resort exception guard to ensure users always see a friendly error page."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        # Ignore Http404 so that handler404 can take over and show the pretty 404 page
        if isinstance(exception, Http404):
            return None

        logger.exception("Unhandled exception caught by SafeErrorPageMiddleware: %s", exception)

        if request.path.startswith('/api/'):
            return JsonResponse(
                {
                    'status': 'error',
                    'message': 'Hệ thống đang bận xử lý sự cố, vui lòng thử lại sau ít phút.',
                },
                status=500,
            )

        context = {
            'safe_mode': True,
            'error_message': 'Hệ thống đang gặp sự cố tạm thời. Vui lòng chờ một chút, admin đang khắc phục.',
        }
        try:
            return render(request, 'Errors/500.html', context=context, status=500)
        except Exception:
            return HttpResponse(
                "<h1>ShieldCall đang bảo trì</h1><p>Vui lòng chờ một chút, admin đang khắc phục sự cố.</p>",
                status=500,
            )


class DynamicBandMiddleware:
    """Simplified middleware without caching to debug domain matching issues directly."""

    def __init__(self, get_response):
        self.get_response = get_response
        self.config_path = os.path.join(settings.BASE_DIR, 'dynamic_band_config.json')

    def __call__(self, request):
        # Determine the host (Manual check for Cloudflare proxy headers)
        host = request.META.get('HTTP_X_FORWARDED_HOST', request.get_host())
        scheme = request.META.get('HTTP_X_FORWARDED_PROTO', 'https' if request.is_secure() else 'http')
        
        # Site URL for emails/push
        set_current_site_url(f"{scheme}://{host}")

        response = self.get_response(request)

        # Skip if not HTML content
        if not ("text/html" in response.get("Content-Type", "") and hasattr(response, 'content')):
            return response

        # Load fresh config every time
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                # Check each domain rule
                for rule in config.get("domains", []):
                    # re.search will match anywhere in string, re.match only at start
                    pattern = rule.get("regex", "")
                    if re.search(pattern, host):
                        # matched, perform replacements
                        content = response.content.decode('utf-8')
                        replacements = rule.get("replacements", {})
                        
                        for find, replace in replacements.items():
                            content = re.sub(find, replace, content)
                        
                        response.content = content.encode('utf-8')
                        if "Content-Length" in response:
                            response["Content-Length"] = len(response.content)
                        break 
            except Exception as e:
                logger.error(f"Error in simple dynamic band middleware: {e}")

        return response
