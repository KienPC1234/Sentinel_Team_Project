import logging

from django.conf import settings
from django.http import HttpResponse, JsonResponse, Http404
from django.shortcuts import render

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
