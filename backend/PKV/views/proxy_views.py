import os
import logging
import httpx
from django.http import HttpResponse, JsonResponse, StreamingHttpResponse

logger = logging.getLogger(__name__)

FRONTEND_HOST = os.getenv('FRONTEND_INTERNAL_URL', 'http://127.0.0.1:3000')


def api_not_found_view(request, path=''):
    """JSON 404 for unmatched /api/* paths (never proxy them to Next.js)."""
    return JsonResponse(
        {
            'error': 'Endpoint không tồn tại hoặc đã bị di chuyển.',
            'code': 'NOT_FOUND',
            'detail': '/api/v1/',
        },
        status=404,
    )

# Headers that should never be forwarded between client and upstream
REQUEST_EXCLUDE_HEADERS = {
    'host', 'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade', 'accept-encoding'
}

RESPONSE_EXCLUDE_HEADERS = {
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailers', 'transfer-encoding', 'upgrade', 'content-length',
    'content-encoding'
}

async def frontend_proxy_view(request, path=''):
    """
    Reverse proxy non-API page requests and Next.js assets to Next.js production server.
    Ensures that incoming requests on Daphne (8001) from Cloudflare Tunnel sc.fptoj.com
    are served directly by the Next.js runtime.
    """
    # Guard against recursive proxy loops between Next.js rewrites and Daphne
    if request.headers.get('x-pkv-gateway-proxy'):
        return HttpResponse("<!-- Loop Detected -->", status=508, content_type="text/plain")

    clean_path = path.lstrip('/')
    if clean_path.startswith('api/'):
        return api_not_found_view(request, path)
    if clean_path.startswith(('media/', 'admin/')):
        return HttpResponse("<!-- Not Found -->", status=404, content_type="text/plain")

    target = f"{FRONTEND_HOST}/{path}"
    query = request.META.get('QUERY_STRING')
    if query:
        target = f"{target}?{query}"

    headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk not in REQUEST_EXCLUDE_HEADERS:
            headers[k] = v

    client_ip = request.META.get('HTTP_X_FORWARDED_FOR') or request.META.get('REMOTE_ADDR')
    if client_ip:
        headers['x-forwarded-for'] = client_ip
    headers['x-forwarded-proto'] = request.scheme
    headers['x-forwarded-host'] = request.get_host()
    headers['x-pkv-gateway-proxy'] = '1'
    # Ngăn httpx tự chèn Accept-Encoding: gzip, deflate làm Next.js nén trước khi strip Content-Encoding.
    headers['accept-encoding'] = 'identity'

    body = request.body if request.method not in ('GET', 'HEAD') else None

    client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=10.0, read=300.0, write=60.0, pool=10.0),
        follow_redirects=False,
    )
    try:
        upstream_request = client.build_request(
            method=request.method,
            url=target,
            headers=headers,
            content=body,
        )
        upstream = await client.send(upstream_request, stream=True)

        if request.method == 'HEAD':
            await upstream.aclose()
            await client.aclose()
            resp = HttpResponse(
                status=upstream.status_code,
                content_type=upstream.headers.get('content-type', 'text/html'),
            )
            for k, v in upstream.headers.items():
                lk = k.lower()
                if lk not in RESPONSE_EXCLUDE_HEADERS and lk != 'content-type':
                    resp[k] = v
            return resp

        async def body_iterator():
            try:
                async for chunk in upstream.aiter_bytes():
                    yield chunk
            finally:
                await upstream.aclose()
                await client.aclose()

        resp = StreamingHttpResponse(
            body_iterator(),
            status=upstream.status_code,
            content_type=upstream.headers.get('content-type', 'text/html'),
        )
        for k, v in upstream.headers.items():
            lk = k.lower()
            if lk not in RESPONSE_EXCLUDE_HEADERS and lk != 'content-type':
                resp[k] = v
        return resp
    except Exception:
        await client.aclose()
        logger.exception("Frontend proxy error connecting to %s", target)
        return HttpResponse(
            "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\">"
            "<title>502 - Cổng giao diện tạm thời không khả dụng</title></head>"
            "<body style=\"font-family:system-ui,sans-serif;background:#020617;color:#f8fafc;"
            "display:flex;min-height:100vh;align-items:center;justify-content:center\">"
            "<p>Giao diện đang khởi động lại. Vui lòng thử lại sau ít giây.</p>"
            "</body></html>",
            status=502,
            content_type="text/html; charset=utf-8",
        )
