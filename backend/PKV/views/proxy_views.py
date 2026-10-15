import os
import logging
import httpx
from django.http import HttpResponse

logger = logging.getLogger(__name__)

FRONTEND_HOST = os.getenv('FRONTEND_INTERNAL_URL', 'http://127.0.0.1:3000')

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
    if clean_path.startswith(('api/', 'media/', 'admin/')):
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

    body = request.body if request.method not in ('GET', 'HEAD') else None

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        try:
            upstream = await client.request(
                method=request.method,
                url=target,
                headers=headers,
                content=body,
            )
            resp = HttpResponse(
                content=upstream.content,
                status=upstream.status_code,
                content_type=upstream.headers.get('content-type', 'text/html'),
            )
            for k, v in upstream.headers.items():
                lk = k.lower()
                if lk not in RESPONSE_EXCLUDE_HEADERS and lk != 'content-type':
                    resp[k] = v
            return resp
        except Exception as e:
            logger.warning(f"Frontend proxy error connecting to {target}: {e}")
            return HttpResponse(
                f"<!-- PKV Gateway: Frontend unavailable ({e}) -->",
                status=502,
                content_type="text/html",
            )
