"""
Django error handlers.

Trang lỗi đẹp (400/403/404/500/502/503/504) do **frontend Next.js** phục vụ.
Backend chỉ cần trả response tối thiểu, không phụ thuộc template — dùng cho
API (JSON) và các route Django (admin/allauth/media).
"""
from django.http import HttpResponse, JsonResponse


def _wants_json(request):
    return (
        request.path.startswith('/api/') or
        request.headers.get('accept', '').startswith('application/json') or
        request.headers.get('x-requested-with') == 'XMLHttpRequest'
    )


def _html(title: str, message: str, status: int) -> HttpResponse:
    body = (
        "<!doctype html><html lang=\"vi\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        f"<title>{status} - {title} | ShieldCall VN</title></head>"
        "<body style=\"margin:0;font-family:system-ui,-apple-system,sans-serif;background:#020617;color:#f8fafc;"
        "display:flex;min-height:100vh;align-items:center;justify-content:center;padding:1.5rem;box-sizing:border-box\">"
        "<div style=\"background:linear-gradient(135deg,rgba(255,255,255,0.08) 0%,rgba(255,255,255,0.02) 100%),rgba(10,15,30,0.85);"
        "border:1px solid rgba(255,255,255,0.12);box-shadow:0 20px 50px -10px rgba(0,0,0,0.7),inset 0 1px 0 rgba(255,255,255,0.2);"
        "border-radius:1.5rem;padding:2.5rem 2rem;max-width:480px;width:100%;text-align:center;position:relative;overflow:hidden\">"
        "<div style=\"display:inline-block;padding:0.35rem 1rem;border-radius:9999px;border:1px solid rgba(34,211,238,0.3);"
        "background:rgba(34,211,238,0.1);color:#67e8f9;font-size:0.75rem;font-weight:800;letter-spacing:0.1em;"
        f"font-family:monospace;margin-bottom:1.25rem\">ERROR {status}</div>"
        f"<h1 style=\"margin:0 0 0.75rem 0;font-size:1.5rem;font-weight:900;color:#ffffff;line-height:1.3\">{title}</h1>"
        f"<p style=\"margin:0 0 1.75rem 0;color:rgba(255,255,255,0.8);font-size:0.95rem;line-height:1.6\">{message}</p>"
        "<div style=\"display:flex;gap:0.75rem;justify-content:center;flex-wrap:wrap\">"
        "<a href=\"/\" style=\"display:inline-flex;align-items:center;padding:0.75rem 1.75rem;border-radius:9999px;"
        "background:#06b6d4;color:#001018;font-weight:800;font-size:0.8rem;text-decoration:none;letter-spacing:0.05em;"
        "text-transform:uppercase;box-shadow:0 6px 20px rgba(6,182,212,0.3)\">Về trang chủ</a>"
        "</div>"
        "<div style=\"margin-top:2rem;padding-top:1rem;border-top:1px solid rgba(255,255,255,0.06);"
        "font-size:0.75rem;color:rgba(255,255,255,0.4);display:flex;justify-content:space-between\">"
        "<span>ShieldCall VN</span><span>Security Gateway</span>"
        "</div>"
        "</div></body></html>"
    )
    return HttpResponse(body, status=status, content_type="text/html; charset=utf-8")


def error_400_view(request, exception=None):
    if _wants_json(request):
        return JsonResponse({"detail": "Bad request", "status_code": 400}, status=400)
    return _html("Yêu cầu không hợp lệ", "Vui lòng kiểm tra lại dữ liệu và thử lại.", 400)


def error_403_view(request, exception=None):
    if _wants_json(request):
        return JsonResponse({"detail": "Permission denied", "status_code": 403}, status=403)
    return _html("Không có quyền truy cập", "Bạn không có quyền truy cập tài nguyên này.", 403)


def error_404_view(request, exception=None):
    if _wants_json(request):
        return JsonResponse({"detail": "Endpoint not found", "status_code": 404}, status=404)
    return _html("Không tìm thấy trang", "Đường dẫn không tồn tại hoặc đã bị di chuyển.", 404)


def error_500_view(request):
    if _wants_json(request):
        return JsonResponse({"detail": "Internal server error", "status_code": 500}, status=500)
    return _html("Lỗi máy chủ", "Đã có lỗi xảy ra. Vui lòng thử lại sau giây lát.", 500)
