from django.contrib import messages
from allauth.account.views import PasswordResetView

from api.utils.security import verify_turnstile_token


class TurnstilePasswordResetView(PasswordResetView):
    """Allauth password reset view with Cloudflare Turnstile verification."""

    def post(self, request, *args, **kwargs):
        token = request.POST.get('cf-turnstile-response')
        forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
        remote_ip = forwarded or request.META.get('REMOTE_ADDR')

        if not verify_turnstile_token(token, remote_ip=remote_ip):
            messages.error(request, 'Xác thực bảo mật thất bại. Vui lòng thử lại.')
            return self.get(request, *args, **kwargs)

        return super().post(request, *args, **kwargs)
