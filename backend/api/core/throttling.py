"""Scoped DRF throttles for expensive anonymous endpoints.

All scopes exempt API-key clients (`request.is_api_key_auth`), because that
path already enforces per-key per-minute limits + quotas in
`api.core.authentication.APIKeyAuthentication`.
"""
from rest_framework.throttling import (
    SimpleRateThrottle,
    AnonRateThrottle as _DRFAnonRateThrottle,
    UserRateThrottle as _DRFUserRateThrottle,
)


def client_ip(request) -> str:
    """IP client đáng tin cậy, KHÔNG dùng `X-Forwarded-For` thô (giả mạo được).

    - Sau Cloudflare: `CF-Connecting-IP` do Cloudflare ghi đè (an toàn để tin).
    - Ngược lại: `REMOTE_ADDR` (không do client đặt).
    Trước đây DRF đọc nguyên chuỗi XFF -> mỗi request đổi XFF là một bucket mới,
    vượt qua toàn bộ rate limit.
    """
    meta = getattr(request, 'META', {}) or {}
    cf = meta.get('HTTP_CF_CONNECTING_IP')
    if cf:
        return cf.strip()
    return meta.get('REMOTE_ADDR') or '0.0.0.0'


class AnonRateThrottle(_DRFAnonRateThrottle):
    """Rate theo IP ẩn danh — dùng IP đáng tin (không tin XFF thô)."""

    def get_ident(self, request):
        return client_ip(request)


class UserRateThrottle(_DRFUserRateThrottle):
    """Rate theo user (đã đăng nhập) hoặc IP đáng tin (ẩn danh)."""

    def get_ident(self, request):
        return client_ip(request)


class _ApiKeyExemptMixin:
    def allow_request(self, request, view):
        if getattr(request, 'is_api_key_auth', False):
            return True
        return super().allow_request(request, view)


class _ScopedBase(_ApiKeyExemptMixin, SimpleRateThrottle):
    """Scope throttle keyed by user (authed) or IP (anonymous)."""
    scope = ''

    def get_ident(self, request):
        return client_ip(request)

    def get_cache_key(self, request, view):
        user = getattr(request, 'user', None)
        if user is not None and user.is_authenticated:
            ident = f'user-{user.pk}'
        else:
            ident = self.get_ident(request)
        return self.cache_format % {'scope': self.scope, 'ident': ident}


class ScanSyncThrottle(_ScopedBase):
    scope = 'scan_sync'  # cheap sync scans: phone, bank account


class ScanThrottle(_ScopedBase):
    scope = 'scan'  # domain / message / email (network + AI assisted)


class ScanHeavyThrottle(_ScopedBase):
    scope = 'scan_heavy'  # Celery-offloaded: image / file / audio


class AIChatThrottle(_ScopedBase):
    scope = 'ai'  # LLM streaming chat


class AuthThrottle(_ScopedBase):
    scope = 'auth'  # login / register / OTP (brute-force surface)


class ReportThrottle(_ScopedBase):
    scope = 'report'  # community report submit (on top of IP throttle)


class TtsThrottle(_ScopedBase):
    scope = 'tts'  # server-side Vietnamese TTS (chế độ người cao tuổi)
    rate = '600/hour'  # hardcode để không phụ thuộc settings.py (file môi trường)


class TtsWarmThrottle(_ScopedBase):
    scope = 'tts_warm'  # prebuild audio theo lô (gọi khi mở trang Elder)
    rate = '60/hour'
