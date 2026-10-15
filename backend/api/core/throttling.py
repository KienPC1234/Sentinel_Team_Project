"""Scoped DRF throttles for expensive anonymous endpoints.

All scopes exempt API-key clients (`request.is_api_key_auth`), because that
path already enforces per-key per-minute limits + quotas in
`api.core.authentication.APIKeyAuthentication`.
"""
from rest_framework.throttling import SimpleRateThrottle


class _ApiKeyExemptMixin:
    def allow_request(self, request, view):
        if getattr(request, 'is_api_key_auth', False):
            return True
        return super().allow_request(request, view)


class _ScopedBase(_ApiKeyExemptMixin, SimpleRateThrottle):
    """Scope throttle keyed by user (authed) or IP (anonymous)."""
    scope = ''

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
