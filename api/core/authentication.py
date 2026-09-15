"""
ShieldCall VN – API Key Authentication Backend
Provides secure token authentication, rate limiting, and quota enforcement
for MCP Server and third-party API clients.
"""
import logging
from django.utils import timezone
from django.core.cache import cache
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed, Throttled
from api.core.models import APIKey

logger = logging.getLogger(__name__)


class APIKeyAuthentication(BaseAuthentication):
    """
    Authenticates requests using ShieldCall API Keys (sc_live_...).
    Supports:
      - Header: X-API-Key: sc_live_...
      - Header: Authorization: Bearer sc_live_...
      - Header: Authorization: Api-Key sc_live_...
      - Query param: ?api_key=sc_live_... (optional fallback)
    """

    def authenticate_header(self, request):
        return 'Bearer realm="api"'

    def authenticate(self, request):
        raw_key = self._extract_raw_key(request)
        if not raw_key:
            return None

        # Basic format check
        if not raw_key.startswith('sc_live_'):
            raise AuthenticationFailed('Định dạng API Key không hợp lệ. Khóa phải bắt đầu bằng "sc_live_".')

        hashed = APIKey.hash_token(raw_key)

        try:
            api_key = APIKey.objects.select_related('user').get(hashed_key=hashed, is_active=True)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('API Key không tồn tại, đã hết hạn hoặc bị vô hiệu hóa.')

        if not api_key.user.is_active:
            raise AuthenticationFailed('Tài khoản liên kết với API Key này đã bị tạm khóa.')

        # Enforce rate limits and quotas
        self._enforce_quotas_and_rate_limits(api_key)

        # Attach helper attributes for views
        request.api_key = api_key
        request.is_api_key_auth = True

        return (api_key.user, api_key)

    def _extract_raw_key(self, request) -> str | None:
        # 1. Check X-API-Key header
        key = request.META.get('HTTP_X_API_KEY')
        if key:
            return key.strip()

        # 2. Check Authorization header
        auth = request.META.get('HTTP_AUTHORIZATION')
        if auth:
            parts = auth.split()
            if len(parts) == 2 and parts[0].lower() in ('bearer', 'api-key', 'token'):
                candidate = parts[1].strip()
                if candidate.startswith('sc_live_'):
                    return candidate

        # 3. Check Query parameter ?api_key=
        if hasattr(request, 'query_params'):
            query_key = request.query_params.get('api_key')
            if query_key and query_key.startswith('sc_live_'):
                return query_key.strip()
        elif hasattr(request, 'GET'):
            query_key = request.GET.get('api_key')
            if query_key and query_key.startswith('sc_live_'):
                return query_key.strip()

        return None

    def _enforce_quotas_and_rate_limits(self, api_key: APIKey):
        now = timezone.now()
        today = now.date()

        # Reset daily counters if day rolled over
        if api_key.last_reset_date != today:
            api_key.requests_today = 0
            if api_key.last_reset_date.month != today.month or api_key.last_reset_date.year != today.year:
                api_key.requests_this_month = 0
            api_key.last_reset_date = today

        # 1. Rate Limit per minute (via Redis cache)
        if api_key.rate_limit_per_minute > 0:
            minute_slot = now.strftime('%Y%m%d%H%M')
            rl_key = f"apikey:rl:{api_key.id}:{minute_slot}"
            try:
                # Atomically increment counter
                count = cache.incr(rl_key)
            except ValueError:
                # Key doesn't exist yet, initialize with 65s TTL
                cache.set(rl_key, 1, timeout=65)
                count = 1
            except Exception as ex:
                logger.warning(f"Cache failure in API key rate limiter: {ex}")
                count = 1

            if count > api_key.rate_limit_per_minute:
                raise Throttled(
                    detail=f"Vượt quá giới hạn tốc độ ({api_key.rate_limit_per_minute} req/phút). Vui lòng thử lại sau giây lát."
                )

        # 2. Daily Quota Check
        if api_key.daily_quota > 0 and api_key.requests_today >= api_key.daily_quota:
            raise Throttled(
                detail=f"Đã đạt giới hạn hạn mức hàng ngày ({api_key.requests_today}/{api_key.daily_quota} req). "
                       f"Hạn mức sẽ được đặt lại vào ngày mới (00:00 UTC)."
            )

        # 3. Monthly Quota Check
        if api_key.monthly_quota > 0 and api_key.requests_this_month >= api_key.monthly_quota:
            raise Throttled(
                detail=f"Đã đạt giới hạn hạn mức hàng tháng ({api_key.requests_this_month}/{api_key.monthly_quota} req)."
            )

        # Record usage
        api_key.requests_today += 1
        api_key.requests_this_month += 1
        api_key.total_requests += 1
        api_key.last_used_at = now
        api_key.save(update_fields=[
            'requests_today', 'requests_this_month', 'total_requests',
            'last_used_at', 'last_reset_date'
        ])

