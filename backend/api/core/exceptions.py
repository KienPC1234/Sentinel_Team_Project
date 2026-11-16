"""Uniform JSON error envelope for DRF views.

The Next.js client already understands a top-level string ``error``. Keep that
shape (so existing UI keeps working) and add a stable machine-readable ``code``
plus optional field ``details``.
"""
from typing import Any, Optional

from rest_framework.views import exception_handler as drf_exception_handler

_STATUS_CODES = {
    400: 'VALIDATION_ERROR',
    401: 'AUTH_REQUIRED',
    403: 'PERMISSION_DENIED',
    404: 'NOT_FOUND',
    405: 'METHOD_NOT_ALLOWED',
    409: 'CONFLICT',
    429: 'RATE_LIMITED',
    500: 'SERVER_ERROR',
    502: 'UPSTREAM_UNAVAILABLE',
    503: 'SERVICE_UNAVAILABLE',
}


def _first_message(data: Any) -> Optional[str]:
    if isinstance(data, str):
        return data.strip() or None
    if isinstance(data, list):
        for item in data:
            msg = _first_message(item)
            if msg:
                return msg
        return None
    if isinstance(data, dict):
        detail = data.get('detail')
        if isinstance(detail, str) and detail.strip():
            return detail.strip()
        for key, value in data.items():
            if key in ('code', 'details', 'field_errors'):
                continue
            msg = _first_message(value)
            if msg:
                return msg
    return None


def api_exception_handler(exc, context):
    response = drf_exception_handler(exc, context)
    if response is None:
        return None

    data = response.data
    code = _STATUS_CODES.get(response.status_code, 'ERROR')

    # Views that already return ``{"error": "..."}`` (manual Response) are not
    # routed through this handler, but some custom APIException subclasses may.
    if isinstance(data, dict) and isinstance(data.get('error'), str):
        data.setdefault('code', code)
        return response

    message = _first_message(data) or 'Yêu cầu không hợp lệ.'
    payload = {'error': message, 'code': code}
    if isinstance(data, dict):
        field_errors = {
            key: value for key, value in data.items()
            if key not in ('detail', 'code', 'error')
        }
        if field_errors:
            payload['details'] = field_errors
    elif isinstance(data, list):
        payload['details'] = data

    response.data = payload
    return response
