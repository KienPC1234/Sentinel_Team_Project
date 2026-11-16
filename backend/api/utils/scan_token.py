"""Signed, expiring access tokens for anonymous scan results.

Anonymous scans are stored with ``user=None``; the browser session used to be
the only way to poll them. That breaks token-only/mobile clients and any
cross-origin Next.js deployment. A signed token keeps the scan id unguessable
without a DB migration and works with both sessions and DRF tokens.
"""
from typing import Optional

from django.conf import settings
from django.core import signing

_SALT = 'shieldcall.scan.access'
_MAX_AGE = int(getattr(settings, 'SCAN_TOKEN_MAX_AGE', 86400))


def issue_scan_token(scan_id: int) -> str:
    """Return an opaque signed token bound to a single scan id."""
    return signing.dumps({'scan_id': int(scan_id)}, salt=_SALT, compress=True)


def read_scan_token(token: Optional[str]) -> Optional[int]:
    """Validate a scan token and return its scan id, or ``None``."""
    if not token or not isinstance(token, str):
        return None
    try:
        payload = signing.loads(token, salt=_SALT, max_age=_MAX_AGE)
    except (signing.BadSignature, signing.SignatureExpired):
        return None
    if not isinstance(payload, dict):
        return None
    try:
        return int(payload.get('scan_id'))
    except (TypeError, ValueError):
        return None
