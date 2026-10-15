"""Cache-backed OTP verification attempt lockout.

Stops brute-forcing 6-digit OTPs (only 10^6 combinations): after
OTP_MAX_VERIFY_FAILS wrong guesses the identifier is blocked for
OTP_VERIFY_BLOCK_SECONDS. Fail-open if cache is down (availability over
strictness), matching the existing login-fail guard style.
"""
from django.core.cache import cache

OTP_MAX_VERIFY_FAILS = 10
OTP_VERIFY_BLOCK_SECONDS = 600


def _otp_fail_key(scope: str, ident: str) -> str:
    return f"otp_fail:{scope}:{ident}"


def otp_verify_blocked(scope: str, ident) -> bool:
    try:
        return int(cache.get(_otp_fail_key(scope, ident), 0)) >= OTP_MAX_VERIFY_FAILS
    except Exception:
        return False


def record_otp_verify_fail(scope: str, ident) -> None:
    try:
        key = _otp_fail_key(scope, ident)
        fails = int(cache.get(key, 0)) + 1
        cache.set(key, fails, timeout=OTP_VERIFY_BLOCK_SECONDS)
    except Exception:
        pass


def clear_otp_verify_fails(scope: str, ident) -> None:
    try:
        cache.delete(_otp_fail_key(scope, ident))
    except Exception:
        pass
