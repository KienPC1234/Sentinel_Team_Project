"""
Custom DRF authentication classes for ShieldCall VN.
"""
from rest_framework.authentication import SessionAuthentication


class CsrfExemptSessionAuthentication(SessionAuthentication):
    """
    SessionAuthentication subclass that skips CSRF validation.
    
    Used for API endpoints where:
    - Requests come from the same-origin frontend (session cookie is valid)
    - CSRF tokens may not be available (e.g., first page load, AJAX calls)
    - Token authentication is the primary auth method
    
    This is safe because:
    - API endpoints use AllowAny or token auth primarily
    - Session auth is a convenience for logged-in users browsing APIs
    """
    def enforce_csrf(self, request):
        return  # Skip CSRF enforcement
