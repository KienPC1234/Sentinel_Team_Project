"""Shared DRF permission classes for ShieldCall VN."""
from rest_framework.permissions import BasePermission


class IsAdminOrSuperAdmin(BasePermission):
    """Allow Django staff/superuser or a profile flagged as ``is_super_admin``.

    Django admin historically relied on ``request.user.is_staff`` plus the
    ``UserProfile.is_super_admin`` escape hatch. DRF's built-in ``IsAdminUser``
    only checks ``is_staff``, so API endpoints need this small extension to keep
    the same authorisation semantics as the server-rendered admin.
    """

    def has_permission(self, request, view):
        user = getattr(request, 'user', None)
        if user is None or not getattr(user, 'is_authenticated', False):
            return False
        if getattr(user, 'is_staff', False) or getattr(user, 'is_superuser', False):
            return True
        profile = getattr(user, 'profile', None)
        return bool(profile is not None and getattr(profile, 'is_super_admin', False))
