"""Shared DRF permission classes."""

from rest_framework.permissions import BasePermission


class IsStaffUser(BasePermission):
    """Staff/admin only — privileged ops (MISP, AI spend, ingest, stealer parse)."""

    message = "Staff privileges required for this action."

    def has_permission(self, request, view) -> bool:
        user = request.user
        return bool(user and user.is_authenticated and user.is_staff)
