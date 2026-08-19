"""Expiring DRF token authentication (short-lived API credentials)."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.utils import timezone
from rest_framework import exceptions
from rest_framework.authentication import TokenAuthentication


class ExpiringTokenAuthentication(TokenAuthentication):
    """
    TokenAuthentication with TTL. Expired tokens are deleted on use.
    Default TTL: AUTH_TOKEN_TTL_HOURS (12).
    """

    keyword = "Token"

    def authenticate_credentials(self, key):
        model = self.get_model()
        try:
            token = model.objects.select_related("user").get(key=key)
        except model.DoesNotExist as exc:
            raise exceptions.AuthenticationFailed("Invalid token.") from exc

        if not token.user.is_active:
            raise exceptions.AuthenticationFailed("User inactive or deleted.")

        ttl_hours = int(getattr(settings, "AUTH_TOKEN_TTL_HOURS", 12) or 12)
        if ttl_hours > 0:
            age = timezone.now() - token.created
            if age > timedelta(hours=ttl_hours):
                token.delete()
                raise exceptions.AuthenticationFailed("Token expired.")

        return (token.user, token)
