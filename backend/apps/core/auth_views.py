"""Auth API — login issues expiring Token; logout deletes it."""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import serializers, status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)


class LoginView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_scope = "auth"

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = authenticate(
            request,
            username=serializer.validated_data["username"],
            password=serializer.validated_data["password"],
        )
        if user is None or not user.is_active:
            return Response(
                {"detail": "Invalid credentials."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        # Rotate token on each login (invalidate previous sessions for this user)
        Token.objects.filter(user=user).delete()
        token = Token.objects.create(user=user)
        ttl = int(getattr(settings, "AUTH_TOKEN_TTL_HOURS", 12) or 12)
        return Response(
            {
                "token": token.key,
                "username": user.username,
                "is_staff": user.is_staff,
                "expires_in_hours": ttl,
            }
        )


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        Token.objects.filter(user=request.user).delete()
        return Response({"status": "logged_out"})


class MeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        return Response(
            {
                "username": user.username,
                "is_staff": user.is_staff,
                "is_superuser": user.is_superuser,
            }
        )
