"""Auth API — login issues expiring Token; logout deletes it."""

from __future__ import annotations

from django.conf import settings
from django.contrib.auth import authenticate, get_user_model, password_validation
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from rest_framework import serializers, status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AccessRequest, AccessRequestAudit


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True)


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(
        max_length=150,
        validators=[UnicodeUsernameValidator()],
    )
    password = serializers.CharField(max_length=128, write_only=True, trim_whitespace=False)
    password_confirm = serializers.CharField(
        max_length=128,
        write_only=True,
        trim_whitespace=False,
    )

    def validate_username(self, value):
        user_model = get_user_model()
        username = user_model.normalize_username(value.strip())
        if not username:
            raise serializers.ValidationError("Tên đăng nhập không được để trống.")
        if user_model.objects.filter(username__iexact=username).exists():
            raise serializers.ValidationError("Tên đăng nhập đã tồn tại.")
        return username

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Mật khẩu nhập lại không khớp."}
            )

        candidate = get_user_model()(username=attrs["username"])
        try:
            password_validation.validate_password(attrs["password"], candidate)
        except ValidationError as exc:
            messages = []
            translations = {
                "password_too_short": "Mật khẩu phải có ít nhất 8 ký tự.",
                "password_too_common": "Mật khẩu quá phổ biến.",
                "password_entirely_numeric": "Mật khẩu không được chỉ gồm chữ số.",
                "password_too_similar": "Mật khẩu quá giống tên đăng nhập.",
            }
            for error in exc.error_list:
                messages.append(translations.get(error.code, str(error.message)))
            raise serializers.ValidationError({"password": messages}) from exc
        return attrs

    @transaction.atomic
    def create(self, validated_data):
        user_model = get_user_model()
        try:
            user = user_model.objects.create_user(
                username=validated_data["username"],
                password=validated_data["password"],
                is_active=False,
                is_staff=False,
                is_superuser=False,
            )
        except IntegrityError as exc:
            raise serializers.ValidationError(
                {"username": "Tên đăng nhập đã tồn tại."}
            ) from exc

        access_request = AccessRequest.objects.create(user=user)
        AccessRequestAudit.objects.create(
            access_request=access_request,
            action=AccessRequestAudit.Action.REGISTERED,
            role=access_request.role,
        )
        return access_request


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
        if user is None:
            inactive_user = (
                get_user_model()
                .objects.filter(username__iexact=serializer.validated_data["username"])
                .first()
            )
            if (
                inactive_user
                and not inactive_user.is_active
                and inactive_user.check_password(serializer.validated_data["password"])
            ):
                access_request = getattr(inactive_user, "access_request", None)
                account_status = getattr(access_request, "status", "inactive")
                details = {
                    AccessRequest.Status.PENDING: "Tài khoản đang chờ quản trị viên phê duyệt.",
                    AccessRequest.Status.REJECTED: "Yêu cầu truy cập đã bị từ chối.",
                    AccessRequest.Status.REVOKED: "Quyền truy cập của tài khoản đã bị thu hồi.",
                }
                return Response(
                    {
                        "detail": details.get(account_status, "Tài khoản chưa được kích hoạt."),
                        "code": f"account_{account_status}",
                    },
                    status=status.HTTP_403_FORBIDDEN,
                )
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
                "is_superuser": user.is_superuser,
                "expires_in_hours": ttl,
            }
        )


class RegisterView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_scope = "registration"

    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        access_request = serializer.save()
        return Response(
            {
                "status": access_request.status,
                "detail": "Yêu cầu tạo tài khoản đã được gửi và đang chờ quản trị viên phê duyệt.",
            },
            status=status.HTTP_201_CREATED,
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
