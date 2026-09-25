from __future__ import annotations

from django.contrib.auth import get_user_model, password_validation
from django.contrib.auth.hashers import make_password
from django.core.exceptions import ValidationError
from django.db import transaction
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.authtoken.models import Token
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AccessRequest, PasswordResetRequest
from .permissions import IsSuperUser


GENERIC_REQUEST_DETAIL = (
    "Nếu tài khoản đã được quản trị viên phê duyệt, yêu cầu đổi mật khẩu "
    "đã được gửi để quản trị viên xem xét."
)


def _password_errors(password: str, user) -> list[str]:
    try:
        password_validation.validate_password(password, user)
    except ValidationError as exc:
        translations = {
            "password_too_short": "Mật khẩu phải có ít nhất 8 ký tự.",
            "password_too_common": "Mật khẩu quá phổ biến.",
            "password_entirely_numeric": "Mật khẩu không được chỉ gồm chữ số.",
            "password_too_similar": "Mật khẩu quá giống tên đăng nhập.",
        }
        return [translations.get(error.code, str(error.message)) for error in exc.error_list]
    return []


class PasswordResetCreateSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(max_length=128, write_only=True, trim_whitespace=False)
    password_confirm = serializers.CharField(
        max_length=128,
        write_only=True,
        trim_whitespace=False,
    )

    def validate(self, attrs):
        if attrs["password"] != attrs["password_confirm"]:
            raise serializers.ValidationError(
                {"password_confirm": "Mật khẩu nhập lại không khớp."}
            )
        return attrs


class PasswordResetRequestSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    reviewed_by = serializers.CharField(source="reviewed_by.username", read_only=True)

    class Meta:
        model = PasswordResetRequest
        fields = (
            "id",
            "username",
            "status",
            "requested_at",
            "reviewed_at",
            "reviewed_by",
            "updated_at",
        )


class PasswordResetCreateView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    throttle_scope = "password_reset"

    @transaction.atomic
    def post(self, request):
        serializer = PasswordResetCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        username = serializer.validated_data["username"].strip()
        candidate = get_user_model()(username=username)
        errors = _password_errors(serializer.validated_data["password"], candidate)
        if errors:
            raise serializers.ValidationError({"password": errors})
        user = (
            get_user_model()
            .objects.select_for_update()
            .filter(username__iexact=username)
            .first()
        )
        access_request = getattr(user, "access_request", None) if user else None
        eligible = bool(
            user
            and user.is_active
            and access_request
            and access_request.status == AccessRequest.Status.APPROVED
        )
        if eligible:
            PasswordResetRequest.objects.update_or_create(
                user=user,
                defaults={
                    "status": PasswordResetRequest.Status.PENDING,
                    "new_password_hash": make_password(
                        serializer.validated_data["password"]
                    ),
                    "requested_at": timezone.now(),
                    "reviewed_at": None,
                    "reviewed_by": None,
                },
            )
        return Response(
            {"detail": GENERIC_REQUEST_DETAIL},
            status=status.HTTP_202_ACCEPTED,
        )


class PasswordResetRequestListView(APIView):
    permission_classes = [IsSuperUser]

    def get(self, request):
        queryset = PasswordResetRequest.objects.select_related("user", "reviewed_by")
        requested_status = request.query_params.get("status", "").strip().lower()
        allowed = {value for value, _label in PasswordResetRequest.Status.choices}
        if requested_status:
            if requested_status not in allowed:
                return Response(
                    {"detail": "Trạng thái không hợp lệ."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            queryset = queryset.filter(status=requested_status)
        rows = list(queryset[:500])
        return Response(
            {
                "count": len(rows),
                "results": PasswordResetRequestSerializer(rows, many=True).data,
            }
        )


class PasswordResetRequestActionView(APIView):
    permission_classes = [IsSuperUser]

    @transaction.atomic
    def post(self, request, pk: int, action: str):
        try:
            reset_request = (
                PasswordResetRequest.objects.select_for_update()
                .select_related("user")
                .get(pk=pk)
            )
        except PasswordResetRequest.DoesNotExist:
            return Response(
                {"detail": "Không tìm thấy yêu cầu đổi mật khẩu."},
                status=status.HTTP_404_NOT_FOUND,
            )
        if action not in {"approve", "reject"}:
            return Response(
                {"detail": "Thao tác không hợp lệ."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if reset_request.status != PasswordResetRequest.Status.PENDING:
            return Response(
                {"detail": "Yêu cầu này đã được xử lý."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = reset_request.user
        access_request = getattr(user, "access_request", None)
        if action == "approve":
            if not (
                user.is_active
                and access_request
                and access_request.status == AccessRequest.Status.APPROVED
                and reset_request.new_password_hash
            ):
                return Response(
                    {"detail": "Tài khoản không còn đủ điều kiện đổi mật khẩu."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            user.password = reset_request.new_password_hash
            user.save(update_fields=["password"])
            Token.objects.filter(user=user).delete()
            reset_request.status = PasswordResetRequest.Status.APPROVED
        else:
            reset_request.status = PasswordResetRequest.Status.REJECTED

        reset_request.new_password_hash = ""
        reset_request.reviewed_at = timezone.now()
        reset_request.reviewed_by = request.user
        reset_request.save(
            update_fields=[
                "status",
                "new_password_hash",
                "reviewed_at",
                "reviewed_by",
                "updated_at",
            ]
        )
        return Response(PasswordResetRequestSerializer(reset_request).data)
