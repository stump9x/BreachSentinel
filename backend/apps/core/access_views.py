from __future__ import annotations

from django.db import transaction
from django.utils import timezone
from rest_framework import serializers, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import AccessRequest, AccessRequestAudit
from .permissions import IsSuperUser


class AccessRequestSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source="user.username", read_only=True)
    is_active = serializers.BooleanField(source="user.is_active", read_only=True)
    is_staff = serializers.BooleanField(source="user.is_staff", read_only=True)
    reviewed_by = serializers.CharField(source="reviewed_by.username", read_only=True)

    class Meta:
        model = AccessRequest
        fields = (
            "id",
            "username",
            "status",
            "role",
            "is_active",
            "is_staff",
            "requested_at",
            "reviewed_at",
            "reviewed_by",
            "updated_at",
        )


class AccessDecisionSerializer(serializers.Serializer):
    role = serializers.ChoiceField(
        choices=AccessRequest.Role.choices,
        required=False,
        default=AccessRequest.Role.ANALYST,
    )


class AccessRequestListView(APIView):
    permission_classes = [IsSuperUser]

    def get(self, request):
        queryset = AccessRequest.objects.select_related("user", "reviewed_by")
        requested_status = request.query_params.get("status", "").strip().lower()
        allowed_statuses = {value for value, _label in AccessRequest.Status.choices}
        if requested_status:
            if requested_status not in allowed_statuses:
                return Response(
                    {"detail": "Trạng thái không hợp lệ."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            queryset = queryset.filter(status=requested_status)
        rows = list(queryset[:500])
        return Response(
            {
                "count": len(rows),
                "results": AccessRequestSerializer(rows, many=True).data,
            }
        )


class AccessRequestActionView(APIView):
    permission_classes = [IsSuperUser]

    @transaction.atomic
    def post(self, request, pk: int, action: str):
        try:
            access_request = (
                AccessRequest.objects.select_for_update()
                .select_related("user", "reviewed_by")
                .get(pk=pk)
            )
        except AccessRequest.DoesNotExist:
            return Response(
                {"detail": "Không tìm thấy yêu cầu truy cập."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if action not in {"approve", "reject", "revoke"}:
            return Response(
                {"detail": "Thao tác không hợp lệ."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if access_request.user_id == request.user.id and action in {"reject", "revoke"}:
            return Response(
                {"detail": "Không thể tự thu hồi quyền truy cập của tài khoản quản trị."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user = access_request.user
        previous_status = access_request.status
        now = timezone.now()

        if action == "approve":
            decision = AccessDecisionSerializer(data=request.data)
            decision.is_valid(raise_exception=True)
            role = decision.validated_data["role"]
            access_request.status = AccessRequest.Status.APPROVED
            access_request.role = role
            user.is_active = True
            user.is_staff = role == AccessRequest.Role.STAFF
            user.save(update_fields=["is_active", "is_staff"])
            audit_action = (
                AccessRequestAudit.Action.ROLE_UPDATED
                if previous_status == AccessRequest.Status.APPROVED
                else AccessRequestAudit.Action.APPROVED
            )
        elif action == "reject":
            if previous_status != AccessRequest.Status.PENDING:
                return Response(
                    {"detail": "Chỉ có thể từ chối yêu cầu đang chờ duyệt."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            access_request.status = AccessRequest.Status.REJECTED
            user.is_active = False
            user.is_staff = False
            user.save(update_fields=["is_active", "is_staff"])
            audit_action = AccessRequestAudit.Action.REJECTED
        else:
            if previous_status != AccessRequest.Status.APPROVED:
                return Response(
                    {"detail": "Chỉ có thể thu hồi tài khoản đã được phê duyệt."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            access_request.status = AccessRequest.Status.REVOKED
            user.is_active = False
            user.is_staff = False
            user.save(update_fields=["is_active", "is_staff"])
            audit_action = AccessRequestAudit.Action.REVOKED

        access_request.reviewed_at = now
        access_request.reviewed_by = request.user
        access_request.save(
            update_fields=["status", "role", "reviewed_at", "reviewed_by", "updated_at"]
        )
        Token.objects.filter(user=user).delete()
        AccessRequestAudit.objects.create(
            access_request=access_request,
            action=audit_action,
            actor=request.user,
            role=access_request.role,
        )
        access_request.refresh_from_db()
        return Response(AccessRequestSerializer(access_request).data)
