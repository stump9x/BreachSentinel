"""API for Logs Scanner: upload dumps, keyword scan, keep hits."""

from __future__ import annotations

import uuid

from django.conf import settings
from django.db.models import Q
from django.utils.dateparse import parse_date
from rest_framework import serializers, status, viewsets
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, JSONParser, MultiPartParser
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.crypto import decrypt_secret
from apps.core.permissions import IsStaffUser
from apps.workers.log_scanner import (
    delete_upload,
    finalize_upload_chunks,
    max_files_per_scan,
    max_hits_per_scan,
    max_upload_bytes,
    store_upload_chunk,
    store_upload_file,
)
from apps.workers.lab_login_verifier import (
    normalize_lab_hostname,
    normalize_lab_proxy,
    normalize_lab_target,
)
from apps.workers.models import LabAllowlistEntry, LabLoginScan, LogScan, LogScanHit, LogUpload
from apps.workers.tasks import run_lab_login_scan_task, run_log_scan_task


class LogUploadSerializer(serializers.ModelSerializer):
    class Meta:
        model = LogUpload
        fields = (
            "id",
            "original_name",
            "size_bytes",
            "sha256",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class LogUploadChunkView(APIView):
    """Receive resumable upload chunks for large Logs Scanner files."""

    permission_classes = [IsStaffUser]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        chunk = request.FILES.get("chunk")
        if chunk is None:
            return Response(
                {"detail": "Missing multipart field 'chunk'."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            upload_id = uuid.UUID(str(request.data.get("upload_id") or ""))
            original_name = str(request.data.get("file_name") or chunk.name)
            file_size = int(request.data.get("file_size") or 0)
            total_chunks = int(request.data.get("total_chunks") or 0)
            chunk_index = int(request.data.get("chunk_index") or 0)
            result = store_upload_chunk(
                uploaded_file=chunk,
                user=request.user,
                upload_id=upload_id,
                original_name=original_name,
                file_size=file_size,
                total_chunks=total_chunks,
                chunk_index=chunk_index,
            )
            if result.get("upload"):
                row = result["upload"]
                return Response(
                    {
                        "complete": True,
                        "received_bytes": file_size,
                        "upload": LogUploadSerializer(row).data,
                    }
                )
            if result["complete"]:
                row = finalize_upload_chunks(
                    user=request.user,
                    upload_id=upload_id,
                    original_name=original_name,
                    file_size=file_size,
                )
                return Response(
                    {
                        "complete": True,
                        "received_bytes": file_size,
                        "upload": LogUploadSerializer(row).data,
                    },
                    status=status.HTTP_201_CREATED,
                )
            return Response(
                {
                    "complete": False,
                    "chunk_index": chunk_index,
                    "received_bytes": result["received_bytes"],
                }
            )
        except (TypeError, ValueError) as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)


class LogScanSerializer(serializers.ModelSerializer):
    upload_ids = serializers.SerializerMethodField()

    class Meta:
        model = LogScan
        fields = (
            "id",
            "keyword",
            "status",
            "hit_count",
            "lines_scanned",
            "files_scanned",
            "error_message",
            "started_at",
            "completed_at",
            "created_at",
            "updated_at",
            "upload_ids",
        )
        read_only_fields = fields

    def get_upload_ids(self, obj):
        return list(obj.uploads.values_list("id", flat=True))


class LabLoginScanSerializer(serializers.ModelSerializer):
    class Meta:
        model = LabLoginScan
        fields = (
            "id",
            "scan",
            "target_domain",
            "target_url",
            "proxy_url",
            "status",
            "candidate_count",
            "attempt_count",
            "success_count",
            "result_summary",
            "is_hidden",
            "error_message",
            "started_at",
            "completed_at",
            "created_by",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class LabAllowlistCreateSerializer(serializers.Serializer):
    host = serializers.CharField(min_length=1, max_length=255)


class LabLoginVisibilitySerializer(serializers.Serializer):
    is_hidden = serializers.BooleanField()


class LabAllowlistView(APIView):
    """Read and extend the exact, lab-only hostname allowlist."""

    permission_classes = [IsStaffUser]

    def get(self, request):
        configured = {
            item.strip().casefold().rstrip(".")
            for item in str(getattr(settings, "BRUTEFORCEAI_ALLOWED_HOSTS", "") or "").split(",")
            if item.strip()
        }
        db_hosts = set(
            LabAllowlistEntry.objects.values_list("host", flat=True)
        )
        rows = [
            {"host": host, "source": "config" if host in configured else "ui"}
            for host in sorted(configured | db_hosts)
        ]
        return Response(rows)

    def post(self, request):
        serializer = LabAllowlistCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            host = normalize_lab_hostname(serializer.validated_data["host"])
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        entry, created = LabAllowlistEntry.objects.get_or_create(
            host=host,
            defaults={"created_by": request.user},
        )
        return Response(
            {"host": entry.host, "source": "ui", "created": created},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )

    def delete(self, request):
        raw_host = request.query_params.get("host", "")
        try:
            host = normalize_lab_hostname(raw_host)
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        configured = {
            item.strip().casefold().rstrip(".")
            for item in str(getattr(settings, "BRUTEFORCEAI_ALLOWED_HOSTS", "") or "").split(",")
            if item.strip()
        }
        if host in configured:
            return Response(
                {"detail": "Hosts configured through environment settings cannot be removed here."},
                status=status.HTTP_409_CONFLICT,
            )

        deleted, _ = LabAllowlistEntry.objects.filter(host=host).delete()
        if not deleted:
            return Response({"detail": "Allowlist entry was not found."}, status=status.HTTP_404_NOT_FOUND)
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogScanCreateSerializer(serializers.Serializer):
    keyword = serializers.CharField(required=False, allow_blank=True, max_length=256)
    upload_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        allow_empty=False,
        max_length=50,
    )
    async_mode = serializers.BooleanField(default=True)

    def validate_upload_ids(self, value):
        limit = max_files_per_scan()
        unique = list(dict.fromkeys(value))
        if len(unique) > limit:
            raise serializers.ValidationError(
                f"Select at most {limit} files per scan."
            )
        return unique


class LabLoginScanCreateSerializer(serializers.Serializer):
    target_url = serializers.CharField(min_length=2, max_length=2048)
    domain = serializers.CharField(min_length=1, max_length=255)
    proxy_url = serializers.CharField(required=False, allow_blank=True, max_length=2048)
    hit_ids = serializers.ListField(
        child=serializers.IntegerField(min_value=1),
        required=False,
        allow_empty=True,
        max_length=20,
    )

    def validate_domain(self, value):
        return value.strip().casefold().rstrip(".")

    def validate_proxy_url(self, value):
        try:
            return normalize_lab_proxy(value)
        except ValueError as exc:
            raise serializers.ValidationError(str(exc)) from exc


class LogScanHitSerializer(serializers.ModelSerializer):
    password = serializers.SerializerMethodField()
    source_file = serializers.SerializerMethodField()

    class Meta:
        model = LogScanHit
        fields = (
            "id",
            "scan",
            "url",
            "domain",
            "username",
            "email",
            "password",
            "is_kept",
            "source_file",
            "created_at",
        )
        read_only_fields = fields

    def get_password(self, obj) -> str:
        # Staff-only Logs Scanner reveals plaintext for analyst triage.
        return decrypt_secret(obj.password or "")

    def get_source_file(self, obj) -> str:
        if obj.upload_id and obj.upload:
            return obj.upload.original_name
        return ""


class LogUploadViewSet(viewsets.ModelViewSet):
    """List / upload / delete credential dump files. Staff only."""

    permission_classes = [IsStaffUser]
    serializer_class = LogUploadSerializer
    parser_classes = [MultiPartParser, FormParser, JSONParser]
    http_method_names = ["get", "post", "delete", "head", "options"]

    def get_queryset(self):
        qs = LogUpload.objects.all()
        user = self.request.user
        if not user.is_superuser:
            qs = qs.filter(uploaded_by=user)

        date_from = self.request.query_params.get("date_from") or ""
        date_to = self.request.query_params.get("date_to") or ""
        q = (self.request.query_params.get("q") or "").strip()
        if date_from:
            parsed = parse_date(date_from)
            if parsed:
                qs = qs.filter(created_at__date__gte=parsed)
        if date_to:
            parsed = parse_date(date_to)
            if parsed:
                qs = qs.filter(created_at__date__lte=parsed)
        if q:
            qs = qs.filter(original_name__icontains=q)
        return qs

    def create(self, request, *args, **kwargs):
        files = request.FILES.getlist("files") or request.FILES.getlist("file")
        if not files:
            single = request.FILES.get("file") or request.FILES.get("files")
            files = [single] if single else []
        if not files:
            return Response(
                {"detail": "No files uploaded. Use multipart field 'files'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        created = []
        errors = []
        for uploaded in files:
            try:
                row = store_upload_file(uploaded_file=uploaded, user=request.user)
                created.append(LogUploadSerializer(row).data)
            except ValueError as exc:
                errors.append(
                    {
                        "name": getattr(uploaded, "name", ""),
                        "error": str(exc),
                    }
                )
        payload = {
            "created": created,
            "errors": errors,
            "max_upload_bytes": max_upload_bytes(),
        }
        code = (
            status.HTTP_201_CREATED
            if created
            else status.HTTP_400_BAD_REQUEST
        )
        return Response(payload, status=code)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        delete_upload(instance)
        return Response(status=status.HTTP_204_NO_CONTENT)


class LogScanViewSet(viewsets.ReadOnlyModelViewSet):
    """Create and poll log keyword scans. Staff only."""

    permission_classes = [IsStaffUser]
    serializer_class = LogScanSerializer
    http_method_names = ["get", "post", "head", "options"]

    def get_queryset(self):
        qs = LogScan.objects.prefetch_related("uploads").all()
        user = self.request.user
        if not user.is_superuser:
            qs = qs.filter(created_by=user)
        return qs

    def create(self, request, *args, **kwargs):
        serializer = LogScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        upload_ids = data["upload_ids"]

        uploads_qs = LogUpload.objects.filter(id__in=upload_ids)
        if not request.user.is_superuser:
            uploads_qs = uploads_qs.filter(uploaded_by=request.user)
        uploads = list(uploads_qs)
        if len(uploads) != len(upload_ids):
            return Response(
                {"detail": "One or more upload_ids are invalid."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan = LogScan.objects.create(
            keyword=(data.get("keyword") or "").strip(),
            status=LogScan.Status.QUEUED,
            created_by=request.user,
        )
        scan.uploads.set(uploads)

        async_mode = data.get("async_mode", True)
        if async_mode:
            run_log_scan_task.delay(scan.id)
            return Response(
                LogScanSerializer(scan).data,
                status=status.HTTP_202_ACCEPTED,
            )

        result = run_log_scan_task.apply(kwargs={"scan_id": scan.id}).get()
        scan.refresh_from_db()
        return Response(
            {**LogScanSerializer(scan).data, "result": result},
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["post"], url_path="credential-test")
    def credential_test(self, request, pk=None):
        scan = self.get_object()
        serializer = LabLoginScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        try:
            target_url, target_domain = normalize_lab_target(data["target_url"])
        except ValueError as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_403_FORBIDDEN)

        requested_ids = list(dict.fromkeys(data.get("hit_ids") or []))
        qs = LogScanHit.objects.filter(scan=scan, domain__iexact=data["domain"])
        if requested_ids:
            qs = qs.filter(id__in=requested_ids)
        hits = list(qs.order_by("id")[:20])
        if not hits:
            return Response(
                {"detail": "No credential hits match the selected lab domain."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        job = LabLoginScan.objects.create(
            scan=scan,
            target_domain=target_domain,
            target_url=target_url,
            proxy_url=data.get("proxy_url", ""),
            hit_ids=[hit.id for hit in hits],
            candidate_count=len(hits),
            created_by=request.user,
        )
        task = run_lab_login_scan_task.delay(job.id)
        return Response(
            {**LabLoginScanSerializer(job).data, "task_id": task.id},
            status=status.HTTP_202_ACCEPTED,
        )

    def get_throttles(self):
        if self.action == "create":
            from rest_framework.throttling import ScopedRateThrottle

            class CreateThrottle(ScopedRateThrottle):
                scope = "log_scan_create"

            return [CreateThrottle()]
        return super().get_throttles()

    @action(detail=True, methods=["get"], url_path="hits")
    def hits(self, request, pk=None):
        scan = self.get_object()
        qs = (
            LogScanHit.objects.filter(scan=scan)
            .select_related("upload")
            .order_by("-id")
        )
        kept = request.query_params.get("kept")
        if kept in {"1", "true", "True"}:
            qs = qs.filter(is_kept=True)
        elif kept in {"0", "false", "False"}:
            qs = qs.filter(is_kept=False)

        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(LogScanHitSerializer(page, many=True).data)
        return Response(LogScanHitSerializer(qs, many=True).data)


class LogScanHitViewSet(viewsets.GenericViewSet):
    """Keep / unkeep / list kept credential hits. Staff only."""

    permission_classes = [IsStaffUser]
    serializer_class = LogScanHitSerializer
    queryset = LogScanHit.objects.select_related("upload", "scan").all()

    def get_queryset(self):
        qs = super().get_queryset()
        user = self.request.user
        if not user.is_superuser:
            qs = qs.filter(
                Q(scan__created_by=user) | Q(kept_by=user) | Q(upload__uploaded_by=user)
            ).distinct()
        return qs

    @action(detail=False, methods=["get"], url_path="kept")
    def kept(self, request):
        qs = self.get_queryset().filter(is_kept=True).order_by("-updated_at", "-id")
        if not request.user.is_superuser:
            qs = qs.filter(kept_by=request.user)
        page = self.paginate_queryset(qs)
        if page is not None:
            return self.get_paginated_response(LogScanHitSerializer(page, many=True).data)
        return Response(LogScanHitSerializer(qs, many=True).data)

    @action(detail=True, methods=["post"], url_path="keep")
    def keep(self, request, pk=None):
        hit = self.get_object()
        hit.is_kept = True
        hit.kept_by = request.user
        hit.save(update_fields=["is_kept", "kept_by", "updated_at"])
        return Response(LogScanHitSerializer(hit).data)

    @action(detail=True, methods=["post"], url_path="unkeep")
    def unkeep(self, request, pk=None):
        hit = self.get_object()
        hit.is_kept = False
        hit.kept_by = None
        hit.save(update_fields=["is_kept", "kept_by", "updated_at"])
        return Response(LogScanHitSerializer(hit).data)

    @action(detail=False, methods=["post"], url_path="clear-kept")
    def clear_kept(self, request):
        qs = LogScanHit.objects.filter(is_kept=True)
        if not request.user.is_superuser:
            qs = qs.filter(kept_by=request.user)
        updated = qs.update(is_kept=False, kept_by=None)
        return Response({"cleared": updated})


class LabLoginScanViewSet(viewsets.ReadOnlyModelViewSet):
    """Poll saved lab login verification jobs without exposing passwords."""

    permission_classes = [IsStaffUser]
    serializer_class = LabLoginScanSerializer

    def _owned_queryset(self):
        qs = LabLoginScan.objects.select_related("scan").all()
        if not self.request.user.is_superuser:
            qs = qs.filter(created_by=self.request.user)
        return qs

    def get_queryset(self):
        qs = self._owned_queryset()
        scan_id = self.request.query_params.get("scan")
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        include_hidden = str(self.request.query_params.get("include_hidden", "")).casefold()
        if self.action == "list" and include_hidden not in {"1", "true", "yes"}:
            qs = qs.filter(is_hidden=False)
        return qs

    @action(detail=True, methods=["patch"], url_path="visibility")
    def visibility(self, request, pk=None):
        serializer = LabLoginVisibilitySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        job = self.get_object()
        job.is_hidden = serializer.validated_data["is_hidden"]
        job.save(update_fields=["is_hidden", "updated_at"])
        return Response(LabLoginScanSerializer(job).data)

    def destroy(self, request, *args, **kwargs):
        job = self.get_object()
        if job.status in {LabLoginScan.Status.QUEUED, LabLoginScan.Status.RUNNING}:
            return Response(
                {"detail": "An active login verification cannot be deleted."},
                status=status.HTTP_409_CONFLICT,
            )
        job.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=False, methods=["delete"], url_path="clear")
    def clear_history(self, request):
        qs = self._owned_queryset().exclude(
            status__in=[LabLoginScan.Status.QUEUED, LabLoginScan.Status.RUNNING]
        )
        count = qs.count()
        qs.delete()
        return Response({"deleted": count})


class LogScanLimitsView(APIView):
    permission_classes = [IsStaffUser]

    def get(self, request):
        return Response(
            {
                "max_upload_bytes": max_upload_bytes(),
                "max_files_per_scan": max_files_per_scan(),
                "max_hits": max_hits_per_scan(),
            }
        )
