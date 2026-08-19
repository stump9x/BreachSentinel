"""Persisted Jobs for Logs Scanner (uploaded stealer dumps)."""

from __future__ import annotations

from django.conf import settings
from django.db import models


class TimeStampedModel(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class LogUpload(TimeStampedModel):
    """A .txt credential dump stored for keyword scanning."""

    original_name = models.CharField(max_length=512)
    size_bytes = models.PositiveBigIntegerField(default=0)
    stored_path = models.CharField(max_length=1024)
    sha256 = models.CharField(max_length=64, blank=True, db_index=True)
    uploaded_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="log_uploads",
    )

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return self.original_name


class LogScan(TimeStampedModel):
    class Status(models.TextChoices):
        QUEUED = "queued", "Queued"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    keyword = models.CharField(max_length=256, blank=True, db_index=True)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.QUEUED,
        db_index=True,
    )
    hit_count = models.PositiveIntegerField(default=0)
    lines_scanned = models.PositiveBigIntegerField(default=0)
    files_scanned = models.PositiveIntegerField(default=0)
    error_message = models.TextField(blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="log_scans",
    )
    uploads = models.ManyToManyField(LogUpload, related_name="scans", blank=True)

    class Meta:
        ordering = ["-created_at", "-id"]

    def __str__(self) -> str:
        return f"LogScan#{self.pk} {self.keyword or '*'} ({self.status})"


class LogScanHit(TimeStampedModel):
    """One url:username:password match from a scan (password stored encrypted)."""

    scan = models.ForeignKey(LogScan, on_delete=models.CASCADE, related_name="hits")
    upload = models.ForeignKey(
        LogUpload,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="hits",
    )
    url = models.CharField(max_length=2048, blank=True)
    domain = models.CharField(max_length=255, blank=True, db_index=True)
    username = models.CharField(max_length=255, blank=True, db_index=True)
    email = models.CharField(max_length=255, blank=True, db_index=True)
    # Encrypted via encrypt_secret(); decrypted for staff on Logs Scanner API only.
    password = models.CharField(max_length=1024, blank=True)
    raw_line = models.TextField(blank=True)
    is_kept = models.BooleanField(default=False, db_index=True)
    kept_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="kept_log_hits",
    )

    class Meta:
        ordering = ["-id"]
        indexes = [
            models.Index(fields=["scan", "is_kept"]),
            models.Index(fields=["domain", "username"]),
        ]

    def __str__(self) -> str:
        return f"{self.domain or self.url}:{self.username}"
