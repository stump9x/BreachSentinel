from django.conf import settings
from django.db import models


class AccessRequest(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        REVOKED = "revoked", "Revoked"

    class Role(models.TextChoices):
        ANALYST = "analyst", "Analyst"
        STAFF = "staff", "Staff"

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="access_request",
    )
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
        db_index=True,
    )
    role = models.CharField(
        max_length=16,
        choices=Role.choices,
        default=Role.ANALYST,
    )
    requested_at = models.DateTimeField(auto_now_add=True, db_index=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="reviewed_access_requests",
    )
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ("-requested_at", "-id")

    def __str__(self) -> str:
        return f"{self.user.username} ({self.status})"


class AccessRequestAudit(models.Model):
    class Action(models.TextChoices):
        REGISTERED = "registered", "Registered"
        APPROVED = "approved", "Approved"
        REJECTED = "rejected", "Rejected"
        REVOKED = "revoked", "Revoked"
        ROLE_UPDATED = "role_updated", "Role updated"

    access_request = models.ForeignKey(
        AccessRequest,
        on_delete=models.CASCADE,
        related_name="audit_events",
    )
    action = models.CharField(max_length=24, choices=Action.choices)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        related_name="access_request_audit_events",
    )
    role = models.CharField(max_length=16, choices=AccessRequest.Role.choices, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        ordering = ("-created_at", "-id")

    def __str__(self) -> str:
        return f"{self.access_request.user.username}: {self.action}"
