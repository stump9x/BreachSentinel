from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AccessRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("pending", "Pending"),
                            ("approved", "Approved"),
                            ("rejected", "Rejected"),
                            ("revoked", "Revoked"),
                        ],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                (
                    "role",
                    models.CharField(
                        choices=[("analyst", "Analyst"), ("staff", "Staff")],
                        default="analyst",
                        max_length=16,
                    ),
                ),
                ("requested_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("reviewed_at", models.DateTimeField(blank=True, null=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "reviewed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="reviewed_access_requests",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "user",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="access_request",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ("-requested_at", "-id")},
        ),
        migrations.CreateModel(
            name="AccessRequestAudit",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "action",
                    models.CharField(
                        choices=[
                            ("registered", "Registered"),
                            ("approved", "Approved"),
                            ("rejected", "Rejected"),
                            ("revoked", "Revoked"),
                            ("role_updated", "Role updated"),
                        ],
                        max_length=24,
                    ),
                ),
                (
                    "role",
                    models.CharField(
                        blank=True,
                        choices=[("analyst", "Analyst"), ("staff", "Staff")],
                        max_length=16,
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                (
                    "access_request",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="audit_events",
                        to="core.accessrequest",
                    ),
                ),
                (
                    "actor",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="access_request_audit_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={"ordering": ("-created_at", "-id")},
        ),
    ]
