# Generated manually for Logs Scanner

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="LogUpload",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("original_name", models.CharField(max_length=512)),
                ("size_bytes", models.PositiveBigIntegerField(default=0)),
                ("stored_path", models.CharField(max_length=1024)),
                ("sha256", models.CharField(blank=True, db_index=True, max_length=64)),
                (
                    "uploaded_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="log_uploads",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at", "-id"],
            },
        ),
        migrations.CreateModel(
            name="LogScan",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "keyword",
                    models.CharField(blank=True, db_index=True, max_length=256),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("queued", "Queued"),
                            ("running", "Running"),
                            ("completed", "Completed"),
                            ("failed", "Failed"),
                        ],
                        db_index=True,
                        default="queued",
                        max_length=16,
                    ),
                ),
                ("hit_count", models.PositiveIntegerField(default=0)),
                ("lines_scanned", models.PositiveBigIntegerField(default=0)),
                ("files_scanned", models.PositiveIntegerField(default=0)),
                ("error_message", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="log_scans",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "uploads",
                    models.ManyToManyField(
                        blank=True, related_name="scans", to="workers.logupload"
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at", "-id"],
            },
        ),
        migrations.CreateModel(
            name="LogScanHit",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("url", models.CharField(blank=True, max_length=2048)),
                ("domain", models.CharField(blank=True, db_index=True, max_length=255)),
                (
                    "username",
                    models.CharField(blank=True, db_index=True, max_length=255),
                ),
                ("email", models.CharField(blank=True, db_index=True, max_length=255)),
                ("password", models.CharField(blank=True, max_length=1024)),
                ("raw_line", models.TextField(blank=True)),
                ("is_kept", models.BooleanField(db_index=True, default=False)),
                (
                    "kept_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="kept_log_hits",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "scan",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="hits",
                        to="workers.logscan",
                    ),
                ),
                (
                    "upload",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="hits",
                        to="workers.logupload",
                    ),
                ),
            ],
            options={
                "ordering": ["-id"],
            },
        ),
        migrations.AddIndex(
            model_name="logscanhit",
            index=models.Index(
                fields=["scan", "is_kept"], name="workers_log_scan_id_7f2a1b_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="logscanhit",
            index=models.Index(
                fields=["domain", "username"], name="workers_log_domain_3c9e4d_idx"
            ),
        ),
    ]
