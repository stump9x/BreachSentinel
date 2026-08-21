# Generated manually for the guarded Logs Scanner lab verifier.

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("workers", "0001_log_scanner"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="LabLoginScan",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("target_domain", models.CharField(db_index=True, max_length=255)),
                ("target_url", models.URLField(max_length=2048)),
                ("hit_ids", models.JSONField(blank=True, default=list)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("completed", "Completed"), ("failed", "Failed")], db_index=True, default="queued", max_length=16)),
                ("candidate_count", models.PositiveIntegerField(default=0)),
                ("attempt_count", models.PositiveIntegerField(default=0)),
                ("success_count", models.PositiveIntegerField(default=0)),
                ("result_summary", models.JSONField(blank=True, default=dict)),
                ("error_message", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="lab_login_scans", to=settings.AUTH_USER_MODEL)),
                ("scan", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="lab_login_scans", to="workers.logscan")),
            ],
            options={"ordering": ["-created_at", "-id"]},
        ),
    ]
