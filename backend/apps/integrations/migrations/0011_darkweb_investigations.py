import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("integrations", "0010_rename_integratio_scan_id_repo_txt_idx_integration_scan_id_a33802_idx"),
    ]

    operations = [
        migrations.CreateModel(
            name="DarkWebInvestigation",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("query", models.CharField(db_index=True, max_length=512)),
                ("refined_query", models.CharField(blank=True, max_length=256)),
                ("preset", models.CharField(choices=[("threat_intel", "Threat intelligence"), ("ransomware_malware", "Ransomware / malware"), ("personal_identity", "Personal identity exposure"), ("corporate_espionage", "Corporate exposure")], default="threat_intel", max_length=32)),
                ("status", models.CharField(choices=[("queued", "Queued"), ("running", "Running"), ("completed", "Completed"), ("partial", "Partial"), ("failed", "Failed")], db_index=True, default="queued", max_length=16)),
                ("summary", models.TextField(blank=True)),
                ("pivots", models.JSONField(blank=True, default=list)),
                ("parameters", models.JSONField(blank=True, default=dict)),
                ("engine_stats", models.JSONField(blank=True, default=list)),
                ("raw_result_count", models.PositiveIntegerField(default=0)),
                ("source_count", models.PositiveIntegerField(default=0)),
                ("scraped_count", models.PositiveIntegerField(default=0)),
                ("provider", models.CharField(blank=True, max_length=32)),
                ("model", models.CharField(blank=True, max_length=128)),
                ("error_message", models.TextField(blank=True)),
                ("started_at", models.DateTimeField(blank=True, null=True)),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("active_slot", models.BooleanField(editable=False, null=True)),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="dark_web_investigations", to=settings.AUTH_USER_MODEL)),
            ],
            options={"ordering": ["-created_at", "-id"]},
        ),
        migrations.CreateModel(
            name="DarkWebMessage",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("role", models.CharField(choices=[("user", "User"), ("assistant", "Assistant")], max_length=16)),
                ("content", models.TextField()),
                ("created_by", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="dark_web_messages", to=settings.AUTH_USER_MODEL)),
                ("investigation", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="messages", to="integrations.darkwebinvestigation")),
            ],
            options={"ordering": ["created_at", "id"]},
        ),
        migrations.CreateModel(
            name="DarkWebSource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("engine", models.CharField(db_index=True, max_length=64)),
                ("title", models.CharField(max_length=512)),
                ("url", models.URLField(max_length=2048)),
                ("url_hash", models.CharField(max_length=64)),
                ("fetch_status", models.CharField(choices=[("found", "Found"), ("scraped", "Scraped"), ("failed", "Failed"), ("skipped", "Skipped")], db_index=True, default="found", max_length=16)),
                ("content_excerpt", models.TextField(blank=True)),
                ("content_hash", models.CharField(blank=True, max_length=64)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("investigation", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="sources", to="integrations.darkwebinvestigation")),
            ],
            options={"ordering": ["id"]},
        ),
        migrations.AddConstraint(
            model_name="darkwebinvestigation",
            constraint=models.UniqueConstraint(condition=models.Q(("active_slot", True)), fields=("active_slot",), name="uniq_active_darkweb_investigation"),
        ),
        migrations.AddConstraint(
            model_name="darkwebsource",
            constraint=models.UniqueConstraint(fields=("investigation", "url_hash"), name="uniq_darkweb_investigation_url"),
        ),
        migrations.AddIndex(
            model_name="darkwebsource",
            index=models.Index(fields=["investigation", "fetch_status"], name="darkweb_inv_fetch_idx"),
        ),
    ]
