from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0013_threat_title_vi"),
    ]

    operations = [
        migrations.AddField(
            model_name="threat",
            name="summary_hash",
            field=models.CharField(blank=True, db_index=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="threat",
            name="summary_source_language",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
        migrations.AddField(
            model_name="threat",
            name="summary_vi",
            field=models.TextField(blank=True, default=""),
        ),
        migrations.AddField(
            model_name="threat",
            name="summary_vi_attempts",
            field=models.PositiveSmallIntegerField(default=0),
        ),
        migrations.AddField(
            model_name="threat",
            name="summary_vi_provider",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.AddField(
            model_name="threat",
            name="summary_vi_status",
            field=models.CharField(
                choices=[
                    ("pending", "Pending"),
                    ("ok", "OK"),
                    ("rule", "Rule"),
                    ("skipped", "Skipped"),
                    ("failed", "Failed"),
                ],
                db_index=True,
                default="pending",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="threat",
            name="summary_vi_translated_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
