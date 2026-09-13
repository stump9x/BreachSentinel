from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("workers", "0007_alter_labloginscan_proxy_url"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="LabProxyProfile",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("created_at", models.DateTimeField(auto_now_add=True, db_index=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("name", models.CharField(max_length=120)),
                ("proxy_url", models.TextField()),
                ("is_default", models.BooleanField(db_index=True, default=False)),
                (
                    "owner",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="lab_proxy_profiles",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["-is_default", "name", "-id"],
            },
        ),
        migrations.AddConstraint(
            model_name="labproxyprofile",
            constraint=models.UniqueConstraint(
                fields=("owner", "name"),
                name="workers_labproxyprofile_owner_name_uniq",
            ),
        ),
        migrations.AddField(
            model_name="labloginscan",
            name="proxy_profile",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="login_scans",
                to="workers.labproxyprofile",
            ),
        ),
    ]
