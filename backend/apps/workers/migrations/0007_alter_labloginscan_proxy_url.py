# Store encrypted proxy URLs without URLField validation/length semantics.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("workers", "0006_labloginscan_proxy_url"),
    ]

    operations = [
        migrations.AlterField(
            model_name="labloginscan",
            name="proxy_url",
            field=models.TextField(blank=True),
        ),
    ]
