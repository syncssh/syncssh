from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0006_publickey_uniq_pubkey_payload_per_org"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="install_fetched_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
