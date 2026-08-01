import hashlib

from django.db import migrations, models


def hash_existing_tokens(apps, schema_editor):
    Server = apps.get_model("core", "Server")
    for server in Server.objects.all():
        raw = server.token or ""
        server.token_hash = hashlib.sha256(raw.encode()).hexdigest()
        server.token_prefix = raw[:12]
        server.save(update_fields=["token_hash", "token_prefix"])


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0002_ip_address_to_charfield"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="token_hash",
            field=models.CharField(
                max_length=64,
                null=True,
                help_text="SHA-256 of the raw sync token; raw token never stored",
            ),
        ),
        migrations.AddField(
            model_name="server",
            name="token_prefix",
            field=models.CharField(
                max_length=20,
                null=True,
                help_text="First few chars of the raw token, for display only",
            ),
        ),
        migrations.RunPython(hash_existing_tokens, migrations.RunPython.noop),
        migrations.AlterField(
            model_name="server",
            name="token_hash",
            field=models.CharField(
                max_length=64,
                unique=True,
                help_text="SHA-256 of the raw sync token; raw token never stored",
            ),
        ),
        migrations.AlterField(
            model_name="server",
            name="token_prefix",
            field=models.CharField(
                max_length=20,
                help_text="First few chars of the raw token, for display only",
            ),
        ),
        migrations.RemoveField(
            model_name="server",
            name="token",
        ),
    ]
