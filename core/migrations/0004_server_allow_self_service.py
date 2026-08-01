from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0003_server_token_hash"),
        # Merges in the sibling branch created on another dev box.
        ("core", "0002_add_deploy_to_all"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="allow_self_service",
            field=models.BooleanField(
                default=False,
                help_text=(
                    "If true, non-admin members may deploy their own public keys "
                    "to this server without admin assignment. Off by default — "
                    "production-style servers should stay locked down."
                ),
            ),
        ),
    ]
