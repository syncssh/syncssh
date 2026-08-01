from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("core", "0008_merge_migrations"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="last_synced_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
