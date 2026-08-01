# Merge migration: 0002_add_deploy_to_all (local) + 0002_ip_address_to_charfield (remote)

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0002_add_deploy_to_all'),
        ('core', '0002_ip_address_to_charfield'),
    ]

    operations = []
