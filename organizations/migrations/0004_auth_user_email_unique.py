"""Enforce case-insensitive uniqueness on auth_user.email.

Django's default User model doesn't make email unique. This blocks the
invite-hijack vector where an attacker registers with a victim's email
before the victim does (SECURITY_AUDIT #9). Postgres-only — uses a
functional unique index on LOWER(email).
"""
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0003_apikey"),
        # Pin auth so the auth_user table exists by the time we add the index.
        ("auth", "0012_alter_user_first_name_max_length"),
    ]

    operations = [
        migrations.RunSQL(
            sql=(
                "CREATE UNIQUE INDEX IF NOT EXISTS auth_user_email_lower_uniq "
                "ON auth_user (LOWER(email)) WHERE email <> '';"
            ),
            reverse_sql="DROP INDEX IF EXISTS auth_user_email_lower_uniq;",
        ),
    ]
