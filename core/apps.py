from django.apps import AppConfig
from django.db.models.signals import post_migrate


def _sync_site_from_settings(sender, **kwargs):
    """Keep the django.contrib.sites row in step with SITE_NAME/SITE_DOMAIN.

    allauth stamps the Site name/domain into verification email subjects and
    bodies; left untouched it reads "example.com". Running this on post_migrate
    means every deploy self-heals the row from the environment.
    """
    from django.conf import settings
    try:
        from django.contrib.sites.models import Site
        Site.objects.update_or_create(
            id=getattr(settings, 'SITE_ID', 1),
            defaults={
                'domain': settings.SITE_DOMAIN,
                'name': settings.SITE_NAME,
            },
        )
    except Exception:
        # Sites table not ready yet, or no DB — don't break the migrate run.
        pass


class CoreConfig(AppConfig):
    name = 'core'

    def ready(self):
        from . import signals  # noqa: F401 — register audit signal handlers
        post_migrate.connect(_sync_site_from_settings, sender=self)
