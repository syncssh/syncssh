"""Generic audit-log safety net.

Attaches post_save / post_delete to a small allowlist of models and writes
one `audit.log()` entry per event. Anything that bypasses this (admin shell,
direct ORM in scripts) still hits these signals — that's the point.

Views can call `audit.log()` directly when they need richer intent (e.g.
"server.token_rotated" instead of "server.updated").
"""

from django.db.models.signals import post_save, post_delete
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.dispatch import receiver

from syncssh import audit
from core.models import PublicKey, Server
from organizations.models import OrganizationMembership, ApiKey, OrganizationInvite


TRACKED_MODELS = [PublicKey, Server, OrganizationMembership, ApiKey, OrganizationInvite]


def _make_save_handler(model):
    def _handler(sender, instance, created, **kwargs):
        verb = "created" if created else "updated"
        audit.log(
            f"{model.__name__.lower()}.{verb}",
            target=instance,
        )
    return _handler


def _make_delete_handler(model):
    def _handler(sender, instance, **kwargs):
        audit.log(
            f"{model.__name__.lower()}.deleted",
            target=instance,
        )
    return _handler


_handlers = []  # keep refs alive (weak=False below already does, but be explicit)
for _model in TRACKED_MODELS:
    _save = _make_save_handler(_model)
    _delete = _make_delete_handler(_model)
    post_save.connect(_save, sender=_model, weak=False)
    post_delete.connect(_delete, sender=_model, weak=False)
    _handlers.extend([_save, _delete])


# -----------------------------------------------------------------------------
# Auth events — no model save, so signals are the only hook.
# -----------------------------------------------------------------------------


@receiver(user_logged_in)
def _on_login(sender, request, user, **kwargs):
    audit.log("auth.login", target=user, actor=user)


@receiver(user_logged_out)
def _on_logout(sender, request, user, **kwargs):
    if user is not None:
        audit.log("auth.logout", target=user, actor=user)


@receiver(user_login_failed)
def _on_login_failed(sender, credentials, request=None, **kwargs):
    # Don't echo passwords. Username is fine; if the attacker controls it,
    # it's already on their side.
    username = (credentials or {}).get("username") or (credentials or {}).get("email")
    audit.log(
        "auth.login_failed",
        actor_kind="system",
        attempted_username=username,
    )
