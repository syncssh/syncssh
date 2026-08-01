"""Authentication-time handling for pending organization invites.

An invite is a security-sensitive membership change. Authentication may resume
the invite flow, but it must never accept an invite automatically: the explicit
CSRF-protected POST in ``InviteAcceptView`` is the only membership-creation
path. These receivers only discard tokens that can no longer be used.
"""

from django.contrib.auth.signals import user_logged_in
from django.dispatch import receiver

from allauth.account.signals import user_signed_up


def _discard_unusable_invite_session(request) -> None:
    if request is None:
        return
    invite_token = request.session.get("invite_token")
    if not invite_token:
        return

    from organizations.models import OrganizationInvite

    try:
        invite = OrganizationInvite.objects.select_related("organization").get(
            token=invite_token
        )
    except OrganizationInvite.DoesNotExist:
        request.session.pop("invite_token", None)
        return

    if invite.is_expired() or invite.is_accepted() or not invite.organization.is_active:
        request.session.pop("invite_token", None)


@receiver(user_signed_up)
def on_user_signed_up(request, user, **kwargs):
    _discard_unusable_invite_session(request)


@receiver(user_logged_in)
def on_user_logged_in(sender, request, user, **kwargs):
    _discard_unusable_invite_session(request)
