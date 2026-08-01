"""Transactional emails for the organizations domain.

Kept out of the views so the send logic (template rendering + multipart
assembly) lives in one place and stays testable. All sends go through Django's
configured ``EMAIL_BACKEND`` — in production that's the Lettermint HTTP API
backend (see ``syncssh.email_backends``).
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string

logger = logging.getLogger(__name__)

# Inline-style palettes for the HTML templates (email clients ignore
# stylesheets). Keys are referenced as {{ c.bg }} etc. in the templates.
# Dark mirrors the app's default look; light tracks the app's light theme.
EMAIL_PALETTES = {
    "dark": {
        "bg": "#0b0e14",
        "card": "#11151c",
        "border": "#232a36",
        "text": "#c9d1d9",
        "heading": "#e6edf3",
        "muted": "#8b949e",
        "accent": "#3fb950",
        "button": "#238636",
        "button_text": "#ffffff",
        "link": "#58a6ff",
    },
    "light": {
        "bg": "#f6f8fa",
        "card": "#ffffff",
        "border": "#d0d7de",
        "text": "#1f2328",
        "heading": "#1f2328",
        "muted": "#57606a",
        "accent": "#1a7f37",
        "button": "#1f883d",
        "button_text": "#ffffff",
        "link": "#0969da",
    },
}


def send_org_invite(invite, invite_url: str, inviter=None) -> bool:
    """Email an organization invite link to ``invite.email``.

    Returns True if the backend accepted the message, False on any failure.
    Never raises: a mail outage must not break invite creation, so the caller
    can still hand back the copyable ``invite_url``.
    """
    context = {
        "organization_name": invite.organization.name,
        "role": invite.get_role_display() if hasattr(invite, "get_role_display") else invite.role,
        "invite_url": invite_url,
        "inviter": getattr(inviter, "username", None) or getattr(inviter, "email", None),
        "expires_at": invite.expires_at.strftime("%b %d, %Y"),
        "app_base_url": getattr(settings, "APP_BASE_URL", "") or invite_url.split("/api/")[0],
        "c": EMAIL_PALETTES.get(
            invite.organization.invite_email_theme, EMAIL_PALETTES["dark"]
        ),
    }

    # Subject must be a single line — strip the trailing newline the template
    # file carries for readability.
    subject = render_to_string("email/org_invite_subject.txt", context).strip()
    text_body = render_to_string("email/org_invite.txt", context)
    html_body = render_to_string("email/org_invite.html", context)

    try:
        message = EmailMultiAlternatives(
            subject=subject,
            body=text_body,
            from_email=settings.DEFAULT_FROM_EMAIL,
            to=[invite.email],
        )
        message.attach_alternative(html_body, "text/html")
        sent = message.send(fail_silently=False)
        return bool(sent)
    except Exception:
        logger.exception("Failed to send org invite email to %s", invite.email)
        return False
