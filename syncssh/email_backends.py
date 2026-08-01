"""Email backends that deliver over an HTTP API instead of SMTP.

Some hosts (DigitalOcean and friends) block outbound SMTP, and the API path
gives better deliverability signals anyway. These backends plug into Django's
normal mail machinery, so allauth verification / password-reset / invite emails
flow through them unchanged — only ``EMAIL_BACKEND`` in the env needs to point
here.

The Lettermint call mirrors the proven one in the sibling pychat app: stdlib
``urllib`` only, no ``requests`` dependency.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from django.conf import settings
from django.core.mail.backends.base import BaseEmailBackend

LETTERMINT_ENDPOINT = 'https://api.lettermint.co/v1/send'


class LettermintAPIBackend(BaseEmailBackend):
    """Send Django ``EmailMessage`` objects via the Lettermint HTTP API.

    Reads ``LETTERMINT_TOKEN`` from settings. Unlike pychat's fire-and-forget
    helper, a failed send raises (unless ``fail_silently``) so allauth's signup
    flow can tell the user their verification email didn't go out.
    """

    def __init__(self, fail_silently=False, **kwargs):
        super().__init__(fail_silently=fail_silently, **kwargs)
        self.token = getattr(settings, 'LETTERMINT_TOKEN', '') or ''
        self.timeout = getattr(settings, 'LETTERMINT_TIMEOUT', 10)

    def send_messages(self, email_messages):
        if not email_messages:
            return 0
        if not self.token:
            if self.fail_silently:
                return 0
            raise ValueError('LETTERMINT_TOKEN is not configured')

        sent = 0
        for message in email_messages:
            if self._send(message):
                sent += 1
        return sent

    def _send(self, message) -> bool:
        payload = self._build_payload(message)
        data = json.dumps(payload).encode('utf-8')
        request = urllib.request.Request(
            LETTERMINT_ENDPOINT,
            data=data,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'x-lettermint-token': self.token,
            },
            method='POST',
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as resp:
                resp.read()
            return True
        except Exception:
            if not self.fail_silently:
                raise
            return False

    @staticmethod
    def _build_payload(message) -> dict:
        # Pull an HTML alternative if the message carries one (allauth sends
        # plain text by default, but this keeps richer emails working too).
        html_body = None
        for content, mimetype in getattr(message, 'alternatives', None) or []:
            if mimetype == 'text/html':
                html_body = content
                break

        payload = {
            'from': message.from_email or settings.DEFAULT_FROM_EMAIL,
            'to': list(message.to),
            'subject': message.subject,
            'text': message.body,
        }
        if html_body:
            payload['html'] = html_body
        if message.cc:
            payload['cc'] = list(message.cc)
        if message.bcc:
            payload['bcc'] = list(message.bcc)
        if message.reply_to:
            payload['reply_to'] = list(message.reply_to)
        return payload
