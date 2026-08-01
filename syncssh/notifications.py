"""Webhook notifications for access-mutating events.

Two halves:
  - `enqueue(action, ...)`: called from the audit funnel; writes an outbox row
    in the same transaction as the mutation so a stalled receiver can't
    suppress the alert. Best-effort — never raises into the request.
  - `deliver(notification)`: POSTs one outbox row with an HMAC signature.
    Called only by `manage.py drain_notifications`, never inline.

Only actions in NOTIFY_ACTIONS fan out. The set is deliberately narrow:
"someone changed who can reach the fleet" events, nothing informational.
"""

from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import socket
import ssl
import urllib.error
import urllib.request
from datetime import timedelta
from urllib.parse import urlparse

from django.conf import settings
from django.utils import timezone

logger = logging.getLogger(__name__)

# publickey.created / .deleted come from the post_save/post_delete signal
# safety net, so they fire for every mutation path — including a direct ORM
# write from a shell on a compromised box. deleted_by_admin is intentionally
# absent: the post_delete signal already covers that row.
NOTIFY_ACTIONS = frozenset({
    "publickey.created",
    "publickey.deleted",
    "publickey.toggled",
    "server.token_rotated",
})

# Retry offsets after attempt N fails (attempt 1 → +1m, 2 → +5m, then failed).
RETRY_BACKOFF = [timedelta(minutes=1), timedelta(minutes=5)]
MAX_ATTEMPTS = 3

DELIVERY_TIMEOUT_SECONDS = 5


def _resolve_webhook_target(url: str):
    """Return ``(parsed_url, public_ips, error)`` for a webhook URL.

    Webhook URLs are operator-supplied, so this is an SSRF surface: without
    checks a hostile org admin could make the control plane POST signed
    requests at cloud metadata endpoints or compose-internal services.

    The resolved addresses are deliberately returned to the caller. Delivery
    connects to one of these exact addresses rather than letting the HTTP
    client resolve the hostname again, which closes the DNS-rebinding gap
    between validation and connection.
    """
    parsed = urlparse(url)
    if parsed.scheme != "https" and not settings.DEBUG:
        return None, (), "Webhook URL must use https."
    if parsed.scheme not in ("https", "http"):
        return None, (), "Webhook URL must use https."
    if not parsed.hostname:
        return None, (), "Webhook URL has no host."
    if parsed.username or parsed.password:
        return None, (), "Webhook URL must not include credentials."
    try:
        port = parsed.port
    except ValueError:
        return None, (), "Webhook URL has an invalid port."
    port = port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(
            parsed.hostname, port, type=socket.SOCK_STREAM
        )
    except socket.gaierror:
        return None, (), "Webhook host does not resolve."
    addresses = []
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except ValueError:
            return None, (), "Webhook host resolved to an invalid address."
        if not ip.is_global and not settings.DEBUG:
            return None, (), "Webhook host resolves to a private or reserved address."
        # getaddrinfo may return duplicate addresses. Preserve resolution order
        # for normal CDN/load-balancer behavior while avoiding needless retries.
        rendered = str(ip)
        if rendered not in addresses:
            addresses.append(rendered)
    if not addresses:
        return None, (), "Webhook host does not resolve."
    return parsed, tuple(addresses), None


def validate_webhook_url(url: str) -> str | None:
    """Return an error string if the URL is unsafe to POST to, else None."""
    _, _, error = _resolve_webhook_target(url)
    return error


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that uses an already-validated destination IP."""

    def __init__(self, host, *, connect_ip, **kwargs):
        self._connect_ip = connect_ip
        super().__init__(host, **kwargs)

    def connect(self):
        self.sock = socket.create_connection(
            (self._connect_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS variant that pins TCP to an approved IP but verifies the hostname."""

    def __init__(self, host, *, connect_ip, **kwargs):
        self._connect_ip = connect_ip
        super().__init__(host, **kwargs)

    def connect(self):
        self.sock = socket.create_connection(
            (self._connect_ip, self.port), self.timeout, self.source_address
        )
        if self._tunnel_host:
            self._tunnel()
        # Keep the original hostname for SNI and certificate verification even
        # though the TCP connection is pinned to the validated IP address.
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class _PinnedHTTPHandler(urllib.request.HTTPHandler):
    def __init__(self, connect_ip):
        super().__init__()
        self._connect_ip = connect_ip

    def http_open(self, request):
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPConnection(
                host, connect_ip=self._connect_ip, **kwargs
            ),
            request,
        )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, connect_ip):
        super().__init__(context=ssl.create_default_context())
        self._connect_ip = connect_ip

    def https_open(self, request):
        return self.do_open(
            lambda host, **kwargs: _PinnedHTTPSConnection(
                host, connect_ip=self._connect_ip, **kwargs
            ),
            request,
            context=self._context,
        )


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Treat every redirect as a failed webhook delivery.

    Redirect targets are a separate SSRF surface, so delivery must not follow
    them. Returning ``None`` makes urllib raise an HTTPError for the 3xx
    response, which the normal retry path records.
    """

    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _open_pinned_webhook(request, *, connect_ip: str, timeout: int):
    """Open a webhook request without redirects or a second DNS lookup."""
    if request.type == "https":
        transport = _PinnedHTTPSHandler(connect_ip)
    else:
        # HTTP is accepted only in DEBUG for local development. It still uses
        # IP pinning and the no-redirect policy so tests/dev do not mask SSRF.
        transport = _PinnedHTTPHandler(connect_ip)
    opener = urllib.request.build_opener(transport, _NoRedirectHandler())
    return opener.open(request, timeout=timeout)


def _target_details(target) -> dict:
    """Pull human-useful fields off the audit target without leaking key
    material — fingerprints only."""
    from core.models import PublicKey, Server

    if isinstance(target, PublicKey):
        return {
            "type": "public_key",
            "id": target.pk,
            "fingerprint": target.fingerprint,
            "title": target.key_title,
            "owner": target.user.username if target.user_id else None,
        }
    if isinstance(target, Server):
        return {
            "type": "server",
            "id": target.pk,
            "name": target.name,
        }
    if target is None:
        return {}
    return {"type": target.__class__.__name__, "id": getattr(target, "pk", None)}


def enqueue(action, *, organization, target=None, actor=None, metadata=None):
    """Write an outbox row if the org has an active webhook. Never raises."""
    from core.models import OutboundNotification, Webhook

    if action not in NOTIFY_ACTIONS or organization is None:
        return
    try:
        try:
            webhook = organization.webhook
        except Webhook.DoesNotExist:
            return
        if not webhook.is_active:
            return
        payload = {
            "event": action,
            "organization": organization.slug,
            "timestamp": timezone.now().isoformat(),
            "actor": actor.username if actor else None,
            "ip": (metadata or {}).get("ip"),
            "target": _target_details(target),
        }
        OutboundNotification.objects.create(
            organization=organization,
            webhook=webhook,
            action=action,
            payload=payload,
            next_attempt_at=timezone.now(),
        )
    except Exception:
        # Same contract as audit.log: notifying must never break the mutation.
        logger.exception("notification enqueue failed: %s", action)


def sign(secret: str, body: bytes) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def deliver(notification) -> None:
    """Attempt one delivery; update status/attempts/next_attempt_at in place."""
    from core.models import OutboundNotification
    from syncssh import audit

    webhook = notification.webhook
    body = json.dumps(notification.payload).encode()
    _, approved_ips, error = _resolve_webhook_target(webhook.url)
    if error is None:
        request = urllib.request.Request(
            webhook.url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "syncssh-webhook",
                "X-SyncSSH-Event": notification.action,
                "X-SyncSSH-Delivery": str(notification.pk),
                "X-SyncSSH-Signature": sign(webhook.secret, body),
            },
            method="POST",
        )
        try:
            # Pin transport to a validated answer from the immediately preceding
            # resolution. The HTTP client therefore cannot re-resolve a hostname
            # that has changed to a private address after validation.
            with _open_pinned_webhook(
                request,
                connect_ip=approved_ips[0],
                timeout=DELIVERY_TIMEOUT_SECONDS,
            ) as resp:
                if 200 <= resp.status < 300:
                    notification.status = OutboundNotification.STATUS_SENT
                    notification.sent_at = timezone.now()
                    notification.attempts += 1
                    notification.last_error = ""
                    notification.save(
                        update_fields=["status", "sent_at", "attempts", "last_error"]
                    )
                    return
                error = f"HTTP {resp.status}"
        except urllib.error.HTTPError as exc:
            error = f"HTTP {exc.code}"
        except (urllib.error.URLError, socket.timeout, OSError) as exc:
            error = str(exc)

    notification.attempts += 1
    notification.last_error = error[:500]
    if notification.attempts >= MAX_ATTEMPTS:
        notification.status = OutboundNotification.STATUS_FAILED
        notification.save(update_fields=["status", "attempts", "last_error"])
        # A dropped alert is itself a security event — make the silence visible.
        audit.log(
            "notification.failed",
            target=notification,
            organization=notification.organization,
            actor_kind="system",
            action_notified=notification.action,
            error=notification.last_error,
        )
    else:
        notification.next_attempt_at = (
            timezone.now() + RETRY_BACKOFF[notification.attempts - 1]
        )
        notification.save(
            update_fields=["attempts", "last_error", "next_attempt_at"]
        )
