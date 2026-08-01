"""Webhook notification tests: outbox enqueue via the audit funnel, HMAC
delivery, retry/backoff, SSRF validation, and endpoint permissions.

    python manage.py test api.tests_notifications
"""

import hashlib
import hmac
import json
from urllib.error import HTTPError
from urllib.parse import urlparse
from unittest import mock

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from core.models import OutboundNotification, PublicKey, Server, Webhook
from organizations.models import Organization, OrganizationMembership, Role
from syncssh import notifications

VALID_KEY = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB6/wj7kkgbHDX8+JgLc5oTVKK6cbnhKTGEwGJ9BiVFC "
    "dev@laptop"
)


def _org(slug="acme"):
    org = Organization.objects.create(name=slug.title(), slug=slug)
    user = User.objects.create_user(
        username=f"owner-{slug}", email=f"owner@{slug}.io", password="pw-123456789"
    )
    OrganizationMembership.objects.create(user=user, organization=org, role=Role.OWNER)
    return org, user


def _webhook(org, url="https://hooks.example.com/syncssh"):
    return Webhook.objects.create(
        organization=org, url=url, secret=Webhook.generate_secret()
    )


def _key(org, user):
    return PublicKey.objects.create(
        user=user, organization=org, key_title="laptop", key_payload=VALID_KEY
    )


class EnqueueTests(TestCase):
    """Mutations must land in the outbox via the audit funnel — including
    direct ORM writes, which only the signal safety net observes."""

    def setUp(self):
        self.org, self.user = _org()
        self.webhook = _webhook(self.org)

    def test_key_created_via_orm_enqueues(self):
        _key(self.org, self.user)
        row = OutboundNotification.objects.get(action="publickey.created")
        self.assertEqual(row.status, OutboundNotification.STATUS_PENDING)
        self.assertEqual(row.payload["organization"], "acme")
        self.assertEqual(row.payload["target"]["type"], "public_key")
        self.assertTrue(row.payload["target"]["fingerprint"].startswith("SHA256:"))
        # Never ship key material, only the fingerprint.
        self.assertNotIn(VALID_KEY.split()[1], json.dumps(row.payload))

    def test_key_deleted_enqueues(self):
        key = _key(self.org, self.user)
        OutboundNotification.objects.all().delete()
        key.delete()
        self.assertTrue(
            OutboundNotification.objects.filter(action="publickey.deleted").exists()
        )

    def test_token_rotation_enqueues(self):
        server = Server.objects.create(
            organization=self.org, name="web-1", ip_address="10.0.0.1",
            ssh_user="ubuntu", token_hash="x", token_prefix="srv_x",
        )
        OutboundNotification.objects.all().delete()
        from syncssh import audit
        audit.log("server.token_rotated", target=server, organization=self.org)
        self.assertTrue(
            OutboundNotification.objects.filter(action="server.token_rotated").exists()
        )

    def test_no_webhook_no_outbox_row(self):
        other_org, other_user = _org(slug="beta")
        _key(other_org, other_user)
        self.assertFalse(
            OutboundNotification.objects.filter(organization=other_org).exists()
        )

    def test_inactive_webhook_not_enqueued(self):
        self.webhook.is_active = False
        self.webhook.save(update_fields=["is_active"])
        OutboundNotification.objects.all().delete()
        _key(self.org, self.user)
        self.assertFalse(OutboundNotification.objects.exists())

    def test_untracked_action_not_enqueued(self):
        from syncssh import audit
        audit.log("auth.login", target=self.user, organization=self.org, actor=self.user)
        self.assertFalse(OutboundNotification.objects.exists())


class DeliveryTests(TestCase):
    def setUp(self):
        self.org, self.user = _org()
        self.webhook = _webhook(self.org)
        _key(self.org, self.user)
        self.notification = OutboundNotification.objects.get()

    def _deliver(self, open_effect, approved_ips=("93.184.216.34",)):
        with mock.patch.object(
            notifications,
            "_resolve_webhook_target",
            return_value=(urlparse(self.webhook.url), approved_ips, None),
        ), mock.patch.object(
            notifications, "_open_pinned_webhook", open_effect
        ):
            notifications.deliver(self.notification)

    def test_successful_delivery_signs_payload(self):
        captured = {}

        def fake_open(request, *, connect_ip, timeout):
            captured["request"] = request
            captured["connect_ip"] = connect_ip
            resp = mock.MagicMock()
            resp.status = 200
            resp.__enter__ = lambda s: resp
            resp.__exit__ = lambda s, *a: False
            return resp

        self._deliver(fake_open)
        self.notification.refresh_from_db()
        self.assertEqual(self.notification.status, OutboundNotification.STATUS_SENT)
        req = captured["request"]
        body = req.data
        expected = "sha256=" + hmac.new(
            self.webhook.secret.encode(), body, hashlib.sha256
        ).hexdigest()
        self.assertEqual(req.get_header("X-syncssh-signature"), expected)
        self.assertEqual(req.get_header("X-syncssh-event"), "publickey.created")
        self.assertEqual(captured["connect_ip"], "93.184.216.34")

    def test_failure_schedules_retry_then_fails_permanently(self):
        boom = mock.MagicMock(side_effect=OSError("connection refused"))

        self._deliver(boom)
        self.notification.refresh_from_db()
        self.assertEqual(self.notification.status, OutboundNotification.STATUS_PENDING)
        self.assertEqual(self.notification.attempts, 1)
        self.assertGreater(self.notification.next_attempt_at, timezone.now())

        self._deliver(boom)
        self.notification.refresh_from_db()
        self.assertEqual(self.notification.attempts, 2)
        self.assertEqual(self.notification.status, OutboundNotification.STATUS_PENDING)

        self._deliver(boom)
        self.notification.refresh_from_db()
        self.assertEqual(self.notification.attempts, 3)
        self.assertEqual(self.notification.status, OutboundNotification.STATUS_FAILED)
        # The dropped alert must itself be auditable.
        from core.models import AuditLog
        self.assertTrue(
            AuditLog.objects.filter(action="notification.failed").exists()
        )

    def test_redirect_response_is_not_followed_and_retries(self):
        redirect = HTTPError(
            self.webhook.url, 302, "Found", hdrs=None, fp=None
        )

        self._deliver(mock.MagicMock(side_effect=redirect))

        self.notification.refresh_from_db()
        self.assertEqual(self.notification.status, OutboundNotification.STATUS_PENDING)
        self.assertEqual(self.notification.attempts, 1)
        self.assertEqual(self.notification.last_error, "HTTP 302")

    @override_settings(DEBUG=False)
    def test_delivery_resolves_once_and_pins_the_validated_ip(self):
        """A rebinding hostname cannot send the request to its later answer."""
        captured = {}
        response = mock.MagicMock()
        response.status = 200
        response.__enter__ = lambda s: response
        response.__exit__ = lambda s, *a: False

        def fake_open(request, *, connect_ip, timeout):
            captured["connect_ip"] = connect_ip
            return response

        with mock.patch(
            "syncssh.notifications.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
        ) as getaddrinfo, mock.patch.object(
            notifications, "_open_pinned_webhook", side_effect=fake_open
        ):
            notifications.deliver(self.notification)

        self.assertEqual(getaddrinfo.call_count, 1)
        self.assertEqual(captured["connect_ip"], "93.184.216.34")
        self.notification.refresh_from_db()
        self.assertEqual(self.notification.status, OutboundNotification.STATUS_SENT)

    def test_pinned_https_handler_uses_context_without_private_hostname_attr(self):
        handler = notifications._PinnedHTTPSHandler("93.184.216.34")
        request = mock.MagicMock()

        with mock.patch.object(handler, "do_open", return_value="ok") as do_open:
            result = handler.https_open(request)

        self.assertEqual(result, "ok")
        self.assertEqual(do_open.call_args.args[1], request)
        self.assertIn("context", do_open.call_args.kwargs)
        self.assertNotIn("check_hostname", do_open.call_args.kwargs)


@override_settings(DEBUG=False)
class SsrfValidationTests(TestCase):
    def test_http_rejected(self):
        self.assertIsNotNone(
            notifications.validate_webhook_url("http://hooks.example.com/x")
        )

    def test_private_address_rejected(self):
        with mock.patch(
            "syncssh.notifications.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("10.0.0.5", 443))],
        ):
            self.assertIsNotNone(
                notifications.validate_webhook_url("https://internal.example.com/x")
            )

    def test_loopback_rejected(self):
        with mock.patch(
            "syncssh.notifications.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("127.0.0.1", 443))],
        ):
            self.assertIsNotNone(
                notifications.validate_webhook_url("https://localtrick.example.com/x")
            )

    def test_public_https_accepted(self):
        with mock.patch(
            "syncssh.notifications.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
        ):
            self.assertIsNone(
                notifications.validate_webhook_url("https://hooks.example.com/x")
            )

    def test_url_credentials_rejected(self):
        self.assertIsNotNone(
            notifications.validate_webhook_url("https://user:pass@hooks.example.com/x")
        )

    def test_redirect_handler_never_returns_a_follow_up_request(self):
        handler = notifications._NoRedirectHandler()
        self.assertIsNone(
            handler.redirect_request(
                mock.MagicMock(), None, 302, "Found", {},
                "http://169.254.169.254/latest/meta-data/",
            )
        )


class WebhookEndpointTests(TestCase):
    def setUp(self):
        self.org, self.owner = _org()
        self.dev = User.objects.create_user(
            username="dev", email="dev@acme.io", password="pw-123456789"
        )
        OrganizationMembership.objects.create(
            user=self.dev, organization=self.org, role=Role.DEVELOPER
        )
        self.client = Client()

    def _login(self, user):
        self.client.force_login(user)

    def _put(self, url="https://hooks.example.com/syncssh"):
        with mock.patch(
            "syncssh.notifications.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("93.184.216.34", 443))],
        ):
            return self.client.put(
                "/api/v1/org/webhook/",
                data=json.dumps({"url": url}),
                content_type="application/json",
            )

    def test_dev_cannot_configure(self):
        self._login(self.dev)
        resp = self._put()
        self.assertEqual(resp.status_code, 403)

    def test_owner_configures_and_secret_shown_once(self):
        self._login(self.owner)
        resp = self._put()
        self.assertEqual(resp.status_code, 201)
        secret = resp.json()["secret"]
        self.assertTrue(secret.startswith("whsec_"))
        # Subsequent GET must not expose the secret.
        resp = self.client.get("/api/v1/org/webhook/")
        self.assertNotIn("secret", resp.json())

    def test_rotate_returns_new_secret(self):
        self._login(self.owner)
        first = self._put().json()["secret"]
        resp = self.client.post("/api/v1/org/webhook/rotate/")
        self.assertEqual(resp.status_code, 200)
        self.assertNotEqual(resp.json()["secret"], first)

    def test_test_event_enqueued(self):
        self._login(self.owner)
        self._put()
        resp = self.client.post("/api/v1/org/webhook/test/")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(
            OutboundNotification.objects.filter(action="webhook.test").exists()
        )

    def test_delete_removes_config(self):
        self._login(self.owner)
        self._put()
        resp = self.client.delete("/api/v1/org/webhook/")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(Webhook.objects.filter(organization=self.org).exists())

    def test_patch_toggles_active_without_rotating_secret(self):
        self._login(self.owner)
        self._put()
        secret_before = Webhook.objects.get(organization=self.org).secret
        resp = self.client.patch(
            "/api/v1/org/webhook/",
            data=json.dumps({"is_active": False}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        webhook = Webhook.objects.get(organization=self.org)
        self.assertFalse(webhook.is_active)
        self.assertEqual(webhook.secret, secret_before)

    def test_dev_cannot_patch(self):
        self._login(self.owner)
        self._put()
        self._login(self.dev)
        resp = self.client.patch(
            "/api/v1/org/webhook/",
            data=json.dumps({"is_active": False}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
