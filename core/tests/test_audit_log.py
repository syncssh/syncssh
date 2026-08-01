"""Tests for the audit-log subsystem."""

from django.test import TestCase, Client, RequestFactory, override_settings
from django.contrib.auth import get_user_model

from core.models import AuditLog, PublicKey, Server
from organizations.models import (
    Organization, OrganizationMembership, Role, OrganizationInvite, ApiKey,
)
from syncssh import audit


User = get_user_model()


class _BaseAuditTest(TestCase):
    def setUp(self):
        AuditLog.objects.all().delete()
        self.factory = RequestFactory()
        self.org = Organization.objects.create(name="Audit Org", slug="audit-org")
        self.admin = User.objects.create_user("audit_admin", password="pass")
        self.dev = User.objects.create_user("audit_dev", password="pass")
        OrganizationMembership.objects.create(user=self.admin, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.dev, organization=self.org, role=Role.DEVELOPER)


class SignalSafetyNetTests(_BaseAuditTest):
    """Models in the TRACKED list emit audit entries automatically."""

    def test_server_create_emits_event(self):
        Server.objects.create(
            organization=self.org, name="s1", ip_address="10.0.0.1",
            ssh_user="root", token_hash="h" * 64, token_prefix="p",
        )
        self.assertTrue(AuditLog.objects.filter(action="server.created").exists())

    def test_server_update_emits_event(self):
        s = Server.objects.create(
            organization=self.org, name="s2", ip_address="10.0.0.2",
            ssh_user="root", token_hash="h2" * 32, token_prefix="p2",
        )
        AuditLog.objects.all().delete()
        s.name = "renamed"
        s.save()
        self.assertTrue(AuditLog.objects.filter(action="server.updated").exists())

    def test_server_delete_emits_event(self):
        s = Server.objects.create(
            organization=self.org, name="s3", ip_address="10.0.0.3",
            ssh_user="root", token_hash="h3" * 32, token_prefix="p3",
        )
        AuditLog.objects.all().delete()
        s.delete()
        self.assertTrue(AuditLog.objects.filter(action="server.deleted").exists())

    def test_publickey_create_emits_event(self):
        PublicKey.objects.create(
            user=self.dev, organization=self.org,
            key_title="x", key_payload="ssh-ed25519 X",
        )
        e = AuditLog.objects.filter(action="publickey.created").first()
        self.assertIsNotNone(e)
        self.assertEqual(e.organization, self.org)
        self.assertEqual(e.target_type, "PublicKey")

    def test_membership_create_emits_event(self):
        u = User.objects.create_user("newcomer", password="pass")
        OrganizationMembership.objects.create(user=u, organization=self.org, role=Role.DEVELOPER)
        self.assertTrue(
            AuditLog.objects.filter(action="organizationmembership.created").exists()
        )

    def test_invite_and_apikey_emit_events(self):
        OrganizationInvite.objects.create(
            organization=self.org, email="x@y.com", created_by=self.admin,
        )
        ApiKey.objects.create(
            organization=self.org, name="ci",
            key_prefix="bb_oak_live_", key_hash="z" * 64, created_by=self.admin,
        )
        self.assertTrue(AuditLog.objects.filter(action="organizationinvite.created").exists())
        self.assertTrue(AuditLog.objects.filter(action="apikey.created").exists())


class RequestContextTests(_BaseAuditTest):
    """Middleware should make `request.user` available to `audit.log()`."""

    def test_actor_filled_from_request_when_middleware_runs(self):
        c = Client()
        c.force_login(self.admin)
        # Trigger anything that goes through middleware + writes a log:
        c.get("/api/v1/auth/me/")
        # Now any direct log() call from inside a real view would have ctx.
        # Simulate by entering the contextvar manually for the assertion path:
        req = self.factory.get("/x")
        req.user = self.admin
        token = audit._request_ctx.set(req)
        try:
            audit.log("test.manual", target=self.org)
        finally:
            audit._request_ctx.reset(token)
        e = AuditLog.objects.filter(action="test.manual").first()
        self.assertEqual(e.actor_user, self.admin)
        self.assertEqual(e.organization, self.org)

    def test_actor_kind_server_for_sync_pull(self):
        token = "audit-srv-token"
        Server.objects.create(
            organization=self.org, name="sync-srv", ip_address="10.0.0.9",
            ssh_user="root", token_hash=Server.hash_token(token),
            token_prefix=token[:12],
        )
        AuditLog.objects.filter(action="server.sync_pulled").delete()
        c = Client()
        c.get("/api/v1/servers/sync", HTTP_AUTHORIZATION=f"Bearer {token}")
        e = AuditLog.objects.filter(action="server.sync_pulled").first()
        self.assertIsNotNone(e)
        self.assertEqual(e.actor_kind, "server")
        self.assertIsNone(e.actor_user)
        self.assertIn("key_count", e.metadata)


class AuthSignalTests(_BaseAuditTest):
    def test_login_event_recorded(self):
        c = Client()
        c.force_login(self.admin)
        self.assertTrue(
            AuditLog.objects.filter(action="auth.login", actor_user=self.admin).exists()
        )


class AuditLogEndpointTests(_BaseAuditTest):
    """`GET /api/v1/audit/` should be admin-gated and org-scoped."""

    def test_developer_forbidden(self):
        c = Client()
        c.force_login(self.dev)
        r = c.get("/api/v1/audit/")
        self.assertEqual(r.status_code, 403)

    def test_admin_sees_own_org_events_only(self):
        Server.objects.create(
            organization=self.org, name="mine", ip_address="10.0.0.5",
            ssh_user="root", token_hash="o" * 64, token_prefix="o",
        )
        other_org = Organization.objects.create(name="Other", slug="other-audit")
        Server.objects.create(
            organization=other_org, name="theirs", ip_address="10.0.0.6",
            ssh_user="root", token_hash="t" * 64, token_prefix="t",
        )
        c = Client()
        c.force_login(self.admin)
        r = c.get("/api/v1/audit/")
        self.assertEqual(r.status_code, 200)
        events = r.json()["events"]
        # Both servers wrote events, but only our org's event appears. The API
        # intentionally uses a descriptive target instead of global model IDs.
        server_events = [e for e in events if e["action"] == "server.created"]
        self.assertEqual(len(server_events), 1)
        self.assertEqual(server_events[0]["target"], "Server")
        for event in events:
            self.assertNotIn("id", event)
            self.assertNotIn("target_id", event)

    def test_user_target_is_an_account_label_without_an_id(self):
        audit.log(
            "auth.signup", target=self.admin, organization=self.org, actor=self.admin
        )
        c = Client()
        c.force_login(self.admin)
        r = c.get("/api/v1/audit/", {"action": "auth.signup"})
        self.assertEqual(r.status_code, 200)
        event = r.json()["events"][0]
        self.assertEqual(event["target"], "Account")
        self.assertNotIn("target_id", event)

    def test_filter_by_action(self):
        c = Client()
        c.force_login(self.admin)
        r = c.get("/api/v1/audit/", {"action": "auth.login"})
        self.assertEqual(r.status_code, 200)
        for e in r.json()["events"]:
            self.assertEqual(e["action"], "auth.login")

    def test_audit_failure_does_not_break_user_action(self):
        """If AuditLog.objects.create raises, the view still succeeds."""
        from unittest.mock import patch
        c = Client()
        c.force_login(self.admin)
        with patch.object(AuditLog.objects, "create", side_effect=RuntimeError("boom")):
            # Server.objects.create triggers post_save → audit.log → patched create.
            # Should not raise; user code keeps going.
            s = Server.objects.create(
                organization=self.org, name="ok", ip_address="10.0.0.99",
                ssh_user="root", token_hash="x" * 64, token_prefix="x",
            )
            self.assertIsNotNone(s.id)
