"""Open-core edition gating: the OSS build hides commercial features while
the cloud build keeps them. Each feature is exercised in both editions via
override_settings(FEATURES=...), the same switch settings.py derives from
SYNCSSH_EDITION.

    python manage.py test api.tests_editions
"""

from datetime import timedelta

from django.contrib.auth.models import User
from django.test import Client, TestCase, override_settings
from django.utils import timezone

from core.models import AuditLog
from organizations.models import Organization, OrganizationMembership, Role

OSS = {"webhooks": False, "invite_email_theming": False, "audit_unlimited_retention": False}
CLOUD = {"webhooks": True, "invite_email_theming": True, "audit_unlimited_retention": True}


def _owner(slug="acme"):
    org = Organization.objects.create(name=slug.title(), slug=slug)
    user = User.objects.create_user(
        username=f"owner-{slug}", email=f"owner@{slug}.io", password="pw-123456789"
    )
    OrganizationMembership.objects.create(user=user, organization=org, role=Role.OWNER)
    return org, user


class WebhookGatingTests(TestCase):
    def setUp(self):
        self.org, self.user = _owner()
        self.client = Client()
        self.client.force_login(self.user)

    @override_settings(FEATURES=OSS)
    def test_webhook_endpoints_404_in_oss(self):
        self.assertEqual(self.client.get("/api/v1/org/webhook/").status_code, 404)
        self.assertEqual(self.client.post("/api/v1/org/webhook/rotate/").status_code, 404)
        self.assertEqual(self.client.post("/api/v1/org/webhook/test/").status_code, 404)

    @override_settings(FEATURES=CLOUD)
    def test_webhook_endpoint_available_in_cloud(self):
        # Not configured yet, but the endpoint responds rather than 404ing.
        res = self.client.get("/api/v1/org/webhook/")
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()["configured"])


class InviteThemeGatingTests(TestCase):
    def setUp(self):
        self.org, self.user = _owner()
        self.client = Client()
        self.client.force_login(self.user)

    @override_settings(FEATURES=OSS)
    def test_theme_change_ignored_in_oss(self):
        original = self.org.invite_email_theme
        other = "dark" if original == "light" else "light"
        res = self.client.patch(
            "/api/v1/org/", data={"invite_email_theme": other}, content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.invite_email_theme, original)

    @override_settings(FEATURES=CLOUD)
    def test_theme_change_applies_in_cloud(self):
        original = self.org.invite_email_theme
        other = "dark" if original == "light" else "light"
        res = self.client.patch(
            "/api/v1/org/", data={"invite_email_theme": other}, content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.invite_email_theme, other)


class AuditRetentionTests(TestCase):
    def setUp(self):
        self.org, self.user = _owner()
        self.client = Client()
        self.client.force_login(self.user)
        AuditLog.objects.create(organization=self.org, action="recent.event")
        old = AuditLog.objects.create(organization=self.org, action="ancient.event")
        # created_at is auto_now_add; bypass it to backdate beyond the window.
        AuditLog.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - timedelta(days=90)
        )

    def _actions(self):
        res = self.client.get("/api/v1/audit/")
        self.assertEqual(res.status_code, 200)
        return {e["action"] for e in res.json()["events"]}

    @override_settings(FEATURES=OSS)
    def test_oss_hides_events_beyond_window(self):
        actions = self._actions()
        self.assertIn("recent.event", actions)
        self.assertNotIn("ancient.event", actions)

    @override_settings(FEATURES=CLOUD)
    def test_cloud_returns_full_history(self):
        actions = self._actions()
        self.assertIn("recent.event", actions)
        self.assertIn("ancient.event", actions)


class FeatureReportingTests(TestCase):
    def setUp(self):
        self.org, self.user = _owner()
        self.client = Client()
        self.client.force_login(self.user)

    @override_settings(FEATURES=OSS)
    def test_me_reports_oss_features(self):
        res = self.client.get("/api/v1/auth/me/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["features"], OSS)
