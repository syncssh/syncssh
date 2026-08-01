"""Regression tests for the security fixes landed in the recent audit pass.

Each test asserts that a documented mitigation actually fires — these are
defensive assertions, not attack tooling. Run with:

    python manage.py test api.tests_security
"""

import json
import os
import subprocess
from unittest import mock

from django.contrib.auth.models import User
from django.core.cache import cache
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta

from core.models import Server
from organizations.models import (
    ApiKey,
    Organization,
    OrganizationInvite,
    OrganizationMembership,
    Role,
    TokenScope,
)


def _make_org_with_owner(email="owner@example.com", username="owner", password="correct-horse-battery-staple"):
    user = User.objects.create_user(username=username, email=email, password=password)
    org = Organization.objects.create(name="Acme", slug="acme")
    OrganizationMembership.objects.create(user=user, organization=org, role=Role.OWNER)
    return user, org, password


def _make_server(org):
    """Create a Server and return (server, raw_token). Mirrors what ServerListView does."""
    raw = Server.generate_token()
    server = Server.objects.create(
        organization=org,
        name="web-1",
        ip_address="10.0.0.1",
        ssh_user="ubuntu",
        token_hash=Server.hash_token(raw),
        token_prefix=raw[:12],
        is_active=True,
    )
    return server, raw


class InstallOneShotTests(TestCase):
    """The install URL embeds the bearer token in plaintext, so it must be
    one-shot to prevent replay from leaked URLs (Referer, history, log scrapers).
    """

    def setUp(self):
        _, self.org, _ = _make_org_with_owner()
        self.server, self.token = _make_server(self.org)

    def test_first_fetch_returns_script(self):
        resp = self.client.get(f"/api/v1/install/{self.token}/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"SYNCSSH BEGIN", resp.content)
        self.assertIn(self.token.encode(), resp.content)

    def test_second_fetch_returns_410(self):
        self.client.get(f"/api/v1/install/{self.token}/")
        resp = self.client.get(f"/api/v1/install/{self.token}/")
        self.assertEqual(resp.status_code, 410)
        # Body must be bash-safe so `curl | bash` doesn't try to execute prose.
        self.assertTrue(
            resp.content.startswith(b"#!/bin/bash"),
            f"410 body should start with shebang; got: {resp.content[:60]!r}",
        )
        self.assertIn(b"exit 1", resp.content)

    def test_rotate_rearms_install(self):
        self.client.get(f"/api/v1/install/{self.token}/")
        new_token = self.server.rotate()
        resp = self.client.get(f"/api/v1/install/{new_token}/")
        self.assertEqual(resp.status_code, 200)

    def test_invalid_token_returns_404_bash_safe(self):
        resp = self.client.get("/api/v1/install/srv_not_a_real_token/")
        self.assertEqual(resp.status_code, 404)
        self.assertTrue(resp.content.startswith(b"#!/bin/bash"))


class WorkerScriptHardeningTests(TestCase):
    """The generated worker must fail safe (no key wipe on fetch failure),
    reject non-key content, and refuse plaintext transport on https deployments.
    """

    def setUp(self):
        _, self.org, _ = _make_org_with_owner()
        self.server, self.token = _make_server(self.org)

    def _fetch_script(self):
        resp = self.client.get(f"/api/v1/install/{self.token}/")
        self.assertEqual(resp.status_code, 200)
        return resp.content.decode()

    def test_fetch_failure_leaves_authorized_keys_untouched(self):
        # The curl line must bail out before the sed that strips the managed
        # block, otherwise every transient outage removes all synced keys.
        script = self._fetch_script()
        curl_line = next(line for line in script.splitlines() if "curl -sf" in line)
        self.assertIn("|| exit 0", curl_line)

    def test_response_filtered_to_public_key_lines(self):
        script = self._fetch_script()
        self.assertIn("grep -E '^(ssh-|ecdsa-|sk-)'", script)

    def test_https_deployment_pins_worker_to_tls(self):
        with mock.patch.dict(
            os.environ, {"SYNC_BASE_URL": "https://keys.example.com"}
        ):
            script = self._fetch_script()
        self.assertIn("--proto '=https'", script)
        self.assertIn("--tlsv1.2", script)

    def test_http_dev_deployment_omits_tls_pin(self):
        with mock.patch.dict(
            os.environ, {"SYNC_BASE_URL": "http://backend:8000"}
        ):
            script = self._fetch_script()
        self.assertNotIn("--proto", script)

    def test_malformed_database_username_is_shell_quoted(self):
        """The renderer must stay safe even if a non-API write bypasses validation."""
        self.server.ssh_user = 'ubuntu"; touch /tmp/syncssh-pwned; #'
        self.server.save(update_fields=["ssh_user"])

        script = self._fetch_script()
        parsed = subprocess.run(
            ["bash", "-n"], input=script, text=True, capture_output=True, check=False
        )

        self.assertEqual(parsed.returncode, 0, parsed.stderr)
        self.assertNotIn('SSH_USER="ubuntu"; touch', script)


class ServerCreateValidationTests(TestCase):
    def setUp(self):
        self.owner, self.org, _ = _make_org_with_owner()
        self.client.force_login(self.owner)

    def _create_server(self, ssh_user):
        return self.client.post(
            "/api/v1/org/servers/",
            data=json.dumps(
                {
                    "name": "web-1",
                    "ip_address": "10.0.0.1",
                    "ssh_user": ssh_user,
                }
            ),
            content_type="application/json",
        )

    def test_shell_syntax_in_ssh_user_is_rejected_before_server_creation(self):
        response = self._create_server('ubuntu"; touch /tmp/syncssh-pwned; #')

        self.assertEqual(response.status_code, 400)
        self.assertIn("ssh_user", response.json()["error"])
        self.assertFalse(Server.objects.filter(organization=self.org).exists())

    def test_valid_unix_account_names_are_accepted(self):
        for username in ("root", "ubuntu", "deploy_bot", "web-01"):
            with self.subTest(username=username):
                response = self._create_server(username)
                self.assertEqual(response.status_code, 201)
                self.assertEqual(response.json()["ssh_user"], username)


class InactiveOrganizationTests(TestCase):
    """Organization.is_active is a tenant-level access and key-revocation switch."""

    def setUp(self):
        self.owner, self.org, self.password = _make_org_with_owner()
        self.server, self.server_token = _make_server(self.org)
        self.member = User.objects.create_user(
            username="inactive-invitee",
            email="inactive-invitee@example.com",
            password="pw-123456789",
        )
        self.invite = OrganizationInvite.objects.create(
            organization=self.org,
            email=self.member.email,
            role=Role.DEVELOPER,
            created_by=self.owner,
            expires_at=timezone.now() + timedelta(days=1),
        )
        raw_key = ApiKey.generate_token()
        self.api_key = ApiKey.objects.create(
            organization=self.org,
            name="automation",
            key_prefix="bb_oak_live_",
            key_hash=ApiKey.hash_token(raw_key),
            scopes=[TokenScope.ADMIN_MEMBERS],
            created_by=self.owner,
        )
        self.api_token = raw_key
        self.org.is_active = False
        self.org.save(update_fields=["is_active"])

    def test_session_api_access_is_blocked(self):
        self.client.force_login(self.owner)

        response = self.client.get("/api/v1/org/")

        self.assertEqual(response.status_code, 403)

    def test_api_key_access_is_blocked(self):
        response = self.client.post(
            "/api/v1/keys/",
            HTTP_AUTHORIZATION=f"Bearer {self.api_token}",
        )

        self.assertEqual(response.status_code, 401)

    def test_sync_returns_empty_success_to_remove_managed_keys(self):
        response = self.client.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {self.server_token}",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")
        self.server.refresh_from_db()
        self.assertIsNone(self.server.last_synced_at)

    def test_install_url_stops_working(self):
        response = self.client.get(f"/api/v1/install/{self.server_token}/")

        self.assertEqual(response.status_code, 404)

    def test_invite_post_cannot_add_a_member(self):
        self.client.force_login(self.member)

        response = self.client.post(f"/api/v1/invites/accept/{self.invite.token}/")

        self.assertEqual(response.status_code, 403)
        self.assertFalse(
            OrganizationMembership.objects.filter(
                user=self.member, organization=self.org
            ).exists()
        )

    def test_pending_invite_is_not_consumed_on_login(self):
        session = self.client.session
        session["invite_token"] = str(self.invite.token)
        session.save()

        self.assertTrue(self.client.login(username=self.member.username, password="pw-123456789"))

        self.assertFalse(
            OrganizationMembership.objects.filter(
                user=self.member, organization=self.org
            ).exists()
        )
        self.assertNotIn("invite_token", self.client.session)


@override_settings(RATELIMIT_ENABLE=True)
class SyncRateLimitTests(TestCase):
    """Two stacked limits on /servers/sync:
       - per-token (10/m): legit cron misconfig safety.
       - per-IP (60/m): closes the spray-many-guesses-each-with-own-bucket loophole.
    """

    def setUp(self):
        cache.clear()
        _, self.org, _ = _make_org_with_owner()
        self.server, self.token = _make_server(self.org)

    def tearDown(self):
        cache.clear()

    def test_per_ip_blocks_token_spray(self):
        """Spraying distinct bad tokens from one IP must hit the 60/m IP cap.
        Before the fix, each guess got its own per-token bucket and the cap
        was effectively unreachable."""
        last_status = None
        for i in range(70):
            resp = self.client.get(
                "/api/v1/servers/sync",
                HTTP_AUTHORIZATION=f"Bearer srv_guess_{i:04d}",
            )
            last_status = resp.status_code
        # 70 distinct tokens > 60/m IP cap → final response must be 429.
        self.assertEqual(last_status, 429)

    def test_per_token_caps_legit_overuse(self):
        """A single valid token over-polling still hits the 10/m per-token cap."""
        for _ in range(10):
            self.client.get(
                "/api/v1/servers/sync",
                HTTP_AUTHORIZATION=f"Bearer {self.token}",
            )
        resp = self.client.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        self.assertEqual(resp.status_code, 429)


@override_settings(RATELIMIT_ENABLE=True)
class LoginRateLimitTests(TestCase):
    """Per-username throttle bounds credential stuffing even when sprayed from
    a proxy pool — the per-IP cap alone cannot do this.
    """

    def setUp(self):
        cache.clear()
        self.user, _, self.password = _make_org_with_owner()

    def tearDown(self):
        cache.clear()

    def _login(self, username, password, ip="1.2.3.4"):
        return self.client.post(
            "/api/v1/auth/login/",
            data=json.dumps({"username": username, "password": password}),
            content_type="application/json",
            REMOTE_ADDR=ip,
        )

    def test_per_username_blocks_distributed_stuffing(self):
        """5 wrong attempts at the same username from rotating IPs must trip
        the per-user bucket on the 6th — even though the per-IP bucket
        (10/m) never fires because each IP only sends one request."""
        # django-ratelimit uses a fixed window keyed off wall-clock time, so
        # without freezing it these 6 requests can straddle a window boundary
        # and reset the counter mid-test.
        with mock.patch("django_ratelimit.core.time.time", return_value=1_700_000_000.0):
            for i in range(5):
                resp = self._login("owner", "wrong", ip=f"10.0.0.{i}")
                self.assertEqual(resp.status_code, 401, f"attempt {i} status {resp.status_code}")
            resp = self._login("owner", "wrong", ip="10.0.0.99")
            self.assertEqual(resp.status_code, 429)

    def test_per_username_isolated_between_accounts(self):
        """Throttling 'owner' must not block attempts at other usernames."""
        User.objects.create_user(username="alice", email="alice@example.com", password="pw")
        for i in range(5):
            self._login("owner", "wrong", ip=f"10.1.0.{i}")
        # 6th attempt at 'owner' would 429; 'alice' must still be reachable.
        resp = self._login("alice", "wrong", ip="10.1.0.50")
        self.assertEqual(resp.status_code, 401)


class CsrfOnAuthTests(TestCase):
    """Signup is no longer @csrf_exempt; login was never exempt. Both must
    reject POSTs from a CSRF-enforcing client when no token is present.
    """

    def test_signup_rejected_without_csrf(self):
        client = Client(enforce_csrf_checks=True)
        resp = client.post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": "new",
                "email": "n@example.com",
                "password1": "correct-horse-battery-staple",
                "password2": "correct-horse-battery-staple",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(User.objects.filter(username="new").exists())

    def test_login_rejected_without_csrf(self):
        _make_org_with_owner()
        client = Client(enforce_csrf_checks=True)
        resp = client.post(
            "/api/v1/auth/login/",
            data=json.dumps({"username": "owner", "password": "correct-horse-battery-staple"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class SignupAuditTests(TestCase):
    """Signup creates a User + Organization, neither of which is a tracked
    model, so without an explicit event there's no audit trail of the account
    being created."""

    def test_signup_logs_auth_signup_event(self):
        from core.models import AuditLog
        resp = self.client.post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": "newbie",
                "email": "newbie@example.com",
                "password1": "correct-horse-battery-staple",
                "password2": "correct-horse-battery-staple",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        user = User.objects.get(username="newbie")
        event = AuditLog.objects.filter(action="auth.signup").first()
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_user_id, user.id)
        self.assertIsNotNone(event.organization_id)


class InviteAcceptTests(TestCase):
    """GET must not mutate (closes the <img src> auto-join vector); POST is
    the only path that creates a membership."""

    def setUp(self):
        owner, self.org, _ = _make_org_with_owner()
        self.victim = User.objects.create_user(
            username="victim", email="victim@example.com", password="pw"
        )
        self.invite = OrganizationInvite.objects.create(
            organization=self.org,
            email="victim@example.com",
            role=Role.DEVELOPER,
            created_by=owner,
            expires_at=timezone.now() + timedelta(days=7),
        )

    def _membership_exists(self):
        return OrganizationMembership.objects.filter(
            user=self.victim, organization=self.org
        ).exists()

    def test_get_does_not_create_membership(self):
        """Hitting GET while authenticated used to auto-join. It must now
        only render the confirm page — no DB mutation."""
        self.client.force_login(self.victim)
        resp = self.client.get(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"<form", resp.content)
        self.assertIn(b"allauth-card", resp.content)
        self.assertFalse(self._membership_exists())

    def test_post_with_csrf_creates_membership(self):
        self.client.force_login(self.victim)
        # Django's default test client bypasses CSRF; that's fine here — we're
        # asserting the happy path of the POST handler, the CSRF-enforced
        # variant is exercised below.
        resp = self.client.post(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("invite=accepted", resp["Location"])
        self.assertTrue(self._membership_exists())
        # The chosen account, not just the invited email, is recorded.
        self.invite.refresh_from_db()
        self.assertEqual(self.invite.accepted_by_id, self.victim.id)
        self.assertNotIn("active_org_id", self.client.session)

    def test_existing_owner_keeps_personal_workspace_after_accepting(self):
        from core.models import PublicKey
        personal_org = Organization.objects.create(name="Personal", slug="victim-personal")
        OrganizationMembership.objects.create(
            user=self.victim, organization=personal_org, role=Role.OWNER
        )
        key = PublicKey.objects.create(
            user=self.victim,
            organization=personal_org,
            key_title="laptop",
            key_payload="ssh-ed25519 AAAA INVITE_COPY_TEST victim@laptop",
        )
        self.client.force_login(self.victim)

        response = self.client.post(f"/api/v1/invites/accept/{self.invite.token}/")

        self.assertEqual(response.status_code, 302)
        self.assertNotIn("active_org_id", self.client.session)
        self.assertEqual(self.client.get("/api/v1/org/").json()["org"]["id"], personal_org.id)
        copied = PublicKey.objects.get(organization=self.org, key_payload=key.key_payload)
        self.assertEqual(copied.user_id, self.victim.id)
        self.assertFalse(copied.deploy_to_all)
        self.assertFalse(copied.servers.exists())

    def test_accept_logs_invite_accepted_event(self):
        """Accepting must leave a clear, org-scoped trail — not just the vague
        generic membership.created/invite.updated rows."""
        from core.models import AuditLog
        self.client.force_login(self.victim)
        self.client.post(f"/api/v1/invites/accept/{self.invite.token}/")
        event = AuditLog.objects.filter(action="invite.accepted").first()
        self.assertIsNotNone(event)
        self.assertEqual(event.organization_id, self.org.id)
        self.assertEqual(event.actor_user_id, self.victim.id)
        self.assertEqual(event.metadata.get("invited_email"), "victim@example.com")

    def test_post_without_csrf_blocked(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.victim)
        resp = client.post(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(resp.status_code, 403)
        self.assertFalse(self._membership_exists())

    def test_post_rejects_wrong_email(self):
        wrong = User.objects.create_user(
            username="wrong", email="other@example.com", password="pw"
        )
        self.client.force_login(wrong)
        resp = self.client.post(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(resp.status_code, 403)

    def test_login_keeps_pending_invite_for_explicit_confirmation(self):
        """Authentication must not silently create membership from session state."""
        client = Client()
        first = client.get(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(first.status_code, 302)

        self.assertTrue(client.login(username="victim", password="pw"))
        self.assertFalse(self._membership_exists())
        self.assertEqual(client.session.get("invite_token"), str(self.invite.token))

        confirm = client.get(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(confirm.status_code, 200)
        self.assertIn(b"Accept invitation", confirm.content)


class InvitedMemberRosterVisibilityTests(TestCase):
    """Invitees must not receive the workspace's full member directory."""

    def setUp(self):
        self.org = Organization.objects.create(name="Private team", slug="private-team")
        self.owner = User.objects.create_user("owner", password="pw", email="owner@x.com")
        self.inviter = User.objects.create_user("inviter", password="pw", email="inviter@x.com")
        self.invitee = User.objects.create_user("invitee", password="pw", email="invitee@x.com")
        self.other_member = User.objects.create_user("other", password="pw", email="other@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.inviter, organization=self.org, role=Role.ADMIN)
        OrganizationMembership.objects.create(user=self.invitee, organization=self.org, role=Role.DEVELOPER)
        OrganizationMembership.objects.create(user=self.other_member, organization=self.org, role=Role.DEVELOPER)
        OrganizationInvite.objects.create(
            organization=self.org,
            email=self.invitee.email,
            role=Role.DEVELOPER,
            created_by=self.inviter,
            accepted_by=self.invitee,
            accepted_at=timezone.now(),
        )

    def _member_ids_for(self, user):
        client = Client()
        client.force_login(user)
        response = client.get("/api/v1/org/")
        self.assertEqual(response.status_code, 200)
        return {member["id"] for member in response.json()["members"]}

    def test_invitee_only_sees_self_owners_and_inviter(self):
        self.assertEqual(
            self._member_ids_for(self.invitee),
            {self.owner.id, self.inviter.id, self.invitee.id},
        )

    def test_owner_still_sees_full_roster(self):
        self.assertEqual(
            self._member_ids_for(self.owner),
            {self.owner.id, self.inviter.id, self.invitee.id, self.other_member.id},
        )


class ActiveOrgResolutionTests(TestCase):
    """get_user_org() must be deterministic and honor the session pointer
    so multi-org users aren't silently routed to the wrong org."""

    def setUp(self):
        self.user = User.objects.create_user(
            username="multi", email="m@example.com", password="pw"
        )
        self.org_a = Organization.objects.create(name="A", slug="a")
        self.org_b = Organization.objects.create(name="B", slug="b")
        # Membership in A created first → must be the default pick.
        OrganizationMembership.objects.create(user=self.user, organization=self.org_a, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.user, organization=self.org_b, role=Role.DEVELOPER)

    def test_default_is_oldest_membership(self):
        self.client.force_login(self.user)
        resp = self.client.get("/api/v1/org/")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["org"]["slug"], "a")
        self.assertEqual(resp.json()["your_role"], Role.OWNER)

    def test_session_active_org_id_overrides(self):
        self.client.force_login(self.user)
        session = self.client.session
        session["active_org_id"] = self.org_b.id
        session.save()
        resp = self.client.get("/api/v1/org/")
        self.assertEqual(resp.json()["org"]["slug"], "b")
        self.assertEqual(resp.json()["your_role"], Role.DEVELOPER)

    def test_default_prefers_owned_workspace_over_older_invited_membership(self):
        user = User.objects.create_user("owner-after-invite", password="pw", email="owner-after@x.com")
        invited_org = Organization.objects.create(name="Invited", slug="invited")
        OrganizationMembership.objects.create(
            user=user, organization=invited_org, role=Role.DEVELOPER
        )
        owned_org = Organization.objects.create(name="Owned", slug="owned")
        OrganizationMembership.objects.create(
            user=user, organization=owned_org, role=Role.OWNER
        )
        self.client.force_login(user)

        response = self.client.get("/api/v1/org/")

        self.assertEqual(response.json()["org"]["slug"], "owned")

    def test_membership_list_contains_only_the_callers_organizations(self):
        self.client.force_login(self.user)
        response = self.client.get("/api/v1/org/memberships/")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            {m["organization"]["id"] for m in response.json()["memberships"]},
            {self.org_a.id, self.org_b.id},
        )

    def test_stale_session_pointer_falls_back(self):
        """If active_org_id points at a non-member org, drop it and use default."""
        ghost = Organization.objects.create(name="Ghost", slug="ghost")
        self.client.force_login(self.user)
        session = self.client.session
        session["active_org_id"] = ghost.id
        session.save()
        resp = self.client.get("/api/v1/org/")
        self.assertEqual(resp.json()["org"]["slug"], "a")

class OrganizationMembershipRemovalTests(TestCase):
    def setUp(self):
        from core.models import PublicKey
        self.org = Organization.objects.create(name="Team", slug="team-removal")
        self.owner = User.objects.create_user("team-owner", password="pw", email="owner@x.com")
        self.other_owner = User.objects.create_user("other-owner", password="pw", email="other@x.com")
        self.developer = User.objects.create_user("team-dev", password="pw", email="dev@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.other_owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.developer, organization=self.org, role=Role.DEVELOPER)
        self.key = PublicKey.objects.create(
            user=self.developer, organization=self.org, key_title="dev laptop",
            key_payload="ssh-ed25519 AAAA REMOVAL_TEST dev@laptop",
        )

    def test_owner_removing_member_revokes_their_keys(self):
        self.client.force_login(self.owner)
        response = self.client.delete(f"/api/v1/org/members/{self.developer.id}/")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(OrganizationMembership.objects.filter(user=self.developer, organization=self.org).exists())
        self.assertFalse(type(self.key).objects.filter(id=self.key.id).exists())

    def test_member_can_leave_and_their_keys_are_removed(self):
        self.client.force_login(self.developer)
        response = self.client.post("/api/v1/org/leave/")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(OrganizationMembership.objects.filter(user=self.developer, organization=self.org).exists())
        self.assertFalse(type(self.key).objects.filter(id=self.key.id).exists())

    def test_member_can_leave_a_named_organization_from_their_account(self):
        self.client.force_login(self.developer)
        response = self.client.post(f"/api/v1/org/memberships/{self.org.id}/leave/")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(OrganizationMembership.objects.filter(user=self.developer, organization=self.org).exists())
        self.assertFalse(type(self.key).objects.filter(id=self.key.id).exists())

    def test_owner_cannot_leave(self):
        self.client.force_login(self.owner)
        response = self.client.post("/api/v1/org/leave/")
        self.assertEqual(response.status_code, 403)
        self.assertTrue(OrganizationMembership.objects.filter(user=self.owner, organization=self.org).exists())

    def test_admin_cannot_remove_an_owner(self):
        admin = User.objects.create_user("team-admin", password="pw", email="admin@x.com")
        OrganizationMembership.objects.create(user=admin, organization=self.org, role=Role.ADMIN)
        self.client.force_login(admin)
        response = self.client.delete(f"/api/v1/org/members/{self.owner.id}/")
        self.assertEqual(response.status_code, 403)


class ServerLastSyncedTests(TestCase):
    """Sync heartbeat: every successful /servers/sync stamps last_synced_at
    so the dashboard can tell a wedged agent from a healthy one."""

    def setUp(self):
        _, self.org, _ = _make_org_with_owner()
        self.server, self.token = _make_server(self.org)

    def test_unsynced_server_has_null_timestamp(self):
        self.server.refresh_from_db()
        self.assertIsNone(self.server.last_synced_at)

    def test_successful_sync_stamps_timestamp(self):
        before = timezone.now()
        resp = self.client.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        self.assertEqual(resp.status_code, 200)
        self.server.refresh_from_db()
        self.assertIsNotNone(self.server.last_synced_at)
        self.assertGreaterEqual(self.server.last_synced_at, before)

    def test_failed_sync_does_not_stamp(self):
        """Invalid token → 401, no heartbeat — otherwise an attacker could
        forge liveness signals for servers they don't control."""
        resp = self.client.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION="Bearer srv_bogus",
        )
        self.assertEqual(resp.status_code, 401)
        self.server.refresh_from_db()
        self.assertIsNone(self.server.last_synced_at)

    def test_server_list_exposes_timestamp(self):
        self.client.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {self.token}",
        )
        user = User.objects.get(username="owner")
        self.client.force_login(user)
        resp = self.client.get("/api/v1/org/servers/")
        servers = resp.json()["servers"]
        self.assertEqual(len(servers), 1)
        self.assertIsNotNone(servers[0]["last_synced_at"])


class PublicKeyFingerprintTests(TestCase):
    """The SHA256 fingerprint is the canonical short identifier for an SSH
    key — what `ssh-keygen -lf` prints. Computed on the fly, exposed in API."""

    # ed25519 key generated for this test only — public, not a real credential.
    SAMPLE = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmkVz/0YRezrI3LSgvUkB4dKbHJI"
        "u4dxgcJ7Mw2y5/A test@example.com"
    )

    def setUp(self):
        from core.models import PublicKey
        self.user, self.org, _ = _make_org_with_owner()
        self.key = PublicKey.objects.create(
            user=self.user,
            organization=self.org,
            key_title="test",
            key_payload=self.SAMPLE,
            is_active=True,
        )

    def test_fingerprint_has_openssh_shape(self):
        fp = self.key.fingerprint
        # ssh-keygen prints "SHA256:<43 chars base64-no-pad>"
        self.assertTrue(fp.startswith("SHA256:"))
        self.assertEqual(len(fp), len("SHA256:") + 43)

    def test_fingerprint_is_deterministic(self):
        from core.models import PublicKey
        twin = PublicKey(key_payload=self.SAMPLE)
        self.assertEqual(self.key.fingerprint, twin.fingerprint)

    def test_fingerprint_changes_with_payload(self):
        from core.models import PublicKey
        other = PublicKey(
            key_payload="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentBase64Blob other@host"
        )
        self.assertNotEqual(self.key.fingerprint, other.fingerprint)

    def test_malformed_payload_returns_empty_string(self):
        """Validators block this at the API edge, but the property must not
        500 if a row somehow has junk in it."""
        from core.models import PublicKey
        for bad in ["", "not a key", "ssh-ed25519 !!!invalid-base64!!!", "only-one-field"]:
            with self.subTest(payload=bad):
                self.assertEqual(PublicKey(key_payload=bad).fingerprint, "")

    def test_api_response_includes_fingerprint(self):
        self.client.force_login(self.user)
        resp = self.client.get("/api/v1/public-keys/")
        keys = resp.json()["keys"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["fingerprint"], self.key.fingerprint)
        self.assertTrue(keys[0]["fingerprint"].startswith("SHA256:"))


class InviteListUrlTests(TestCase):
    """Pending invites must carry a re-copyable invite_url on the list so
    admins can re-share without revoke-and-recreate (the dead end the share-
    it-yourself flow would have otherwise)."""

    def setUp(self):
        self.user, self.org, _ = _make_org_with_owner()
        self.invite = OrganizationInvite.objects.create(
            organization=self.org,
            email="dev@example.com",
            role=Role.DEVELOPER,
            created_by=self.user,
            expires_at=timezone.now() + timedelta(days=7),
        )

    def test_list_response_includes_invite_url(self):
        self.client.force_login(self.user)
        resp = self.client.get("/api/v1/invites/")
        self.assertEqual(resp.status_code, 200)
        invites = resp.json()["invites"]
        self.assertEqual(len(invites), 1)
        url = invites[0]["invite_url"]
        self.assertIn(f"/api/v1/invites/accept/{self.invite.token}/", url)


class InviteListFilterPaginationTests(TestCase):
    """The list defaults to pending so expired/accepted invites don't clutter
    the view, while keeping every bucket reachable (and counted) for audit."""

    def setUp(self):
        self.user, self.org, _ = _make_org_with_owner()
        now = timezone.now()
        # Two pending, one accepted, three expired — distinct counts per bucket.
        for i in range(2):
            OrganizationInvite.objects.create(
                organization=self.org, email=f"pending{i}@example.com",
                role=Role.DEVELOPER, created_by=self.user,
                expires_at=now + timedelta(days=7),
            )
        self.joiner = User.objects.create_user(
            username="joiner", email="accepted@example.com", password="pw"
        )
        OrganizationInvite.objects.create(
            organization=self.org, email="accepted@example.com",
            role=Role.DEVELOPER, created_by=self.user,
            expires_at=now + timedelta(days=7), accepted_at=now,
            accepted_by=self.joiner,
        )
        for i in range(3):
            OrganizationInvite.objects.create(
                organization=self.org, email=f"expired{i}@example.com",
                role=Role.DEVELOPER, created_by=self.user,
                expires_at=now - timedelta(days=1),
            )
        self.client.force_login(self.user)

    def test_defaults_to_pending_only(self):
        data = self.client.get("/api/v1/invites/").json()
        self.assertEqual(data["status"], "pending")
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["invites"]), 2)
        self.assertTrue(all(not i["is_accepted"] and not i["is_expired"] for i in data["invites"]))

    def test_counts_cover_every_bucket(self):
        counts = self.client.get("/api/v1/invites/").json()["counts"]
        self.assertEqual(counts, {"pending": 2, "accepted": 1, "expired": 3, "all": 6})

    def test_status_filters(self):
        self.assertEqual(self.client.get("/api/v1/invites/?status=expired").json()["total"], 3)
        self.assertEqual(self.client.get("/api/v1/invites/?status=accepted").json()["total"], 1)
        self.assertEqual(self.client.get("/api/v1/invites/?status=all").json()["total"], 6)

    def test_accepted_invite_reports_the_username(self):
        accepted = self.client.get("/api/v1/invites/?status=accepted").json()["invites"]
        self.assertEqual(accepted[0]["accepted_by"], "joiner")

    def test_newest_first(self):
        emails = [i["email"] for i in self.client.get("/api/v1/invites/?status=all").json()["invites"]]
        # Expired invites were created last, so they lead a newest-first list.
        self.assertTrue(emails[0].startswith("expired"))

    def test_pagination_slices_and_flags_next(self):
        first = self.client.get("/api/v1/invites/?status=all&page=1&page_size=4").json()
        self.assertEqual(len(first["invites"]), 4)
        self.assertTrue(first["has_next"])
        second = self.client.get("/api/v1/invites/?status=all&page=2&page_size=4").json()
        self.assertEqual(len(second["invites"]), 2)
        self.assertFalse(second["has_next"])


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="no-reply@syncssh.dev",
)
class InviteEmailTests(TestCase):
    """Creating an invite must actually email the recipient — the dashboard's
    copy/mailto fallback used to be the *only* delivery path, so invites
    silently went nowhere in production."""

    def setUp(self):
        self.user, self.org, _ = _make_org_with_owner()
        self.client.force_login(self.user)

    def test_creating_invite_sends_email(self):
        from django.core import mail

        resp = self.client.post(
            "/api/v1/invites/",
            data=json.dumps({"email": "newdev@example.com", "role": Role.DEVELOPER}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        self.assertTrue(resp.json()["email_sent"])

        self.assertEqual(len(mail.outbox), 1)
        msg = mail.outbox[0]
        self.assertEqual(msg.to, ["newdev@example.com"])
        self.assertEqual(msg.from_email, "no-reply@syncssh.dev")
        self.assertIn(self.org.name, msg.subject)
        # The accept link and an HTML alternative must both be present.
        token = resp.json()["token"]
        self.assertIn(f"/api/v1/invites/accept/{token}/", msg.body)
        self.assertTrue(any(mt == "text/html" for _, mt in msg.alternatives))

    def test_invite_still_created_when_email_fails(self):
        from organizations.models import OrganizationInvite

        with mock.patch(
            "api.views_org.send_org_invite", return_value=False
        ):
            resp = self.client.post(
                "/api/v1/invites/",
                data=json.dumps({"email": "newdev@example.com"}),
                content_type="application/json",
            )
        self.assertEqual(resp.status_code, 201)
        self.assertFalse(resp.json()["email_sent"])
        self.assertTrue(
            OrganizationInvite.objects.filter(email="newdev@example.com").exists()
        )

    def test_invite_send_email_false_skips_delivery(self):
        """`send_email: false` — admin shares the link themselves; no mail
        goes out, and the response says so via `email_skipped`."""
        from django.core import mail
        from organizations.models import OrganizationInvite

        resp = self.client.post(
            "/api/v1/invites/",
            data=json.dumps({"email": "newdev@example.com", "send_email": False}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 201)
        body = resp.json()
        self.assertFalse(body["email_sent"])
        self.assertTrue(body["email_skipped"])
        self.assertEqual(len(mail.outbox), 0)
        self.assertTrue(
            OrganizationInvite.objects.filter(email="newdev@example.com").exists()
        )


class ChangePasswordTests(TestCase):
    """POST /api/v1/auth/change-password/ — requires the current password (a
    stolen session cookie alone must not be able to take over the account),
    keeps the current session alive, and leaves an audit trail."""

    def setUp(self):
        cache.clear()
        self.user, self.org, self.password = _make_org_with_owner()
        self.client.force_login(self.user)
        self.new_password = "battery-staple-horse-correct"

    def tearDown(self):
        cache.clear()

    def _change(self, current, pw1, pw2):
        return self.client.post(
            "/api/v1/auth/change-password/",
            data=json.dumps({
                "current_password": current,
                "new_password1": pw1,
                "new_password2": pw2,
            }),
            content_type="application/json",
        )

    def test_requires_authentication(self):
        resp = Client().post(
            "/api/v1/auth/change-password/",
            data=json.dumps({}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)

    def test_wrong_current_password_rejected(self):
        resp = self._change("not-my-password", self.new_password, self.new_password)
        self.assertEqual(resp.status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_mismatched_new_passwords_rejected(self):
        resp = self._change(self.password, self.new_password, "something-else-entirely")
        self.assertEqual(resp.status_code, 400)

    def test_weak_new_password_rejected(self):
        resp = self._change(self.password, "short", "short")
        self.assertEqual(resp.status_code, 400)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.password))

    def test_success_changes_password_and_keeps_session(self):
        resp = self._change(self.password, self.new_password, self.new_password)
        self.assertEqual(resp.status_code, 200)
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password(self.new_password))
        # update_session_auth_hash must keep this session valid.
        me = self.client.get("/api/v1/auth/me/")
        self.assertEqual(me.status_code, 200)

    def test_success_logs_audit_event(self):
        from core.models import AuditLog
        self._change(self.password, self.new_password, self.new_password)
        event = AuditLog.objects.filter(action="auth.password_changed").first()
        self.assertIsNotNone(event)
        self.assertEqual(event.actor_user_id, self.user.id)

    @override_settings(RATELIMIT_ENABLE=True)
    def test_rate_limited_per_user(self):
        """5 wrong current-password guesses trip the throttle on the 6th —
        the endpoint must not be a password oracle for a hijacked session."""
        for _ in range(5):
            resp = self._change("wrong-guess", self.new_password, self.new_password)
            self.assertEqual(resp.status_code, 400)
        resp = self._change("wrong-guess", self.new_password, self.new_password)
        self.assertEqual(resp.status_code, 429)

    def test_rejected_without_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        resp = client.post(
            "/api/v1/auth/change-password/",
            data=json.dumps({
                "current_password": self.password,
                "new_password1": self.new_password,
                "new_password2": self.new_password,
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)


class OrgRenameTests(TestCase):
    """PATCH /api/v1/org/ — rename is owner/admin only, audit-logged, and
    never touches the slug (it's the stable identifier in webhook payloads)."""

    def setUp(self):
        self.owner, self.org, self.password = _make_org_with_owner()
        self.dev = User.objects.create_user(
            username="dev", email="dev@example.com", password="pw-123456789"
        )
        OrganizationMembership.objects.create(
            user=self.dev, organization=self.org, role=Role.DEVELOPER
        )
        self.client = Client()

    def _rename(self, name):
        return self.client.patch(
            "/api/v1/org/",
            data=json.dumps({"name": name}),
            content_type="application/json",
        )

    def test_owner_renames_and_slug_unchanged(self):
        self.client.force_login(self.owner)
        resp = self._rename("Acme Rockets")
        self.assertEqual(resp.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.name, "Acme Rockets")
        self.assertEqual(self.org.slug, "acme")

    def test_rename_is_audit_logged(self):
        from core.models import AuditLog

        self.client.force_login(self.owner)
        self._rename("Acme Rockets")
        row = AuditLog.objects.get(action="org.renamed")
        self.assertEqual(row.metadata["old_name"], "Acme")
        self.assertEqual(row.metadata["new_name"], "Acme Rockets")

    def test_developer_cannot_rename(self):
        self.client.force_login(self.dev)
        resp = self._rename("Hijacked")
        self.assertEqual(resp.status_code, 403)
        self.org.refresh_from_db()
        self.assertEqual(self.org.name, "Acme")

    def test_blank_name_rejected(self):
        self.client.force_login(self.owner)
        resp = self._rename("   ")
        self.assertEqual(resp.status_code, 400)

    def test_anonymous_rejected(self):
        resp = self._rename("Nope")
        self.assertEqual(resp.status_code, 401)


class UserPrefsTests(TestCase):
    """PATCH /api/v1/auth/me/ — theme preference."""

    def setUp(self):
        self.user, self.org, self.password = _make_org_with_owner()
        self.client = Client()
        self.client.force_login(self.user)

    def _patch(self, body):
        return self.client.patch(
            "/api/v1/auth/me/", data=json.dumps(body), content_type="application/json"
        )

    def test_theme_roundtrip(self):
        resp = self._patch({"theme": "dark"})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["user"]["prefs"]["theme"], "dark")
        resp = self.client.get("/api/v1/auth/me/")
        self.assertEqual(resp.json()["user"]["prefs"]["theme"], "dark")

    def test_unset_theme_is_empty_not_defaulted(self):
        # No profile row yet: the API must not invent a preference, or the
        # server would flip an existing localStorage choice on first load.
        resp = self.client.get("/api/v1/auth/me/")
        self.assertEqual(resp.json()["user"]["prefs"]["theme"], "")

    def test_invalid_theme_rejected(self):
        resp = self._patch({"theme": "solarized"})
        self.assertEqual(resp.status_code, 400)

    def test_no_gravatar_hash_in_payload(self):
        # Gravatar support was removed for privacy (email-derived identifier
        # sent to a third party); make sure the hash doesn't sneak back in.
        resp = self.client.get("/api/v1/auth/me/")
        self.assertNotIn("gravatar_hash", resp.json()["user"])

    def test_anonymous_rejected(self):
        resp = Client().patch(
            "/api/v1/auth/me/",
            data=json.dumps({"theme": "dark"}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 401)


class InviteEmailThemeTests(TestCase):
    """Org-level palette for outgoing invite emails."""

    def setUp(self):
        self.owner, self.org, self.password = _make_org_with_owner()
        self.client = Client()
        self.client.force_login(self.owner)

    def _patch(self, body):
        return self.client.patch(
            "/api/v1/org/", data=json.dumps(body), content_type="application/json"
        )

    def test_patch_updates_theme(self):
        resp = self._patch({"invite_email_theme": "light"})
        self.assertEqual(resp.status_code, 200)
        self.org.refresh_from_db()
        self.assertEqual(self.org.invite_email_theme, "light")

    def test_invalid_theme_rejected(self):
        resp = self._patch({"invite_email_theme": "sepia"})
        self.assertEqual(resp.status_code, 400)

    def test_invite_email_uses_org_palette(self):
        from django.core import mail
        from organizations.emails import EMAIL_PALETTES, send_org_invite
        from organizations.models import OrganizationInvite

        self.org.invite_email_theme = "light"
        self.org.save(update_fields=["invite_email_theme"])
        invite = OrganizationInvite.objects.create(
            organization=self.org,
            email="new@example.com",
            role=Role.DEVELOPER,
            created_by=self.owner,
            expires_at=timezone.now() + timedelta(days=7),
        )
        self.assertTrue(send_org_invite(invite, "https://app.example.com/invite/x"))
        html = mail.outbox[0].alternatives[0][0]
        self.assertIn(EMAIL_PALETTES["light"]["bg"], html)
        self.assertNotIn(EMAIL_PALETTES["dark"]["bg"], html)


class AllauthSignupGateTests(TestCase):
    """/accounts/signup/ exists only for the invite-accept bounce.

    Without a pending invite in the session, an allauth signup would create an
    org-less account (only the API SignupView creates a workspace), so the
    view must bounce those visitors to the React signup instead.
    """

    def test_signup_without_invite_redirects_to_react_signup(self):
        resp = self.client.get("/accounts/signup/")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp["Location"].endswith("/signup"))

    def test_signup_post_without_invite_is_also_bounced(self):
        resp = self.client.post("/accounts/signup/", {
            "username": "orgless",
            "email": "orgless@example.com",
            "password1": "S3cure-enough-pass",
            "password2": "S3cure-enough-pass",
        })
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp["Location"].endswith("/signup"))
        self.assertFalse(User.objects.filter(username="orgless").exists())

    def test_signup_with_invite_token_renders(self):
        session = self.client.session
        session["invite_token"] = "pending-invite-token"
        session.save()
        resp = self.client.get("/accounts/signup/")
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, "Create Account")
