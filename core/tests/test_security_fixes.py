"""Regression tests for SECURITY_AUDIT findings #1, #2, #3, #4, #5, #6, #7, #8, #9, #11."""
import json
from datetime import timedelta
from unittest import mock

from django.core.cache import cache
from django.test import TestCase, Client, RequestFactory, override_settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from api.views import ServerSyncView
from core.models import Server, PublicKey
from syncssh.middleware import ClientIPMiddleware
from organizations.models import (
    ApiKey,
    Organization,
    OrganizationInvite,
    OrganizationMembership,
    Role,
    TokenScope,
)

User = get_user_model()


class KeyPayloadInjectionTests(TestCase):
    """#1 — key_payload must not allow breakout from SYNCSSH markers."""

    def setUp(self):
        # Use OWNER role here so we're testing payload validation in isolation,
        # not the separate self-service-deployment access check.
        self.user = User.objects.create_user(username="owner", password="pw", email="o@example.com")
        self.org = Organization.objects.create(name="Org", slug="org")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=Role.OWNER)
        self.client = Client()
        self.client.force_login(self.user)

    def _post(self, payload, title="t"):
        return self.client.post(
            "/api/v1/public-keys/",
            data=json.dumps({"key_title": title, "key_payload": payload}),
            content_type="application/json",
        )

    def test_valid_ed25519_accepted(self):
        good = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITESTKEYAAAAAAAAAAAAAAA me@host"
        self.assertEqual(self._post(good).status_code, 201)

    def test_newline_in_payload_rejected(self):
        evil = (
            "ssh-ed25519 AAAA decoy\n"
            "# === SYNCSSH END ===\n"
            "ssh-ed25519 AAAA attacker\n"
            "# === SYNCSSH BEGIN ==="
        )
        self.assertEqual(self._post(evil).status_code, 400)

    def test_marker_substring_rejected(self):
        evil = "ssh-ed25519 AAAA SYNCSSH END leak"
        self.assertEqual(self._post(evil).status_code, 400)

    def test_unknown_key_type_rejected(self):
        self.assertEqual(self._post("totally not a ssh key").status_code, 400)

    def test_empty_payload_rejected(self):
        self.assertEqual(self._post("").status_code, 400)

    def test_carriage_return_rejected(self):
        evil = "ssh-ed25519 AAAA decoy\r# === SYNCSSH END ===\rssh-ed25519 AAAA attacker"
        self.assertEqual(self._post(evil).status_code, 400)

    def test_oversize_payload_rejected(self):
        oversized = "ssh-ed25519 " + ("A" * 9000) + " huge"
        self.assertEqual(self._post(oversized).status_code, 400)


class ServerTokenLeakTests(TestCase):
    """#2 — DEVELOPERs must not see Server.token in list responses."""

    def setUp(self):
        self.org = Organization.objects.create(name="Org", slug="org")
        self.owner = User.objects.create_user(username="owner", password="pw", email="o@x.com")
        self.dev = User.objects.create_user(username="dev", password="pw", email="d@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.dev, organization=self.org, role=Role.DEVELOPER)
        self.raw_token = "srv_secret_token_xyz"
        Server.objects.create(
            organization=self.org,
            name="prod-1",
            ip_address="10.0.0.1",
            ssh_user="root",
            token_hash=Server.hash_token(self.raw_token),
            token_prefix=self.raw_token[:12],
            is_active=True,
        )

    def _list_as(self, user):
        c = Client()
        c.force_login(user)
        resp = c.get("/api/v1/org/servers/")
        self.assertEqual(resp.status_code, 200)
        return resp.json()["servers"][0]

    def test_owner_sees_only_prefix_not_full_token(self):
        entry = self._list_as(self.owner)
        self.assertEqual(entry.get("token_prefix"), self.raw_token[:12])
        # Full raw token must never appear after creation
        self.assertNotIn("token", entry)

    def test_developer_does_not_see_token_or_prefix(self):
        entry = self._list_as(self.dev)
        self.assertNotIn("token", entry)
        self.assertNotIn("token_prefix", entry)

    def test_raw_token_never_in_list_response(self):
        for actor in (self.owner, self.dev):
            c = Client()
            c.force_login(actor)
            resp = c.get("/api/v1/org/servers/")
            self.assertNotIn(self.raw_token.encode(), resp.content)


class MemberAndServerPiiRedactionTests(TestCase):
    """Non-admins must not see member emails or the (ip_address, ssh_user)
    SSH-target tuple — recon/phishing surface if a low-privilege account is
    compromised. Admins still see everything."""

    def setUp(self):
        self.org = Organization.objects.create(name="Org", slug="org")
        self.owner = User.objects.create_user(username="owner", password="pw", email="owner@x.com")
        self.dev = User.objects.create_user(username="dev", password="pw", email="dev@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.dev, organization=self.org, role=Role.DEVELOPER)
        Server.objects.create(
            organization=self.org,
            name="prod-1",
            ip_address="10.0.0.1",
            ssh_user="root",
            token_hash=Server.hash_token("srv_secret_token_xyz"),
            token_prefix="srv_secret_t",
            is_active=True,
        )

    def _get(self, user, path):
        c = Client()
        c.force_login(user)
        resp = c.get(path)
        self.assertEqual(resp.status_code, 200)
        return resp.json()

    def test_developer_servers_omit_ip_and_ssh_user(self):
        entry = self._get(self.dev, "/api/v1/org/servers/")["servers"][0]
        self.assertNotIn("ip_address", entry)
        self.assertNotIn("ssh_user", entry)
        # id + name must still be present for self-service deploy.
        self.assertEqual(entry["name"], "prod-1")

    def test_admin_servers_include_ip_and_ssh_user(self):
        entry = self._get(self.owner, "/api/v1/org/servers/")["servers"][0]
        self.assertEqual(entry["ip_address"], "10.0.0.1")
        self.assertEqual(entry["ssh_user"], "root")

    def test_developer_members_omit_email(self):
        members = self._get(self.dev, "/api/v1/org/")["members"]
        self.assertTrue(members)
        for m in members:
            self.assertNotIn("email", m)
        # The SSH target / contact list must not leak in the raw bytes either.
        c = Client()
        c.force_login(self.dev)
        body = c.get("/api/v1/org/servers/").content
        self.assertNotIn(b"10.0.0.1", body)

    def test_admin_members_include_email(self):
        members = self._get(self.owner, "/api/v1/org/")["members"]
        emails = {m.get("email") for m in members}
        self.assertIn("owner@x.com", emails)
        self.assertIn("dev@x.com", emails)

    def test_dashboard_key_count_matches_role_visibility(self):
        PublicKey.objects.create(
            user=self.owner,
            organization=self.org,
            key_title="owner key",
            key_payload="ssh-ed25519 AAAA OWNER_DASHBOARD_KEY owner",
            is_active=True,
        )
        PublicKey.objects.create(
            user=self.dev,
            organization=self.org,
            key_title="developer key",
            key_payload="ssh-ed25519 AAAA DEVELOPER_DASHBOARD_KEY dev",
            is_active=True,
        )
        PublicKey.objects.create(
            user=self.dev,
            organization=self.org,
            key_title="inactive developer key",
            key_payload="ssh-ed25519 AAAA INACTIVE_DASHBOARD_KEY dev",
            is_active=False,
        )

        self.assertEqual(self._get(self.owner, "/api/v1/org/")["key_count"], 2)
        self.assertEqual(self._get(self.dev, "/api/v1/org/")["key_count"], 1)


class RemovedMemberRevocationTests(TestCase):
    """#3 — keys belonging to removed members must stop syncing."""

    def setUp(self):
        self.factory = RequestFactory()
        self.view = ServerSyncView.as_view()
        self.org = Organization.objects.create(name="Org", slug="org")
        self.user = User.objects.create_user(username="dev", password="pw", email="d@x.com")
        self.membership = OrganizationMembership.objects.create(
            user=self.user, organization=self.org, role=Role.DEVELOPER
        )
        self.raw_token = "srv_token_revoke"
        self.server = Server.objects.create(
            organization=self.org,
            name="prod-1",
            ip_address="10.0.0.1",
            ssh_user="root",
            token_hash=Server.hash_token(self.raw_token),
            token_prefix=self.raw_token[:12],
            is_active=True,
        )
        self.key = PublicKey.objects.create(
            user=self.user,
            organization=self.org,
            key_title="dev key",
            key_payload="ssh-ed25519 AAAA REVOCATION_KEY dev",
            is_active=True,
        )

    def _sync(self):
        req = self.factory.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        return self.view(req).content

    def test_key_returned_while_member(self):
        self.assertIn(b"REVOCATION_KEY", self._sync())

    def test_key_not_returned_after_membership_removed(self):
        self.membership.delete()
        self.assertNotIn(b"REVOCATION_KEY", self._sync())

    def test_key_not_returned_if_user_moved_to_different_org(self):
        other_org = Organization.objects.create(name="Other", slug="other")
        self.membership.delete()
        OrganizationMembership.objects.create(
            user=self.user, organization=other_org, role=Role.DEVELOPER
        )
        self.assertNotIn(b"REVOCATION_KEY", self._sync())


class TokenHashingAndHeaderTests(TestCase):
    """#4 — token hashed in DB, Bearer header preferred, rotation works."""

    def setUp(self):
        self.factory = RequestFactory()
        self.view = ServerSyncView.as_view()
        self.org = Organization.objects.create(name="Org", slug="org")
        self.user = User.objects.create_user(username="dev", password="pw", email="d@x.com")
        OrganizationMembership.objects.create(user=self.user, organization=self.org, role=Role.DEVELOPER)
        self.raw_token = "srv_known_token_for_test"
        self.server = Server.objects.create(
            organization=self.org,
            name="prod-1",
            ip_address="10.0.0.1",
            ssh_user="root",
            token_hash=Server.hash_token(self.raw_token),
            token_prefix=self.raw_token[:12],
            is_active=True,
        )
        PublicKey.objects.create(
            user=self.user,
            organization=self.org,
            key_title="dev key",
            key_payload="ssh-ed25519 AAAA HASH_TEST_KEY dev",
            is_active=True,
        )

    def test_raw_token_not_persisted_in_db(self):
        # The Server model no longer has a 'token' field; only the hash.
        with self.assertRaises(AttributeError):
            _ = self.server.token  # noqa
        self.assertEqual(
            self.server.token_hash,
            Server.hash_token(self.raw_token),
        )
        self.assertNotEqual(self.server.token_hash, self.raw_token)

    def test_bearer_header_authenticates(self):
        req = self.factory.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        resp = self.view(req)
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"HASH_TEST_KEY", resp.content)

    def test_query_param_is_rejected(self):
        req = self.factory.get("/api/v1/servers/sync", {"token": self.raw_token})
        self.assertEqual(self.view(req).status_code, 400)

    def test_bearer_header_ignores_query_parameter(self):
        req = self.factory.get(
            "/api/v1/servers/sync?token=bogus",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        self.assertEqual(self.view(req).status_code, 200)

    def test_wrong_bearer_token_rejected(self):
        req = self.factory.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION="Bearer not_the_real_token",
        )
        self.assertEqual(self.view(req).status_code, 401)

    def test_rotation_invalidates_old_token(self):
        new_raw = self.server.rotate()
        self.assertNotEqual(new_raw, self.raw_token)
        # Old token rejected
        req_old = self.factory.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {self.raw_token}",
        )
        self.assertEqual(self.view(req_old).status_code, 401)
        # New token works
        req_new = self.factory.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {new_raw}",
        )
        self.assertEqual(self.view(req_new).status_code, 200)

    def test_rotation_updates_prefix(self):
        old_prefix = self.server.token_prefix
        new_raw = self.server.rotate()
        self.assertEqual(self.server.token_prefix, new_raw[:12])
        self.assertNotEqual(self.server.token_prefix, old_prefix)


class ClientIPMiddlewareTests(TestCase):
    def _middleware(self, **environment):
        with mock.patch.dict("os.environ", environment, clear=True):
            return ClientIPMiddleware(lambda request: request.META["REMOTE_ADDR"])

    def test_forwarded_header_ignored_from_untrusted_peer(self):
        middleware = self._middleware(
            TRUSTED_PROXY="xff",
            TRUSTED_PROXY_CIDRS="172.28.0.0/24",
        )
        request = RequestFactory().get(
            "/", REMOTE_ADDR="203.0.113.10", HTTP_X_FORWARDED_FOR="198.51.100.8"
        )
        self.assertEqual(middleware(request), "203.0.113.10")

    def test_xff_accepted_from_trusted_peer(self):
        middleware = self._middleware(
            TRUSTED_PROXY="xff",
            TRUSTED_PROXY_CIDRS="172.28.0.0/24",
        )
        request = RequestFactory().get(
            "/",
            REMOTE_ADDR="172.28.0.5",
            HTTP_X_FORWARDED_FOR="192.0.2.10, 198.51.100.8",
        )
        self.assertEqual(middleware(request), "198.51.100.8")

    def test_cloudflare_header_requires_cloudflare_upstream(self):
        middleware = self._middleware(
            TRUSTED_PROXY="cloudflare",
            TRUSTED_PROXY_CIDRS="172.28.0.0/24",
            CLOUDFLARE_PROXY_CIDRS="203.0.113.0/24",
        )
        request = RequestFactory().get(
            "/",
            REMOTE_ADDR="172.28.0.5",
            HTTP_X_FORWARDED_FOR="198.51.100.9",
            HTTP_CF_CONNECTING_IP="192.0.2.25",
        )
        self.assertEqual(middleware(request), "172.28.0.5")

    def test_cloudflare_header_accepted_from_cloudflare_upstream(self):
        middleware = self._middleware(
            TRUSTED_PROXY="cloudflare",
            TRUSTED_PROXY_CIDRS="172.28.0.0/24",
            CLOUDFLARE_PROXY_CIDRS="203.0.113.0/24",
        )
        request = RequestFactory().get(
            "/",
            REMOTE_ADDR="172.28.0.5",
            HTTP_X_FORWARDED_FOR="203.0.113.40",
            HTTP_CF_CONNECTING_IP="192.0.2.25",
        )
        self.assertEqual(middleware(request), "192.0.2.25")


class ApiKeyCreatePrivilegeTests(TestCase):
    """#5 — caller can't mint a key with scopes it doesn't itself hold."""

    def setUp(self):
        self.org = Organization.objects.create(name="Org", slug="org")
        self.owner = User.objects.create_user(username="owner", password="pw", email="o@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        # Caller holds ADMIN_MEMBERS but NOT WRITE_KEYS.
        self.caller_raw = ApiKey.generate_token()
        self.caller_key = ApiKey.objects.create(
            organization=self.org,
            name="admin-only key",
            key_prefix="bb_oak_live_",
            key_hash=ApiKey.hash_token(self.caller_raw),
            scopes=[TokenScope.ADMIN_MEMBERS],
            created_by=self.owner,
        )
        # Caller with no ADMIN_MEMBERS scope at all.
        self.weak_raw = ApiKey.generate_token()
        self.weak_key = ApiKey.objects.create(
            organization=self.org,
            name="read-only key",
            key_prefix="bb_oak_live_",
            key_hash=ApiKey.hash_token(self.weak_raw),
            scopes=[TokenScope.READ_SERVERS],
            created_by=self.owner,
        )

    def _post(self, raw_token, scopes_header=None, name="new-key"):
        c = Client()
        headers = {
            "HTTP_AUTHORIZATION": f"Bearer {raw_token}",
            "HTTP_X_KEY_NAME": name,
        }
        if scopes_header is not None:
            headers["HTTP_X_KEY_SCOPES"] = scopes_header
        return c.post("/api/v1/keys/", **headers)

    def test_caller_without_admin_scope_rejected(self):
        resp = self._post(self.weak_raw, scopes_header="read_servers")
        self.assertEqual(resp.status_code, 403)

    def test_cannot_escalate_to_unowned_scope(self):
        # Caller has only ADMIN_MEMBERS; tries to mint a key with WRITE_KEYS.
        resp = self._post(self.caller_raw, scopes_header="write_keys")
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"exceed", resp.content)

    def test_subset_scopes_allowed(self):
        # Caller holds both; mints a key that's a strict subset.
        self.caller_key.scopes = [TokenScope.ADMIN_MEMBERS, TokenScope.WRITE_KEYS]
        self.caller_key.save(update_fields=["scopes"])
        resp = self._post(self.caller_raw, scopes_header="write_keys")
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertEqual(body["scopes"], ["write_keys"])
        self.assertTrue(body["token"].startswith("bb_oak_live_"))

    def test_invalid_scope_silently_dropped(self):
        """Unknown values in X-Key-Scopes are filtered; mint still succeeds
        if a valid baseline remains in the caller's permissions."""
        self.caller_key.scopes = [TokenScope.ADMIN_MEMBERS, TokenScope.READ_SERVERS]
        self.caller_key.save(update_fields=["scopes"])
        # Pure junk → falls back to default ["read_servers"]
        resp = self._post(self.caller_raw, scopes_header="not_a_real_scope")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["scopes"], ["read_servers"])

    def test_created_by_falls_back_to_caller_key_creator(self):
        self.caller_key.scopes = [TokenScope.ADMIN_MEMBERS, TokenScope.READ_SERVERS]
        self.caller_key.save(update_fields=["scopes"])
        resp = self._post(self.caller_raw, scopes_header="read_servers")
        self.assertEqual(resp.status_code, 200)
        minted = ApiKey.objects.get(id=resp.json()["id"])
        # Must be a real User row, not AnonymousUser (which would have crashed
        # before the fix).
        self.assertEqual(minted.created_by, self.owner)

    def test_no_auth_returns_401(self):
        c = Client()
        resp = c.post("/api/v1/keys/")
        self.assertEqual(resp.status_code, 401)

    def test_rotate_without_scope_returns_403_not_500(self):
        """Regression for the old `raise HttpResponseForbidden` bug: missing
        scope should produce 403, not a TypeError → 500."""
        target = ApiKey.objects.create(
            organization=self.org,
            name="target",
            key_prefix="bb_oak_live_",
            key_hash=ApiKey.hash_token(ApiKey.generate_token()),
            scopes=[TokenScope.READ_SERVERS],
            created_by=self.owner,
        )
        c = Client()
        resp = c.post(
            f"/api/v1/org/keys/{target.id}/rotate/",
            HTTP_AUTHORIZATION=f"Bearer {self.weak_raw}",
        )
        self.assertEqual(resp.status_code, 403)


class SignupPasswordValidationTests(TestCase):
    """#6 — SignupView must run AUTH_PASSWORD_VALIDATORS."""

    def _signup(self, password, username="newuser", email="n@example.com"):
        c = Client()
        return c.post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": username,
                "email": email,
                "password1": password,
                "password2": password,
                "account_type": "solo",
            }),
            content_type="application/json",
        )

    def test_single_char_password_rejected(self):
        resp = self._signup("a")
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username="newuser").exists())

    def test_common_password_rejected(self):
        # "password" is in Django's bundled common-password list.
        resp = self._signup("password")
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username="newuser").exists())

    def test_purely_numeric_password_rejected(self):
        resp = self._signup("12345678901")
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username="newuser").exists())

    def test_password_matching_username_rejected(self):
        resp = self._signup("longusername123", username="longusername123")
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(User.objects.filter(username="longusername123").exists())

    def test_strong_password_accepted(self):
        resp = self._signup("Tr0ub4dor&3-Correct-Horse")
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(User.objects.filter(username="newuser").exists())

    def test_signup_does_not_auto_login_when_verification_mandatory(self):
        """#10 — signup must NOT bypass the mandatory email-verification gate."""
        c = Client()
        resp = c.post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": "pendinguser",
                "email": "pending@x.com",
                "password1": "Tr0ub4dor&3-Correct-Horse",
                "password2": "Tr0ub4dor&3-Correct-Horse",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertTrue(body["verification_required"])
        self.assertNotIn("user", body)
        # No session means no auto-login. /auth/me/ should 401.
        me = c.get("/api/v1/auth/me/")
        self.assertEqual(me.status_code, 401)

    def test_signup_creates_unverified_email_address(self):
        """Allauth EmailAddress is created so the confirm-email flow works."""
        from allauth.account.models import EmailAddress

        Client().post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": "newuser",
                "email": "verify@x.com",
                "password1": "Tr0ub4dor&3-Correct-Horse",
                "password2": "Tr0ub4dor&3-Correct-Horse",
            }),
            content_type="application/json",
        )
        ea = EmailAddress.objects.get(user__username="newuser")
        self.assertEqual(ea.email, "verify@x.com")
        self.assertFalse(ea.verified)
        self.assertTrue(ea.primary)

    def test_duplicate_email_rejected_case_insensitive(self):
        """#9 — attacker can't pre-register the victim's email."""
        User.objects.create_user(
            username="legit", password="pw", email="Victim@Example.COM"
        )
        resp = self._signup("Tr0ub4dor&3", username="attacker", email="victim@example.com")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(User.objects.filter(email__iexact="victim@example.com").count(), 1)
        # Same generic message — no enumeration.
        body = resp.content.lower()
        for leak in (b"already", b"taken", b"exists", b"in use"):
            self.assertNotIn(leak, body)

    def test_db_level_email_unique_index_blocks_direct_inserts(self):
        """Defense-in-depth: even bypassing SignupView, the DB rejects dups."""
        from django.db import IntegrityError, transaction

        User.objects.create_user(username="a", password="pw", email="dup@x.com")
        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                User.objects.create_user(username="b", password="pw", email="DUP@X.COM")

    def test_duplicate_username_error_does_not_leak_existence(self):
        """#7 — error message must not confirm the account exists."""
        User.objects.create_user(username="alice", password="pw", email="alice@x.com")
        resp = self._signup(
            "Tr0ub4dor&3-Correct-Horse",
            username="alice",
            email="other@x.com",
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.content.lower()
        for leak in (b"already", b"taken", b"exists", b"in use"):
            self.assertNotIn(leak, body)


class InviteSessionConsumerTests(TestCase):
    """#11 — authentication resumes, but never auto-accepts, an invite."""

    def setUp(self):
        self.org = Organization.objects.create(name="Org", slug="org")
        self.inviter = User.objects.create_user(
            username="inviter", password="pw", email="inviter@x.com"
        )
        OrganizationMembership.objects.create(
            user=self.inviter, organization=self.org, role=Role.OWNER
        )
        self.invitee_email = "invitee@x.com"
        self.invite = OrganizationInvite.objects.create(
            organization=self.org,
            email=self.invitee_email,
            role=Role.DEVELOPER,
            created_by=self.inviter,
        )

    def test_login_preserves_invite_until_explicit_confirmation(self):
        invitee = User.objects.create_user(
            username="invitee", password="pw_strong_123", email=self.invitee_email
        )
        c = Client()
        # Simulate the InviteAcceptView's anonymous path stashing the token.
        s = c.session
        s["invite_token"] = str(self.invite.token)
        s.save()
        # Login resumes the flow but must not create a membership.
        ok = c.login(username="invitee", password="pw_strong_123")
        self.assertTrue(ok)
        self.assertFalse(
            OrganizationMembership.objects.filter(user=invitee, organization=self.org).exists()
        )
        self.invite.refresh_from_db()
        self.assertIsNone(self.invite.accepted_at)
        self.assertIn("invite_token", c.session)

        response = c.post(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            OrganizationMembership.objects.filter(user=invitee, organization=self.org).exists()
        )
        self.assertNotIn("invite_token", c.session)

    def test_signup_pends_verification_does_not_consume_invite_yet(self):
        """Mandatory email verification means signup does NOT log in, so the
        invite stays in the session until the user actually authenticates."""
        c = Client()
        s = c.session
        s["invite_token"] = str(self.invite.token)
        s.save()
        resp = c.post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": "invitee",
                "email": self.invitee_email,
                "password1": "Tr0ub4dor&3-Correct-Horse",
                "password2": "Tr0ub4dor&3-Correct-Horse",
            }),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.json().get("verification_required"))
        invitee = User.objects.get(username="invitee")
        # Not joined yet — must verify email first.
        self.assertFalse(
            OrganizationMembership.objects.filter(user=invitee, organization=self.org).exists()
        )
        self.invite.refresh_from_db()
        self.assertIsNone(self.invite.accepted_at)
        # Invite token still parked in session for the post-verify login.
        self.assertIn("invite_token", c.session)

    def test_post_verification_login_still_requires_confirmation(self):
        c = Client()
        s = c.session
        s["invite_token"] = str(self.invite.token)
        s.save()
        c.post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": "invitee",
                "email": self.invitee_email,
                "password1": "Tr0ub4dor&3-Correct-Horse",
                "password2": "Tr0ub4dor&3-Correct-Horse",
            }),
            content_type="application/json",
        )
        # Simulate clicking the email confirmation link: flip verified=True
        # and log the user in (which is exactly what allauth does on confirm
        # with ACCOUNT_LOGIN_ON_EMAIL_CONFIRMATION=True).
        from allauth.account.models import EmailAddress
        ea = EmailAddress.objects.get(user__username="invitee")
        ea.verified = True
        ea.save(update_fields=["verified"])
        invitee = User.objects.get(username="invitee")
        invitee.set_password("Tr0ub4dor&3-Correct-Horse")  # ensure usable
        invitee.save()
        self.assertTrue(c.login(username="invitee", password="Tr0ub4dor&3-Correct-Horse"))
        self.assertFalse(
            OrganizationMembership.objects.filter(user=invitee, organization=self.org).exists()
        )
        self.invite.refresh_from_db()
        self.assertIsNone(self.invite.accepted_at)

        response = c.post(f"/api/v1/invites/accept/{self.invite.token}/")
        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            OrganizationMembership.objects.filter(user=invitee, organization=self.org).exists()
        )

    def test_login_with_wrong_email_does_not_join(self):
        wrong = User.objects.create_user(
            username="wrong", password="pw_strong_123", email="someone@else.com"
        )
        c = Client()
        s = c.session
        s["invite_token"] = str(self.invite.token)
        s.save()
        c.login(username="wrong", password="pw_strong_123")
        self.assertFalse(
            OrganizationMembership.objects.filter(user=wrong, organization=self.org).exists()
        )
        self.invite.refresh_from_db()
        self.assertIsNone(self.invite.accepted_at)
        # Token stays in session so a different account on the same browser
        # could still claim it.
        self.assertIn("invite_token", c.session)

    def test_login_with_expired_invite_clears_session(self):
        self.invite.expires_at = timezone.now() - timedelta(hours=1)
        self.invite.save(update_fields=["expires_at"])
        invitee = User.objects.create_user(
            username="invitee", password="pw_strong_123", email=self.invitee_email
        )
        c = Client()
        s = c.session
        s["invite_token"] = str(self.invite.token)
        s.save()
        c.login(username="invitee", password="pw_strong_123")
        self.assertFalse(
            OrganizationMembership.objects.filter(user=invitee, organization=self.org).exists()
        )
        self.assertNotIn("invite_token", c.session)

    def test_login_with_unknown_token_clears_session(self):
        invitee = User.objects.create_user(
            username="invitee", password="pw_strong_123", email=self.invitee_email
        )
        c = Client()
        s = c.session
        s["invite_token"] = "00000000-0000-0000-0000-000000000000"
        s.save()
        c.login(username="invitee", password="pw_strong_123")
        self.assertNotIn("invite_token", c.session)


class AdminOnlyListReadTests(TestCase):
    """Org-admin reads: invite list + api-key list must be 403 for DEVELOPER."""

    def setUp(self):
        self.org = Organization.objects.create(name="Org", slug="org")
        self.owner = User.objects.create_user(username="owner", password="pw", email="o@x.com")
        self.dev = User.objects.create_user(username="dev", password="pw", email="d@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.dev, organization=self.org, role=Role.DEVELOPER)
        OrganizationInvite.objects.create(
            organization=self.org,
            email="secret-pending@x.com",
            role=Role.ADMIN,
            created_by=self.owner,
        )
        ApiKey.objects.create(
            organization=self.org,
            name="prod-deploy",
            key_prefix="bb_oak_live_",
            key_hash=ApiKey.hash_token(ApiKey.generate_token()),
            scopes=[TokenScope.ADMIN_MEMBERS],
            created_by=self.owner,
        )

    def _as(self, user, path):
        c = Client()
        c.force_login(user)
        return c.get(path)

    def test_developer_cannot_list_invites(self):
        resp = self._as(self.dev, "/api/v1/invites/")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"secret-pending@x.com", resp.content)

    def test_owner_can_list_invites(self):
        resp = self._as(self.owner, "/api/v1/invites/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"secret-pending@x.com", resp.content)

    def test_developer_cannot_list_api_keys(self):
        resp = self._as(self.dev, "/api/v1/org/keys/")
        self.assertEqual(resp.status_code, 403)
        self.assertNotIn(b"prod-deploy", resp.content)

    def test_owner_can_list_api_keys(self):
        resp = self._as(self.owner, "/api/v1/org/keys/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"prod-deploy", resp.content)


class SelfServiceKeyDeploymentTests(TestCase):
    """Developers may only deploy keys to servers an admin has marked as
    `allow_self_service=True`. Empty server_ids is rejected for non-admins."""

    def setUp(self):
        self.org = Organization.objects.create(name="Org", slug="org")
        self.owner = User.objects.create_user(username="owner", password="pw", email="o@x.com")
        self.dev = User.objects.create_user(username="dev", password="pw", email="d@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.dev, organization=self.org, role=Role.DEVELOPER)
        self.prod = self._mk("prod-web", allow_self_service=False)
        self.staging = self._mk("staging", allow_self_service=True)

    def _mk(self, name, allow_self_service=False):
        raw = Server.generate_token()
        return Server.objects.create(
            organization=self.org,
            name=name,
            ip_address="10.0.0.1",
            ssh_user="root",
            token_hash=Server.hash_token(raw),
            token_prefix=raw[:12],
            is_active=True,
            allow_self_service=allow_self_service,
        )

    def _post_key(self, user, server_ids, title="t", deploy_to_all=False):
        c = Client()
        c.force_login(user)
        return c.post(
            "/api/v1/public-keys/",
            data=json.dumps({
                "key_title": title,
                "key_payload": "ssh-ed25519 AAAA TEST_KEY tester",
                "server_ids": server_ids,
                "deploy_to_all": deploy_to_all,
            }),
            content_type="application/json",
        )

    def test_dev_with_empty_server_ids_registers_key_without_deployment(self):
        resp = self._post_key(self.dev, server_ids=[])
        self.assertEqual(resp.status_code, 201)
        key = PublicKey.objects.get(user=self.dev)
        self.assertFalse(key.deploy_to_all)
        self.assertEqual(key.servers.count(), 0)

    def test_dev_targeting_non_self_service_rejected(self):
        resp = self._post_key(self.dev, server_ids=[self.prod.id])
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(PublicKey.objects.filter(user=self.dev).count(), 0)

    def test_dev_targeting_self_service_allowed(self):
        resp = self._post_key(self.dev, server_ids=[self.staging.id])
        self.assertEqual(resp.status_code, 201)
        key = PublicKey.objects.get(user=self.dev)
        self.assertEqual(list(key.servers.values_list("id", flat=True)), [self.staging.id])

    def test_dev_mixed_targets_all_or_nothing(self):
        # Even one non-self-service in the list rejects the whole request.
        resp = self._post_key(self.dev, server_ids=[self.staging.id, self.prod.id])
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(PublicKey.objects.filter(user=self.dev).count(), 0)

    def test_admin_can_deploy_to_locked_server(self):
        resp = self._post_key(self.owner, server_ids=[self.prod.id])
        self.assertEqual(resp.status_code, 201)

    def test_admin_with_empty_server_ids_deploys_globally(self):
        # Existing "global" behavior preserved for admins via deploy_to_all=True.
        resp = self._post_key(self.owner, server_ids=[], deploy_to_all=True)
        self.assertEqual(resp.status_code, 201)
        key = PublicKey.objects.get(user=self.owner)
        self.assertEqual(key.servers.count(), 0)
        self.assertTrue(key.deploy_to_all)

    def test_admin_can_toggle_self_service_flag(self):
        c = Client()
        c.force_login(self.owner)
        resp = c.patch(
            f"/api/v1/org/servers/{self.prod.id}/",
            data=json.dumps({"allow_self_service": True}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 200)
        self.prod.refresh_from_db()
        self.assertTrue(self.prod.allow_self_service)

    def test_developer_cannot_toggle_self_service_flag(self):
        c = Client()
        c.force_login(self.dev)
        resp = c.patch(
            f"/api/v1/org/servers/{self.prod.id}/",
            data=json.dumps({"allow_self_service": True}),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 403)
        self.prod.refresh_from_db()
        self.assertFalse(self.prod.allow_self_service)


@override_settings(RATELIMIT_ENABLE=True)
class RateLimitingTests(TestCase):
    """#8 — abuse-prone endpoints must return 429 after their limit."""

    def setUp(self):
        cache.clear()  # ratelimit state is process-wide cache; isolate tests

    def _login(self):
        return Client().post(
            "/api/v1/auth/login/",
            data=json.dumps({"username": "x", "password": "y"}),
            content_type="application/json",
        )

    def _signup(self, username):
        return Client().post(
            "/api/v1/auth/signup/",
            data=json.dumps({
                "username": username,
                "email": f"{username}@x.com",
                "password1": "Tr0ub4dor&3-Correct-Horse",
                "password2": "Tr0ub4dor&3-Correct-Horse",
            }),
            content_type="application/json",
        )

    def test_login_blocks_after_5_per_minute_per_username(self):
        # Per-username throttle (5/m) trips before the per-IP cap (10/m) for a
        # single attacker hammering one account. Distributed stuffing against
        # one user from many IPs is bounded by this same per-username bucket —
        # asserted separately in api/tests_security.py.
        #
        # django-ratelimit uses a fixed window keyed off wall-clock time, so
        # without freezing it these 8 requests can straddle a window boundary
        # and reset the counter mid-test.
        with mock.patch("django_ratelimit.core.time.time", return_value=1_700_000_000.0):
            codes = [self._login().status_code for _ in range(8)]
        self.assertEqual(codes[:5].count(401), 5)
        self.assertEqual(codes[-1], 429)

    def test_signup_blocks_after_5_per_hour(self):
        with mock.patch("django_ratelimit.core.time.time", return_value=1_700_000_000.0):
            codes = [self._signup(f"u{i}").status_code for i in range(7)]
        # 5 successful (200), then the 6th and 7th get 429.
        self.assertEqual(codes[-1], 429)
        self.assertEqual(sum(1 for c in codes if c == 429), 2)

    def test_install_script_blocks_after_10_per_hour(self):
        # Use a known-bad token; we just want to count rate-limit responses.
        c = Client()
        codes = [c.get(f"/api/v1/install/bogus_token_{i}/").status_code for i in range(12)]
        # 10 reach the view (return 404), then 429.
        self.assertEqual(codes[-1], 429)

    def test_sync_blocks_after_10_per_minute_per_token(self):
        # Even invalid tokens count — bucket is keyed off the presented token.
        c = Client()
        codes = []
        for _ in range(12):
            codes.append(c.get(
                "/api/v1/servers/sync",
                HTTP_AUTHORIZATION="Bearer same_bogus",
            ).status_code)
        # First 10 → 401 (invalid token), then 429.
        self.assertEqual(codes[-1], 429)

    def test_sync_per_ip_cap_blocks_token_spraying(self):
        """Spraying many distinct tokens from one IP must hit the per-IP cap
        (60/m). Before the stacked IP limit, each new token got its own
        per-token bucket and an attacker had no global ceiling on guesses.
        Regression test for that bypass."""
        c = Client()
        last = None
        for i in range(70):
            last = c.get(
                "/api/v1/servers/sync",
                HTTP_AUTHORIZATION=f"Bearer guess_{i:04d}",
            ).status_code
        self.assertEqual(last, 429)


# -----------------------------------------------------------------------------
# Findings #12, #13, #14 — production settings hardening
# -----------------------------------------------------------------------------


class ProductionSettingsHardeningTests(TestCase):
    """Boot syncssh/settings.py under simulated production env vars and assert
    that DEBUG-off branches produce a safe configuration."""

    def _load_settings(self, env):
        """Execute settings.py in a fresh namespace with a temporarily-patched
        os.environ. We exec rather than importlib.reload because reload leaks
        attributes between calls (Python keeps attrs absent from the new run).
        """
        import os
        import types
        from pathlib import Path

        settings_path = Path(__file__).resolve().parents[2] / "syncssh" / "settings.py"
        source = settings_path.read_text()

        original = dict(os.environ)
        try:
            for k in env:
                os.environ.pop(k, None)
            for k, v in env.items():
                if v is not None:
                    os.environ[k] = v
            ns = {"__file__": str(settings_path)}
            exec(compile(source, str(settings_path), "exec"), ns)
        finally:
            os.environ.clear()
            os.environ.update(original)

        return types.SimpleNamespace(
            **{k: v for k, v in ns.items() if not k.startswith("__")}
        )

    def test_debug_defaults_to_false_when_env_unset(self):
        mod = self._load_settings({
            "DEBUG": None,
            "SECRET_KEY": "x" * 50,
        })
        self.assertFalse(mod.DEBUG)

    def test_missing_secret_key_in_production_raises(self):
        with self.assertRaises(RuntimeError):
            self._load_settings({"DEBUG": "False", "SECRET_KEY": None})

    def test_insecure_secret_key_in_production_raises(self):
        with self.assertRaises(RuntimeError):
            self._load_settings({
                "DEBUG": "False",
                "SECRET_KEY": "django-insecure-anything",
            })

    def test_production_hardening_applied_when_debug_false(self):
        mod = self._load_settings({
            "DEBUG": "False",
            "SECRET_KEY": "a-strong-production-secret-" + "x" * 30,
        })
        self.assertTrue(mod.SESSION_COOKIE_SECURE)
        self.assertTrue(mod.CSRF_COOKIE_SECURE)
        self.assertTrue(mod.SESSION_COOKIE_HTTPONLY)
        self.assertTrue(mod.SECURE_SSL_REDIRECT)
        self.assertEqual(mod.SECURE_HSTS_SECONDS, 31536000)
        self.assertTrue(mod.SECURE_HSTS_INCLUDE_SUBDOMAINS)
        self.assertTrue(mod.SECURE_HSTS_PRELOAD)
        self.assertEqual(
            mod.SECURE_PROXY_SSL_HEADER,
            ("HTTP_X_FORWARDED_PROTO", "https"),
        )
        self.assertEqual(mod.X_FRAME_OPTIONS, "DENY")
        self.assertTrue(mod.SECURE_CONTENT_TYPE_NOSNIFF)

    def test_debug_mode_skips_https_only_cookies(self):
        mod = self._load_settings({"DEBUG": "True", "SECRET_KEY": None})
        self.assertTrue(mod.DEBUG)
        self.assertFalse(getattr(mod, "SESSION_COOKIE_SECURE", False))
        self.assertFalse(getattr(mod, "SECURE_SSL_REDIRECT", False))


# -----------------------------------------------------------------------------
# Admin visibility & cross-user actions on public keys
# (org-wide listing, duplicate-payload blocking, audit-on-cross-user)
# -----------------------------------------------------------------------------


class AdminPublicKeyVisibilityTests(TestCase):
    """Admin/Owner sees + can act on every public key in the org. Devs only see
    their own. Duplicate payloads in the same org are rejected at create time."""

    PAYLOAD = "ssh-ed25519 AAAA SHARED_KEY user@host"
    PAYLOAD_2 = "ssh-ed25519 AAAA UNIQUE_KEY user@host"

    def setUp(self):
        self.org = Organization.objects.create(name="Visi Org", slug="visi-org")
        self.owner = User.objects.create_user("vowner", password="pw", email="vo@x.com")
        self.dev = User.objects.create_user("vdev", password="pw", email="vd@x.com")
        OrganizationMembership.objects.create(user=self.owner, organization=self.org, role=Role.OWNER)
        OrganizationMembership.objects.create(user=self.dev, organization=self.org, role=Role.DEVELOPER)
        self.dev_key = PublicKey.objects.create(
            user=self.dev, organization=self.org,
            key_title="dev-laptop", key_payload=self.PAYLOAD_2,
        )

    def test_admin_sees_dev_key_in_list(self):
        c = Client()
        c.force_login(self.owner)
        r = c.get("/api/v1/public-keys/")
        self.assertEqual(r.status_code, 200)
        titles = [k["key_title"] for k in r.json()["keys"]]
        self.assertIn("dev-laptop", titles)
        dev_entry = next(k for k in r.json()["keys"] if k["key_title"] == "dev-laptop")
        self.assertEqual(dev_entry["owner_username"], "vdev")
        self.assertFalse(dev_entry["is_own"])

    def test_developer_does_not_see_others_keys(self):
        other = User.objects.create_user("other_dev", password="pw", email="od@x.com")
        OrganizationMembership.objects.create(user=other, organization=self.org, role=Role.DEVELOPER)
        c = Client()
        c.force_login(other)
        r = c.get("/api/v1/public-keys/")
        self.assertEqual(r.status_code, 200)
        # 'other' has no keys, and dev's key must not appear:
        self.assertEqual(len(r.json()["keys"]), 0)

    def test_duplicate_payload_in_same_org_rejected(self):
        from core.models import AuditLog
        AuditLog.objects.filter(action="publickey.duplicate_rejected").delete()
        c = Client()
        c.force_login(self.owner)
        r = c.post(
            "/api/v1/public-keys/",
            data=json.dumps({"key_title": "dup", "key_payload": self.PAYLOAD_2}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 409)
        self.assertIn("vdev", r.json()["error"])
        self.assertEqual(r.json()["existing_owner"], "vdev")
        # The attempt is recorded so admins can spot repeat probes.
        e = AuditLog.objects.filter(action="publickey.duplicate_rejected").first()
        self.assertIsNotNone(e)
        self.assertEqual(e.actor_user, self.owner)
        self.assertEqual(e.metadata.get("existing_owner"), "vdev")
        self.assertEqual(e.metadata.get("attempted_title"), "dup")

    def test_same_payload_allowed_in_different_org(self):
        other_org = Organization.objects.create(name="Other", slug="vis-other")
        u = User.objects.create_user("xuser", password="pw", email="x@x.com")
        OrganizationMembership.objects.create(user=u, organization=other_org, role=Role.OWNER)
        c = Client()
        c.force_login(u)
        r = c.post(
            "/api/v1/public-keys/",
            data=json.dumps({"key_title": "ok", "key_payload": self.PAYLOAD_2}),
            content_type="application/json",
        )
        self.assertEqual(r.status_code, 201)

    def test_admin_can_delete_dev_key_and_audit_records_intent(self):
        from core.models import AuditLog
        AuditLog.objects.filter(action="publickey.deleted_by_admin").delete()
        c = Client()
        c.force_login(self.owner)
        r = c.delete(f"/api/v1/public-keys/{self.dev_key.id}/")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(PublicKey.objects.filter(id=self.dev_key.id).exists())
        e = AuditLog.objects.filter(action="publickey.deleted_by_admin").first()
        self.assertIsNotNone(e)
        self.assertEqual(e.actor_user, self.owner)
        self.assertEqual(e.metadata.get("owner_username"), "vdev")

    def test_dev_cannot_delete_other_users_key(self):
        other = User.objects.create_user("hacker", password="pw", email="h@x.com")
        OrganizationMembership.objects.create(user=other, organization=self.org, role=Role.DEVELOPER)
        c = Client()
        c.force_login(other)
        r = c.delete(f"/api/v1/public-keys/{self.dev_key.id}/")
        self.assertEqual(r.status_code, 403)
        self.assertTrue(PublicKey.objects.filter(id=self.dev_key.id).exists())

    def test_admin_can_toggle_dev_key_and_audit_records_intent(self):
        from core.models import AuditLog
        AuditLog.objects.filter(action="publickey.toggled").delete()
        c = Client()
        c.force_login(self.owner)
        r = c.patch(f"/api/v1/public-keys/{self.dev_key.id}/toggle/")
        self.assertEqual(r.status_code, 200)
        self.dev_key.refresh_from_db()
        self.assertFalse(self.dev_key.is_active)
        e = AuditLog.objects.filter(action="publickey.toggled").first()
        self.assertIsNotNone(e)
        self.assertEqual(e.metadata.get("new_state"), "inactive")
        self.assertTrue(e.metadata.get("by_admin"))

    def test_self_toggle_logs_toggled_without_admin_flag(self):
        from core.models import AuditLog
        AuditLog.objects.filter(action="publickey.toggled").delete()
        c = Client()
        c.force_login(self.dev)
        r = c.patch(f"/api/v1/public-keys/{self.dev_key.id}/toggle/")
        self.assertEqual(r.status_code, 200)
        e = AuditLog.objects.filter(action="publickey.toggled").first()
        self.assertIsNotNone(e)
        self.assertFalse(e.metadata.get("by_admin"))

    def test_dev_cannot_toggle_other_users_key(self):
        other = User.objects.create_user("hacker2", password="pw", email="h2@x.com")
        OrganizationMembership.objects.create(user=other, organization=self.org, role=Role.DEVELOPER)
        c = Client()
        c.force_login(other)
        r = c.patch(f"/api/v1/public-keys/{self.dev_key.id}/toggle/")
        self.assertEqual(r.status_code, 404)  # filtered out; equivalent to "not found"
        self.dev_key.refresh_from_db()
        self.assertTrue(self.dev_key.is_active)
