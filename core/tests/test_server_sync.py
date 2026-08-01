from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model

from api.views import ServerSyncView
from core.models import PublicKey, Server
from organizations.models import Organization, OrganizationMembership, Role

User = get_user_model()


class ServerSyncViewTests(TestCase):
    def setUp(self):
        self.factory = RequestFactory()
        self.view = ServerSyncView.as_view()

        self.user = User.objects.create_user(username="testuser", password="pass")
        self.org = Organization.objects.create(name="Test Org", slug="test-org")
        OrganizationMembership.objects.create(
            user=self.user, organization=self.org, role=Role.DEVELOPER
        )
        self.server_token = "valid-token-abc"
        self.server = Server.objects.create(
            organization=self.org,
            name="server-1",
            ip_address="10.0.0.1",
            ssh_user="root",
            token_hash=Server.hash_token(self.server_token),
            token_prefix=self.server_token[:12],
            is_active=True,
        )
        self.other_server_token = "other-token-xyz"
        self.other_server = Server.objects.create(
            organization=self.org,
            name="server-2",
            ip_address="10.0.0.2",
            ssh_user="root",
            token_hash=Server.hash_token(self.other_server_token),
            token_prefix=self.other_server_token[:12],
            is_active=True,
        )

    def _make_key(self, payload, is_active=True, org=None, deploy_to_all=True):
        return PublicKey.objects.create(
            user=self.user,
            organization=org or self.org,
            key_payload=payload,
            key_title="test key",
            is_active=is_active,
            deploy_to_all=deploy_to_all,
        )

    def _request(self, token):
        return self.factory.get(
            "/api/v1/servers/sync",
            HTTP_AUTHORIZATION=f"Bearer {token}",
        )

    # -------------------------------------------------------------------------
    # Auth / token validation
    # -------------------------------------------------------------------------

    def test_missing_token_returns_400(self):
        request = self.factory.get("/api/v1/servers/sync")
        response = self.view(request)
        self.assertEqual(response.status_code, 400)

    def test_invalid_token_returns_401(self):
        request = self._request("bogus")
        response = self.view(request)
        self.assertEqual(response.status_code, 401)

    def test_inactive_server_token_returns_401(self):
        self.server.is_active = False
        self.server.save()
        request = self._request(self.server_token)
        response = self.view(request)
        self.assertEqual(response.status_code, 401)

    # -------------------------------------------------------------------------
    # No authorized keys
    # -------------------------------------------------------------------------

    def test_no_keys_returns_empty_body(self):
        request = self._request(self.server_token)
        response = self.view(request)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"")

    # -------------------------------------------------------------------------
    # Global keys (no explicit server restriction)
    # -------------------------------------------------------------------------

    def test_global_key_returned_for_any_server_in_org(self):
        """Key with no servers M2M → deploys to ALL servers in the org."""
        self._make_key("ssh-ed25519 GLOBAL_KEY")
        for token in [self.server_token, self.other_server_token]:
            request = self._request(token)
            response = self.view(request)
            self.assertIn(b"GLOBAL_KEY", response.content)

    def test_inactive_key_not_returned(self):
        self._make_key("ssh-ed25519 INACTIVE_KEY", is_active=False)
        request = self._request(self.server_token)
        response = self.view(request)
        self.assertNotIn(b"INACTIVE_KEY", response.content)

    def test_key_from_different_org_not_returned(self):
        other_org = Organization.objects.create(name="Other Org", slug="other-org")
        self._make_key("ssh-ed25519 OTHER_ORG_KEY", org=other_org)
        request = self._request(self.server_token)
        response = self.view(request)
        self.assertNotIn(b"OTHER_ORG_KEY", response.content)

    # -------------------------------------------------------------------------
    # Server-scoped keys
    # -------------------------------------------------------------------------

    def test_server_scoped_key_returned_only_for_assigned_server(self):
        """Key with explicit server list → only that server gets it."""
        key = self._make_key("ssh-ed25519 SCOPED_KEY", deploy_to_all=False)
        key.servers.add(self.server)

        request = self._request(self.server_token)
        self.assertIn(b"SCOPED_KEY", self.view(request).content)

        request2 = self._request(self.other_server_token)
        self.assertNotIn(b"SCOPED_KEY", self.view(request2).content)

    def test_multiple_scoped_servers(self):
        """Key assigned to both servers should appear for both."""
        key = self._make_key("ssh-ed25519 MULTI_SCOPED_KEY", deploy_to_all=False)
        key.servers.add(self.server, self.other_server)
        for token in [self.server_token, self.other_server_token]:
            request = self._request(token)
            self.assertIn(b"MULTI_SCOPED_KEY", self.view(request).content)

    # -------------------------------------------------------------------------
    # Response format
    # -------------------------------------------------------------------------

    def test_multiple_keys_newline_separated(self):
        for i in range(3):
            self._make_key(f"ssh-ed25519 KEY_{i}")
        request = self._request(self.server_token)
        lines = self.view(request).content.decode().strip().split("\n")
        self.assertEqual(len(lines), 3)

    def test_content_type_is_text_plain(self):
        request = self._request(self.server_token)
        self.assertEqual(self.view(request)["Content-Type"], "text/plain")

    def test_no_duplicate_keys(self):
        """A key matching both Q conditions shouldn't appear twice (distinct())."""
        key = self._make_key("ssh-ed25519 DEDUP_KEY", deploy_to_all=False)
        key.servers.add(self.server)
        request = self._request(self.server_token)
        lines = [l for l in self.view(request).content.decode().split("\n") if "DEDUP_KEY" in l]
        self.assertEqual(len(lines), 1)
