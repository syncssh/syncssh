import os
import shlex
from typing import Optional
from urllib.parse import quote

from django.conf import settings
from django.db.models import Q
from django.http import HttpResponse, HttpResponseForbidden, HttpResponseBadRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from django_ratelimit.decorators import ratelimit

from core.models import PublicKey, Server
from organizations.models import OrganizationInvite, OrganizationMembership, ApiKey, TokenScope
from syncssh import audit


def _extract_server_token(request) -> Optional[str]:
    """Extract a server token from the Authorization header."""
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        candidate = auth[7:].strip()
        if candidate:
            return candidate
    return None


def _sync_ratelimit_key(group, request) -> str:
    """Rate-limit by the presented token, falling back to IP if absent.

    Legit traffic is ~1 req/min per server, so any single token blowing past
    10/min is either misconfigured cron or abuse.
    """
    return _extract_server_token(request) or (request.META.get("REMOTE_ADDR") or "anon")


# Two stacked limits:
#   - per-token (10/m): catches misconfigured cron on one server.
#   - per-IP (60/m):  catches token spraying — without this, every guessed
#                     token gets its own fresh bucket and the per-token cap is
#                     effectively useless against brute force.
@method_decorator(ratelimit(key="ip", rate="60/m", method="GET", block=True), name="get")
@method_decorator(ratelimit(key=_sync_ratelimit_key, rate="10/m", method="GET", block=True), name="get")
class ServerSyncView(View):
    """
    GET /api/v1/servers/sync

    Auth: `Authorization: Bearer <server_token>`.
    Returns newline-separated public keys authorized for that server.

    Token is hashed and looked up by hash — raw never stored.
    Falls into two cases for each key:
      1. servers M2M is empty  -> key deploys to ALL servers in the org
      2. servers contains this  -> key deploys only to listed servers
    """

    def get(self, request):
        token = _extract_server_token(request)
        if not token:
            return HttpResponse(status=400, content="server token required in Bearer header")

        try:
            server = Server.objects.select_related("organization").get(
                token_hash=Server.hash_token(token),
                is_active=True,
            )
        except Server.DoesNotExist:
            audit.log("server.sync_invalid_token", actor_kind="server")
            return HttpResponse(status=401, content="Invalid or inactive server token")

        # An inactive organization is a tenant-level kill switch. Return a
        # successful *empty* sync rather than 401 so the installed worker
        # removes its managed authorized_keys block; its fail-safe behavior
        # intentionally preserves existing keys after failed fetches.
        if not server.organization.is_active:
            return HttpResponse("", content_type="text/plain")

        keys = PublicKey.objects.filter(
            organization=server.organization,
            is_active=True,
            # Owner must still be a member of this org — revoke on removal.
            user__memberships__organization=server.organization,
        ).filter(
            # deploy_to_all=True: key deploys to ALL active org servers
            # deploy_to_all=False: key deploys only to servers in its M2M list
            Q(deploy_to_all=True) | Q(servers=server)
        ).values_list("key_payload", flat=True).distinct()

        keys_list = list(keys)
        # Stamp the heartbeat. update_fields avoids touching other columns
        # (cheap, and won't race with admin-side edits to the same row).
        from django.utils import timezone
        server.last_synced_at = timezone.now()
        server.save(update_fields=["last_synced_at"])
        audit.log(
            "server.sync_pulled",
            target=server,
            organization=server.organization,
            actor_kind="server",
            key_count=len(keys_list),
        )
        return HttpResponse("\n".join(keys_list), content_type="text/plain")


@method_decorator(ratelimit(key="ip", rate="10/h", method="GET", block=True), name="get")
class InstallScriptView(View):
    """
    GET /install/<token>

    Returns a bash installer script that self-writes the worker
    with the real sync URL embedded directly.
    """

    @staticmethod
    def _bash_error(msg: str) -> str:
        """Render an error so `curl ... | bash` prints a clear message and exits 1
        instead of trying to execute the prose as commands."""
        safe = msg.replace("'", "'\\''")
        return f"#!/bin/bash\necho 'syncssh-install: {safe}' >&2\nexit 1\n"

    SCRIPT_TEMPLATE = """#!/bin/bash
# === SYNCSSH BEGIN ===
set -e

SSH_USER={ssh_user}
INSTALL_DIR="$HOME/.syncssh"
CONFIG_FILE="$INSTALL_DIR/sync-ssh.sh"

# Determine target user's home directory
TARGET_HOME=$(getent passwd "$SSH_USER" | cut -d: -f6)

mkdir -p "$TARGET_HOME/.syncssh"
mkdir -p "$TARGET_HOME/.ssh"
chmod 700 "$TARGET_HOME/.ssh"
chown "$SSH_USER:$SSH_USER" "$TARGET_HOME/.syncssh"
chown "$SSH_USER:$SSH_USER" "$TARGET_HOME/.ssh"

cat > "$CONFIG_FILE" << 'ENDWORKER'
#!/bin/bash
# Spread fleet syncs across the cron minute so servers don't all hit the
# control plane at the same instant; the install-time run skips the wait.
[ "$1" = "--now" ] || sleep $((RANDOM % 30))
# Bail out before touching authorized_keys if the fetch fails: a transient
# outage must not strip the managed keys until the next successful sync.
KEYS=$(curl -sf {curl_hardening}-H {authorization_header} {sync_url}) || exit 0
# Keep only lines that look like public keys, so a proxy error page or captive
# portal can never land arbitrary content in authorized_keys.
KEYS=$(printf '%s\\n' "$KEYS" | grep -E '^(ssh-|ecdsa-|sk-)' || true)
# Rebuild the file aside and swap it in with mv, so sshd never reads a
# half-written authorized_keys or one with the managed block missing.
TMP=$(mktemp "$HOME/.ssh/.authorized_keys.syncssh.XXXXXX") || exit 0
sed '/^# === SYNCSSH BEGIN ===$/,/^# === SYNCSSH END ===$/d' "$HOME/.ssh/authorized_keys" 2>/dev/null > "$TMP"
if [ -n "$KEYS" ]; then
    echo -e "# === SYNCSSH BEGIN ===\\n$KEYS\\n# === SYNCSSH END ===" >> "$TMP"
fi
chmod 600 "$TMP"
mv "$TMP" "$HOME/.ssh/authorized_keys"
ENDWORKER

chmod 700 "$CONFIG_FILE"
chown "$SSH_USER:$SSH_USER" "$CONFIG_FILE"

# Install cron as target user — || true guards against set -e killing the subshell when no crontab exists yet
(crontab -u "$SSH_USER" -l 2>/dev/null || true) | grep -v "syncssh" | crontab -u "$SSH_USER" - || true
((crontab -u "$SSH_USER" -l 2>/dev/null || true); echo "* * * * * $CONFIG_FILE") | crontab -u "$SSH_USER" -

echo "syncssh agent installed. Running initial sync..."
bash "$CONFIG_FILE" --now
echo "Done."
# === SYNCSSH END ===
"""

    def get(self, request, token):
        try:
            server = Server.objects.select_related("organization").get(
                token_hash=Server.hash_token(token),
                is_active=True,
                organization__is_active=True,
            )
        except Server.DoesNotExist:
            # Log failures so brute-force probing surfaces in the audit feed.
            audit.log("server.install_script_invalid_token", actor_kind="server")
            return HttpResponse(
                status=404,
                content=self._bash_error("Invalid or inactive server token."),
                content_type="text/plain",
            )

        # One-shot: the install URL embeds the bearer token in plaintext, so a
        # leaked URL (Referer, browser history, log scrapers) must not be
        # replayable. Rotate the server to re-arm.
        if server.install_fetched_at is not None:
            audit.log(
                "server.install_script_replay_blocked",
                target=server,
                organization=server.organization,
                actor_kind="server",
            )
            return HttpResponse(
                status=410,
                content=self._bash_error(
                    "Install URL already used. Rotate the server token to re-install."
                ),
                content_type="text/plain",
            )

        from django.utils import timezone
        server.install_fetched_at = timezone.now()
        server.save(update_fields=["install_fetched_at"])

        audit.log(
            "server.install_script_fetched",
            target=server,
            organization=server.organization,
            actor_kind="server",
        )
        # Agent-facing URL: this is baked into the install script and resolved
        # by the *target server*, not a browser. When the target lives on the
        # same docker network as the backend it must use the compose hostname
        # (backend:8000), which a browser can't resolve — hence a dedicated var
        # that falls back to APP_BASE_URL for the common single-host case.
        base = (
            os.environ.get('SYNC_BASE_URL')
            or os.environ.get('APP_BASE_URL', 'http://localhost:8000')
        )
        # Bare URL — token travels in Authorization header from the worker.
        sync_url = f"{base}/api/v1/servers/sync"
        # Pin the worker to TLS when the deployment is https, so a later
        # redirect or misconfiguration can't silently downgrade the key fetch
        # to plaintext. Left off for http dev/compose-internal deployments.
        curl_hardening = (
            "--proto '=https' --tlsv1.2 " if sync_url.startswith("https://") else ""
        )
        script = self.SCRIPT_TEMPLATE.format(
            # All values interpolated into the shell script are quoted here as
            # a second line of defence. This protects scripts generated for
            # records inserted through Django admin or direct ORM use, even if
            # they bypass the API's strict ssh_user validation.
            sync_url=shlex.quote(sync_url),
            ssh_user=shlex.quote(server.ssh_user),
            authorization_header=shlex.quote(f"Authorization: Bearer {token}"),
            curl_hardening=curl_hardening,
        )
        return HttpResponse(script, content_type="text/plain")


@method_decorator(ratelimit(key="ip", rate="20/m", method="GET", block=True), name="get")
@method_decorator(ratelimit(key="ip", rate="20/m", method="POST", block=True), name="post")
class InviteAcceptView(View):
    """
    GET  /api/v1/invites/accept/<token>  — render a confirm page (read-only).
    POST /api/v1/invites/accept/<token>  — actually join (CSRF-protected).

    Split because the previous GET auto-joined: a hostile site could embed
    `<img src=".../accept/<token>/">` and silently absorb any logged-in user
    whose email matched. Now joining requires an explicit POST with CSRF,
    which `<img>`/cross-origin forms cannot forge.
    """

    def get(self, request, token):
        invite = get_object_or_404(OrganizationInvite, token=token)

        if not invite.organization.is_active:
            return HttpResponseForbidden("Organization is inactive")

        if invite.is_expired() or invite.is_accepted():
            if request.user.is_authenticated:
                return HttpResponseRedirect("/")
            return HttpResponseForbidden("Invite is expired or already accepted")

        if not request.user.is_authenticated:
            # Stash + bounce to login; no DB mutation, so still safe on GET.
            request.session["invite_token"] = str(token)
            return HttpResponseRedirect("/accounts/login/?next=" + request.path)

        if request.user.email.lower() != invite.email.lower():
            return HttpResponseForbidden(
                "This invite was sent to a different email address"
            )

        # This is intentionally server-rendered: a visitor may be anonymous
        # when entering the flow, so the SPA cannot safely own the CSRF form.
        return render(request, "invites/accept.html", {"invite": invite})

    def post(self, request, token):
        if not request.user.is_authenticated:
            return HttpResponseForbidden("Login required")
        invite = get_object_or_404(OrganizationInvite, token=token)
        if not invite.organization.is_active:
            return HttpResponseForbidden("Organization is inactive")
        if invite.is_expired() or invite.is_accepted():
            return HttpResponseForbidden("Invite is expired or already accepted")
        if request.user.email.lower() != invite.email.lower():
            return HttpResponseForbidden(
                "This invite was sent to a different email address"
            )
        return self._join_organization(request, invite)

    def _join_organization(self, request, invite):
        user = request.user
        OrganizationMembership.objects.get_or_create(
            user=user,
            organization=invite.organization,
            defaults={"role": invite.role},
        )
        from django.utils import timezone
        invite.accepted_at = timezone.now()
        invite.accepted_by = user
        invite.save(update_fields=["accepted_at", "accepted_by"])
        request.session.pop("invite_token", None)
        # Keys are scoped to organizations. Copy the user's active keys from
        # their owned workspace so the inviting owner can see them, but never
        # grant SSH access as a side effect of accepting an invite: copied keys
        # have no server assignments and explicitly do not deploy everywhere.
        copied_key_count = 0
        seen_payloads = set()
        personal_keys = PublicKey.objects.filter(
            user=user,
            is_active=True,
            organization__memberships__user=user,
            organization__memberships__role="OWNER",
        ).order_by("created_at")
        for key in personal_keys:
            if key.key_payload in seen_payloads:
                continue
            seen_payloads.add(key.key_payload)
            if PublicKey.objects.filter(
                organization=invite.organization,
                key_payload=key.key_payload,
            ).exists():
                continue
            PublicKey.objects.create(
                user=user,
                organization=invite.organization,
                key_title=key.key_title,
                key_payload=key.key_payload,
                is_active=True,
                deploy_to_all=False,
            )
            copied_key_count += 1
        # Explicit event: the generic post_save on the invite only yields a vague
        # "organizationinvite.updated", which doesn't read as "someone joined".
        # Pin the org + actor so it lands in the inviting org's log as the user.
        audit.log(
            "invite.accepted",
            target=invite,
            organization=invite.organization,
            actor=user,
            invited_email=invite.email,
            role=invite.role,
            copied_key_count=copied_key_count,
        )
        frontend_url = settings.FRONTEND_BASE_URL.rstrip("/")
        # Joining a foreign organization never moves an existing owner away
        # from their own workspace. Invite-only users naturally land in their
        # sole membership via get_user_org's fallback.
        return HttpResponseRedirect(
            f"{frontend_url}/?invite=accepted&organization={quote(invite.organization.name)}"
        )


def validate_api_key(request) -> Optional[ApiKey]:
    """Extract and validate an API key from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[7:]
    if not token:
        return None
    prefix = "bb_oak_live_"
    if not token.startswith(prefix):
        return None
    candidates = ApiKey.objects.filter(
        key_prefix=prefix,
        is_active=True,
        organization__is_active=True,
    ).select_related("organization")
    token_hash = ApiKey.hash_token(token)
    for key in candidates:
        if key.key_hash == token_hash and not key.is_expired():
            key.mark_used()
            return key
    return None


def check_scope(api_key: ApiKey, scope: str) -> Optional[HttpResponseForbidden]:
    """Return a 403 response if the key lacks the scope, else None."""
    if scope not in api_key.scopes:
        return HttpResponseForbidden(f"This key lacks the '{scope}' scope")
    return None


_VALID_SCOPES = set(TokenScope.values)


def _parse_scopes_header(raw: str) -> Optional[list]:
    """Parse and validate X-Key-Scopes against the TokenScope enum."""
    if not raw:
        return None
    requested = [s.strip() for s in raw.split(",") if s.strip()]
    if not requested:
        return None
    if any(s not in _VALID_SCOPES for s in requested):
        return None
    return requested


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="ip", rate="30/m", method="POST", block=True), name="post")
class ApiKeyCreateView(View):
    """
    POST /api/v1/keys/

    Mint a new API key. Caller authenticates with an existing key that holds
    `admin_members`. The new key's scopes must be a subset of the caller's —
    no privilege escalation. Returns raw token ONCE.

    CSRF-exempt because the caller is a machine with a bearer token, not a
    browser with a session cookie.
    """

    def post(self, request):
        key = validate_api_key(request)
        if not key:
            return HttpResponse(status=401, content="Invalid API key")
        if (resp := check_scope(key, TokenScope.ADMIN_MEMBERS)):
            return resp

        name = (request.headers.get("X-Key-Name") or "Unnamed Key").strip()[:255]
        requested_scopes = _parse_scopes_header(
            request.headers.get("X-Key-Scopes", "")
        ) or ["read_servers"]

        # Privilege ceiling: new key cannot exceed the caller's scopes.
        caller_scopes = set(key.scopes or [])
        excess = set(requested_scopes) - caller_scopes
        if excess:
            return HttpResponseForbidden(
                f"Requested scopes exceed caller's permissions: {sorted(excess)}"
            )

        # Validate every requested scope against the enum (defence in depth —
        # _parse_scopes_header already rejected unknowns).
        if any(s not in _VALID_SCOPES for s in requested_scopes):
            return HttpResponseBadRequest("Invalid scope value")

        raw_token = ApiKey.generate_token()
        new_key = ApiKey.objects.create(
            organization=key.organization,
            name=name,
            key_prefix="bb_oak_live_",
            key_hash=ApiKey.hash_token(raw_token),
            scopes=requested_scopes,
            # `request.user` is AnonymousUser on a pure-bearer call; chain to
            # the human who minted the calling key, fall back to NULL.
            created_by=key.created_by,
        )
        return JsonResponse({
            "id": new_key.id,
            "name": new_key.name,
            "token": raw_token,
            "scopes": new_key.scopes,
            "warning": "This is the only time this token will be shown. Store it securely.",
        })


@method_decorator(csrf_exempt, name="dispatch")
@method_decorator(ratelimit(key="ip", rate="30/m", method="POST", block=True), name="post")
class ApiKeyRotateView(View):
    """
    POST /api/v1/org/keys/<id>/rotate/

    Rotate an existing API key — issues a new token, invalidates old one.
    Bearer-auth only; CSRF-exempt for the same reason as ApiKeyCreateView.
    """

    def post(self, request, key_id):
        key = validate_api_key(request)
        if not key:
            return HttpResponse(status=401, content="Invalid API key")
        if (resp := check_scope(key, TokenScope.ADMIN_MEMBERS)):
            return resp

        target = get_object_or_404(ApiKey, id=key_id, organization=key.organization)
        new_token = target.rotate()
        return JsonResponse({
            "id": target.id,
            "name": target.name,
            "token": new_token,
            "warning": "This is the only time this token will be shown. Store it securely.",
        })
