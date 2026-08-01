import json
import os
import re
from django.utils import timezone
from django.db.models import Q
from django.http import JsonResponse
from django.views import View
from django.core.exceptions import PermissionDenied
from organizations.models import Organization, OrganizationMembership, ApiKey, OrganizationInvite, Role, TokenScope
from core.models import Server, PublicKey
from organizations.emails import send_org_invite
from syncssh import audit
from syncssh.editions import feature_enabled


# Server values are embedded in an administrator-run Bash installer. Keep the
# accepted value to ordinary POSIX/Linux account names rather than trying to
# blacklist shell metacharacters.
_SSH_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def _valid_ssh_username(value) -> bool:
    return isinstance(value, str) and bool(_SSH_USERNAME_RE.fullmatch(value))


def require_session_auth(view_func):
    """Decorator: require authenticated session."""
    def wrapper(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        return view_func(self, request, *args, **kwargs)
    return wrapper


def get_user_org(request):
    """Return the membership for the user's *active* org, or None.

    Resolution order:
      1. `request.session['active_org_id']` if it points at a real membership.
      2. Oldest workspace the user owns. Their own workspace is the safe,
         unsurprising default after they accept an external invitation.
      3. Oldest remaining membership (for users who only belong by invite).
    """
    if not request.user.is_authenticated:
        return None
    memberships = OrganizationMembership.objects.filter(
        user=request.user,
        organization__is_active=True,
    ).select_related("organization").order_by("created_at")

    active_id = request.session.get("active_org_id")
    if active_id:
        for m in memberships:
            if m.organization_id == active_id:
                return m
        # Stale session pointer (org left/deleted) — drop it and fall through.
        request.session.pop("active_org_id", None)

    return memberships.filter(role=Role.OWNER).first() or memberships.first()


def require_role(membership, *roles):
    """Raise PermissionDenied if membership doesn't have one of the required roles."""
    if not membership or membership.role not in roles:
        raise PermissionDenied("Insufficient permissions")


def _visible_memberships(membership):
    """Return the roster the active member is allowed to see.

    A member accepted through an invite only needs to identify themself, the
    workspace owner(s), and the person who invited them.  Do not expose the
    rest of the workspace directory to that member.  Owners still receive the
    complete roster because they manage membership from the dashboard.
    """
    org = membership.organization
    members = OrganizationMembership.objects.filter(organization=org)
    if membership.role == Role.OWNER:
        return members

    inviter_ids = OrganizationInvite.objects.filter(
        organization=org,
        accepted_by=membership.user,
    ).exclude(created_by__isnull=True).values_list("created_by_id", flat=True)

    # A normal (non-invite) membership keeps the existing roster behavior.
    # This also supports older memberships created before accepted_by existed.
    if not inviter_ids.exists():
        return members

    return members.filter(
        Q(user=membership.user)
        | Q(role=Role.OWNER)
        | Q(user_id__in=inviter_ids)
    )


class OrgView(View):
    """GET /api/v1/org/ — org details + members + your role
       PATCH /api/v1/org/ — rename the org (owner/admin)"""

    @require_session_auth
    def get(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)
        org = membership.organization
        # Member emails are a phishing contact list — only OWNER/ADMIN need the
        # full roster. Non-admins get usernames/roles but no email addresses.
        is_admin = membership.role in [Role.OWNER, Role.ADMIN]
        visible_keys = PublicKey.objects.filter(organization=org, is_active=True)
        if not is_admin:
            visible_keys = visible_keys.filter(user=request.user)
        members = []
        for m in _visible_memberships(membership).select_related("user"):
            entry = {
                "id": m.user.id,
                "username": m.user.username,
                "role": m.role,
                "joined_at": m.created_at.isoformat(),
            }
            if is_admin:
                entry["email"] = m.user.email
            members.append(entry)
        return JsonResponse({
            "org": {
                "id": org.id,
                "name": org.name,
                "slug": org.slug,
                "invite_email_theme": org.invite_email_theme,
            },
            "your_role": membership.role,
            "members": members,
            "server_count": Server.objects.filter(organization=org, is_active=True).count(),
            "key_count": visible_keys.count(),
        })

    @require_session_auth
    def patch(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)
        if membership.role not in (Role.OWNER, Role.ADMIN):
            return JsonResponse({"error": "Insufficient permissions"}, status=403)
        try:
            data = json.loads(request.body)
        except (ValueError, TypeError):
            return JsonResponse({"error": "Invalid JSON body"}, status=400)

        org = membership.organization
        if "name" in data:
            name = (data.get("name") or "").strip()
            if not name or len(name) > 255:
                return JsonResponse({"error": "A workspace name is required (max 255 characters)."}, status=400)
            old_name = org.name
            if name != old_name:
                org.name = name
                org.save(update_fields=["name"])
                audit.log("org.renamed", organization=org, old_name=old_name, new_name=name)

        if "invite_email_theme" in data and feature_enabled("invite_email_theming"):
            theme = data.get("invite_email_theme")
            if theme not in ("light", "dark"):
                return JsonResponse({"error": "invite_email_theme must be 'light' or 'dark'"}, status=400)
            if theme != org.invite_email_theme:
                org.invite_email_theme = theme
                org.save(update_fields=["invite_email_theme"])
                audit.log("org.invite_email_theme_changed", organization=org, theme=theme)

        return JsonResponse({"org": {
            "id": org.id,
            "name": org.name,
            "slug": org.slug,
            "invite_email_theme": org.invite_email_theme,
        }})


def _remove_membership(request, membership, *, action):
    """Revoke one user's access and every key they own in this workspace."""
    organization = membership.organization
    member = membership.user
    public_key_count = PublicKey.objects.filter(
        organization=organization, user=member
    ).count()
    # Keys must go first: server sync also checks membership, but deleting the
    # key records makes revocation immediate and prevents stale assignments.
    PublicKey.objects.filter(organization=organization, user=member).delete()
    audit.log(
        action,
        target=membership,
        organization=organization,
        actor=request.user,
        member_username=member.username,
        removed_public_key_count=public_key_count,
    )
    membership.delete()
    if request.session.get("active_org_id") == organization.id:
        request.session.pop("active_org_id", None)


class OrganizationMemberView(View):
    """DELETE /api/v1/org/members/<user_id>/ — revoke another member."""

    @require_session_auth
    def delete(self, request, user_id):
        actor_membership = get_user_org(request)
        if not actor_membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if actor_membership.role not in (Role.OWNER, Role.ADMIN):
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        if user_id == request.user.id:
            return JsonResponse({"error": "Use the leave workspace action for yourself."}, status=400)

        membership = OrganizationMembership.objects.filter(
            organization=actor_membership.organization, user_id=user_id
        ).select_related("user", "organization").first()
        if not membership:
            return JsonResponse({"error": "Member not found"}, status=404)
        # Only owners can revoke elevated roles. This prevents an admin from
        # taking over a workspace by removing its owners or peer admins.
        if actor_membership.role != Role.OWNER and membership.role != Role.DEVELOPER:
            return JsonResponse({"error": "Only an owner can remove this member."}, status=403)
        _remove_membership(request, membership, action="membership.removed")
        return JsonResponse({"ok": True})


class OrganizationLeaveView(View):
    """POST /api/v1/org/leave/ — leave the active workspace."""

    @require_session_auth
    def post(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role == Role.OWNER:
            return JsonResponse(
                {"error": "Workspace owners cannot leave. Remove members instead."},
                status=403,
            )
        _remove_membership(request, membership, action="membership.left")
        return JsonResponse({"ok": True})


class OrganizationMembershipListView(View):
    """List only the caller's memberships — never another org's roster."""

    @require_session_auth
    def get(self, request):
        memberships = OrganizationMembership.objects.filter(
            user=request.user,
            organization__is_active=True,
        ).select_related("organization").order_by("created_at")
        return JsonResponse({
            "memberships": [
                {
                    "organization": {
                        "id": membership.organization_id,
                        "name": membership.organization.name,
                    },
                    "role": membership.role,
                    "joined_at": membership.created_at.isoformat(),
                    "is_personal": membership.role == Role.OWNER,
                }
                for membership in memberships
            ]
        })


class OrganizationMembershipLeaveView(View):
    """Leave one named membership without changing the current workspace."""

    @require_session_auth
    def post(self, request, organization_id):
        membership = OrganizationMembership.objects.filter(
            user=request.user,
            organization_id=organization_id,
            organization__is_active=True,
        ).select_related("user", "organization").first()
        if not membership:
            return JsonResponse({"error": "Membership not found"}, status=404)
        if membership.role == Role.OWNER:
            return JsonResponse(
                {"error": "Workspace owners cannot leave. Remove members instead."},
                status=403,
            )
        _remove_membership(request, membership, action="membership.left")
        return JsonResponse({"ok": True})

class ServerListView(View):
    """GET /api/v1/org/servers/ — list servers
       POST /api/v1/org/servers/ — create server"""

    @require_session_auth
    def get(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)
        org = membership.organization
        # The (ip_address, ssh_user) pair is the full SSH target tuple — recon
        # gold if a low-privilege account is compromised. Self-service deploy
        # only needs id + name, so non-admins get the redacted entry. Token
        # prefix is likewise OWNER/ADMIN only.
        is_admin = membership.role in [Role.OWNER, Role.ADMIN]
        servers = []
        for s in Server.objects.filter(organization=org):
            entry = {
                "id": s.id,
                "name": s.name,
                "is_active": s.is_active,
                "allow_self_service": s.allow_self_service,
                "last_synced_at": s.last_synced_at.isoformat() if s.last_synced_at else None,
            }
            if is_admin:
                entry["ip_address"] = s.ip_address
                entry["ssh_user"] = s.ssh_user
                entry["token_prefix"] = s.token_prefix
            servers.append(entry)
        # Echo the server's clock so the client can render sync-age relative to
        # OUR time, not the viewer's device clock (which may be skewed and would
        # otherwise make fresh servers look "stale").
        return JsonResponse({"servers": servers, "now": timezone.now().isoformat()})

    @require_session_auth
    def post(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        ssh_user = data.get("ssh_user", "")
        if not _valid_ssh_username(ssh_user):
            return JsonResponse(
                {
                    "error": (
                        "ssh_user must be a valid Unix account name "
                        "(lowercase letters, digits, underscores, or hyphens)."
                    )
                },
                status=400,
            )

        raw_token = Server.generate_token()
        server = Server.objects.create(
            organization=membership.organization,
            name=data.get("name", ""),
            ip_address=data.get("ip_address", ""),
            ssh_user=ssh_user,
            token_hash=Server.hash_token(raw_token),
            token_prefix=raw_token[:12],
            is_active=True,
        )
        return JsonResponse({
            "id": server.id,
            "name": server.name,
            "ip_address": server.ip_address,
            "ssh_user": server.ssh_user,
            "token": raw_token,
            "token_prefix": server.token_prefix,
            "is_active": server.is_active,
            "warning": "This is the only time the full token will be shown. Store it securely or rotate to issue a new one.",
        }, status=201)


class ServerDetailView(View):
    """DELETE /api/v1/org/servers/<id>/ — remove server.
    PATCH  /api/v1/org/servers/<id>/ — admin toggles allow_self_service."""

    @require_session_auth
    def delete(self, request, server_id):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        server = Server.objects.filter(id=server_id, organization=membership.organization).first()
        if not server:
            return JsonResponse({"error": "Server not found"}, status=404)
        server.delete()
        return JsonResponse({"ok": True})

    @require_session_auth
    def patch(self, request, server_id):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        server = Server.objects.filter(id=server_id, organization=membership.organization).first()
        if not server:
            return JsonResponse({"error": "Server not found"}, status=404)
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)
        # Only allow_self_service is currently editable here.
        if "allow_self_service" in data:
            server.allow_self_service = bool(data["allow_self_service"])
            server.save(update_fields=["allow_self_service"])
        return JsonResponse({
            "id": server.id,
            "allow_self_service": server.allow_self_service,
        })


class ServerRotateView(View):
    """POST /api/v1/org/servers/<id>/rotate/ — issue a new sync token.

    The previous token stops working immediately. The new raw token is
    returned ONCE; admins must re-run the install command on the agent.
    """

    @require_session_auth
    def post(self, request, server_id):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        server = Server.objects.filter(id=server_id, organization=membership.organization).first()
        if not server:
            return JsonResponse({"error": "Server not found"}, status=404)
        raw_token = server.rotate()
        audit.log("server.token_rotated", target=server, organization=server.organization)
        return JsonResponse({
            "id": server.id,
            "token": raw_token,
            "token_prefix": server.token_prefix,
            "warning": "This is the only time the full token will be shown. Re-run the install command on the agent.",
        })


class ApiKeyListView(View):
    """GET /api/v1/org/keys/ — list keys
       POST /api/v1/org/keys/ — create key (returns raw ONCE)"""

    @require_session_auth
    def get(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        keys = [
            {
                "id": k.id,
                "name": k.name,
                "key_prefix": k.key_prefix,
                "scopes": k.scopes,
                "is_active": k.is_active,
                "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
                "created_at": k.created_at.isoformat(),
            }
            for k in ApiKey.objects.filter(organization=membership.organization)
        ]
        return JsonResponse({"keys": keys})

    @require_session_auth
    def post(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        scopes = data.get("scopes") or ["read_servers"]
        if not isinstance(scopes, list) or any(s not in TokenScope.values for s in scopes):
            return JsonResponse({"error": "Invalid scope value(s)"}, status=400)

        raw_token = ApiKey.generate_token()
        key = ApiKey.objects.create(
            organization=membership.organization,
            name=(data.get("name") or "Unnamed Key")[:255],
            key_prefix="bb_oak_live_",
            key_hash=ApiKey.hash_token(raw_token),
            scopes=scopes,
            created_by=request.user,
        )
        return JsonResponse({
            "id": key.id,
            "name": key.name,
            "token": raw_token,
            "scopes": key.scopes,
            "warning": "This is the only time this token will be shown.",
        }, status=201)


class ApiKeyDeleteView(View):
    """DELETE /api/v1/org/keys/<id>/ — revoke key"""

    @require_session_auth
    def delete(self, request, key_id):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        key = ApiKey.objects.filter(id=key_id, organization=membership.organization).first()
        if not key:
            return JsonResponse({"error": "Key not found"}, status=404)
        key.is_active = False
        key.save(update_fields=["is_active"])
        return JsonResponse({"ok": True})


class InviteListView(View):
    """GET /api/v1/invites/ — list pending invites
       POST /api/v1/invites/ — create invite"""

    @require_session_auth
    def get(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)

        base = os.environ.get('APP_BASE_URL', 'http://localhost:8000')
        now = timezone.now()
        org_invites = OrganizationInvite.objects.filter(organization=membership.organization)

        # Status is derived from expires_at/accepted_at rather than stored, so the
        # filters below mirror the model's is_expired()/is_accepted() at the DB
        # level. Kept in one place so the counts and the list can't drift apart.
        status_filters = {
            "pending": Q(accepted_at__isnull=True, expires_at__gt=now),
            "accepted": Q(accepted_at__isnull=False),
            "expired": Q(accepted_at__isnull=True, expires_at__lte=now),
        }

        # Tab badges: how many invites sit in each bucket, regardless of the
        # current filter/page, so admins can see expired history exists.
        counts = {
            key: org_invites.filter(q).count() for key, q in status_filters.items()
        }
        counts["all"] = sum(counts.values())

        # Default to pending — the actionable set — so expired invites don't
        # pollute the first view. Other buckets stay one tab away for audit.
        status = request.GET.get("status", "pending")
        if status in status_filters:
            qs = org_invites.filter(status_filters[status])
        else:
            status = "all"
            qs = org_invites
        # Newest first.
        qs = qs.order_by("-created_at")

        total = counts.get(status, counts["all"])
        try:
            page = max(1, int(request.GET.get("page", 1)))
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(request.GET.get("page_size", 20))
        except (TypeError, ValueError):
            page_size = 20
        page_size = min(max(page_size, 1), 100)

        start = (page - 1) * page_size
        # Include the full invite_url on every row so the dashboard can offer
        # re-copy + mailto: actions without rebuilding the URL on the frontend.
        # Matches the URL the POST handler returns at creation time.
        invites = [
            {
                "id": i.id,
                "email": i.email,
                "role": i.role,
                "token": str(i.token),
                "invite_url": f"{base}/api/v1/invites/accept/{i.token}/",
                "created_at": i.created_at.isoformat(),
                "expires_at": i.expires_at.isoformat(),
                "accepted_at": i.accepted_at.isoformat() if i.accepted_at else None,
                "accepted_by": i.accepted_by.username if i.accepted_by_id else None,
                "is_expired": i.is_expired(),
                "is_accepted": i.is_accepted(),
            }
            for i in qs.select_related("accepted_by")[start:start + page_size]
        ]
        return JsonResponse({
            "invites": invites,
            "status": status,
            "page": page,
            "page_size": page_size,
            "total": total,
            "has_next": start + page_size < total,
            "counts": counts,
        })

    @require_session_auth
    def post(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)
        data = json.loads(request.body)
        invite = OrganizationInvite.objects.create(
            organization=membership.organization,
            email=data.get("email", ""),
            role=data.get("role", Role.DEVELOPER),
            created_by=request.user,
        )
        base = os.environ.get('APP_BASE_URL', 'http://localhost:8000')
        invite_url = f"{base}/api/v1/invites/accept/{invite.token}/"

        # Email the invite link — unless the admin opted out (`send_email:
        # false`) to share the URL over their own channel. A mail failure must
        # not fail invite creation — the caller still gets `invite_url` to
        # copy/share manually — so we just report delivery via `email_sent`
        # and audit-log the outcome.
        send_email = data.get("send_email", True)
        email_sent = (
            send_org_invite(invite, invite_url, inviter=request.user)
            if send_email
            else False
        )
        audit.log(
            "invite.created",
            target=invite,
            organization=membership.organization,
            invited_email=invite.email,
            role=invite.role,
            email_sent=email_sent,
            email_skipped=not send_email,
        )

        return JsonResponse({
            "id": invite.id,
            "email": invite.email,
            "role": invite.role,
            "token": str(invite.token),
            "invite_url": invite_url,
            "email_sent": email_sent,
            "email_skipped": not send_email,
        }, status=201)
