import json
import re
from typing import Optional

from django.db import IntegrityError
from django.http import JsonResponse
from django.views import View

from core.models import PublicKey
from organizations.models import OrganizationMembership, Role
from syncssh import audit
from .views_org import get_user_org


# Recognized OpenSSH key types. Anything else (including raw text, options like
# command="...", or from="...") is rejected so it cannot land in authorized_keys.
_SSH_KEY_RE = re.compile(
    r"^(?:"
    r"ssh-(?:rsa|ed25519|dss)"
    r"|ecdsa-sha2-[A-Za-z0-9._-]+"
    r"|sk-ssh-ed25519@openssh\.com"
    r"|sk-ecdsa-sha2-[A-Za-z0-9._-]+@openssh\.com"
    r")\s+[A-Za-z0-9+/=]+(?:\s+\S.*)?$"
)

# Strings that, if accepted into a payload, let an attacker break out of the
# managed SYNCSSH block and pin lines into authorized_keys permanently.
_FORBIDDEN_SUBSTRINGS = ("SYNCSSH BEGIN", "SYNCSSH END")

_MAX_KEY_LEN = 8192


def validate_ssh_public_key(raw: str) -> Optional[str]:
    """Return the cleaned single-line key, or None if invalid."""
    if not raw:
        return None
    cleaned = raw.strip()
    if not cleaned or len(cleaned) > _MAX_KEY_LEN:
        return None
    if "\n" in cleaned or "\r" in cleaned or "\x00" in cleaned:
        return None
    if any(marker in cleaned for marker in _FORBIDDEN_SUBSTRINGS):
        return None
    if not _SSH_KEY_RE.match(cleaned):
        return None
    return cleaned


class PublicKeyListView(View):
    """
    GET /api/v1/public-keys/  — list current user's keys in their org
    POST /api/v1/public-keys/  — add a new key
    DELETE /api/v1/public-keys/<id>/ — remove a key
    """

    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)
        is_admin = membership.role in (Role.OWNER, Role.ADMIN)
        # Admins/Owners see every key in the org so they can audit + revoke leavers.
        # Developers see only their own.
        qs = PublicKey.objects.filter(organization=membership.organization).select_related("user")
        if not is_admin:
            qs = qs.filter(user=request.user)
        keys = [
            {
                "id": k.id,
                "key_title": k.key_title,
                "key_payload": k.key_payload,
                "fingerprint": k.fingerprint,
                "is_active": k.is_active,
                "deploy_to_all": k.deploy_to_all,
                "assigned_servers": [s.id for s in k.servers.all()],
                "created_at": k.created_at.isoformat(),
                "owner_username": k.user.username,
                "is_own": k.user_id == request.user.id,
            }
            for k in qs
        ]
        return JsonResponse({"keys": keys})

    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        cleaned_payload = validate_ssh_public_key(data.get("key_payload", ""))
        if cleaned_payload is None:
            return JsonResponse(
                {"error": "Invalid SSH public key. Must be a single-line OpenSSH key (ssh-ed25519, ssh-rsa, ecdsa-sha2-*)."},
                status=400,
            )

        title = (data.get("key_title") or "Untitled Key").strip()[:255]
        server_ids = data.get("server_ids") or []
        deploy_to_all = bool(data.get("deploy_to_all", True))
        from core.models import Server  # local import: avoid model graph cycle

        is_admin = membership.role in ("OWNER", "ADMIN")
        if not is_admin:
            # Self-service rules:
            #   - Non-admins cannot deploy_to_all (would bypass the lock on
            #     non-self-service servers).
            #   - server_ids must be non-empty and every target must be flagged
            #     `allow_self_service=True` by an admin.
            if deploy_to_all:
                return JsonResponse(
                    {"error": "Only admins can deploy a key to all servers."},
                    status=403,
                )
            allowed_ids = set(
                Server.objects.filter(
                    id__in=server_ids,
                    organization=membership.organization,
                    allow_self_service=True,
                ).values_list("id", flat=True)
            )
            if set(server_ids) - allowed_ids:
                return JsonResponse(
                    {"error": "One or more selected servers are not available for self-service."},
                    status=403,
                )


        # Block duplicate payloads at the org level (unique constraint). Surface
        # the existing owner so the requester knows who to talk to.
        existing = PublicKey.objects.filter(
            organization=membership.organization,
            key_payload=cleaned_payload,
        ).select_related("user").first()
        if existing:
            audit.log(
                "publickey.duplicate_rejected",
                target=existing,
                organization=membership.organization,
                existing_owner=existing.user.username,
                attempted_title=title,
            )
            return JsonResponse(
                {
                    "error": (
                        f"This public key is already registered to {existing.user.username} "
                        "in this organization. Ask them to share access or remove their copy first."
                    ),
                    "existing_owner": existing.user.username,
                },
                status=409,
            )
        try:
            key = PublicKey.objects.create(
                user=request.user,
                organization=membership.organization,
                key_title=title,
                key_payload=cleaned_payload,
                is_active=True,
                deploy_to_all=deploy_to_all,
            )
        except IntegrityError:
            # Race: another request inserted the same payload between our SELECT
            # and INSERT. Return the same friendly 409.
            return JsonResponse(
                {"error": "This public key is already registered in this organization."},
                status=409,
            )
        if server_ids and not deploy_to_all:
            key.servers.set(
                Server.objects.filter(id__in=server_ids, organization=membership.organization)
            )
        return JsonResponse({
            "id": key.id,
            "key_title": key.key_title,
            "key_payload": key.key_payload,
            "fingerprint": key.fingerprint,
            "is_active": key.is_active,
            "assigned_servers": [s.id for s in key.servers.all()],
            "created_at": key.created_at.isoformat(),
        }, status=201)



class PublicKeyToggleView(View):
    """PATCH /api/v1/public-keys/<id>/toggle/ — flip is_active"""

    def patch(self, request, key_id):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)
        is_admin = membership.role in (Role.OWNER, Role.ADMIN)
        # Admins can toggle anyone's key in the org; devs can only toggle their own.
        qs = PublicKey.objects.filter(id=key_id, organization=membership.organization)
        if not is_admin:
            qs = qs.filter(user=request.user)
        key = qs.first()
        if not key:
            return JsonResponse({"error": "Key not found"}, status=404)
        key.is_active = not key.is_active
        key.save(update_fields=["is_active"])
        audit.log(
            "publickey.toggled",
            target=key,
            organization=membership.organization,
            owner_username=key.user.username,
            new_state="active" if key.is_active else "inactive",
            by_admin=is_admin and key.user_id != request.user.id,
        )
        return JsonResponse({"id": key.id, "is_active": key.is_active})


class PublicKeyUpdateView(View):
    """
    DELETE /api/v1/public-keys/<id>/  — owner removes their key
    PATCH  /api/v1/public-keys/<id>/  — admin reassigns key's server targeting
    """

    def patch(self, request, key_id):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)

        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)

        if membership.role not in ["OWNER", "ADMIN"]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)

        key = PublicKey.objects.filter(id=key_id, organization=membership.organization).first()
        if not key:
            return JsonResponse({"error": "Key not found"}, status=404)

        data = json.loads(request.body)
        server_ids = data.get("server_ids", [])
        deploy_to_all = data.get("deploy_to_all", key.deploy_to_all)

        from core.models import Server
        if deploy_to_all:
            key.deploy_to_all = True
            key.servers.clear()
        else:
            key.deploy_to_all = False
            if server_ids:
                key.servers.set(Server.objects.filter(id__in=server_ids, organization=membership.organization))

        key.save()

        return JsonResponse({
            "id": key.id,
            "key_title": key.key_title,
            "key_payload": key.key_payload,
            "fingerprint": key.fingerprint,
            "is_active": key.is_active,
            "deploy_to_all": key.deploy_to_all,
            "assigned_servers": [s.id for s in key.servers.all()],
        })

    def delete(self, request, key_id):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)

        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member of any organization"}, status=403)

        key = PublicKey.objects.filter(
            id=key_id, organization=membership.organization
        ).select_related("user").first()
        if not key:
            return JsonResponse({"error": "Key not found"}, status=404)

        is_admin = membership.role in (Role.OWNER, Role.ADMIN)
        cross_user = key.user_id != request.user.id
        if cross_user and not is_admin:
            return JsonResponse({"error": "Insufficient permissions"}, status=403)

        if cross_user:
            # Distinct verb so admin actions are easy to filter in audit log.
            # Captured BEFORE delete so target_id / owner_username are intact.
            audit.log(
                "publickey.deleted_by_admin",
                target=key,
                organization=membership.organization,
                owner_username=key.user.username,
                key_title=key.key_title,
            )
        key.delete()
        return JsonResponse({"ok": True})
