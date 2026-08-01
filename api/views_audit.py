"""Admin-only audit-log browser."""
from datetime import timedelta

from django.http import JsonResponse
from django.utils import timezone
from django.views import View

from core.models import AuditLog
from organizations.models import Role
from syncssh.editions import AUDIT_RETENTION_DAYS, feature_enabled
from .views_org import require_session_auth, get_user_org


TARGET_LABELS = {
    "User": "Account",
    "OrganizationMembership": "Member",
    "OrganizationInvite": "Invitation",
    "PublicKey": "SSH key",
    "Server": "Server",
    "ApiKey": "API key",
    "Organization": "Organization",
}


def _target_label(event):
    """Return a useful target description without exposing database IDs."""
    if not event.target_type:
        return None
    return TARGET_LABELS.get(event.target_type, "Related item")


class AuditLogListView(View):
    """GET /api/v1/audit/?action=&actor=&since=&limit=

    Admin-only. Returns events for the requesting user's org, newest first.
    """

    MAX_LIMIT = 200
    DEFAULT_LIMIT = 50

    @require_session_auth
    def get(self, request):
        membership = get_user_org(request)
        if not membership:
            return JsonResponse({"error": "Not a member"}, status=403)
        if membership.role not in [Role.OWNER, Role.ADMIN]:
            return JsonResponse({"error": "Admin or Owner role required"}, status=403)

        qs = AuditLog.objects.filter(
            organization=membership.organization
        ).select_related("actor_user").order_by("-created_at")

        # OSS keeps a rolling window; the cloud edition retains full history.
        if not feature_enabled("audit_unlimited_retention"):
            cutoff = timezone.now() - timedelta(days=AUDIT_RETENTION_DAYS)
            qs = qs.filter(created_at__gte=cutoff)

        action = request.GET.get("action")
        if action:
            qs = qs.filter(action=action)

        actor = request.GET.get("actor")
        if actor:
            qs = qs.filter(actor_user__username=actor)

        since = request.GET.get("since")
        if since:
            qs = qs.filter(created_at__gte=since)

        try:
            limit = min(int(request.GET.get("limit", self.DEFAULT_LIMIT)), self.MAX_LIMIT)
        except (TypeError, ValueError):
            limit = self.DEFAULT_LIMIT

        events = [
            {
                "action": e.action,
                "actor_kind": e.actor_kind,
                "actor_username": e.actor_user.username if e.actor_user else None,
                # Database primary keys are global sequences. Do not return
                # them: a User#N target would disclose an approximate account
                # count to an organization administrator.
                "target": _target_label(e),
                "metadata": e.metadata,
                "created_at": e.created_at.isoformat(),
            }
            for e in qs[:limit]
        ]
        return JsonResponse({"events": events, "count": len(events)})
