"""Org webhook configuration.

GET    /api/v1/org/webhook/         — current config (never returns the secret)
PUT    /api/v1/org/webhook/         — create/replace; returns the secret ONCE
PATCH  /api/v1/org/webhook/         — pause/resume (is_active) without rotating
POST   /api/v1/org/webhook/rotate/  — new secret; returns it ONCE
POST   /api/v1/org/webhook/test/    — enqueue a test event
DELETE /api/v1/org/webhook/         — remove

Owner/Admin only: the webhook receives security notifications, so letting a
dev point it elsewhere would let them silence or redirect alerts.
"""

import json

from django.http import JsonResponse
from django.utils import timezone
from django.views import View

from core.models import OutboundNotification, Webhook
from organizations.models import Role
from syncssh import audit
from syncssh.editions import FeatureGatedView
from syncssh.notifications import validate_webhook_url

from .views_org import get_user_org, require_session_auth


def _require_admin(request):
    """Return (membership, error_response). Error is None when authorized."""
    membership = get_user_org(request)
    if not membership:
        return None, JsonResponse({"error": "Not a member of any organization"}, status=403)
    if membership.role not in (Role.OWNER, Role.ADMIN):
        return None, JsonResponse({"error": "Insufficient permissions"}, status=403)
    return membership, None


def _webhook_json(webhook):
    return {
        "url": webhook.url,
        "is_active": webhook.is_active,
        "created_at": webhook.created_at.isoformat(),
    }


class WebhookView(FeatureGatedView, View):
    required_feature = "webhooks"

    @require_session_auth
    def get(self, request):
        membership, err = _require_admin(request)
        if err:
            return err
        try:
            webhook = membership.organization.webhook
        except Webhook.DoesNotExist:
            return JsonResponse({"configured": False})
        return JsonResponse({"configured": True, **_webhook_json(webhook)})

    @require_session_auth
    def put(self, request):
        membership, err = _require_admin(request)
        if err:
            return err
        try:
            data = json.loads(request.body)
        except (ValueError, TypeError):
            return JsonResponse({"error": "Invalid JSON body"}, status=400)

        url = (data.get("url") or "").strip()
        if not url or len(url) > 500:
            return JsonResponse({"error": "A webhook URL is required."}, status=400)
        url_error = validate_webhook_url(url)
        if url_error:
            return JsonResponse({"error": url_error}, status=400)

        org = membership.organization
        secret = Webhook.generate_secret()
        webhook, created = Webhook.objects.update_or_create(
            organization=org,
            defaults={
                "url": url,
                "secret": secret,
                "is_active": bool(data.get("is_active", True)),
            },
        )
        audit.log(
            "webhook.configured" if created else "webhook.updated",
            target=webhook,
            organization=org,
            url=url,
        )
        # Secret is returned exactly once, like server/API tokens.
        return JsonResponse(
            {"configured": True, "secret": secret, **_webhook_json(webhook)},
            status=201 if created else 200,
        )

    @require_session_auth
    def patch(self, request):
        """Toggle is_active only. PUT always mints a new secret, so pausing
        deliveries must not go through it — receivers keep their secret."""
        membership, err = _require_admin(request)
        if err:
            return err
        try:
            webhook = membership.organization.webhook
        except Webhook.DoesNotExist:
            return JsonResponse({"error": "No webhook configured"}, status=404)
        try:
            data = json.loads(request.body)
        except (ValueError, TypeError):
            return JsonResponse({"error": "Invalid JSON body"}, status=400)
        if "is_active" not in data:
            return JsonResponse({"error": "is_active is required"}, status=400)
        webhook.is_active = bool(data["is_active"])
        webhook.save(update_fields=["is_active"])
        audit.log(
            "webhook.resumed" if webhook.is_active else "webhook.paused",
            target=webhook,
            organization=membership.organization,
            url=webhook.url,
        )
        return JsonResponse({"configured": True, **_webhook_json(webhook)})

    @require_session_auth
    def delete(self, request):
        membership, err = _require_admin(request)
        if err:
            return err
        try:
            webhook = membership.organization.webhook
        except Webhook.DoesNotExist:
            return JsonResponse({"error": "No webhook configured"}, status=404)
        audit.log(
            "webhook.deleted",
            organization=membership.organization,
            url=webhook.url,
        )
        webhook.delete()
        return JsonResponse({"deleted": True})


class WebhookRotateView(FeatureGatedView, View):
    required_feature = "webhooks"

    @require_session_auth
    def post(self, request):
        membership, err = _require_admin(request)
        if err:
            return err
        try:
            webhook = membership.organization.webhook
        except Webhook.DoesNotExist:
            return JsonResponse({"error": "No webhook configured"}, status=404)
        secret = Webhook.generate_secret()
        webhook.secret = secret
        webhook.save(update_fields=["secret"])
        audit.log(
            "webhook.secret_rotated",
            target=webhook,
            organization=membership.organization,
        )
        return JsonResponse({"secret": secret})


class WebhookTestView(FeatureGatedView, View):
    required_feature = "webhooks"

    @require_session_auth
    def post(self, request):
        membership, err = _require_admin(request)
        if err:
            return err
        org = membership.organization
        try:
            webhook = org.webhook
        except Webhook.DoesNotExist:
            return JsonResponse({"error": "No webhook configured"}, status=404)
        notification = OutboundNotification.objects.create(
            organization=org,
            webhook=webhook,
            action="webhook.test",
            payload={
                "event": "webhook.test",
                "organization": org.slug,
                "timestamp": timezone.now().isoformat(),
                "actor": request.user.username,
                "target": {},
            },
            next_attempt_at=timezone.now(),
        )
        return JsonResponse({"queued": True, "delivery_id": notification.pk})
