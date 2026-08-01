"""Minimal audit-log infrastructure.

Three primitives:
  - `_request_ctx`: contextvar holding the current request, set by middleware.
  - `AuditContextMiddleware`: stamps + clears the contextvar per request.
  - `log(action, target=None, ...)`: fire-and-forget; pulls actor/IP from ctx.

Generic post_save/post_delete signals (see `core/signals.py`) drive the bulk
of entries; explicit `log()` calls cover things signals can't see — login
events, token rotations as a distinct verb, sync pulls, etc.
"""

from contextvars import ContextVar

_request_ctx: ContextVar = ContextVar("audit_request", default=None)


def get_current_request():
    return _request_ctx.get()


class AuditContextMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        token = _request_ctx.set(request)
        try:
            return self.get_response(request)
        finally:
            _request_ctx.reset(token)


def _client_ip(request):
    if not request:
        return None
    # ClientIPMiddleware validates any forwarded headers and normalizes the
    # accepted address into REMOTE_ADDR. Never trust forwarding headers again
    # here or audit attribution can diverge from rate limiting.
    return request.META.get("REMOTE_ADDR")


def _infer_organization(target, request):
    """Best-effort: target.organization → request.user's first membership.

    Returning None is fine — AuditLog.organization is nullable for events that
    are genuinely org-less (failed login on unknown user).
    """
    if target is not None:
        org = getattr(target, "organization", None)
        if org is not None:
            return org
    if request is not None:
        user = getattr(request, "user", None)
        if user and getattr(user, "is_authenticated", False):
            membership = user.memberships.first() if hasattr(user, "memberships") else None
            if membership:
                return membership.organization
    return None


def log(action, target=None, *, organization=None, actor=None,
        actor_kind=None, **metadata):
    """Write one AuditLog row. Never raises — audit failures must not break
    the user-facing operation."""
    from core.models import AuditLog  # local import: avoid app-loading cycle
    try:
        request = get_current_request()
        if actor is None and request is not None:
            req_user = getattr(request, "user", None)
            if req_user and getattr(req_user, "is_authenticated", False):
                actor = req_user
        if organization is None:
            organization = _infer_organization(target, request)
        meta = {"ip": _client_ip(request)} if request else {}
        meta.update(metadata)
        AuditLog.objects.create(
            organization=organization,
            actor_user=actor,
            actor_kind=actor_kind or (AuditLog.ACTOR_USER if actor else AuditLog.ACTOR_SYSTEM),
            action=action,
            target_type=target.__class__.__name__ if target is not None else "",
            target_id=getattr(target, "id", None) or getattr(target, "pk", None),
            metadata=meta,
        )
        # Fan access-mutating events out to the org's webhook outbox. Riding
        # the audit funnel means every mutation path is covered, including
        # direct ORM writes that only the signal safety net sees.
        from syncssh import notifications
        notifications.enqueue(
            action, organization=organization, target=target,
            actor=actor, metadata=meta,
        )
    except Exception:
        # Audit is a best-effort cross-cutting concern; swallow failures rather
        # than 500ing the user request. Surface via logs if needed later.
        import logging
        logging.getLogger(__name__).exception("audit.log failed: %s", action)
