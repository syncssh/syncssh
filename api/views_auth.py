import json
from django.conf import settings
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.contrib.messages import get_messages
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.models import User
from django.middleware.csrf import get_token

from allauth.account.models import EmailAddress
from django_ratelimit.decorators import ratelimit


def _drain_messages(request):
    """Consume any pending django.contrib.messages entries so they don't
    pile up across requests. Allauth queues messages that our React API
    consumers never render."""
    if hasattr(request, "_messages"):
        list(get_messages(request))


@method_decorator(ratelimit(key="ip", rate="5/h", method="POST", block=True), name="post")
class SignupView(View):
    """POST /api/v1/auth/signup/ — self-service signup with auto-org creation."""

    def post(self, request):
        data = json.loads(request.body)
        username = data.get("username")
        email = data.get("email")
        password1 = data.get("password1")
        password2 = data.get("password2")
        # Self-reported intent ("solo" | "team"), not a plan or a limit: both
        # paths create the identical org + OWNER membership. Recorded only on
        # the auth.signup audit event below, as a signal of how many signups
        # consider themselves teams. Documented in INSTALL.md Quickstart.
        account_type = data.get("account_type", "solo")

        if not all([username, email, password1, password2]):
            return JsonResponse({"error": "All fields required"}, status=400)

        if password1 != password2:
            return JsonResponse({"error": "Passwords do not match"}, status=400)

        # Single generic message for any "we won't tell you why" case — no
        # username/email enumeration. Rate-limit (#8) bounds brute force.
        if User.objects.filter(username=username).exists():
            return JsonResponse(
                {"error": "Could not create account. Try a different username or sign in."},
                status=400,
            )
        if User.objects.filter(email__iexact=email).exists():
            return JsonResponse(
                {"error": "Could not create account. Try a different email or sign in."},
                status=400,
            )

        # AUTH_PASSWORD_VALIDATORS aren't applied by create_user — run them here.
        # Build a transient User to give UserAttributeSimilarityValidator real
        # fields to compare against (catches password == username, etc).
        try:
            validate_password(password1, user=User(username=username, email=email))
        except ValidationError as e:
            return JsonResponse({"error": " ".join(e.messages)}, status=400)

        user = User.objects.create_user(username=username, email=email, password=password1)

        from organizations.models import Organization, OrganizationMembership
        from django.utils.text import slugify
        org_name = f"{username}'s workspace"
        base_slug = slugify(f"{username} workspace")[:40] or "workspace"
        slug = base_slug
        n = 2
        while Organization.objects.filter(slug=slug).exists():
            slug = f"{base_slug}-{n}"
            n += 1
        org = Organization.objects.create(name=org_name, slug=slug)
        OrganizationMembership.objects.create(user=user, organization=org, role="OWNER")

        # Neither User nor Organization is a tracked model, so without this the
        # only trace of a signup is a generic membership.created row. Log it
        # explicitly, pinned to the new workspace + user (who isn't logged in
        # yet when email verification is mandatory).
        from syncssh import audit
        audit.log(
            "auth.signup",
            target=user,
            organization=org,
            actor=user,
            account_type=account_type,
        )

        # If allauth is configured for mandatory email verification, send the
        # confirmation email and DO NOT log the user in. They land in the
        # session only after clicking the link (allauth then fires
        # user_logged_in → our invite-consumer signal handles any pending
        # invite token in the same flow).
        verification_required = (
            getattr(settings, "ACCOUNT_EMAIL_VERIFICATION", "optional") == "mandatory"
        )

        if verification_required:
            email_address = EmailAddress.objects.create(
                user=user, email=email, primary=True, verified=False
            )
            email_address.send_confirmation(request, signup=True)
            _drain_messages(request)
            return JsonResponse({
                "ok": True,
                "verification_required": True,
                "email": email,
            })

        # No verification gate — mark the email verified and log in immediately.
        EmailAddress.objects.get_or_create(
            user=user,
            email=email,
            defaults={"primary": True, "verified": True},
        )
        login(request, user, backend="django.contrib.auth.backends.ModelBackend")
        _drain_messages(request)
        return JsonResponse({
            "ok": True,
            "user": {"id": user.id, "username": user.username, "email": user.email},
            "org": {"id": org.id, "name": org.name},
        })


def _login_username_key(group, request) -> str:
    """Rate-limit key: the username being attempted, lower-cased.

    `request.body` is cached by Django so reading it here doesn't break the
    later json.loads in the view. We're deliberately lenient on parse errors —
    a malformed body just falls through to an empty key (no per-user budget
    consumed) and the IP-keyed limit still bounds raw abuse.
    """
    try:
        return (json.loads(request.body).get("username") or "").strip().lower()
    except (ValueError, AttributeError):
        return ""


# Two stacked limits: per-IP catches single-host bursts; per-username caps
# credential stuffing against a known account even when sprayed from a proxy
# pool. The per-user budget is what `key='ip'` alone cannot give us.
@method_decorator(ratelimit(key=_login_username_key, rate="5/m", method="POST", block=True), name="post")
@method_decorator(ratelimit(key="ip", rate="10/m", method="POST", block=True), name="post")
class LoginView(View):
    """POST /api/v1/auth/login/"""

    def post(self, request):
        data = json.loads(request.body)
        username = data.get("username")
        password = data.get("password")
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user, backend="django.contrib.auth.backends.ModelBackend")
            _drain_messages(request)
            return JsonResponse({"ok": True, "user": _user_json(user)})
        return JsonResponse({"ok": False, "error": "Invalid credentials"}, status=401)


# Keyed per-user (falls back to IP pre-auth): the current-password check is a
# password oracle for a hijacked session, so give it a tight budget.
@method_decorator(ratelimit(key="user_or_ip", rate="5/h", method="POST", block=True), name="post")
class ChangePasswordView(View):
    """POST /api/v1/auth/change-password/ — session-auth, requires the current
    password so a stolen cookie alone can't lock the owner out."""

    def post(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Not authenticated"}, status=401)

        data = json.loads(request.body)
        current = data.get("current_password")
        password1 = data.get("new_password1")
        password2 = data.get("new_password2")

        if not all([current, password1, password2]):
            return JsonResponse({"error": "All fields required"}, status=400)
        if not request.user.check_password(current):
            return JsonResponse({"error": "Current password is incorrect"}, status=400)
        if password1 != password2:
            return JsonResponse({"error": "New passwords do not match"}, status=400)

        try:
            validate_password(password1, user=request.user)
        except ValidationError as e:
            return JsonResponse({"error": " ".join(e.messages)}, status=400)

        request.user.set_password(password1)
        request.user.save(update_fields=["password"])
        # set_password invalidates the session hash — refresh it so the user
        # stays logged in here while every other session gets kicked.
        update_session_auth_hash(request, request.user)

        from syncssh import audit
        audit.log("auth.password_changed", target=request.user, actor=request.user)

        return JsonResponse({"ok": True})


class LogoutView(View):
    """POST /api/v1/auth/logout/"""

    def post(self, request):
        logout(request)
        _drain_messages(request)
        return JsonResponse({"ok": True})


def _user_json(user):
    from core.models import UserProfile

    try:
        theme = user.profile.theme
    except UserProfile.DoesNotExist:
        theme = ""
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "prefs": {"theme": theme},
    }


class MeView(View):
    """GET /api/v1/auth/me/ — who am I + preferences
       PATCH /api/v1/auth/me/ — update preferences (theme)"""

    def get(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"authenticated": False}, status=401)
        from django.conf import settings
        return JsonResponse({
            "authenticated": True,
            "user": _user_json(request.user),
            # Lets the dashboard warn admins when verification/invite mail can't
            # actually be delivered (console backend, no SMTP configured).
            "email_delivery_configured": settings.EMAIL_DELIVERY_CONFIGURED,
            # Edition feature flags — a single backend switch drives which
            # commercial features the frontend renders (see syncssh.editions).
            "features": settings.FEATURES,
        })

    def patch(self, request):
        if not request.user.is_authenticated:
            return JsonResponse({"error": "Authentication required"}, status=401)
        from core.models import UserProfile

        try:
            data = json.loads(request.body)
        except (ValueError, TypeError):
            return JsonResponse({"error": "Invalid JSON body"}, status=400)

        theme = data.get("theme")
        if theme not in ("light", "dark"):
            return JsonResponse({"error": "theme must be 'light' or 'dark'"}, status=400)
        UserProfile.objects.update_or_create(
            user=request.user, defaults={"theme": theme}
        )
        return JsonResponse({"user": _user_json(request.user)})


class CsrfTokenView(View):
    """GET /api/v1/auth/csrf/"""

    def get(self, request):
        return JsonResponse({"csrfToken": get_token(request)})
