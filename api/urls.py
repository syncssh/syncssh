from django.urls import path
from .views import ServerSyncView, InstallScriptView, InviteAcceptView, ApiKeyCreateView, ApiKeyRotateView
from .views_auth import LoginView, LogoutView, MeView, CsrfTokenView, SignupView, ChangePasswordView
from .views_org import OrgView, OrganizationLeaveView, OrganizationMembershipListView, OrganizationMembershipLeaveView, OrganizationMemberView, ServerListView, ServerDetailView, ServerRotateView, ApiKeyListView, ApiKeyDeleteView, InviteListView
from .views_pubkeys import PublicKeyListView, PublicKeyToggleView, PublicKeyUpdateView
from .views_audit import AuditLogListView
from .views_webhooks import WebhookView, WebhookRotateView, WebhookTestView

urlpatterns = [
    path("auth/signup/", SignupView.as_view(), name="auth-signup"),
    # Auth
    path("auth/login/", LoginView.as_view(), name="auth-login"),
    path("auth/logout/", LogoutView.as_view(), name="auth-logout"),
    path("auth/me/", MeView.as_view(), name="auth-me"),
    path("auth/csrf/", CsrfTokenView.as_view(), name="auth-csrf"),
    path("auth/change-password/", ChangePasswordView.as_view(), name="auth-change-password"),
    # Server sync (machine endpoint)
    path("servers/sync", ServerSyncView.as_view(), name="server-sync"),
    path("install/<str:token>/", InstallScriptView.as_view(), name="install-script"),
    # Org JSON API
    path("org/", OrgView.as_view(), name="org"),
    path("org/leave/", OrganizationLeaveView.as_view(), name="org-leave"),
    path("org/memberships/", OrganizationMembershipListView.as_view(), name="org-memberships"),
    path("org/memberships/<int:organization_id>/leave/", OrganizationMembershipLeaveView.as_view(), name="org-membership-leave"),
    path("org/members/<int:user_id>/", OrganizationMemberView.as_view(), name="org-member"),
    path("org/servers/", ServerListView.as_view(), name="server-list"),
    path("org/servers/<int:server_id>/", ServerDetailView.as_view(), name="server-detail"),
    path("org/servers/<int:server_id>/rotate/", ServerRotateView.as_view(), name="server-rotate"),
    path("org/keys/", ApiKeyListView.as_view(), name="apikey-list"),
    # Bearer-auth mint endpoint for CI/CD (caller is another API key, not a session).
    path("keys/", ApiKeyCreateView.as_view(), name="apikey-create-bearer"),
    path("org/keys/<int:key_id>/", ApiKeyDeleteView.as_view(), name="apikey-delete"),
    path("org/keys/<int:key_id>/rotate/", ApiKeyRotateView.as_view(), name="apikey-rotate"),
    path("invites/", InviteListView.as_view(), name="invite-list"),
    # Invite accept (public)
    path("invites/accept/<uuid:token>/", InviteAcceptView.as_view(), name="invite-accept"),
    # Public Keys
    path("public-keys/", PublicKeyListView.as_view(), name="pubkey-list"),
    path("public-keys/<int:key_id>/", PublicKeyUpdateView.as_view(), name="pubkey-update"),
    path("public-keys/<int:key_id>/toggle/", PublicKeyToggleView.as_view(), name="pubkey-toggle"),
    # Audit log (admin-only)
    path("audit/", AuditLogListView.as_view(), name="audit-log"),
    # Webhook notifications (admin-only)
    path("org/webhook/", WebhookView.as_view(), name="webhook"),
    path("org/webhook/rotate/", WebhookRotateView.as_view(), name="webhook-rotate"),
    path("org/webhook/test/", WebhookTestView.as_view(), name="webhook-test"),
]
