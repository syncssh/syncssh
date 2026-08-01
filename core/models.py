import base64
import hashlib
import secrets

from django.db import models
from django.conf import settings

from organizations.models import Organization


class Server(models.Model):
    """Target VPS that polls for authorized keys.

    Token storage mirrors ApiKey: only SHA-256 hash is persisted, full token is
    shown ONCE at creation/rotation. A short prefix is kept for display so
    admins can identify which server owns which token.
    """

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="servers",
    )
    name = models.CharField(max_length=255)
    ip_address = models.CharField(max_length=253)
    ssh_user = models.CharField(max_length=255, help_text="Remote SSH user (e.g. ubuntu, root)")
    token_hash = models.CharField(
        max_length=64,
        unique=True,
        help_text="SHA-256 of the raw sync token; raw token never stored",
    )
    token_prefix = models.CharField(
        max_length=20,
        help_text="First few chars of the raw token, for display only",
    )
    is_active = models.BooleanField(default=True)
    allow_self_service = models.BooleanField(
        default=False,
        help_text=(
            "If true, non-admin members may deploy their own public keys "
            "to this server without admin assignment. Off by default — "
            "production-style servers should stay locked down."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True)
    # Stamped the first time /install/<token> is fetched. After that, the
    # endpoint returns 410 Gone — the install URL is one-shot, so a leaked URL
    # (browser history, Referer, log scrapers) cannot be replayed to recover
    # the token. Cleared on rotate() so the admin can re-install with the new
    # token.
    install_fetched_at = models.DateTimeField(null=True, blank=True)
    # Stamped on every successful /servers/sync GET so the dashboard can show
    # "last synced 3 min ago" instead of just an Active/Inactive badge that
    # can't tell whether the agent is actually polling. Nullable for servers
    # registered but never enrolled yet.
    last_synced_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "servers"
        # Stable list order — without this, Postgres returns heap order and an
        # updated row (e.g. toggling allow_self_service) jumps to the end.
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.name} ({self.ip_address})"

    @classmethod
    def generate_token(cls) -> str:
        return f"srv_{secrets.token_urlsafe(32)}"

    @classmethod
    def hash_token(cls, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    @staticmethod
    def _prefix_of(token: str) -> str:
        return token[:12]

    def rotate(self) -> str:
        """Issue a new raw token; persist only its hash + prefix."""
        raw = self.generate_token()
        self.token_hash = self.hash_token(raw)
        self.token_prefix = self._prefix_of(raw)
        # Re-arm the one-shot install endpoint so the admin can re-install.
        self.install_fetched_at = None
        self.save(update_fields=["token_hash", "token_prefix", "install_fetched_at"])
        return raw


class PublicKey(models.Model):
    """SSH public key scoped to a User and optionally restricted to specific Servers."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="public_keys",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="public_keys",
    )
    # Granular server mapping: if empty, key deploys to ALL servers in org.
    # If non-empty, key only deploys to listed servers.
    servers = models.ManyToManyField(
        Server,
        blank=True,
        related_name="assigned_keys",
    )
    deploy_to_all = models.BooleanField(
        default=True,
        help_text="If True, key deploys to all active org servers. If False, only to selected servers.",
    )
    key_title = models.CharField(max_length=255)
    key_payload = models.TextField(help_text="SSH public key material (openssh format)")
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "public_keys"
        # Stable list order so an updated key doesn't jump on re-fetch.
        ordering = ["created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "key_payload"],
                name="uniq_pubkey_payload_per_org",
            ),
        ]

    def __str__(self):
        return f"{self.key_title} ({self.user})"

    def deployed_to_servers(self):
        """Return queryset of servers this key should be deployed to."""
        if self.deploy_to_all:
            return self.organization.servers.filter(is_active=True)
        return self.servers.filter(is_active=True)

    @property
    def fingerprint(self) -> str:
        """SHA256 fingerprint in OpenSSH format (`SHA256:<base64-no-pad>`).

        Matches `ssh-keygen -lf <pubkey>` output. Computed on the fly because
        the payload is bounded (≤8 KiB by validation) so hashing it on every
        list response is cheaper than maintaining a stored column + migration.
        Returns empty string on a malformed payload so the API can fall back
        gracefully rather than 500-ing.
        """
        parts = self.key_payload.split()
        if len(parts) < 2:
            return ""
        try:
            blob = base64.b64decode(parts[1], validate=True)
        except (ValueError, base64.binascii.Error):
            return ""
        digest = hashlib.sha256(blob).digest()
        b64 = base64.b64encode(digest).rstrip(b"=").decode("ascii")
        return f"SHA256:{b64}"


class AuditLog(models.Model):
    """Append-only record of who did what, scoped per organization.

    Written by generic post_save/post_delete signals on tracked models (the
    safety net) and by explicit audit.log() calls from views where intent
    matters more than mechanism (token rotation, sync pulls, login events).
    """

    ACTOR_USER = "user"
    ACTOR_SERVER = "server"
    ACTOR_SYSTEM = "system"
    ACTOR_KIND_CHOICES = [
        (ACTOR_USER, "User"),
        (ACTOR_SERVER, "Server"),
        (ACTOR_SYSTEM, "System"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="audit_logs",
        null=True,
        blank=True,
        help_text="May be null for org-less events (e.g. login attempt for unknown user)",
    )
    actor_user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    actor_kind = models.CharField(
        max_length=16, choices=ACTOR_KIND_CHOICES, default=ACTOR_USER
    )
    action = models.CharField(
        max_length=64,
        help_text="Dot-namespaced verb, e.g. 'publickey.created', 'server.token_rotated'",
    )
    target_type = models.CharField(max_length=32, blank=True)
    target_id = models.BigIntegerField(null=True, blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "audit_logs"
        indexes = [
            models.Index(fields=["organization", "-created_at"]),
            models.Index(fields=["target_type", "target_id"]),
        ]

    def __str__(self):
        actor = self.actor_user or self.actor_kind
        return f"{actor} {self.action} {self.target_type}#{self.target_id}"


class Webhook(models.Model):
    """Per-org endpoint that receives signed notifications for access-mutating
    events (key add/remove, token rotation). One per org for now.

    The signing secret is stored in plaintext — unlike a bearer token it never
    grants access to us; it only lets the *receiver* authenticate our POSTs.
    """

    organization = models.OneToOneField(
        Organization,
        on_delete=models.CASCADE,
        related_name="webhook",
    )
    url = models.URLField(max_length=500)
    secret = models.CharField(max_length=128)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "webhooks"

    def __str__(self):
        return f"{self.organization.slug} → {self.url}"

    @classmethod
    def generate_secret(cls) -> str:
        return f"whsec_{secrets.token_urlsafe(32)}"


class OutboundNotification(models.Model):
    """Outbox row for one webhook delivery.

    Enqueued in the same transaction as the mutation it reports, so an
    attacker who controls the request path can't suppress the alert by
    stalling the receiver. Drained by `manage.py drain_notifications`.
    """

    STATUS_PENDING = "pending"
    STATUS_SENT = "sent"
    STATUS_FAILED = "failed"
    STATUS_CHOICES = [
        (STATUS_PENDING, "Pending"),
        (STATUS_SENT, "Sent"),
        (STATUS_FAILED, "Failed"),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="outbound_notifications",
    )
    webhook = models.ForeignKey(
        Webhook,
        on_delete=models.CASCADE,
        related_name="notifications",
    )
    action = models.CharField(max_length=64)
    payload = models.JSONField(default=dict)
    status = models.CharField(
        max_length=16, choices=STATUS_CHOICES, default=STATUS_PENDING, db_index=True
    )
    attempts = models.PositiveSmallIntegerField(default=0)
    next_attempt_at = models.DateTimeField(db_index=True)
    last_error = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    sent_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "outbound_notifications"
        ordering = ["created_at"]

    def __str__(self):
        return f"{self.action} → {self.webhook_id} [{self.status}]"

class UserProfile(models.Model):
    """Per-user preferences, created lazily on first write.

    An empty theme means "no server-side preference yet" — the client keeps
    its local choice instead of having a server default flip it on first load.
    """

    THEME_CHOICES = [("light", "Light"), ("dark", "Dark")]

    user = models.OneToOneField(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="profile",
    )
    theme = models.CharField(max_length=8, choices=THEME_CHOICES, blank=True, default="")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_profiles"

    def __str__(self):
        return f"profile of {self.user_id}"
