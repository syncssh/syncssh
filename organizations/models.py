from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.contrib.postgres.indexes import BTreeIndex
import uuid
import secrets
import hashlib


User = get_user_model()


class Role(models.TextChoices):
    OWNER = "OWNER", "Owner"
    ADMIN = "ADMIN", "Admin"
    DEVELOPER = "DEVELOPER", "Developer"


class TokenScope(models.TextChoices):
    READ_SERVERS = "read_servers", "Read Servers"
    WRITE_KEYS = "write_keys", "Write Keys"
    ADMIN_MEMBERS = "admin_members", "Administer Members"


class Organization(models.Model):
    """B2B tenant boundary."""

    name = models.CharField(max_length=255)
    slug = models.SlugField(unique=True, max_length=50)
    created_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True)
    # Palette for outgoing invite emails; dark matches the app's default look.
    invite_email_theme = models.CharField(
        max_length=8, choices=[("dark", "Dark"), ("light", "Light")], default="dark"
    )

    class Meta:
        db_table = "organizations"

    def __str__(self):
        return self.name


class ApiKey(models.Model):
    """
    Rotatable, scoped API key for server-to-server and CI/CD auth.

    Token format: bb_oak_live_<32-char-random>
    Only the prefix (bb_oak_live_) is stored in DB. Full key shown ONCE at creation.
    Validation: hash input → compare to stored SHA-256 hash.
    """

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="api_keys",
    )
    name = models.CharField(max_length=255, help_text="Label for this key (e.g. ci-server-prod)")
    key_prefix = models.CharField(max_length=32, editable=False)
    key_hash = models.CharField(max_length=64, editable=False, help_text="SHA-256 of the full token")
    scopes = models.JSONField(default=list, help_text="List of TokenScope values")
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_api_keys",
    )
    last_used_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "api_keys"
        # Stable list order so a rotated/updated key doesn't jump on re-fetch.
        ordering = ["created_at"]
        indexes = [
            BTreeIndex(fields=["key_prefix"]),
        ]

    def __str__(self):
        return f"{self.name} ({self.organization})"

    @classmethod
    def generate_token(cls):
        """Generate a new random token with prefix."""
        random_part = secrets.token_urlsafe(32)
        return f"bb_oak_live_{random_part}"

    @classmethod
    def hash_token(cls, token: str) -> str:
        """Return SHA-256 hex digest of a token."""
        return hashlib.sha256(token.encode()).hexdigest()

    def rotate(self):
        """Generate a new token, invalidate the old one."""
        new_token = self.generate_token()
        self.key_hash = self.hash_token(new_token)
        self.key_prefix = "bb_oak_live_"
        self.save(update_fields=["key_hash", "key_prefix"])
        return new_token

    def is_expired(self):
        if not self.expires_at:
            return False
        return timezone.now() > self.expires_at

    def mark_used(self):
        self.last_used_at = timezone.now()
        self.save(update_fields=["last_used_at"])


class OrganizationMembership(models.Model):
    """Junction table: User belongs to Organization with a Role."""

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="memberships",
    )
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.DEVELOPER)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organization_memberships"
        unique_together = ("user", "organization")

    def __str__(self):
        return f"{self.user} @ {self.organization} ({self.role})"


class OrganizationInvite(models.Model):
    """Email-based invite for org enrollment."""

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="invites",
    )
    email = models.EmailField()
    role = models.CharField(max_length=20, choices=Role.choices, default=Role.DEVELOPER)
    token = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    expires_at = models.DateTimeField()
    accepted_at = models.DateTimeField(null=True, blank=True)
    # Who actually accepted. The invited `email` is only the address it was sent
    # to; the recipient picks their own username at signup, so record the real
    # account rather than inferring it from the email later.
    accepted_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="accepted_invites",
    )
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name="sent_invites",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "organization_invites"

    def __str__(self):
        return f"{self.email} → {self.organization} ({self.role})"

    def is_expired(self):
        return timezone.now() > self.expires_at

    def is_accepted(self):
        return self.accepted_at is not None

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(hours=72)
        super().save(*args, **kwargs)