from django.contrib import admin
from .models import Organization, OrganizationMembership, OrganizationInvite, ApiKey


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "is_active", "created_at")
    list_filter = ("is_active",)
    search_fields = ("name", "slug")
    prepopulated_fields = {"slug": ("name",)}


@admin.register(OrganizationMembership)
class OrganizationMembershipAdmin(admin.ModelAdmin):
    list_display = ("user", "organization", "role", "created_at")
    list_filter = ("role", "organization")
    search_fields = ("user__username", "user__email", "organization__name")
    raw_id_fields = ("user",)


@admin.register(OrganizationInvite)
class OrganizationInviteAdmin(admin.ModelAdmin):
    list_display = ("email", "organization", "role", "token", "expires_at", "accepted_at", "is_expired")
    list_filter = ("role", "organization")
    search_fields = ("email", "organization__name")
    raw_id_fields = ("organization", "created_by")
    readonly_fields = ("token", "created_at")


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "key_prefix", "scopes", "is_active", "last_used_at", "created_at")
    list_filter = ("is_active", "organization")
    search_fields = ("name", "organization__name")
    raw_id_fields = ("organization", "created_by")
    readonly_fields = ("key_prefix", "key_hash", "created_at")