from django.contrib import admin
from .models import Server, PublicKey


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "ip_address", "ssh_user", "is_active", "created_at")
    list_filter = ("is_active", "organization")
    search_fields = ("name", "ip_address", "token_prefix")
    raw_id_fields = ("organization",)


@admin.register(PublicKey)
class PublicKeyAdmin(admin.ModelAdmin):
    list_display = ("key_title", "user", "organization", "is_active", "created_at")
    list_filter = ("is_active", "organization")
    search_fields = ("key_title", "user__username", "user__email")
    raw_id_fields = ("user", "organization")
    filter_horizontal = ("servers",)