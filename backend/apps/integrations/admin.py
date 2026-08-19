from django.contrib import admin

from .models import AIBriefing, IntegrationSyncLog


@admin.register(AIBriefing)
class AIBriefingAdmin(admin.ModelAdmin):
    list_display = ("title", "provider", "status", "window_hours", "created_at")
    list_filter = ("provider", "status")
    search_fields = ("title", "content")
    readonly_fields = ("created_at", "updated_at", "raw_response")


@admin.register(IntegrationSyncLog)
class IntegrationSyncLogAdmin(admin.ModelAdmin):
    list_display = (
        "target",
        "direction",
        "status",
        "records_processed",
        "created_at",
    )
    list_filter = ("target", "direction", "status")
    readonly_fields = ("created_at", "updated_at", "details")
