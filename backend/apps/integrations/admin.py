from django.contrib import admin

from .models import AIBriefing, DarkWebInvestigation, DarkWebSource, IntegrationSyncLog


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


class DarkWebSourceInline(admin.TabularInline):
    model = DarkWebSource
    extra = 0
    fields = ("engine", "title", "fetch_status", "url", "created_at")
    readonly_fields = fields


@admin.register(DarkWebInvestigation)
class DarkWebInvestigationAdmin(admin.ModelAdmin):
    list_display = (
        "query",
        "preset",
        "status",
        "source_count",
        "scraped_count",
        "provider",
        "created_at",
    )
    list_filter = ("preset", "status", "provider")
    search_fields = ("query", "refined_query", "summary")
    readonly_fields = (
        "created_at",
        "updated_at",
        "started_at",
        "completed_at",
        "engine_stats",
        "parameters",
    )
    inlines = (DarkWebSourceInline,)
