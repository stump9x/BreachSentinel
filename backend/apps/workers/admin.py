from django.contrib import admin

from apps.workers.models import LogScan, LogScanHit, LogUpload


@admin.register(LogUpload)
class LogUploadAdmin(admin.ModelAdmin):
    list_display = ("id", "original_name", "size_bytes", "uploaded_by", "created_at")
    search_fields = ("original_name", "sha256")
    readonly_fields = ("sha256", "stored_path", "size_bytes", "created_at", "updated_at")


@admin.register(LogScan)
class LogScanAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "keyword",
        "status",
        "hit_count",
        "files_scanned",
        "created_by",
        "created_at",
    )
    list_filter = ("status",)
    search_fields = ("keyword",)


@admin.register(LogScanHit)
class LogScanHitAdmin(admin.ModelAdmin):
    list_display = ("id", "domain", "username", "is_kept", "scan", "created_at")
    list_filter = ("is_kept",)
    search_fields = ("domain", "username", "email", "url")
    readonly_fields = ("password", "raw_line")
