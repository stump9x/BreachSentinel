from django.contrib import admin

from .models import AccessRequest, AccessRequestAudit


@admin.register(AccessRequest)
class AccessRequestAdmin(admin.ModelAdmin):
    list_display = (
        "username",
        "status",
        "role",
        "requested_at",
        "reviewed_by",
        "reviewed_at",
    )
    list_filter = ("status", "role")
    search_fields = ("user__username",)
    readonly_fields = ("requested_at", "updated_at")

    @admin.display(ordering="user__username", description="Username")
    def username(self, obj):
        return obj.user.username


@admin.register(AccessRequestAudit)
class AccessRequestAuditAdmin(admin.ModelAdmin):
    list_display = ("username", "action", "role", "actor", "created_at")
    list_filter = ("action", "role")
    search_fields = ("access_request__user__username", "actor__username")
    readonly_fields = ("access_request", "action", "role", "actor", "created_at")

    @admin.display(ordering="access_request__user__username", description="Username")
    def username(self, obj):
        return obj.access_request.user.username

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
