from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .views import (
    AIBriefingViewSet,
    ExtractEntitiesView,
    ForumClaimIngestView,
    GenerateBriefingView,
    GitHubScanViewSet,
    IntegrationSyncLogViewSet,
    IntegrationsHealthView,
    KeywordSummaryView,
    MISPStatusView,
    MISPSyncView,
    SearxScanView,
    SearxSearchView,
    SearxStatusView,
    WeeklyDigestView,
)

router = DefaultRouter()
router.register(r"ai/briefings", AIBriefingViewSet, basename="ai-briefing")
router.register(r"integrations/logs", IntegrationSyncLogViewSet, basename="integration-log")
router.register(r"github/scans", GitHubScanViewSet, basename="github-scan")

urlpatterns = [
    path("integrations/health/", IntegrationsHealthView.as_view(), name="integrations-health"),
    path(
        "integrations/forum-claims/",
        ForumClaimIngestView.as_view(),
        name="forum-claims-ingest",
    ),
    path("ai/briefings/generate/", GenerateBriefingView.as_view(), name="ai-briefing-generate"),
    path("ai/keyword-summary/", KeywordSummaryView.as_view(), name="ai-keyword-summary"),
    path("ai/weekly-digest/", WeeklyDigestView.as_view(), name="ai-weekly-digest"),
    path("ai/extract-entities/", ExtractEntitiesView.as_view(), name="ai-extract-entities"),
    path("misp/status/", MISPStatusView.as_view(), name="misp-status"),
    path("misp/sync/", MISPSyncView.as_view(), name="misp-sync"),
    path("searx/status/", SearxStatusView.as_view(), name="searx-status"),
    path("searx/search/", SearxSearchView.as_view(), name="searx-search"),
    path("searx/scan/", SearxScanView.as_view(), name="searx-scan"),
    path("", include(router.urls)),
]
