from django.urls import include, path
from rest_framework.routers import DefaultRouter

from .log_scan_views import (
    LabAllowlistView,
    LabLoginScanViewSet,
    LogScanHitViewSet,
    LogScanLimitsView,
    LogScanViewSet,
    LogUploadChunkView,
    LogUploadViewSet,
)
from .osint_views import OSINTHealthProxyView, OSINTScanView, OSINTSitesView
from .views import IngestFeedsView, ParseStealerView, WorkerHealthView

router = DefaultRouter()
router.register(r"logs/uploads", LogUploadViewSet, basename="log-upload")
router.register(r"logs/scans", LogScanViewSet, basename="log-scan")
router.register(r"logs/hits", LogScanHitViewSet, basename="log-hit")
router.register(r"logs/credential-tests", LabLoginScanViewSet, basename="lab-login-scan")

urlpatterns = [
    path("workers/health/", WorkerHealthView.as_view(), name="workers-health"),
    path("workers/parse-stealer/", ParseStealerView.as_view(), name="workers-parse-stealer"),
    path("workers/ingest-feeds/", IngestFeedsView.as_view(), name="workers-ingest-feeds"),
    path("osint/health/", OSINTHealthProxyView.as_view(), name="osint-health"),
    path("osint/sites/", OSINTSitesView.as_view(), name="osint-sites"),
    path("osint/scan/", OSINTScanView.as_view(), name="osint-scan"),
    path("logs/limits/", LogScanLimitsView.as_view(), name="log-scan-limits"),
    path("logs/lab-allowlist/", LabAllowlistView.as_view(), name="lab-allowlist"),
    path("logs/uploads/chunk/", LogUploadChunkView.as_view(), name="log-upload-chunk"),
    path("", include(router.urls)),
]
