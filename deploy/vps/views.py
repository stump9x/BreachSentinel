from datetime import timedelta

from django.conf import settings
from django.db import IntegrityError
from django.utils import timezone
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.views import APIView

from apps.core.permissions import IsStaffUser
from apps.intel.models import Indicator
from apps.integrations.ai.briefings import (
    create_ai_briefing,
    create_keyword_summary,
    create_weekly_trending_digest,
)
from apps.integrations.ai.groq_pool import groq_keys_configured
from apps.integrations.ai.ner import extract_entities, flatten_entities
from apps.integrations.misp.client import misp_configured
from apps.integrations.misp.sync import (
    export_indicators_to_misp,
    import_attributes_from_misp,
)
from apps.integrations.github.client import github_configured
from apps.integrations.models import AIBriefing, GitHubScan, IntegrationSyncLog
from apps.integrations.searx.client import searx_configured, search_searx
from apps.integrations.searx.leak_scan import (
    ingest_searx_hits,
    scan_leak_keywords_via_searx,
)
from apps.integrations.serializers import (
    AIBriefingSerializer,
    ExtractEntitiesSerializer,
    GenerateBriefingSerializer,
    GitHubFindingSerializer,
    GitHubRepositorySummarySerializer,
    GitHubScanBulkDeleteSerializer,
    GitHubScanCreateSerializer,
    GitHubScanSerializer,
    IntegrationSyncLogSerializer,
    KeywordSummarySerializer,
    MISPSyncSerializer,
    SearxScanSerializer,
    SearxSearchSerializer,
)
from apps.integrations.tasks import (
    generate_daily_briefing,
    misp_export_task,
    misp_import_task,
    scan_searx_leaks,
    run_github_scan_task,
)


class AIBriefingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = AIBriefing.objects.all()
    serializer_class = AIBriefingSerializer


class IntegrationSyncLogViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = IntegrationSyncLog.objects.all()
    serializer_class = IntegrationSyncLogSerializer
    filterset_fields = ("target", "direction", "status")


class GenerateBriefingView(APIView):
    permission_classes = [IsStaffUser]

    def post(self, request):
        serializer = GenerateBriefingSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if data.get("async_mode"):
            task = generate_daily_briefing.delay(window_hours=data["window_hours"])
            return Response(
                {"task_id": task.id, "status": "queued"},
                status=status.HTTP_202_ACCEPTED,
            )
        briefing = create_ai_briefing(
            window_hours=data["window_hours"], user=request.user
        )
        return Response(
            AIBriefingSerializer(briefing).data,
            status=status.HTTP_201_CREATED,
        )


class KeywordSummaryView(APIView):
    permission_classes = [IsStaffUser]

    def post(self, request):
        serializer = KeywordSummarySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        briefing = create_keyword_summary(
            keyword=data["keyword"],
            window_hours=data["window_hours"],
            user=request.user,
        )
        return Response(
            AIBriefingSerializer(briefing).data,
            status=status.HTTP_201_CREATED,
        )


class WeeklyDigestView(APIView):
    permission_classes = [IsStaffUser]

    def post(self, request):
        briefing = create_weekly_trending_digest(user=request.user)
        return Response(
            AIBriefingSerializer(briefing).data,
            status=status.HTTP_201_CREATED,
        )


class ExtractEntitiesView(APIView):
    permission_classes = [IsStaffUser]

    def post(self, request):
        serializer = ExtractEntitiesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        text = serializer.validated_data["text"]
        persist = serializer.validated_data["persist"]
        entities = extract_entities(text)
        created = 0
        if persist:
            for row in flatten_entities(entities):
                _, was_created = Indicator.objects.update_or_create(
                    ioc_type=row["ioc_type"],
                    normalized_value=Indicator.normalize(row["ioc_type"], row["value"]),
                    defaults={
                        "value": row["value"],
                        "source": "ner_extract",
                        "confidence": Indicator.Confidence.MEDIUM,
                        "description": "Extracted by Phase 6 NER helper",
                        "last_seen": timezone.now(),
                        "is_active": True,
                    },
                )
                if was_created:
                    created += 1
        return Response(
            {
                "entities": entities,
                "persisted_created": created,
            }
        )


class MISPStatusView(APIView):
    def get(self, request):
        return Response(
            {
                "configured": misp_configured(),
                "verify_ssl": bool(getattr(settings, "MISP_VERIFY_SSL", True)),
            }
        )


class MISPSyncView(APIView):
    permission_classes = [IsStaffUser]

    def post(self, request):
        serializer = MISPSyncSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        direction = data["direction"]
        limit = data["limit"]
        async_mode = data["async_mode"]

        if async_mode:
            tasks = {}
            if direction in {"export", "both"}:
                tasks["export"] = misp_export_task.delay(limit=limit).id
            if direction in {"import", "both"}:
                tasks["import"] = misp_import_task.delay(limit=limit).id
            return Response(
                {"status": "queued", "tasks": tasks},
                status=status.HTTP_202_ACCEPTED,
            )

        logs = []
        if direction in {"export", "both"}:
            logs.append(export_indicators_to_misp(limit=limit))
        if direction in {"import", "both"}:
            logs.append(import_attributes_from_misp(limit=limit))
        return Response(
            {
                "status": "completed",
                "results": IntegrationSyncLogSerializer(logs, many=True).data,
            }
        )


class IntegrationsHealthView(APIView):
    """Authenticated recon of optional integration wiring (not for anonymous)."""

    def get(self, request):
        return Response(
            {
                "service": "breachsentinel-integrations",
                "phase": 6,
                "ai": {
                    "groq_configured": groq_keys_configured(),
                    "anthropic_configured": bool(
                        getattr(settings, "ANTHROPIC_API_KEY", "")
                    ),
                    "huggingface_configured": bool(
                        getattr(settings, "HUGGINGFACE_API_TOKEN", "")
                    ),
                },
                "forum_claims_clearnet": True,
                "misp_configured": misp_configured(),
                "searxng_configured": searx_configured(),
            }
        )


class ForumClaimIngestView(APIView):
    """Manual/webhook clearnet claim headlines → The Wire (metadata-only)."""

    permission_classes = [IsStaffUser]

    def post(self, request):
        from apps.integrations.serializers import ForumClaimIngestSerializer
        from apps.workers.feeds.forum_enrich import enrich_forum_items
        from apps.workers.feeds.forum_safety import prepare_wire_item_for_safety
        from apps.workers.services import ingest_rss_items
        from apps.workers.tasks import ingest_forum_claims

        serializer = ForumClaimIngestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if data.get("async_mode") and not data.get("items"):
            task = ingest_forum_claims.delay(limit_per_feed=25)
            return Response(
                {"task_id": task.id, "status": "queued"},
                status=status.HTTP_202_ACCEPTED,
            )

        prepared = []
        skipped_unsafe = 0
        for row in data.get("items") or []:
            link = str(row.get("link") or row.get("url") or "")
            item = {
                "title": row.get("title"),
                "link": link,
                "summary": "",
                "published": row.get("published") or "",
                "feed": row.get("feed") or "claim-webhook",
                "feed_url": link,
                "category": "news",
                "discovery": "forum-claim",
                "forum_claim": True,
                "metadata_only": True,
                "feed_notes": "claim/dark-web news webhook",
            }
            safe = prepare_wire_item_for_safety(item)
            if safe is None:
                skipped_unsafe += 1
                continue
            prepared.append(safe)

        prepared = enrich_forum_items(prepared)
        stats = ingest_rss_items(prepared, source_label="claim-webhook")
        stats["skipped_unsafe_webhook"] = skipped_unsafe
        stats["submitted"] = len(data.get("items") or [])
        return Response(stats)


class SearxStatusView(APIView):
    def get(self, request):
        from apps.integrations.web_reader.channels import channel_doctor

        doctor = channel_doctor()
        return Response(
            {
                "configured": searx_configured()
                or bool(doctor.get("exa_configured"))
                or any(
                    c.get("id") in {"x_twitter", "reddit_search"} and c.get("ok")
                    for c in doctor.get("channels") or []
                ),
                "engines": getattr(
                    settings,
                    "SEARXNG_ENGINES",
                    "duckduckgo,brave,bing,gitlab,bitbucket,npm,stackoverflow,qwant,ahmia",
                ),
                "channels": doctor.get("channels") or [],
                "query_packs": doctor.get("query_packs"),
                "enrich": doctor.get("enrich"),
                "web_reader": next(
                    (
                        c
                        for c in doctor.get("channels") or []
                        if c.get("id") == "web_reader"
                    ),
                    {},
                ),
                "exa": next(
                    (c for c in doctor.get("channels") or [] if c.get("id") == "exa"),
                    {},
                ),
            }
        )


class SearxSearchView(APIView):
    """Ad-hoc privacy-respecting metasearch (OSINT). Optional persist → DataLeak."""

    def post(self, request):
        from apps.integrations.web_reader.channels.reddit import (
            reddit_search_configured,
            search_reddit,
        )
        from apps.integrations.web_reader.channels.x_twitter import (
            x_twitter_configured,
        )
        from apps.integrations.web_reader.exa import (
            discover_exa_hits,
            exa_configured as _exa_ok,
            should_call_exa,
        )

        if (
            not searx_configured()
            and not _exa_ok()
            and not x_twitter_configured()
            and not reddit_search_configured()
        ):
            return Response(
                {
                    "detail": (
                        "No discovery channel configured. Set SEARXNG_URL, "
                        "EXA_API_KEY, X cookies, and/or REDDIT_COOKIE."
                    ),
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        serializer = SearxSearchSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        engines = data.get("engines") or None

        from apps.integrations.searx.leak_scan import merge_hits_balanced
        from apps.integrations.web_reader.channels.x_twitter import (
            search_x_twitter_detail,
        )
        from apps.integrations.web_reader.phrase import filter_hits_by_phrase

        groups: list = []
        channel_stats: dict = {}
        phrase = data["query"]

        # Prefer free/cheap channels first — Exa only as gated fallback.
        if x_twitter_configured():
            x_detail = search_x_twitter_detail(
                data["query"], limit=min(data["limit"], 15)
            )
            x_raw = list(x_detail.get("hits") or [])
            x_hits = filter_hits_by_phrase(x_raw, phrase)
            groups.append(x_hits)
            channel_stats["x_twitter"] = {
                "count": len(x_hits),
                "raw": len(x_raw),
                "error": x_detail.get("error") if not x_hits else None,
            }
        if reddit_search_configured():
            reddit_raw = search_reddit(data["query"], limit=min(data["limit"], 20))
            reddit_hits = filter_hits_by_phrase(reddit_raw, phrase)
            groups.append(reddit_hits)
            channel_stats["reddit_search"] = {
                "count": len(reddit_hits),
                "raw": len(reddit_raw),
                "error": None if reddit_hits else ("no_phrase_match" if reddit_raw else "no_hits"),
            }
        if searx_configured():
            searx_raw = search_searx(
                data["query"],
                engines=engines,
                limit=data["limit"],
                exact=data["exact"],
            )
            searx_hits = filter_hits_by_phrase(searx_raw, phrase)
            groups.append(searx_hits)
            channel_stats["searx"] = {
                "count": len(searx_hits),
                "raw": len(searx_raw),
                "error": None,
            }

        kept_before_exa = sum(len(g) for g in groups)
        force_exa = bool(data.get("use_exa"))
        if should_call_exa(
            purpose="osint",
            kept_hits=kept_before_exa,
            force=force_exa,
            configured=_exa_ok(),
        ):
            exa_raw = discover_exa_hits(
                data["query"], limit=min(max(data["limit"], 10), 20)
            )
            exa_hits = filter_hits_by_phrase(exa_raw, phrase)
            groups.append(exa_hits)
            channel_stats["exa"] = {
                "count": len(exa_hits),
                "raw": len(exa_raw),
                "error": None,
                "skipped": False,
            }
        elif _exa_ok():
            channel_stats["exa"] = {
                "count": 0,
                "raw": 0,
                "error": None,
                "skipped": True,
                "reason": (
                    "mode_off"
                    if str(getattr(settings, "EXA_OSINT_MODE", "fallback")).lower()
                    == "off"
                    else "enough_hits"
                ),
            }

        results = merge_hits_balanced(*groups, limit=data["limit"])
        # Final safety net: never surface/persist phrase-less hits.
        results = filter_hits_by_phrase(results, phrase)
        # Prefer X/Reddit cards near the top (still newest-first within each band).
        from apps.integrations.web_reader.recency import hit_recency_ts

        _social = {"x_twitter", "reddit_search"}
        results.sort(
            key=lambda h: (
                0 if str(h.get("engine") or "") in _social else 1,
                -hit_recency_ts(h),
            )
        )
        persist_stats = None
        if data["persist"] and results:
            persist_stats = ingest_searx_hits(
                results,
                keyword=data["query"],
                rule=None,
                recipient=request.user if request.user.is_authenticated else None,
            )
        return Response(
            {
                "query": data["query"],
                "count": len(results),
                "results": results,
                "persist": persist_stats,
                "channels": channel_stats,
            }
        )


class SearxScanView(APIView):
    """Trigger Watcher-style keyword sweep across SearxNG. Staff only."""

    permission_classes = [IsStaffUser]

    def post(self, request):
        serializer = SearxScanSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        if not searx_configured():
            from apps.integrations.web_reader.exa import exa_configured as _exa_ok

            if not _exa_ok():
                return Response(
                    {"detail": "SearxNG is not configured.", "skipped": True},
                    status=status.HTTP_503_SERVICE_UNAVAILABLE,
                )
        if data["async_mode"]:
            task = scan_searx_leaks.delay(
                limit_per_keyword=data["limit_per_keyword"]
            )
            return Response(
                {"task_id": task.id, "status": "queued"},
                status=status.HTTP_202_ACCEPTED,
            )
        result = scan_leak_keywords_via_searx(
            limit_per_keyword=data["limit_per_keyword"]
        )
        return Response({"status": "completed", "result": result})


class GitHubScanViewSet(
    mixins.CreateModelMixin,
    mixins.DestroyModelMixin,
    viewsets.ReadOnlyModelViewSet,
):
    queryset = GitHubScan.objects.select_related("created_by").all()
    serializer_class = GitHubScanSerializer
    permission_classes = [IsStaffUser]
    filterset_fields = ("status",)
    search_fields = ("keyword",)
    ordering_fields = ("created_at", "file_count", "alert_count", "repository_count")
    ordering = ("-created_at", "-id")

    def get_throttles(self):
        self.throttle_scope = (
            "github_scan_create" if getattr(self, "action", None) == "create" else None
        )
        return super().get_throttles()

    def create(self, request, *args, **kwargs):
        if not github_configured():
            return Response(
                {"detail": "GitHub Scanner is not configured. Set GITHUB_TOKEN."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        serializer = GitHubScanCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        stale_minutes = max(
            5,
            int(getattr(settings, "GITHUB_SCAN_STALE_MINUTES", 20) or 20),
        )
        stale_cutoff = timezone.now() - timedelta(minutes=stale_minutes)
        GitHubScan.objects.filter(
            status__in=(GitHubScan.Status.QUEUED, GitHubScan.Status.RUNNING),
            updated_at__lt=stale_cutoff,
        ).update(
            status=GitHubScan.Status.FAILED,
            active_slot=None,
            error_message="Scan exceeded the execution window.",
            completed_at=timezone.now(),
        )
        active = GitHubScan.objects.filter(
            status__in=(GitHubScan.Status.QUEUED, GitHubScan.Status.RUNNING)
        ).first()
        if active is not None:
            return Response(
                {
                    "detail": "A GitHub scan is already queued or running.",
                    "scan_id": active.id,
                },
                status=status.HTTP_409_CONFLICT,
            )
        try:
            max_results = max(
                1,
                min(int(getattr(settings, "GITHUB_SCAN_MAX_RESULTS", 1500) or 1500), 1500),
            )
            scan = GitHubScan.objects.create(
                keyword=serializer.validated_data["keyword"],
                max_results=max_results,
                created_by=request.user,
            )
        except IntegrityError:
            active = GitHubScan.objects.filter(active_slot=True).first()
            return Response(
                {
                    "detail": "A GitHub scan is already queued or running.",
                    "scan_id": active.id if active else None,
                },
                status=status.HTTP_409_CONFLICT,
            )
        try:
            task = run_github_scan_task.delay(scan.id)
        except Exception:  # noqa: BLE001
            scan.status = GitHubScan.Status.FAILED
            scan.error_message = "Task queue unavailable."
            scan.completed_at = timezone.now()
            scan.save(
                update_fields=[
                    "status",
                    "error_message",
                    "completed_at",
                    "updated_at",
                ]
            )
            return Response(
                {"detail": "Unable to queue GitHub scan.", "scan_id": scan.id},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(
            {
                **GitHubScanSerializer(scan).data,
                "task_id": task.id,
            },
            status=status.HTTP_202_ACCEPTED,
        )

    @action(detail=False, methods=["get"])
    def status(self, request):
        return Response({"configured": github_configured()})

    def destroy(self, request, *args, **kwargs):
        scan = self.get_object()
        if scan.status in {GitHubScan.Status.QUEUED, GitHubScan.Status.RUNNING}:
            return Response(
                {"detail": "Cannot delete a queued or running scan."},
                status=status.HTTP_409_CONFLICT,
            )
        scan_id = scan.id
        scan.delete()
        return Response({"deleted": [scan_id]}, status=status.HTTP_200_OK)

    @action(detail=False, methods=["post"], url_path="bulk-delete")
    def bulk_delete(self, request):
        serializer = GitHubScanBulkDeleteSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        ids = list(dict.fromkeys(serializer.validated_data["ids"]))
        qs = GitHubScan.objects.filter(id__in=ids)
        blocked = list(
            qs.filter(
                status__in=(GitHubScan.Status.QUEUED, GitHubScan.Status.RUNNING)
            ).values_list("id", flat=True)
        )
        deletable = qs.exclude(id__in=blocked)
        deleted_ids = list(deletable.values_list("id", flat=True))
        deletable.delete()
        return Response(
            {
                "deleted": deleted_ids,
                "blocked": blocked,
            },
            status=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        scan = self.get_object()
        queryset = scan.findings.all()
        severity = (request.query_params.get("severity") or "").strip().lower()
        alerts_only = (request.query_params.get("alerts_only") or "").lower()
        repository = (request.query_params.get("repository") or "").strip()
        after_id = (request.query_params.get("after_id") or "").strip()
        if severity in {"info", "medium", "high", "critical"}:
            queryset = queryset.filter(severity=severity)
        if alerts_only in {"1", "true", "yes"}:
            queryset = queryset.exclude(alert_types=[])
        if repository:
            queryset = queryset.filter(repository=repository[:512])
        if after_id.isdigit():
            # Incremental stream: only rows persisted after the last seen id.
            queryset = queryset.filter(id__gt=int(after_id)).order_by("id")
        page = self.paginate_queryset(queryset)
        serializer = GitHubFindingSerializer(page or queryset, many=True)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)

    @action(detail=True, methods=["get"])
    def repositories(self, request, pk=None):
        """Repo rollup for progressive UI (Details expands files per repo)."""
        from django.db.models import Count, Q, Sum

        scan = self.get_object()
        rows = (
            scan.findings.values("repository", "owner", "repository_url")
            .annotate(
                file_count=Count("id"),
                match_total=Sum("keyword_matches"),
                alert_count=Count("id", filter=~Q(alert_types=[])),
                non_text_count=Count("id", filter=Q(is_text_file=False)),
                text_count=Count("id", filter=Q(is_text_file=True)),
            )
            # Hide weak repos that only have a single .txt hit.
            .exclude(non_text_count=0, text_count=1, file_count=1)
            # Repos with real secret alerts first.
            .order_by(
                "-alert_count",
                "-non_text_count",
                "-match_total",
                "-file_count",
                "repository",
            )
        )
        page = self.paginate_queryset(rows)
        serializer = GitHubRepositorySummarySerializer(page or rows, many=True)
        if page is not None:
            return self.get_paginated_response(serializer.data)
        return Response(serializer.data)
