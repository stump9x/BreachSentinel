from celery import shared_task

from apps.integrations.ai.briefings import (
    create_ai_briefing,
    create_keyword_summary,
    create_weekly_trending_digest,
)
from apps.integrations.misp.sync import (
    export_indicators_to_misp,
    import_attributes_from_misp,
)


@shared_task(name="integrations.generate_daily_briefing")
def generate_daily_briefing(window_hours: int = 24) -> dict:
    briefing = create_ai_briefing(window_hours=window_hours)
    return {
        "id": briefing.id,
        "status": briefing.status,
        "provider": briefing.provider,
    }


@shared_task(name="integrations.generate_weekly_digest")
def generate_weekly_digest() -> dict:
    briefing = create_weekly_trending_digest()
    return {
        "id": briefing.id,
        "status": briefing.status,
        "provider": briefing.provider,
    }


@shared_task(name="integrations.misp_export")
def misp_export_task(limit: int = 50) -> dict:
    log = export_indicators_to_misp(limit=limit)
    return {
        "id": log.id,
        "status": log.status,
        "message": log.message,
        "records_processed": log.records_processed,
    }


@shared_task(name="integrations.misp_import")
def misp_import_task(limit: int = 50) -> dict:
    log = import_attributes_from_misp(limit=limit)
    return {
        "id": log.id,
        "status": log.status,
        "message": log.message,
        "records_processed": log.records_processed,
    }


@shared_task(name="integrations.keyword_summary")
def keyword_summary_task(keyword: str, window_hours: int = 168) -> dict:
    briefing = create_keyword_summary(keyword=keyword, window_hours=window_hours)
    return {
        "id": briefing.id,
        "status": briefing.status,
        "provider": briefing.provider,
    }


@shared_task(bind=True, name="integrations.scan_searx_leaks", max_retries=2)
def scan_searx_leaks(self, limit_per_keyword: int = 15) -> dict:
    """Watcher-style periodic SearxNG keyword sweep → Data Leaks."""
    from apps.integrations.searx.leak_scan import scan_leak_keywords_via_searx

    try:
        return scan_leak_keywords_via_searx(limit_per_keyword=limit_per_keyword)
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc, countdown=60) from exc


@shared_task(bind=True, name="integrations.enrich_searx_leak", max_retries=2)
def enrich_searx_leak(self, leak_id: int) -> dict:
    """Fetch page body for a Searx/Exa DataLeak and attach secret evidence."""
    from apps.intel.models import DataLeak
    from apps.integrations.web_reader.enrich import enrich_leak_from_url

    try:
        leak = DataLeak.objects.filter(pk=leak_id).first()
        if not leak:
            return {"skipped": True, "reason": "missing"}
        keyword = str((leak.metadata or {}).get("keyword") or "")
        return enrich_leak_from_url(leak, keyword=keyword)
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc, countdown=45) from exc


@shared_task(bind=True, name="integrations.discover_unstable_intel_sites", max_retries=2)
def discover_unstable_intel_sites(self, limit_per_domain: int = 5) -> dict:
    """Searx fallback for curated sites without stable RSS → filtered Wire items."""
    from apps.integrations.searx.site_discovery import discover_unstable_site_items
    from apps.workers.services import ingest_rss_items

    try:
        items, discovery = discover_unstable_site_items(
            limit_per_domain=limit_per_domain
        )
        stats = ingest_rss_items(items, source_label="searx-site")
        return {
            **stats,
            **discovery,
            "fetched": len(items),
        }
    except Exception as exc:  # noqa: BLE001
        raise self.retry(exc=exc, countdown=120) from exc


@shared_task(bind=True, name="integrations.discover_exa_wire", max_retries=2)
def discover_exa_wire(
    self, limit: int | None = None, limit_per_domain: int | None = None
) -> dict:
    """Exa semantic CTI + curated domains → The Wire (Threat ingest)."""
    from django.conf import settings

    from apps.core.task_lock import single_flight
    from apps.integrations.web_reader.exa_wire import discover_exa_wire_items
    from apps.workers.services import ingest_rss_items

    if limit is None:
        limit = int(getattr(settings, "EXA_WIRE_LIMIT", 8) or 8)
    if limit_per_domain is None:
        limit_per_domain = int(getattr(settings, "EXA_WIRE_LIMIT_PER_DOMAIN", 2) or 2)

    with single_flight("integrations.discover_exa_wire", ttl_sec=900) as acquired:
        if not acquired:
            return {"skipped": True, "reason": "already_running"}
        try:
            items, discovery = discover_exa_wire_items(
                limit=limit, limit_per_domain=limit_per_domain
            )
            if discovery.get("skipped"):
                return {**discovery, "fetched": 0, "created": 0}
            stats = ingest_rss_items(items, source_label="exa-wire")
            return {
                **stats,
                **discovery,
                "fetched": len(items),
            }
        except Exception as exc:  # noqa: BLE001
            raise self.retry(exc=exc, countdown=120) from exc


@shared_task(bind=True, name="integrations.discover_x_wire", max_retries=2)
def discover_x_wire(
    self, limit_per_account: int | None = None
) -> dict:
    """Curated X CTI accounts → The Wire (Threat ingest)."""
    from django.conf import settings

    from apps.core.task_lock import single_flight
    from apps.integrations.web_reader.x_wire import discover_x_wire_items
    from apps.workers.services import ingest_rss_items

    if limit_per_account is None:
        limit_per_account = int(
            getattr(settings, "X_WIRE_LIMIT_PER_ACCOUNT", 8) or 8
        )

    with single_flight("integrations.discover_x_wire", ttl_sec=900) as acquired:
        if not acquired:
            return {"skipped": True, "reason": "already_running"}
        try:
            items, discovery = discover_x_wire_items(
                limit_per_account=limit_per_account
            )
            if discovery.get("skipped"):
                return {**discovery, "fetched": 0, "created": 0}
            stats = ingest_rss_items(items, source_label="x-wire")
            return {
                **stats,
                **discovery,
                "fetched": len(items),
            }
        except Exception as exc:  # noqa: BLE001
            raise self.retry(exc=exc, countdown=120) from exc


@shared_task(bind=True, name="integrations.translate_threat_titles", max_retries=1)
def translate_threat_titles_task(
    self, threat_ids: list[int] | None = None, limit: int = 40
) -> dict:
    """Translate Wire titles first, then summaries without blocking ingestion."""
    from apps.core.task_lock import single_flight
    from apps.integrations.ai.summary_translate import translate_summaries
    from apps.integrations.ai.translate import translate_threats

    # One translator at a time avoids Google/Ollama pile-ups fighting RSS workers.
    with single_flight("integrations.translate_threat_titles", ttl_sec=900) as acquired:
        if not acquired:
            return {"skipped": True, "reason": "already_running"}
        try:
            title_stats = translate_threats(threat_ids, limit=limit)
            summary_stats = translate_summaries(
                threat_ids,
                limit=min(max(1, limit), 15),
            )
            return {"titles": title_stats, "summaries": summary_stats}
        except Exception as exc:  # noqa: BLE001
            raise self.retry(exc=exc, countdown=30) from exc


@shared_task(name="integrations.run_github_scan")
def run_github_scan_task(scan_id: int) -> dict:
    from django.db import transaction

    from apps.integrations.github.scanner import run_github_scan
    from apps.integrations.models import GitHubScan

    with transaction.atomic():
        scan = GitHubScan.objects.select_for_update().get(pk=scan_id)
        if scan.status != GitHubScan.Status.QUEUED:
            return {
                "id": scan.id,
                "status": scan.status,
                "skipped": True,
            }
        scan.status = GitHubScan.Status.RUNNING
        scan.save(update_fields=["status", "updated_at"])
    run_github_scan(scan)
    return {
        "id": scan.id,
        "status": scan.status,
        "repositories": scan.repository_count,
        "files": scan.file_count,
        "alerts": scan.alert_count,
    }
