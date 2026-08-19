"""Purge stale non-Vietnam Wire RSS items so The Wire can rescan from today."""

from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.core.management.base import BaseCommand
from django.db.models import Q
from django.utils import timezone

from apps.intel.models import FeedSource, Threat


class Command(BaseCommand):
    help = (
        "Delete non-Vietnam Wire items older than WIRE_MAX_AGE_DAYS "
        "(default 7). Vietnam rows are kept forever when "
        "WIRE_VIETNAM_MAX_AGE_DAYS=0 (default)."
    )

    def add_arguments(self, parser):
        parser.add_argument(
            "--from-today",
            action="store_true",
            help="Delete every non-Vietnam Wire RSS item (keep all Vietnam-tagged).",
        )
        parser.add_argument(
            "--reset-feed-cache",
            action="store_true",
            help="Clear conditional RSS caches so feeds re-download on next sweep.",
        )

    def handle(self, *args, **options):
        now = timezone.now()
        general_days = int(getattr(settings, "WIRE_MAX_AGE_DAYS", 7) or 7)
        vietnam_days = int(getattr(settings, "WIRE_VIETNAM_MAX_AGE_DAYS", 0) or 0)

        rss_sources = (
            Threat.Source.NEWS,
            Threat.Source.CERT,
            Threat.Source.RANSOMWARE,
            Threat.Source.X,
        )
        base = Threat.objects.filter(source__in=rss_sources).filter(
            Q(raw_payload__has_key="feed_source")
            | Q(raw_payload__has_key="discovery")
            | Q(raw_payload__has_key="feed")
        )

        vn_old_count = 0
        if vietnam_days > 0:
            vietnam_cut = now - timedelta(days=vietnam_days)
            vn_old = base.filter(tags__slug="vietnam", published_at__lt=vietnam_cut)
            vn_old_count = vn_old.distinct().count()
            vn_old.distinct().delete()

        if options["from_today"]:
            stale = base.exclude(tags__slug="vietnam")
        else:
            cut = now - timedelta(days=general_days)
            stale = base.exclude(tags__slug="vietnam").filter(published_at__lt=cut)

        stale_count = stale.distinct().count()
        stale.distinct().delete()

        cache_cleared = 0
        if options["reset_feed_cache"]:
            cache_cleared = FeedSource.objects.filter(is_active=True).update(
                http_etag="",
                http_last_modified="",
                last_body_sha256="",
                processing_version=0,
                sitemap_last_scanned_at=None,
            )

        self.stdout.write(
            self.style.SUCCESS(
                f"Purged vietnam_old={vn_old_count} non_vietnam={stale_count} "
                f"feed_cache_reset={cache_cleared}"
            )
        )
