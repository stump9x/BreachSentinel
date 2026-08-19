"""Remove untranslated news while preserving non-news intelligence records."""

from __future__ import annotations

from django.core.management.base import BaseCommand
from django.db.models import Q

from apps.intel.models import Threat


class Command(BaseCommand):
    help = "Delete untranslated News/RSS threats and report other hidden records."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Report counts without deleting untranslated news.",
        )

    def handle(self, *args, **options):
        untranslated = Threat.objects.filter(
            Q(title_vi="") | Q(title_vi__isnull=True)
        )
        news = untranslated.filter(source=Threat.Source.NEWS)
        news_count = news.count()
        other_count = untranslated.exclude(source=Threat.Source.NEWS).count()

        if not options["dry_run"] and news_count:
            news.delete()

        action = "would_delete" if options["dry_run"] else "deleted"
        self.stdout.write(
            self.style.SUCCESS(
                f"Untranslated Wire cleanup · {action}_news={news_count} "
                f"hidden_non_news={other_count}"
            )
        )
