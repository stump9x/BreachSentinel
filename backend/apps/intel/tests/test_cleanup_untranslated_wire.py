from io import StringIO

from django.core.management import call_command
from django.test import TestCase

from apps.intel.models import Threat


class CleanupUntranslatedWireTests(TestCase):
    def test_deletes_only_untranslated_news(self):
        untranslated_news = Threat.objects.create(
            title="Untranslated RSS story",
            source=Threat.Source.NEWS,
        )
        translated_news = Threat.objects.create(
            title="Translated RSS story",
            title_vi="Tin RSS đã dịch",
            source=Threat.Source.NEWS,
        )
        untranslated_ransomware = Threat.objects.create(
            title="Ransomware record pending translation",
            source=Threat.Source.RANSOMWARE,
        )

        out = StringIO()
        call_command("cleanup_untranslated_wire", stdout=out)

        self.assertFalse(Threat.objects.filter(pk=untranslated_news.pk).exists())
        self.assertTrue(Threat.objects.filter(pk=translated_news.pk).exists())
        self.assertTrue(
            Threat.objects.filter(pk=untranslated_ransomware.pk).exists()
        )
        self.assertIn("deleted_news=1", out.getvalue())
        self.assertIn("hidden_non_news=1", out.getvalue())

    def test_dry_run_does_not_delete(self):
        threat = Threat.objects.create(
            title="Pending RSS story",
            source=Threat.Source.NEWS,
        )

        call_command("cleanup_untranslated_wire", dry_run=True)

        self.assertTrue(Threat.objects.filter(pk=threat.pk).exists())
