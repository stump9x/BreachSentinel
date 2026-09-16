from django.test import SimpleTestCase

from apps.workers.feeds.clients import _is_wokb_apt_source, _parse_wokb_apt_items


class WokbFeedTests(SimpleTestCase):
    def test_source_url_matching_is_narrow(self):
        self.assertTrue(
            _is_wokb_apt_source("https://www.wokb.cz/Blog/apt_blog.html")
        )
        self.assertFalse(_is_wokb_apt_source("https://www.wokb.cz/Blog/cyber_blog.html"))

    def test_table_rows_are_normalized_and_deduplicated(self):
        body = """
        <table>
          <tr><td>DATE</td><td>NAME</td><td>Info</td></tr>
          <tr>
            <td>10.9.26</td>
            <td><a href="https://example.com/report">APT report</a></td>
            <td>Threat research summary.</td><td>APT blog</td><td>Example</td>
          </tr>
          <tr>
            <td>10.9.26</td>
            <td><a href="https://example.com/report">APT report duplicate</a></td>
            <td>Duplicate.</td><td>APT blog</td><td>Example</td>
          </tr>
        </table>
        """
        items = _parse_wokb_apt_items(
            body,
            source_url="https://www.wokb.cz/Blog/apt_blog.html",
            limit=15,
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["title"], "APT report")
        self.assertEqual(items[0]["link"], "https://example.com/report")
        self.assertEqual(items[0]["summary"], "Threat research summary.")
        self.assertEqual(items[0]["published"], "2026-09-10T00:00:00+00:00")
