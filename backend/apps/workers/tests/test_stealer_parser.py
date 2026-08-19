from django.test import SimpleTestCase

from apps.workers.parsers.stealer import (
    detect_stealer_family,
    extract_domain,
    parse_stealer_log,
)


class StealerParserTests(SimpleTestCase):
    def test_detect_family(self):
        self.assertEqual(detect_stealer_family("RedLine Logs dump"), "redline")
        self.assertEqual(detect_stealer_family("vidar stolen"), "vidar")
        self.assertEqual(detect_stealer_family("plain text"), "unknown")

    def test_extract_domain(self):
        self.assertEqual(extract_domain("https://Login.Corp.Example/path"), "login.corp.example")
        self.assertEqual(extract_domain("corp.example"), "corp.example")

    def test_parse_colon_and_pipe_lines(self):
        content = """
# comment
https://mail.corp.example/login:alice@corp.example:Passw0rd!
https://vpn.corp.example | bob | hunter2
ignored-line-without-creds
"""
        parsed = parse_stealer_log(content, stealer_family="redline")
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].email, "alice@corp.example")
        self.assertEqual(parsed[0].domain, "mail.corp.example")
        self.assertEqual(parsed[0].password, "Passw0rd!")
        self.assertEqual(parsed[1].username, "bob")
        self.assertEqual(parsed[1].stealer_family, "redline")

    def test_email_login_is_kept_in_username_and_password_is_preserved(self):
        parsed = parse_stealer_log(
            "login.microsoftonline.com/:pickfoma21@holycross.ac.uk:M@ria310805"
        )
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].url, "https://login.microsoftonline.com/")
        self.assertEqual(parsed[0].domain, "login.microsoftonline.com")
        self.assertEqual(parsed[0].username, "pickfoma21@holycross.ac.uk")
        self.assertEqual(parsed[0].email, "pickfoma21@holycross.ac.uk")
        self.assertEqual(parsed[0].password, "M@ria310805")

    def test_colon_in_url_port_and_password_is_preserved(self):
        parsed = parse_stealer_log("https://example.com:8443/login:alice:p:a:ss")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].url, "https://example.com:8443/login")
        self.assertEqual(parsed[0].username, "alice")
        self.assertEqual(parsed[0].password, "p:a:ss")

    def test_parse_multiline_blocks(self):
        content = """
=== RedLine ===
URL: https://portal.acme.example/oauth
Username: eve@acme.example
Password: S3cret!
URL: ftp://files.acme.example
User: backup
Password: qwerty
"""
        parsed = parse_stealer_log(content)
        self.assertEqual(detect_stealer_family(content), "redline")
        self.assertEqual(len(parsed), 2)
        self.assertEqual(parsed[0].email, "eve@acme.example")
        self.assertEqual(parsed[1].username, "backup")
        self.assertEqual(parsed[1].domain, "files.acme.example")

    def test_dedupe(self):
        content = """
https://a.example:u:p
https://a.example:u:p
"""
        self.assertEqual(len(parse_stealer_log(content)), 1)
