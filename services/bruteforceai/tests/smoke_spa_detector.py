"""Playwright smoke test against a local synthetic SPA login form."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading

from bs_multisignal_detector import _attempt_login_multisignal


HTML = b"""<!doctype html><html><body>
<form id="login-form">
  <input id="email" type="email">
  <input id="password" type="password">
  <button type="submit">Sign in</button>
</form>
<div id="message"></div>
<script>
document.querySelector('#login-form').addEventListener('submit', (event) => {
  event.preventDefault();
  const email = document.querySelector('#email').value;
  const password = document.querySelector('#password').value;
  setTimeout(() => {
    if (email === 'lab@example.test' && password === 'correct-pass') {
      localStorage.setItem('lab_auth_token', 'synthetic-token');
      history.pushState({}, '', '/dashboard');
      document.querySelector('#login-form').remove();
      document.querySelector('#message').textContent = 'Welcome Dashboard - Logout';
    } else {
      document.querySelector('#message').textContent = 'Invalid credentials';
    }
  }, 250);
});
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(HTML)))
        self.end_headers()
        self.wfile.write(HTML)

    def log_message(self, *_args):
        return


class FakeBruteForceAI:
    retry_attempts = 1
    show_browser = False
    browser_wait = 0
    proxy = None
    dom_threshold = 100
    external_ip = "127.0.0.1"

    def __init__(self):
        self.attempts = []

    def _get_random_user_agent(self):
        return None

    def _save_brute_force_attempt(self, value):
        self.attempts.append(value)


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{server.server_port}/login"
selectors = {
    "login_username_selector": "#email",
    "login_password_selector": "#password",
    "login_submit_button_selector": "button[type='submit']",
    "failed_dom_length": len(HTML),
}

try:
    failed = FakeBruteForceAI()
    assert _attempt_login_multisignal(
        failed, url, selectors, "lab@example.test", "wrong-pass"
    ) is False
    assert failed.attempts[-1]["success"] is False

    succeeded = FakeBruteForceAI()
    assert _attempt_login_multisignal(
        succeeded, url, selectors, "lab@example.test", "correct-pass"
    ) is True
    assert succeeded.attempts[-1]["success"] is True
    print("spa_smoke_test=passed")
finally:
    server.shutdown()
    server.server_close()
