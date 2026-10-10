from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from authentication.password_validation_models import PasswordValidationConfig
from login_page.scanners.tc05_password_validation import scan_password_validation


class _Handler(BaseHTTPRequestHandler):
    vulnerable = False
    valid_password = "Correct!123"

    def _send(self, code: int, body: str, location: str | None = None, cookie: str | None = None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        if location:
            self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path.startswith("/login"):
            self._send(200, '<form method="POST" action="/login"><input name="username"><input type="password" name="password"><button type="submit">Login</button></form>')
            return
        if self.path.startswith("/dashboard"):
            cookies = self.headers.get("Cookie", "")
            if "auth=1" in cookies:
                self._send(200, "Welcome dashboard logout")
            else:
                self._send(302, "", "/login")
            return
        self._send(404, "Not found")

    def do_POST(self):
        if self.path != "/login":
            self._send(404, "Not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        data = parse_qs(self.rfile.read(length).decode())
        username = data.get("username", [""])[0]
        password = data.get("password", [""])[0]
        if username == "alice" and (self.vulnerable or password == self.valid_password):
            self._send(302, "", "/dashboard", "auth=1; Path=/")
            return
        self._send(200, "Invalid password")

    def log_message(self, *_args):
        return


def _server(vulnerable: bool):
    handler = type("Handler", (_Handler,), {"vulnerable": vulnerable})
    server = HTTPServer(("127.0.0.1", 0), handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def test_safe_login_rejects_wrong_password():
    server, _ = _server(False)
    try:
        result = scan_password_validation(
            f"http://127.0.0.1:{server.server_port}",
            PasswordValidationConfig(
                login_path="/login",
                authorized_username="alice",
                authorized_password="Correct!123",
                allow_browser_fallback=False,
                protected_urls=("/dashboard",),
            ),
        )
        assert result.status == "SAFE"
    finally:
        server.shutdown()
        server.server_close()


def test_vulnerable_login_accepts_wrong_password():
    server, _ = _server(True)
    try:
        result = scan_password_validation(
            f"http://127.0.0.1:{server.server_port}",
            PasswordValidationConfig(
                login_path="/login",
                authorized_username="alice",
                authorized_password="Correct!123",
                allow_browser_fallback=False,
                protected_urls=("/dashboard",),
            ),
        )
        assert result.status == "UNSAFE"
        assert result.details.get("assessment_state") == "CONFIRMED"
        assert result.details.get("confirmed_condition")
    finally:
        server.shutdown()
        server.server_close()
