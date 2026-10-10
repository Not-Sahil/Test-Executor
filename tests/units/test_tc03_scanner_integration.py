from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from login_page.scanners.tc03_blank_credentials import TC03Config, scan_blank_credentials


class _BlankCredentialHandler(BaseHTTPRequestHandler):
    server_version = "TC03TestServer/1.0"

    def log_message(self, format, *args):  # noqa: A002
        return

    def do_GET(self):  # noqa: N802
        if self.path.startswith("/login"):
            body = (
                '<html><form method="POST" action="/login">'
                '<input type="hidden" name="csrf" value="abc123">'
                '<input name="username">'
                '<input name="password" type="password">'
                '<button type="submit">Login</button>'
                '</form></html>'
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())
            return

        if self.path == "/dashboard":
            if self.headers.get("Cookie") == "session=authenticated":
                body = "<html>Welcome Alice <a>Logout</a></html>"
                self.send_response(200)
            else:
                body = "<html>Login required</html>"
                self.send_response(302)
                self.send_header("Location", "/login")
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):  # noqa: N802
        if self.path != "/login":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode()
        form = parse_qs(raw, keep_blank_values=True)
        username = form.get("username", [None])[0]
        password = form.get("password", [None])[0]
        csrf = form.get("csrf", [None])[0]

        if csrf != "abc123":
            body = "CSRF token required"
            self.send_response(403)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body.encode())))
            self.end_headers()
            self.wfile.write(body.encode())
            return

        # Intended vulnerability for the integration test: Alice authenticates
        # with a blank password.
        if username == "alice" and password == "":
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie", "session=authenticated; Path=/")
            self.end_headers()
            return

        body = "Invalid username or password"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body.encode())))
        self.end_headers()
        self.wfile.write(body.encode())


def test_tc03_confirms_blank_password_with_authorized_username():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _BlankCredentialHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        target = f"http://127.0.0.1:{server.server_port}"
        result = scan_blank_credentials(
            target,
            TC03Config(
                login_path="/login",
                verify_tls=True,
                timeout=2.0,
                min_delay_seconds=0.0,
                max_attempts=10,
                include_optional_variants=False,
                stop_on_confirmed=True,
                authorized_username="alice",
                protected_urls=("/dashboard",),
                allow_browser_fallback=False,
            ),
        )

        assert result.status == "UNSAFE"
        assert result.details["assessment_state"] == "CONFIRMED"
        assert result.details["confirmed_variant"]["variant"]["case_id"] == "TC03-D"
        assert result.details["confirmed_variant"]["authenticated"] is True
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
