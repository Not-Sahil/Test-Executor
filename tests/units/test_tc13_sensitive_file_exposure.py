from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from pre_login.scanners.tc13_sensitive_file_exposure import (
    scan_sensitive_file_exposure,
    _analyse_text,
)


def _mock_response(status_code: int = 200, content: bytes = b"", headers: dict | None = None):
    mock = MagicMock()
    mock.status_code = status_code
    mock.content = content
    mock.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
    return mock


def test_spa_soft_404_classified_as_safe():
    """Verify that an SPA soft-404 returning React HTML for /config.php is classified as SAFE."""
    react_html = (
        b'<!doctype html><html lang="en"><head><title>Devportal</title>'
        b'<script defer="defer" src="/static/js/main.js"></script></head>'
        b'<body><div id="root"></div></body></html>'
    )
    resp = _mock_response(200, react_html, {"Content-Type": "text/html; charset=utf-8"})

    with patch("pre_login.scanners.tc13_sensitive_file_exposure.request", return_value=resp):
        res = scan_sensitive_file_exposure("https://example.com", max_probes=10)
        assert res["status"] == "SAFE"
        # All tested probes should be recognized as application fallback
        assert res["details"]["statistics"]["unsafe_count"] == 0
        assert all(t.get("likely_application_fallback") for t in res["details"]["tested"])


def test_waf_request_rejected_page_classified_as_safe():
    """Verify that WAF block pages returning 200 OK with 'Request Rejected' are classified as SAFE."""
    waf_html = b"<html><head><title>Request Rejected</title></head><body>The requested URL was rejected.</body></html>"
    resp = _mock_response(200, waf_html, {"Content-Type": "text/html; charset=utf-8"})

    with patch("pre_login.scanners.tc13_sensitive_file_exposure.request", return_value=resp):
        res = scan_sensitive_file_exposure("https://example.com", max_probes=10)
        assert res["status"] == "SAFE"
        assert res["details"]["statistics"]["unsafe_count"] == 0


def test_genuine_php_config_exposure_classified_as_unsafe():
    """Verify that an actual PHP config file exposing database credentials is classified as UNSAFE."""
    real_php_config = (
        b"<?php\n"
        b"$db_host = 'localhost';\n"
        b"$db_user = 'admin';\n"
        b"$db_pass = 'SuperSecretP@ss123';\n"
        b"$conn = mysqli_connect($db_host, $db_user, $db_pass);\n"
    )

    def side_effect(url, **kwargs):
        if "_soft_404_baseline_check" in url:
            return _mock_response(404, b"Not Found", {"Content-Type": "text/plain"})
        if "config.php" in url:
            return _mock_response(200, real_php_config, {"Content-Type": "text/plain"})
        return _mock_response(404, b"Not Found", {"Content-Type": "text/plain"})

    with patch("pre_login.scanners.tc13_sensitive_file_exposure.request", side_effect=side_effect):
        res = scan_sensitive_file_exposure("https://example.com", max_probes=15)
        assert res["status"] == "UNSAFE"
        assert any(f.get("path") == "/config.php" for f in res["details"]["findings"])


def test_genuine_env_file_exposure_classified_as_unsafe():
    """Verify that an actual .env file exposing environment variables is classified as UNSAFE."""
    env_content = (
        b"DB_HOST=127.0.0.1\n"
        b"DB_PORT=5432\n"
        b"DB_DATABASE=app_production\n"
        b"SECRET_KEY=base64:AbCdEf1234567890\n"
    )

    def side_effect(url, **kwargs):
        if "_soft_404_baseline_check" in url:
            return _mock_response(404, b"Not Found", {"Content-Type": "text/plain"})
        if ".env" in url:
            return _mock_response(200, env_content, {"Content-Type": "text/plain"})
        return _mock_response(404, b"Not Found", {"Content-Type": "text/plain"})

    with patch("pre_login.scanners.tc13_sensitive_file_exposure.request", side_effect=side_effect):
        res = scan_sensitive_file_exposure("https://example.com", max_probes=10)
        assert res["status"] == "UNSAFE"
        assert any(".env" in f.get("path", "") for f in res["details"]["findings"])
