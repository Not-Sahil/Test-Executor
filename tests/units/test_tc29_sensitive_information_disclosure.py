from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from pre_login.scanners.tc29_sensitive_information_disclosure import (
    _redact_sensitive,
    scan_sensitive_information_disclosure,
)


def _mock_response(status_code: int = 200, text: str = "<html><body><h1>Welcome</h1></body></html>", headers: dict | None = None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.headers = headers or {"Content-Type": "text/html"}
    resp.url = "https://example.com/"
    return resp


def test_redact_sensitive_masks_credentials_and_keys():
    raw_aws = "Config: aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
    redacted = _redact_sensitive(raw_aws)
    assert "AKIA<REDACTED_AWS_KEY>" in redacted
    assert "AKIAIOSFODNN7EXAMPLE" not in redacted

    raw_pw = '{"password": "SuperSecretPassword123"}'
    redacted_pw = _redact_sensitive(raw_pw)
    assert "password=<redacted>" in redacted_pw
    assert "SuperSecretPassword123" not in redacted_pw


def test_sensitive_info_stack_trace_returns_unsafe():
    stack_text = (
        "<html><body>"
        "<h1>Server Error</h1>"
        "<pre>Traceback (most recent call last):\n"
        '  File "/var/www/app/server.py", line 42, in get\n'
        "    db.connect()\n"
        "OperationalError: connection timed out</pre>"
        "</body></html>"
    )
    resp = _mock_response(500, stack_text)

    with patch("requests.Session.get", return_value=resp):
        res = scan_sensitive_information_disclosure("https://example.com/")
        assert res["status"] == "UNSAFE"
        assert "Application Discloses Sensitive Information confirmed" in res["summary"]
        assert len(res["details"]["confirmed_disclosures"]) > 0


def test_sensitive_info_private_ip_returns_review_required():
    body_text = "<html><body><!-- Internal cluster node: 10.240.12.5 --></body></html>"
    resp = _mock_response(200, body_text)

    with patch("requests.Session.get", return_value=resp):
        res = scan_sensitive_information_disclosure("https://example.com/")
        assert res["status"] == "REVIEW REQUIRED"
        assert "disclosed internal infrastructure" in res["summary"]


def test_sensitive_info_clean_public_metadata_returns_safe():
    body_text = "<html><body><h1>About Us</h1><p>Our product is version 1.2.3</p></body></html>"
    resp = _mock_response(200, body_text)

    with patch("requests.Session.get", return_value=resp):
        res = scan_sensitive_information_disclosure("https://example.com/")
        assert res["status"] == "SAFE"
        assert "No sensitive information disclosure" in res["summary"]


def test_sensitive_info_all_connections_fail_returns_incomplete():
    with patch("requests.Session.get", side_effect=ConnectionError("Down")):
        res = scan_sensitive_information_disclosure("https://broken.invalid/")
        assert res["status"] == "INCOMPLETE"
