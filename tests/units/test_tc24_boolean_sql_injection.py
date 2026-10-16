from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from pre_login.scanners.tc24_boolean_sql_injection import scan_boolean_sql_injection


def _mock_response(status_code: int = 200, text: str = "<html><body><h1>Search results</h1><p>Item 1</p></body></html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = "https://example.com/search?q=test"
    return resp


def test_boolean_differential_confirmed_returns_unsafe():
    baseline_resp = _mock_response(200, "<html><body><h1>Search results</h1><p>Item 1</p><div>User: admin</div></body></html>")
    true_resp = _mock_response(200, "<html><body><h1>Search results</h1><p>Item 1</p><div>User: admin</div></body></html>")
    false_resp = _mock_response(200, "<html><body><h1>No items found</h1><p>Zero records match your query.</p></body></html>")

    with patch("requests.Session.get") as mock_get:
        def get_side_effect(url, **kwargs):
            if "1%3D1" in url or "1'='1" in url or "1=1" in url:
                return true_resp
            if "1%3D2" in url or "1'='2" in url or "1=2" in url:
                return false_resp
            return baseline_resp

        mock_get.side_effect = get_side_effect
        res = scan_boolean_sql_injection("https://example.com/search?q=test")
        assert res["status"] == "UNSAFE"
        assert "Boolean-based SQL injection was confirmed" in res["summary"]
        assert len(res["details"]["confirmed_pairs"]) > 0


def test_boolean_database_error_leak_returns_unsafe():
    baseline_resp = _mock_response(200, "Normal search response")
    error_resp = _mock_response(500, "Warning: mysqli::query(): You have an error in your SQL syntax near '' OR 1=1' at line 1")

    with patch("requests.Session.get") as mock_get:
        def get_side_effect(url, **kwargs):
            if "q=" in url and url != "https://example.com/search?q=test":
                return error_resp
            return baseline_resp

        mock_get.side_effect = get_side_effect
        res = scan_boolean_sql_injection("https://example.com/search?q=test")
        assert res["status"] == "UNSAFE"
        assert "database error" in res["evidence"][0].lower()


def test_boolean_identical_responses_returns_safe():
    identical_resp = _mock_response(200, "Constant identical static response without change")

    with patch("requests.Session.get", return_value=identical_resp):
        res = scan_boolean_sql_injection("https://example.com/search?q=test")
        assert res["status"] == "SAFE"
        assert "No boolean-based SQL injection indicators were observed" in res["summary"]


def test_boolean_dynamic_token_normalization():
    # Responses differ ONLY in dynamic CSRF and timestamp tokens
    baseline_resp = _mock_response(200, "Content with csrf_token: aabbccdd and time: 2026-10-16T12:00:00Z")
    true_resp = _mock_response(200, "Content with csrf_token: 11223344 and time: 2026-10-16T12:00:01Z")
    false_resp = _mock_response(200, "Content with csrf_token: 55667788 and time: 2026-10-16T12:00:02Z")

    with patch("requests.Session.get") as mock_get:
        def get_side_effect(url, **kwargs):
            if "1=1" in url or "1'='1" in url:
                return true_resp
            if "1=2" in url or "1'='2" in url:
                return false_resp
            return baseline_resp

        mock_get.side_effect = get_side_effect
        res = scan_boolean_sql_injection("https://example.com/search?q=test")
        # Since dynamic tokens are normalized, body similarity is 1.0, so no false positive!
        assert res["status"] == "SAFE"


def test_boolean_connection_failure_returns_incomplete():
    with patch("requests.Session.get", side_effect=ConnectionError("Failed to reach target")):
        res = scan_boolean_sql_injection("https://broken.invalid/test")
        assert res["status"] == "INCOMPLETE"
