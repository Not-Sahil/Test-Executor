from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from pre_login.scanners.tc26_blind_sql_injection import scan_blind_sql_injection


def _mock_response(status_code: int = 200, text: str = "<html><body><h1>Search results</h1><p>Item 1</p></body></html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = "https://example.com/search?q=test"
    return resp


def test_blind_conditional_error_inference_returns_unsafe():
    baseline_resp = _mock_response(200, "Normal content")
    resp_true = _mock_response(200, "Normal content")
    resp_false = _mock_response(500, "Internal Server Error")  # Divide by zero triggered

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc26_blind_sql_injection.execute_probe") as mock_probe:
            def probe_side_effect(session, target, payload, **kwargs):
                if "1/0" in payload or "THEN 1" in payload:
                    # Depending on true vs false payload
                    if "1=1" in payload or "'a'='a'" in payload:
                        return (resp_true, 0.05, None)
                    else:
                        return (resp_false, 0.05, None)
                return (baseline_resp, 0.05, None)

            mock_probe.side_effect = probe_side_effect
            res = scan_blind_sql_injection("https://example.com/search?q=test")
            assert res["status"] == "UNSAFE"
            assert "Blind SQL injection confirmed" in res["summary"]
            assert res["details"]["technique_used"] == "conditional_error_inference"


def test_blind_content_differential_inference_returns_unsafe():
    baseline_resp = _mock_response(200, "<html><body><h1>Dashboard</h1><p>Record exists and user is verified</p></body></html>")
    resp_true = _mock_response(200, "<html><body><h1>Dashboard</h1><p>Record exists and user is verified</p></body></html>")
    resp_false = _mock_response(200, "<html><body><h1>Dashboard</h1><p>Unknown entity or invalid filter</p></body></html>")

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc26_blind_sql_injection.execute_probe") as mock_probe:
            def probe_side_effect(session, target, payload, **kwargs):
                if "=4" in payload or "1=1" in payload:
                    return (resp_true, 0.05, None)
                return (resp_false, 0.05, None)

            mock_probe.side_effect = probe_side_effect
            res = scan_blind_sql_injection("https://example.com/search?q=test")
            # Should detect content differential inference or conditional error
            assert res["status"] in ("UNSAFE", "REVIEW REQUIRED")


def test_blind_identical_behavior_returns_safe():
    identical_resp = _mock_response(200, "Static page content identical for all inputs")

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = identical_resp

        with patch("pre_login.scanners.tc26_blind_sql_injection.execute_probe") as mock_probe:
            mock_probe.return_value = (identical_resp, 0.04, None)

            res = scan_blind_sql_injection("https://example.com/search?q=test")
            assert res["status"] == "SAFE"
            assert "No blind SQL injection indicators were observed" in res["summary"]


def test_blind_baseline_failure_returns_incomplete():
    with patch("requests.Session.get", side_effect=ConnectionResetError("Connection reset by peer")):
        res = scan_blind_sql_injection("https://broken.invalid/page")
        assert res["status"] == "INCOMPLETE"
