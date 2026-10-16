from __future__ import annotations

import time
from unittest.mock import MagicMock, patch
import requests

from pre_login.scanners.tc25_time_based_sql_injection import scan_time_based_sql_injection


def _mock_response(status_code: int = 200, text: str = "<html><body><p>Normal Page</p></body></html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = "https://example.com/item?id=10"
    return resp


def test_time_based_reproducible_delay_returns_unsafe():
    baseline_resp = _mock_response()

    with patch("requests.Session.get") as mock_get:
        # Control requests are fast
        mock_get.return_value = baseline_resp

        # We mock execute_probe to return controlled elapsed times
        with patch("pre_login.scanners.tc25_time_based_sql_injection.execute_probe") as mock_probe:
            # Observation 1: 2.5s, Observation 2: 2.4s
            mock_probe.side_effect = [
                (baseline_resp, 2.5, None),
                (baseline_resp, 2.4, None),
            ]

            res = scan_time_based_sql_injection("https://example.com/item?id=10")
            assert res["status"] == "UNSAFE"
            assert "Time-based SQL injection was confirmed" in res["summary"]
            assert len(res["details"]["confirmed_observations"]) == 1
            assert res["details"]["confirmed_observations"][0]["parameter"] == "id"


def test_time_based_transient_delay_returns_review_required():
    baseline_resp = _mock_response()

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc25_time_based_sql_injection.execute_probe") as mock_probe:
            # First probe delayed, repeated probe fast (network jitter)
            mock_probe.side_effect = [
                (baseline_resp, 2.3, None),
                (baseline_resp, 0.05, None),
                # Remaining probes normal
                (baseline_resp, 0.05, None),
                (baseline_resp, 0.05, None),
                (baseline_resp, 0.05, None),
                (baseline_resp, 0.05, None),
                (baseline_resp, 0.05, None),
            ]

            res = scan_time_based_sql_injection("https://example.com/item?id=10")
            assert res["status"] == "REVIEW REQUIRED"
            assert "Suspicious timing delays or timeouts were observed" in res["summary"]


def test_time_based_timeout_alone_does_not_mark_unsafe():
    baseline_resp = _mock_response()

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc25_time_based_sql_injection.execute_probe") as mock_probe:
            # Timeouts on probes
            mock_probe.return_value = (None, None, "Request timed out after 10.0s")

            res = scan_time_based_sql_injection("https://example.com/item?id=10")
            # Must be REVIEW REQUIRED or INCOMPLETE, NEVER UNSAFE
            assert res["status"] in ("REVIEW REQUIRED", "INCOMPLETE")
            assert res["status"] != "UNSAFE"


def test_time_based_consistent_baseline_returns_safe():
    baseline_resp = _mock_response()

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc25_time_based_sql_injection.execute_probe") as mock_probe:
            # All probes return quickly matching baseline
            mock_probe.return_value = (baseline_resp, 0.04, None)

            res = scan_time_based_sql_injection("https://example.com/item?id=10")
            assert res["status"] == "SAFE"
            assert "No time-based SQL injection delays were observed" in res["summary"]


def test_time_based_baseline_failure_returns_incomplete():
    with patch("requests.Session.get", side_effect=requests.RequestException("Host unreachable")):
        res = scan_time_based_sql_injection("https://example.com/item?id=10")
        assert res["status"] == "INCOMPLETE"
        assert "Could not establish baseline" in res["summary"]
