from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from pre_login.scanners.tc28_poor_input_validation import scan_poor_input_validation


def _mock_response(status_code: int = 200, text: str = "<html><body><form><input name='age'/></form></body></html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = "https://example.com/profile?age=25"
    return resp


def test_poor_input_validation_server_crash_returns_unsafe():
    baseline_resp = _mock_response(200, "Normal profile page")
    crash_resp = _mock_response(500, "Unhandled Exception: System.NullReferenceException: Object reference not set to an instance of an object.")

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc28_poor_input_validation.execute_probe") as mock_probe:
            def probe_side_effect(session, target, val, **kwargs):
                if val == "" or "\x00" in val:
                    return (crash_resp, 0.05, None)
                return (baseline_resp, 0.05, None)

            mock_probe.side_effect = probe_side_effect
            res = scan_poor_input_validation("https://example.com/profile?age=25")
            assert res["status"] == "UNSAFE"
            assert "Poor Input Validation identified" in res["summary"]
            assert res["details"]["unhandled_exception_count"] > 0


def test_poor_input_validation_proper_422_rejections_returns_safe():
    baseline_resp = _mock_response(200, "Normal profile page")
    valid_err_resp = _mock_response(422, '{"error": "Validation error: field must be a valid integer"}')

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc28_poor_input_validation.execute_probe") as mock_probe:
            mock_probe.return_value = (valid_err_resp, 0.04, None)

            res = scan_poor_input_validation("https://example.com/profile?age=25")
            assert res["status"] == "SAFE"
            assert "The application enforced appropriate server-side validation" in res["summary"]


def test_poor_input_validation_malformed_input_accepted_returns_review_required():
    baseline_resp = _mock_response(200, "Normal page")
    accept_resp = _mock_response(200, "Profile updated successfully")

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc28_poor_input_validation.execute_probe") as mock_probe:
            # Returns 200 OK without validation error for all inputs including malformed JSON / null bytes
            mock_probe.return_value = (accept_resp, 0.04, None)

            res = scan_poor_input_validation("https://example.com/profile?age=25")
            assert res["status"] == "REVIEW REQUIRED"
            assert "returned 200 OK for malformed inputs" in res["summary"]


def test_poor_input_validation_baseline_failure_returns_incomplete():
    with patch("requests.Session.get", side_effect=ConnectionError("Failed")):
        res = scan_poor_input_validation("https://broken.invalid/profile")
        assert res["status"] == "INCOMPLETE"
