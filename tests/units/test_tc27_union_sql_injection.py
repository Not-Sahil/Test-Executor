from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from pre_login.scanners.tc27_union_sql_injection import scan_union_sql_injection


def _mock_response(status_code: int = 200, text: str = "<html><body><h1>Catalog</h1><p>Items listed here</p></body></html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = "https://example.com/products?cat=electronics"
    return resp


def test_union_canary_execution_without_reflection_returns_unsafe():
    baseline_resp = _mock_response(200, "Normal product catalog")
    ref_resp = _mock_response(200, "Normal product catalog")  # Benign token not reflected
    union_resp = _mock_response(200, "Catalog items: <span>tc_union_canary_c2</span>")  # Canary injected via SQL query!

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc27_union_sql_injection.execute_probe") as mock_probe:
            def probe_side_effect(session, target, payload, **kwargs):
                if "refchk_" in payload:
                    return (ref_resp, 0.05, None)
                if "UNION" in payload and "tc_union_canary_c2" in payload:
                    return (union_resp, 0.05, None)
                return (baseline_resp, 0.05, None)

            mock_probe.side_effect = probe_side_effect
            res = scan_union_sql_injection("https://example.com/products?cat=electronics")
            assert res["status"] == "UNSAFE"
            assert "UNION-based SQL injection was confirmed" in res["summary"]
            assert len(res["details"]["confirmed_findings"]) > 0


def test_union_canary_reflection_only_returns_review_required():
    baseline_resp = _mock_response(200, "Search results for: ")

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = baseline_resp

        with patch("pre_login.scanners.tc27_union_sql_injection.execute_probe") as mock_probe:
            def probe_side_effect(session, target, payload, **kwargs):
                # Target reflects ANY input directly into HTML (e.g. search reflection)
                resp = _mock_response(200, f"Search results for: {payload}")
                return (resp, 0.05, None)

            mock_probe.side_effect = probe_side_effect
            res = scan_union_sql_injection("https://example.com/products?cat=electronics")
            # Should NOT be UNSAFE because reflection control prevents false positive!
            assert res["status"] == "REVIEW REQUIRED"
            assert "Suspicious UNION-related indicators observed" in res["summary"]


def test_union_clean_target_returns_safe():
    clean_resp = _mock_response(200, "Clean static response")

    with patch("requests.Session.get") as mock_get:
        mock_get.return_value = clean_resp

        with patch("pre_login.scanners.tc27_union_sql_injection.execute_probe") as mock_probe:
            mock_probe.return_value = (clean_resp, 0.04, None)

            res = scan_union_sql_injection("https://example.com/products?cat=electronics")
            assert res["status"] == "SAFE"
            assert "No UNION-based SQL injection indicators were observed" in res["summary"]


def test_union_baseline_failure_returns_incomplete():
    with patch("requests.Session.get", side_effect=ConnectionAbortedError("Aborted")):
        res = scan_union_sql_injection("https://broken.invalid/products")
        assert res["status"] == "INCOMPLETE"
