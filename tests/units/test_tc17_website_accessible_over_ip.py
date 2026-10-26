from __future__ import annotations

from unittest.mock import patch
import pytest

from pre_login.scanners.tc17_website_accessible_over_ip import (
    scan_ip_access,
    _resolve_all,
)


def _mock_snapshot_raw(status_code: int = 200, title: str = "My Test Application", body: str = "Welcome to My Test Application Content with user portal", location: str = "") -> str:
    loc_header = f"\r\nLocation: {location}" if location else ""
    return (
        f"HTTP/1.1 {status_code} OK\r\n"
        f"Content-Type: text/html\r\n"
        f"Server: nginx{loc_header}\r\n\r\n"
        f"<html><head><title>{title}</title></head><body><h1>{title}</h1><p>{body}</p></body></html>"
    )


def test_direct_raw_ip_serves_application_returns_unsafe():
    # Baseline for domain
    domain_raw = _mock_snapshot_raw(title="Customer Portal", body="Authenticated customer portal features")
    # Raw IP returns matching content
    raw_ip_raw = _mock_snapshot_raw(title="Customer Portal", body="Authenticated customer portal features")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.1"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if kwargs.get("connect_ip"):
                return domain_raw, None
            if "198.51.100.1" in url:
                return raw_ip_raw, None
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://portal.example.com")
        assert res["status"] == "UNSAFE"
        assert "directly accessible via its public IP address" in res["summary"]
        assert res["details"]["security_bypass_confirmed"] is True


def test_forced_ip_access_returns_review_required():
    # Raw IP fails/is blocked, but forced-host (SNI/Host header) returns application
    domain_raw = _mock_snapshot_raw(title="Secure Shop", body="Shop online store")
    forced_raw = _mock_snapshot_raw(title="Secure Shop", body="Shop online store")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["203.0.113.5"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if kwargs.get("connect_ip"):
                return forced_raw, None
            if "203.0.113.5" in url:
                return None, "Connection refused"
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://shop.example.com")
        assert res["status"] == "REVIEW REQUIRED"
        assert "serves the application when the original hostname is preserved" in res["summary"]


def test_direct_ip_canonical_redirect_returns_safe():
    domain_raw = _mock_snapshot_raw(title="Main Site", body="Welcome to Main Site")
    redirect_raw = _mock_snapshot_raw(status_code=301, title="Redirecting", location="https://mainsite.com/")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.2"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if "198.51.100.2" in url or kwargs.get("connect_ip") == "198.51.100.2":
                return redirect_raw, None
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://mainsite.com")
        assert res["status"] == "SAFE"
        assert "redirects clients back to the intended canonical hostname" in res["summary"]


def test_default_virtual_host_returns_safe():
    domain_raw = _mock_snapshot_raw(title="Custom App", body="Custom application logic")
    default_vhost_raw = _mock_snapshot_raw(title="Welcome to nginx!", body="Thank you for using nginx default web server page")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.3"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if "198.51.100.3" in url or kwargs.get("connect_ip") == "198.51.100.3":
                return default_vhost_raw, None
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://app.example.com")
        assert res["status"] == "SAFE"
        assert "default server or virtual-host page" in res["summary"]


def test_restricted_ip_access_returns_safe():
    domain_raw = _mock_snapshot_raw(title="Private App", body="Internal content")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.4"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if "198.51.100.4" in url or kwargs.get("connect_ip") == "198.51.100.4":
                return None, "Connection refused"
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://private.example.com")
        assert res["status"] == "SAFE"
        assert "restricted, blocked, or not exposed" in res["summary"]


def test_dns_failure_returns_incomplete():
    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": [], "ipv6": []}):
        res = scan_ip_access("https://nonexistent-host-1234567.invalid")
        assert res["status"] == "INCOMPLETE"
        assert "could not be resolved" in res["summary"]


def test_baseline_failure_returns_incomplete():
    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.5"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request", return_value=(None, "Could not resolve host")):
        res = scan_ip_access("https://broken.example.com")
        assert res["status"] == "INCOMPLETE"
        assert "normal hostname request could not be completed" in res["summary"]


def test_ipv6_bracket_formatting():
    domain_raw = _mock_snapshot_raw(title="App", body="Body")
    captured_urls = []

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": [], "ipv6": ["2001:db8::1"]}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            captured_urls.append(url)
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        scan_ip_access("https://ipv6.example.com")
        assert any("[2001:db8::1]" in u for u in captured_urls)


def test_protocol_divergence_http_redirect_https_unsafe():
    """Verify that when HTTP redirects canonically but HTTPS exposes the app, UNSAFE is returned and divergence is noted."""
    domain_raw = _mock_snapshot_raw(title="Secret Portal", body="Internal customer data and dashboard")
    http_redirect = _mock_snapshot_raw(status_code=301, title="Redirect", location="https://portal.example.com/")
    https_exposed = _mock_snapshot_raw(status_code=200, title="Secret Portal", body="Internal customer data and dashboard")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.10"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if "http://" in url and not kwargs.get("connect_ip"):
                return http_redirect, None
            if "https://" in url and not kwargs.get("connect_ip") and "198.51.100.10" in url:
                return https_exposed, None
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://portal.example.com")
        assert res["status"] == "UNSAFE"
        assert res["details"]["protocol_divergence_observed"] is True
        assert len(res["details"]["http_results"]) > 0
        assert len(res["details"]["https_results"]) > 0
        assert any("Protocol divergence" in e for e in res["evidence"])


def test_tls_handshake_rejection_treated_as_restricted_safe():
    """Verify TLS cert rejection / handshake failure on direct IP is handled as access restriction, returning SAFE."""
    domain_raw = _mock_snapshot_raw(title="Protected App", body="Protected application payload")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.11"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if "198.51.100.11" in url or kwargs.get("connect_ip") == "198.51.100.11":
                return None, "curl: (60) SSL certificate problem: self-signed certificate"
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://secure.example.com")
        assert res["status"] == "SAFE"
        assert "restricted, blocked, or not exposed" in res["summary"]
        assert any("TLS" in r.get("reason", "") for r in res["details"]["restricted_ips"])


def test_sensitive_admin_exposure_returns_unsafe():
    """Verify that discovering an admin panel on direct IP returns UNSAFE."""
    domain_raw = _mock_snapshot_raw(title="Company Website", body="Welcome to company main website")
    admin_raw = _mock_snapshot_raw(status_code=200, title="phpMyAdmin 5.2.0", body="phpMyAdmin Database Management System login page")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.12"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if "198.51.100.12" in url:
                return admin_raw, None
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://corp.example.com")
        assert res["status"] == "UNSAFE"
        assert res["details"]["sensitive_exposure_confirmed"] is True
        assert "secondary application interface" in res["summary"]


def test_timeout_classified_as_restricted_safe():
    """Verify that network timeouts when accessing direct IP are classified as restricted access when baseline succeeds."""
    domain_raw = _mock_snapshot_raw(title="My Site", body="My Site Content")

    with patch("pre_login.scanners.tc17_website_accessible_over_ip._resolve_all", return_value={"ipv4": ["198.51.100.13"], "ipv6": []}), \
         patch("pre_login.scanners.tc17_website_accessible_over_ip._curl_request") as mock_curl:
        def curl_side_effect(url, **kwargs):
            if "198.51.100.13" in url or kwargs.get("connect_ip") == "198.51.100.13":
                return None, "curl: (28) Connection timed out after 10000 milliseconds"
            return domain_raw, None

        mock_curl.side_effect = curl_side_effect
        res = scan_ip_access("https://mysite.example.com")
        assert res["status"] == "SAFE"
        assert "restricted, blocked, or not exposed" in res["summary"]

