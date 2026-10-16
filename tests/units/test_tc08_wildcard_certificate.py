from __future__ import annotations

import datetime
from typing import Any
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from pre_login.scanners.tc08_wildcard_certificate import (
    _certificate_matches_hostname,
    _validate_wildcard_syntax,
    _wildcard_matches_hostname,
    scan_wildcard_certificate,
)


def _generate_test_cert_der(
    common_name: str = "example.com",
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
    days_valid: int = 30,
    days_before: int = 1,
) -> bytes:
    """Generate deterministic self-signed DER certificate fixtures."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(days=days_before)
    not_after = now + datetime.timedelta(days=days_valid)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )

    san_items: list[x509.GeneralName] = []
    for name in (dns_names or []):
        san_items.append(x509.DNSName(name))
    for ip_str in (ip_addresses or []):
        import ipaddress
        san_items.append(x509.IPAddress(ipaddress.ip_address(ip_str)))

    if san_items:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_items),
            critical=False,
        )

    cert = builder.sign(key, hashes.SHA256())
    from cryptography.hazmat.primitives.serialization import Encoding
    return cert.public_bytes(Encoding.DER)


def test_wildcard_single_label_matching_rfc6125():
    # *.example.com matches app.example.com
    assert _wildcard_matches_hostname("*.example.com", "app.example.com") is True
    assert _wildcard_matches_hostname("*.example.com", "www.example.com") is True

    # *.example.com does NOT match the apex domain
    assert _wildcard_matches_hostname("*.example.com", "example.com") is False

    # *.example.com does NOT match multi-level subdomains
    assert _wildcard_matches_hostname("*.example.com", "a.b.example.com") is False
    assert _wildcard_matches_hostname("*.example.com", "dev.api.example.com") is False

    # Literal hostname match
    assert _wildcard_matches_hostname("example.com", "example.com") is True
    assert _wildcard_matches_hostname("example.com", "other.com") is False


def test_wildcard_syntax_validation():
    # Valid single-label wildcard
    valid = _validate_wildcard_syntax("*.example.com")
    assert valid["valid"] is True
    assert valid["depth"] == 2

    # Malformed / overly broad wildcards
    broad = _validate_wildcard_syntax("*.com")
    assert broad["depth"] == 1

    invalid_prefix = _validate_wildcard_syntax("sub.*.example.com")
    assert invalid_prefix["valid"] is False

    no_wildcard = _validate_wildcard_syntax("example.com")
    assert no_wildcard["valid"] is False


def test_certificate_matches_hostname_distinctions():
    dns_names = ["*.example.com", "example.com"]
    ip_addresses = ["192.168.1.1"]

    matches, match_type = _certificate_matches_hostname("app.example.com", dns_names, ip_addresses)
    assert matches is True
    assert match_type == "wildcard_san"

    matches, match_type = _certificate_matches_hostname("example.com", dns_names, ip_addresses)
    assert matches is True
    assert match_type == "exact_san"

    matches, match_type = _certificate_matches_hostname("sub.app.example.com", dns_names, ip_addresses)
    assert matches is False
    assert match_type == "none"

    matches, match_type = _certificate_matches_hostname("192.168.1.1", dns_names, ip_addresses)
    assert matches is True
    assert match_type == "exact_ip"


def test_valid_wildcard_with_matching_hostname_returns_safe():
    der = _generate_test_cert_der(
        common_name="app.example.com",
        dns_names=["*.example.com"],
    )

    with patch(
        "pre_login.scanners.tc08_wildcard_certificate._fetch_certificate",
        return_value={
            "certificate": __import__(
                "pre_login.scanners.tc08_wildcard_certificate",
                fromlist=["_extract_certificate"],
            )._extract_certificate(der),
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "verification_failed": False,
            "verification_error": "",
        },
    ), patch(
        "pre_login.scanners.tc08_wildcard_certificate.resolve_host",
        return_value=[],
    ):
        res = scan_wildcard_certificate("https://app.example.com")
        assert res["status"] == "SAFE"
        assert "valid wildcard certificate is in use" in res["summary"]
        assert res["details"]["hostname_matches_certificate"] is True


def test_valid_certificate_with_exact_san_returns_safe():
    der = _generate_test_cert_der(
        common_name="example.com",
        dns_names=["example.com", "*.example.com"],
    )

    with patch(
        "pre_login.scanners.tc08_wildcard_certificate._fetch_certificate",
        return_value={
            "certificate": __import__(
                "pre_login.scanners.tc08_wildcard_certificate",
                fromlist=["_extract_certificate"],
            )._extract_certificate(der),
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "verification_failed": False,
            "verification_error": "",
        },
    ), patch(
        "pre_login.scanners.tc08_wildcard_certificate.resolve_host",
        return_value=[],
    ):
        res = scan_wildcard_certificate("https://example.com")
        assert res["status"] == "SAFE"
        assert "exact SAN match" in res["summary"]


def test_hostname_mismatch_returns_unsafe():
    der = _generate_test_cert_der(
        common_name="other.com",
        dns_names=["*.other.com"],
    )

    with patch(
        "pre_login.scanners.tc08_wildcard_certificate._fetch_certificate",
        return_value={
            "certificate": __import__(
                "pre_login.scanners.tc08_wildcard_certificate",
                fromlist=["_extract_certificate"],
            )._extract_certificate(der),
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "verification_failed": False,
            "verification_error": "",
        },
    ):
        # Target app.example.com does not match *.other.com
        res = scan_wildcard_certificate("https://app.example.com")
        assert res["status"] == "UNSAFE"
        assert "does not match" in res["summary"]
        assert res["details"]["hostname_matches_certificate"] is False


def test_wildcard_against_multi_level_subdomain_returns_unsafe():
    # *.example.com does NOT match a.b.example.com
    der = _generate_test_cert_der(
        common_name="*.example.com",
        dns_names=["*.example.com"],
    )

    with patch(
        "pre_login.scanners.tc08_wildcard_certificate._fetch_certificate",
        return_value={
            "certificate": __import__(
                "pre_login.scanners.tc08_wildcard_certificate",
                fromlist=["_extract_certificate"],
            )._extract_certificate(der),
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "verification_failed": False,
            "verification_error": "",
        },
    ):
        res = scan_wildcard_certificate("https://a.b.example.com")
        assert res["status"] == "UNSAFE"
        assert "does not match" in res["summary"]


def test_expired_certificate_returns_unsafe():
    # Expired 5 days ago
    der = _generate_test_cert_der(
        common_name="app.example.com",
        dns_names=["*.example.com"],
        days_valid=-5,
        days_before=30,
    )

    with patch(
        "pre_login.scanners.tc08_wildcard_certificate._fetch_certificate",
        return_value={
            "certificate": __import__(
                "pre_login.scanners.tc08_wildcard_certificate",
                fromlist=["_extract_certificate"],
            )._extract_certificate(der),
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "verification_failed": True,
            "verification_error": "certificate has expired",
        },
    ):
        res = scan_wildcard_certificate("https://app.example.com")
        assert res["status"] == "UNSAFE"
        assert "expired" in res["summary"].lower()


def test_untrusted_chain_returns_review_required():
    der = _generate_test_cert_der(
        common_name="app.example.com",
        dns_names=["*.example.com"],
        days_valid=30,
    )

    with patch(
        "pre_login.scanners.tc08_wildcard_certificate._fetch_certificate",
        return_value={
            "certificate": __import__(
                "pre_login.scanners.tc08_wildcard_certificate",
                fromlist=["_extract_certificate"],
            )._extract_certificate(der),
            "tls_version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "cipher_bits": 256,
            "verification_failed": True,
            "verification_error": "self-signed certificate in certificate chain",
        },
    ):
        res = scan_wildcard_certificate("https://app.example.com")
        assert res["status"] == "REVIEW REQUIRED"
        assert "could not be verified" in res["summary"]


def test_connection_failure_returns_incomplete():
    with patch(
        "pre_login.scanners.tc08_wildcard_certificate._fetch_certificate",
        side_effect=ConnectionRefusedError("Connection refused by peer"),
    ):
        res = scan_wildcard_certificate("https://nonexistent.test.local:443")
        assert res["status"] in {"INCOMPLETE", "ERROR"}
