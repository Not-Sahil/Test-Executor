from __future__ import annotations

import ipaddress
import socket
import ssl
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from .common import (
    normalize_url,
    request,
    result,
    connection_result,
    resolve_host,
)


# ============================================================================
# Configuration
# ============================================================================

# Small, deliberately bounded set of conventional environment/service names.
#
# This is NOT intended to be subdomain brute forcing.
CANDIDATE_LABELS = (
    "www",
    "api",
    "dev",
    "staging",
    "test",
    "admin",
    "portal",
    "vpn",
    "mail",
)

# Labels that deserve additional attention when they resolve.
SENSITIVE_LABELS = {
    "admin",
    "portal",
    "vpn",
    "internal",
    "private",
    "staging",
    "dev",
    "test",
}

MAX_CANDIDATES = 10


# ============================================================================
# Data model
# ============================================================================

@dataclass
class TLSHostObservation:
    hostname: str
    resolved_ips: list[str]
    reachable_tls: bool
    tls_version: str = ""
    cipher: str = ""
    certificate_sha256: str = ""
    presented_wildcards: list[str] | None = None
    target_matches_certificate: bool | None = None
    error_type: str = ""
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)

        if data["presented_wildcards"] is None:
            data["presented_wildcards"] = []

        return data


# ============================================================================
# Domain helpers
# ============================================================================

def _normalise_dns_name(value: str) -> str:
    value = value.strip().rstrip(".")
    try:
        # Normalize IDN / Punycode (RFC 5890 / RFC 6125)
        value = value.encode("idna").decode("ascii")
    except Exception:
        pass
    return value.lower()


def _is_ip_address(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _registrable_parent_from_wildcard(wildcard: str) -> str:
    """
    Remove the leading "*.".

    This deliberately does not attempt public-suffix parsing because a fully
    correct registrable-domain calculation requires a Public Suffix List.
    """

    if wildcard.startswith("*."):
        return wildcard[2:]

    return wildcard


def _wildcard_depth(wildcard: str) -> int:
    """
    Number of labels beneath the wildcard.

    Example:
        *.example.com          -> 2
        *.internal.example.com -> 3
    """

    parent = _registrable_parent_from_wildcard(wildcard)

    if not parent:
        return 0

    return len(parent.split("."))


# ============================================================================
# Certificate parsing
# ============================================================================

def _extract_certificate(der_bytes: bytes) -> dict[str, Any]:
    certificate = x509.load_der_x509_certificate(
        der_bytes
    )

    dns_names: list[str] = []
    ip_names: list[str] = []

    try:
        san = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value

        for name in san:
            if isinstance(name, x509.DNSName):
                dns_names.append(
                    _normalise_dns_name(name.value)
                )

            elif isinstance(name, x509.IPAddress):
                ip_names.append(
                    str(name.value)
                )

    except x509.ExtensionNotFound:
        pass

    common_name = ""

    try:
        common_name_attributes = certificate.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME
        )

        if common_name_attributes:
            common_name = _normalise_dns_name(
                common_name_attributes[0].value
            )

    except Exception:
        common_name = ""

    wildcard_sans = [
        name
        for name in dns_names
        if name.startswith("*.")
    ]
    wildcards = list(wildcard_sans)
    if not dns_names and common_name.startswith("*.") and common_name not in wildcards:
        wildcards.append(common_name)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    try:
        not_before = certificate.not_valid_before_utc
        not_after = certificate.not_valid_after_utc
    except AttributeError:
        not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)

    is_expired = now > not_after
    is_not_yet_valid = now < not_before

    return {
        "serial_number": format(
            certificate.serial_number,
            "x",
        ),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "is_expired": is_expired,
        "is_not_yet_valid": is_not_yet_valid,
        "common_name": common_name,
        "dns_names": dns_names,
        "ip_addresses": ip_names,
        "wildcard_sans": wildcard_sans,
        "wildcards": wildcards,
        "signature_algorithm": (
            certificate.signature_hash_algorithm.name
            if certificate.signature_hash_algorithm
            else ""
        ),
        "public_key_type": (
            certificate.public_key().__class__.__name__
        ),
        "fingerprint_sha256": certificate.fingerprint(
            __import__(
                "cryptography.hazmat.primitives.hashes",
                fromlist=["SHA256"],
            ).SHA256()
        ).hex(),
    }


# ============================================================================
# Wildcard validation
# ============================================================================

def _validate_wildcard_syntax(
    wildcard: str,
) -> dict[str, Any]:

    value = _normalise_dns_name(wildcard)

    valid = True
    reasons: list[str] = []

    if not value.startswith("*."):
        valid = False
        reasons.append(
            "Wildcard does not begin with '*.'."
        )

    # A wildcard should consist of exactly one wildcard label followed
    # by at least one normal DNS label.
    labels = value.split(".")

    if len(labels) < 3:
        valid = False
        reasons.append(
            "Wildcard appears too broad or malformed."
        )

    if labels[0] != "*":
        valid = False
        reasons.append(
            "Wildcard is not the complete left-most label."
        )

    if "*" in labels[1:]:
        valid = False
        reasons.append(
            "Wildcard character appears outside the left-most label."
        )

    return {
        "wildcard": value,
        "valid": valid,
        "reasons": reasons,
        "depth": _wildcard_depth(value),
        "parent": _registrable_parent_from_wildcard(value),
    }


def _wildcard_matches_hostname(
    wildcard: str,
    hostname: str,
) -> bool:
    """
    Implement the RFC 6125-style one-label wildcard rule:

        *.example.com
            matches
        www.example.com

        but does not match
        example.com

        and does not match
        api.dev.example.com
    """

    wildcard = _normalise_dns_name(wildcard)
    hostname = _normalise_dns_name(hostname)

    if not wildcard.startswith("*."):
        return wildcard == hostname

    suffix = wildcard[2:]

    if not suffix:
        return False

    hostname_labels = hostname.split(".")
    suffix_labels = suffix.split(".")

    # Need exactly one additional left-most label.
    if len(hostname_labels) != len(suffix_labels) + 1:
        return False

    return hostname_labels[1:] == suffix_labels


def _certificate_matches_hostname(
    hostname: str,
    dns_names: list[str],
    ip_addresses: list[str],
    common_name: str = "",
) -> tuple[bool, str]:
    """Check hostname against certificate identities. Returns (matches, match_type)."""
    hostname = _normalise_dns_name(hostname)

    if _is_ip_address(hostname):
        if hostname in {_normalise_dns_name(value) for value in ip_addresses}:
            return True, "exact_ip"
        return False, "none"

    # 1. Exact SAN match
    for name in dns_names:
        if "*" not in name and _normalise_dns_name(name) == hostname:
            return True, "exact_san"

    # 2. Wildcard SAN match
    for name in dns_names:
        if "*" in name and _wildcard_matches_hostname(name, hostname):
            return True, "wildcard_san"

    # 3. Legacy CN fallback (only when no DNS SANs exist, per RFC 6125)
    if not dns_names and common_name:
        cn = _normalise_dns_name(common_name)
        if "*" in cn and _wildcard_matches_hostname(cn, hostname):
            return True, "wildcard_cn"
        if cn == hostname:
            return True, "exact_cn"

    return False, "none"


# ============================================================================
# TLS connection
# ============================================================================

def _fetch_certificate(
    hostname: str,
    port: int,
    *,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:

    verification_failed = False
    verification_error = ""

    der = None
    tls_version = ""
    cipher_info = None

    if verify_tls:
        try:
            context = ssl.create_default_context()
            with socket.create_connection(
                (hostname, port),
                timeout=timeout,
            ) as raw_sock:
                with context.wrap_socket(
                    raw_sock,
                    server_hostname=hostname,
                ) as tls_sock:
                    der = tls_sock.getpeercert(binary_form=True)
                    tls_version = tls_sock.version() or ""
                    cipher_info = tls_sock.cipher()
        except ssl.SSLCertVerificationError as exc:
            verification_failed = True
            verification_error = str(exc)
        except ssl.SSLError as exc:
            if "CERTIFICATE_VERIFY_FAILED" in str(exc) or "certificate verify failed" in str(exc).lower():
                verification_failed = True
                verification_error = str(exc)
            else:
                raise

    if der is None:
        unverified_context = ssl.create_default_context()
        unverified_context.check_hostname = False
        unverified_context.verify_mode = ssl.CERT_NONE

        with socket.create_connection(
            (hostname, port),
            timeout=timeout,
        ) as raw_sock:
            with unverified_context.wrap_socket(
                raw_sock,
                server_hostname=hostname,
            ) as tls_sock:
                der = tls_sock.getpeercert(binary_form=True)
                if not tls_version:
                    tls_version = tls_sock.version() or ""
                if not cipher_info:
                    cipher_info = tls_sock.cipher()

    if not der:
        raise RuntimeError(
            "TLS server did not provide a parseable peer certificate."
        )

    parsed_certificate = _extract_certificate(der)

    return {
        "certificate": parsed_certificate,
        "tls_version": tls_version,
        "cipher": cipher_info[0] if cipher_info else "",
        "cipher_bits": (
            cipher_info[2]
            if cipher_info and len(cipher_info) >= 3
            else None
        ),
        "verification_failed": verification_failed,
        "verification_error": verification_error,
    }


# ============================================================================
# Candidate-host testing
# ============================================================================

def _build_candidate_hosts(
    wildcard: str,
) -> list[str]:

    parent = _registrable_parent_from_wildcard(
        wildcard
    )

    candidates: list[str] = []

    for label in CANDIDATE_LABELS:

        candidate = f"{label}.{parent}"

        if candidate not in candidates:
            candidates.append(candidate)

    return candidates[:MAX_CANDIDATES]


def _probe_candidate_host(
    hostname: str,
    *,
    timeout: float,
    verify_tls: bool,
    reference_fingerprint: str,
) -> TLSHostObservation:

    try:
        ips = resolve_host(hostname)
    except Exception as exc:
        return TLSHostObservation(
            hostname=hostname,
            resolved_ips=[],
            reachable_tls=False,
            error_type=type(exc).__name__,
            error=str(exc)[:500],
        )

    if not ips:
        return TLSHostObservation(
            hostname=hostname,
            resolved_ips=[],
            reachable_tls=False,
        )

    try:
        tls_data = _fetch_certificate(
            hostname,
            443,
            verify_tls=verify_tls,
            timeout=timeout,
        )

        certificate = tls_data["certificate"]

        return TLSHostObservation(
            hostname=hostname,
            resolved_ips=ips,
            reachable_tls=True,
            tls_version=tls_data["tls_version"],
            cipher=tls_data["cipher"],
            certificate_sha256=certificate[
                "fingerprint_sha256"
            ],
            presented_wildcards=certificate[
                "wildcard_sans"
            ],
            target_matches_certificate=(
                _certificate_matches_hostname(
                    hostname,
                    certificate["dns_names"],
                    certificate["ip_addresses"],
                    certificate.get("common_name", ""),
                )[0]
            ),
        )

    except Exception as exc:
        return TLSHostObservation(
            hostname=hostname,
            resolved_ips=ips,
            reachable_tls=False,
            error_type=type(exc).__name__,
            error=str(exc)[:500],
        )


# ============================================================================
# Main scanner
# ============================================================================

def scan_wildcard_certificate(
    url: str,
    verify_tls: bool = True,
    timeout: float = 12.0,
) -> dict:

    target = normalize_url(url)
    parsed = urlparse(target)

    # ------------------------------------------------------------------
    # 1. Applicability
    # ------------------------------------------------------------------

    inferred_https = parsed.scheme.lower() == "http"
    if inferred_https:
        target = parsed._replace(scheme="https").geturl()
        parsed = urlparse(target)

    if not parsed.hostname:
        return result(
            "INCOMPLETE",
            "The target URL does not contain a valid hostname.",
            details={
                "target": target,
                "https_inferred_from_http_target": inferred_https,
            },
        )

    host = _normalise_dns_name(
        parsed.hostname
    )

    port = parsed.port or 443

    details: dict[str, Any] = {
        "target": target,
        "https_inferred_from_http_target": inferred_https,
        "hostname": host,
        "port": port,
        "tls_verification": verify_tls,
    }

    # ------------------------------------------------------------------
    # 2. Retrieve actual presented certificate
    # ------------------------------------------------------------------

    try:
        tls_data = _fetch_certificate(
            host,
            port,
            verify_tls=verify_tls,
            timeout=timeout,
        )

    except Exception as exc:
        return connection_result(
            exc,
            target=target,
        )

    certificate = tls_data.get("certificate")
    if not certificate:
        return result(
            "INCOMPLETE",
            "Certificate inspection failed: could not parse peer certificate.",
            details=details,
        )

    details.update(
        {
            "tls_version": tls_data["tls_version"],
            "cipher": tls_data["cipher"],
            "cipher_bits": tls_data["cipher_bits"],
            "certificate": certificate,
            "verification_failed": tls_data.get("verification_failed", False),
            "verification_error": tls_data.get("verification_error", ""),
        }
    )

    dns_names = certificate["dns_names"]
    ip_addresses = certificate["ip_addresses"]
    wildcards = certificate.get("wildcards") or certificate.get("wildcard_sans") or []

    # ------------------------------------------------------------------
    # 3. Check certificate validity period (expiry / not yet valid)
    # ------------------------------------------------------------------

    if certificate.get("is_expired"):
        return result(
            "UNSAFE",
            f"The presented TLS certificate expired on {certificate['not_after']}.",
            details=details,
            evidence=[
                f"Requested hostname: {host}",
                f"Certificate expired on: {certificate['not_after']}",
                f"Certificate valid from: {certificate['not_before']}",
            ],
        )

    if certificate.get("is_not_yet_valid"):
        return result(
            "UNSAFE",
            f"The presented TLS certificate is not valid before {certificate['not_before']}.",
            details=details,
            evidence=[
                f"Requested hostname: {host}",
                f"Certificate not valid before: {certificate['not_before']}",
            ],
        )

    # ------------------------------------------------------------------
    # 4. Validate certificate identity against requested hostname
    # ------------------------------------------------------------------

    hostname_matches, match_type = _certificate_matches_hostname(
        host,
        dns_names,
        ip_addresses,
        common_name=certificate.get("common_name", ""),
    )

    details["hostname_matches_certificate"] = hostname_matches
    details["certificate_match_type"] = match_type

    if not hostname_matches:
        mismatch_evidence = [
            f"Requested hostname: {host}",
            "Certificate DNS names: " + (", ".join(dns_names) if dns_names else "none"),
            "Certificate CN: " + (certificate.get("common_name") or "none"),
            "Certificate IP names: " + (", ".join(ip_addresses) if ip_addresses else "none"),
        ]
        if wildcards:
            for wc in wildcards:
                mismatch_evidence.append(
                    f"Identity '{wc}' is a single-label wildcard: it matches single-level subdomains "
                    f"(e.g., 'app.{_registrable_parent_from_wildcard(wc)}'), but per RFC 6125 does NOT match "
                    f"the apex domain '{_registrable_parent_from_wildcard(wc)}' or multi-level subdomains."
                )
        return result(
            "UNSAFE",
            "The hostname used for the TLS connection does not match any DNS, CN, or IP identity presented by the certificate.",
            details=details,
            evidence=mismatch_evidence,
        )

    # ------------------------------------------------------------------
    # 5. Check certificate chain verification trust
    # ------------------------------------------------------------------

    if tls_data.get("verification_failed"):
        return result(
            "REVIEW REQUIRED",
            "The target presented a certificate that could not be verified against the local trust store (untrusted chain or self-signed certificate).",
            details=details,
            evidence=[
                f"TLS certificate verification error: {tls_data.get('verification_error')}",
                "Review whether the certificate is issued by a private or untrusted CA.",
            ],
        )

    # ------------------------------------------------------------------
    # 6. No wildcard
    # ------------------------------------------------------------------

    if not wildcards:
        return result(
            "SAFE",
            "The presented certificate does not contain a wildcard DNS identity and matches the requested hostname exactly.",
            details=details,
        )

    # ------------------------------------------------------------------
    # 5. Validate all wildcard SANs
    # ------------------------------------------------------------------

    wildcard_analysis = [
        _validate_wildcard_syntax(
            wildcard
        )
        for wildcard in wildcards
    ]

    details["wildcard_analysis"] = (
        wildcard_analysis
    )

    invalid_wildcards = [
        item
        for item in wildcard_analysis
        if not item["valid"]
    ]

    if invalid_wildcards:

        evidence = []

        for item in invalid_wildcards:
            evidence.append(
                f"Invalid/suspicious wildcard "
                f"{item['wildcard']}: "
                + "; ".join(
                    item["reasons"]
                )
            )

        return result(
            "REVIEW REQUIRED",
            "The certificate contains one or more wildcard identities whose syntax or scope does not conform cleanly to the expected wildcard model.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # 6. Identify which wildcard actually matches the target
    # ------------------------------------------------------------------

    matching_wildcards = [
        wildcard
        for wildcard in wildcards
        if _wildcard_matches_hostname(
            wildcard,
            host,
        )
    ]

    details["matching_wildcards"] = (
        matching_wildcards
    )

    # ------------------------------------------------------------------
    # 7. Check wildcard scope
    # ------------------------------------------------------------------

    broad_scope = []

    for item in wildcard_analysis:

        wildcard = item["wildcard"]
        parent = item["parent"]

        # A normal public-domain wildcard such as *.example.com is expected.
        #
        # We flag broader/more unusual scope for review, rather than calling
        # it a vulnerability automatically.
        if item["depth"] <= 1:
            broad_scope.append(
                {
                    "wildcard": wildcard,
                    "reason": (
                        "Wildcard has unusually broad scope."
                    ),
                }
            )

        if parent in {
            "com",
            "net",
            "org",
            "co.uk",
            "com.au",
            "in",
        }:
            broad_scope.append(
                {
                    "wildcard": wildcard,
                    "reason": (
                        "Wildcard appears to terminate at a broad "
                        "public suffix boundary."
                    ),
                }
            )

    details["broad_scope_findings"] = (
        broad_scope
    )

    if broad_scope:

        return result(
            "REVIEW REQUIRED",
            "The certificate contains a wildcard identity with unusually broad apparent scope. Review the certificate's intended coverage and whether multiple security boundaries share the same certificate.",
            details=details,
            evidence=[
                (
                    f"{item['wildcard']}: "
                    f"{item['reason']}"
                )
                for item in broad_scope
            ],
        )

    # ------------------------------------------------------------------
    # 8. Probe a small, bounded set of conventional sibling hosts
    # ------------------------------------------------------------------

    candidate_hosts: list[str] = []

    for wildcard in matching_wildcards:

        candidate_hosts.extend(
            _build_candidate_hosts(
                wildcard
            )
        )

    # Remove duplicates while preserving order.
    candidate_hosts = list(
        dict.fromkeys(candidate_hosts)
    )

    sibling_observations: list[dict[str, Any]] = []

    reference_fingerprint = certificate[
        "fingerprint_sha256"
    ]

    for candidate in candidate_hosts:

        # Don't probe the target itself twice.
        if candidate == host:
            continue

        observation = _probe_candidate_host(
            candidate,
            timeout=timeout,
            verify_tls=verify_tls,
            reference_fingerprint=(
                reference_fingerprint
            ),
        )

        observation_dict = observation.as_dict()

        observation_dict[
            "uses_same_certificate"
        ] = (
            observation.certificate_sha256
            == reference_fingerprint
            if observation.certificate_sha256
            else False
        )

        observation_dict[
            "sensitive_label"
        ] = (
            candidate.split(".", 1)[0]
            in SENSITIVE_LABELS
        )

        sibling_observations.append(
            observation_dict
        )

    details["sibling_host_observations"] = (
        sibling_observations
    )

    # ------------------------------------------------------------------
    # 9. Determine whether potentially sensitive siblings use it
    # ------------------------------------------------------------------

    sensitive_siblings = [
        observation
        for observation in sibling_observations
        if observation.get("sensitive_label")
        and observation.get("reachable_tls")
        and observation.get(
            "uses_same_certificate"
        )
    ]

    details["sensitive_siblings_using_same_certificate"] = (
        sensitive_siblings
    )

    sibling_evidence = [
        f"Sibling host '{observation['hostname']}' also presents this wildcard certificate."
        for observation in sensitive_siblings
    ]

    # ------------------------------------------------------------------
    # 10. Check whether the target's wildcard is the only broad identity
    # ------------------------------------------------------------------

    other_dns_identities = [
        name
        for name in dns_names
        if name not in wildcards
    ]

    details["non_wildcard_dns_identities"] = (
        other_dns_identities
    )

    # ------------------------------------------------------------------
    # 11. Normal wildcard configuration
    # ------------------------------------------------------------------

    if match_type == "exact_san":
        return result(
            "SAFE",
            "The presented certificate matches the requested hostname via an exact SAN match. The certificate also includes a valid wildcard identity with appropriate scope.",
            details=details,
            evidence=[
                f"Matching exact SAN: {host}",
                *[f"Wildcard identity: {wildcard}" for wildcard in wildcards],
                *sibling_evidence,
            ],
        )

    return result(
        "SAFE",
        "A syntactically valid wildcard certificate is in use and correctly validates for the requested hostname.",
        details=details,
        evidence=[
            f"Matching wildcard identity: {', '.join(matching_wildcards or wildcards)}",
            f"Requested hostname: {host}",
            *[f"Wildcard identity: {wildcard}" for wildcard in wildcards],
            *sibling_evidence,
        ],
    )