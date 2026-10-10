from __future__ import annotations

import socket
import ssl
from dataclasses import asdict, dataclass
from typing import Any
from urllib.parse import urlparse

from core.http_client import is_tls_verification_error

from .common import normalize_url, result, connection_result


# ============================================================================
# Policy
# ============================================================================

DEPRECATED_PROTOCOLS = {
    "SSLv2",
    "SSLv3",
    "TLSv1",
    "TLSv1.1",
}

# Explicitly unsafe legacy/weak families.
#
# This is intentionally more precise than a generic substring list.
UNSAFE_CIPHER_TOKENS = (
    "RC4",
    "RC2",
    "DES-CBC",
    "_DES_",
    "3DES",
    "NULL",
    "EXPORT",
    "_EXP_",
    "_ANON_",
    "ADH_",
    "_MD5",
)

# Cipher families that deserve review rather than automatic UNSAFE.
REVIEW_CIPHER_TOKENS = (
    "CBC",
)

# TLS 1.3 cipher suites generally considered modern.
TLS13_APPROVED_CIPHERS = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
}

# Common modern TLS 1.2 suites.
#
# This is not intended to be an exhaustive allow-list. Its purpose is to
# identify clearly modern configurations while still allowing the scanner to
# report other negotiated suites for review.
MODERN_TLS12_CIPHERS = {
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "ECDHE-ECDSA-CHACHA20-POLY1305",
    "DHE-RSA-AES128-GCM-SHA256",
    "DHE-RSA-AES256-GCM-SHA384",
    "DHE-RSA-CHACHA20-POLY1305",
}


# ============================================================================
# Data model
# ============================================================================

@dataclass
class TLSProbe:
    protocol: str
    attempted: bool
    supported: bool
    negotiated_protocol: str = ""
    cipher: str = ""
    cipher_bits: int | None = None
    error_type: str = ""
    error: str = ""
    locally_unavailable: bool = False

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================================
# TLS helpers
# ============================================================================

def _tls_version_name(version: ssl.TLSVersion) -> str:
    return str(version).replace("TLSVersion.", "")


def _create_context(
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
    *,
    verify_tls: bool = True,
) -> ssl.SSLContext:
    """
    Build a client context for a narrowly scoped protocol probe.

    verify_tls controls certificate validation. Protocol negotiation itself
    still occurs even when validation is disabled.
    """

    context = ssl.create_default_context()

    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    if minimum is not None:
        context.minimum_version = minimum

    if maximum is not None:
        context.maximum_version = maximum

    return context


def _connect(
    host: str,
    port: int,
    *,
    minimum: ssl.TLSVersion | None = None,
    maximum: ssl.TLSVersion | None = None,
    verify_tls: bool = True,
    timeout: float = 12.0,
) -> tuple[ssl.SSLSocket, tuple | None]:
    """
    Establish one TLS connection.

    SNI is deliberately supplied using the hostname because many real-world
    servers select their TLS configuration and certificate based on SNI.
    """

    context = _create_context(
        minimum,
        maximum,
        verify_tls=verify_tls,
    )

    raw_sock = socket.create_connection(
        (host, port),
        timeout=timeout,
    )

    tls_sock = context.wrap_socket(
        raw_sock,
        server_hostname=host,
    )

    return tls_sock, tls_sock.cipher()


def _probe_protocol(
    host: str,
    port: int,
    version: ssl.TLSVersion,
    *,
    verify_tls: bool,
    timeout: float,
) -> TLSProbe:
    protocol_name = _tls_version_name(version)

    try:
        sock, cipher = _connect(
            host,
            port,
            minimum=version,
            maximum=version,
            verify_tls=verify_tls,
            timeout=timeout,
        )

        try:
            negotiated = sock.version() or ""
            cipher_name = cipher[0] if cipher else ""
            cipher_bits = cipher[2] if cipher and len(cipher) >= 3 else None

            return TLSProbe(
                protocol=protocol_name,
                attempted=True,
                supported=True,
                negotiated_protocol=negotiated,
                cipher=cipher_name,
                cipher_bits=cipher_bits,
            )
        finally:
            sock.close()

    except (
        ssl.SSLError,
        ConnectionError,
        TimeoutError,
        OSError,
    ) as exc:

        # Some old protocol versions are unavailable in the local Python/
        # OpenSSL build. That is materially different from the server
        # rejecting them.
        message = str(exc)

        unavailable = _looks_locally_unavailable(
            version,
            exc,
            message,
        )

        return TLSProbe(
            protocol=protocol_name,
            attempted=True,
            supported=False,
            error_type=type(exc).__name__,
            error=message[:500],
            locally_unavailable=unavailable,
        )


def _looks_locally_unavailable(
    version: ssl.TLSVersion,
    exc: BaseException,
    message: str,
) -> bool:
    """
    Heuristic classification for cases where the local OpenSSL/Python build
    prevents an old protocol from being tested.

    This should never be interpreted as evidence that the server disabled it.
    """

    lower = message.lower()

    old_protocol = version in {
        getattr(ssl.TLSVersion, "SSLv2", None),
        getattr(ssl.TLSVersion, "SSLv3", None),
        getattr(ssl.TLSVersion, "TLSv1", None),
        getattr(ssl.TLSVersion, "TLSv1_1", None),
    }

    if not old_protocol:
        return False

    local_only_phrases = (
        "no protocols available",
        "unsupported protocol",
        "protocol version",
        "version too low",
        "no ciphers available",
    )

    return any(
        phrase in lower
        for phrase in local_only_phrases
    )


def _get_supported_tls_versions() -> list[tuple[str, ssl.TLSVersion]]:
    """
    Return versions exposed by the local Python ssl module.
    """

    candidates = [
        ("SSLv2", getattr(ssl.TLSVersion, "SSLv2", None)),
        ("SSLv3", getattr(ssl.TLSVersion, "SSLv3", None)),
        ("TLSv1", getattr(ssl.TLSVersion, "TLSv1", None)),
        ("TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
        ("TLSv1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
        ("TLSv1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ]

    return [
        (name, value)
        for name, value in candidates
        if value is not None
    ]


# ============================================================================
# Cipher analysis
# ============================================================================

def _classify_cipher(
    protocol: str,
    cipher: str,
    bits: int | None,
) -> dict[str, Any]:
    upper = cipher.upper()

    unsafe_matches = [
        token
        for token in UNSAFE_CIPHER_TOKENS
        if token.upper() in upper
    ]

    review_matches = [
        token
        for token in REVIEW_CIPHER_TOKENS
        if token.upper() in upper
    ]

    if unsafe_matches:
        classification = "UNSAFE"

    elif review_matches:
        classification = "REVIEW REQUIRED"

    elif bits is not None and bits < 128:
        classification = "UNSAFE"

    elif protocol == "TLSv1.3":
        if cipher in TLS13_APPROVED_CIPHERS:
            classification = "SAFE"
        else:
            classification = "REVIEW REQUIRED"

    elif protocol == "TLSv1.2":
        if cipher in MODERN_TLS12_CIPHERS:
            classification = "SAFE"
        else:
            classification = "REVIEW REQUIRED"

    else:
        classification = "REVIEW REQUIRED"

    return {
        "cipher": cipher,
        "protocol": protocol,
        "bits": bits,
        "classification": classification,
        "unsafe_tokens": unsafe_matches,
        "review_tokens": review_matches,
    }


# ============================================================================
# Certificate metadata
# ============================================================================

def _certificate_metadata(
    host: str,
    port: int,
    *,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """
    Collect certificate cryptographic metadata.

    This is intentionally supporting evidence for TC07. Certificate expiry
    belongs primarily to TC09.
    """

    context = _create_context(
        verify_tls=verify_tls,
    )

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as raw_sock:
            with context.wrap_socket(
                raw_sock,
                server_hostname=host,
            ) as tls_sock:

                certificate = tls_sock.getpeercert()
                version = tls_sock.version()
                cipher = tls_sock.cipher()

                return {
                    "available": True,
                    "tls_version": version,
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": (
                        cipher[2]
                        if cipher and len(cipher) >= 3
                        else None
                    ),
                    "subject": certificate.get("subject", ()),
                    "issuer": certificate.get("issuer", ()),
                    "serial_number": certificate.get(
                        "serialNumber",
                        "",
                    ),
                    "signature_algorithm": certificate.get(
                        "signatureAlgorithm",
                        "",
                    ),
                }

    except Exception as exc:
        return {
            "available": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
        }


# ============================================================================
# TLS compression
# ============================================================================

def _compression_name(tls_sock: ssl.SSLSocket) -> str | None:
    """
    Return negotiated TLS compression when exposed by the runtime.

    Modern TLS stacks normally return None because TLS compression is not
    negotiated.
    """

    try:
        compression = tls_sock.compression()
        return compression
    except Exception:
        return None


def _test_baseline(
    host: str,
    port: int,
    *,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    try:
        context = _create_context(
            verify_tls=verify_tls,
        )

        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as raw_sock:

            with context.wrap_socket(
                raw_sock,
                server_hostname=host,
            ) as tls_sock:

                cipher = tls_sock.cipher()

                return {
                    "success": True,
                    "protocol": tls_sock.version(),
                    "cipher": cipher[0] if cipher else "",
                    "cipher_bits": (
                        cipher[2]
                        if cipher and len(cipher) >= 3
                        else None
                    ),
                    "compression": _compression_name(
                        tls_sock
                    ),
                }

    except Exception as exc:
        return {
            "success": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:500],
        }


# ============================================================================
# Main scanner
# ============================================================================

def scan_weak_cipher(
    url: str,
    verify_tls: bool = True,
    timeout: float = 12.0,
) -> dict:
    """
    TC07 - Weak TLS Protocols / Cipher Suites

    Scope:
        Evaluate the HTTPS/TLS configuration exposed by the target.

    Does:
        - baseline TLS handshake
        - explicit legacy protocol probes
        - modern TLS protocol probes
        - cipher classification for negotiated sessions
        - certificate crypto metadata collection
        - TLS compression observation
        - conservative result classification

    Does NOT:
        - brute-force arbitrary application resources
        - exploit TLS vulnerabilities
        - perform destructive actions
        - replace a full dedicated TLS scanner
    """

    target = normalize_url(url)
    parsed = urlparse(target)

    inferred_https = parsed.scheme.lower() == "http"
    if inferred_https:
        # A site URL supplied over HTTP can still expose HTTPS on the same host.
        # Try the same host/path over HTTPS rather than skipping TLS-specific tests.
        target = parsed._replace(scheme="https").geturl()
        parsed = urlparse(target)

    if not parsed.hostname:
        return result(
            "INCOMPLETE",
            "The target URL does not contain a valid hostname for TLS testing.",
            details={
                "target": target,
                "https_inferred_from_http_target": inferred_https,
            },
        )

    host = parsed.hostname
    port = parsed.port or 443

    details: dict[str, Any] = {
        "target": target,
        "https_inferred_from_http_target": inferred_https,
        "hostname": host,
        "port": port,
        "tls_verification": verify_tls,
    }

    # ------------------------------------------------------------------
    # 1. Baseline handshake
    # ------------------------------------------------------------------

    baseline = _test_baseline(
        host,
        port,
        verify_tls=verify_tls,
        timeout=timeout,
    )

    if (
        not baseline["success"]
        and verify_tls
        and is_tls_verification_error(baseline.get("error", ""))
    ):
        verify_tls = False
        details["tls_verification"] = False
        details["tls_verification_fallback"] = True
        baseline = _test_baseline(
            host,
            port,
            verify_tls=False,
            timeout=timeout,
        )

    details["baseline"] = baseline

    if not baseline["success"]:
        return connection_result(
            RuntimeError(
                baseline.get(
                    "error",
                    "TLS handshake failed",
                )
            ),
            target=target,
        )

    baseline_analysis = _classify_cipher(
        baseline.get("protocol", ""),
        baseline.get("cipher", ""),
        baseline.get("cipher_bits"),
    )

    details["baseline_cipher_analysis"] = baseline_analysis

    # ------------------------------------------------------------------
    # 2. Explicit protocol probes
    # ------------------------------------------------------------------

    protocol_probes: list[TLSProbe] = []

    for _, version in _get_supported_tls_versions():

        # SSLv2 is generally not exposed by modern Python/OpenSSL.
        # If unavailable locally, we don't fabricate a negative result.
        probe = _probe_protocol(
            host,
            port,
            version,
            verify_tls=verify_tls,
            timeout=timeout,
        )

        protocol_probes.append(probe)

    details["protocol_probes"] = [
        probe.as_dict()
        for probe in protocol_probes
    ]

    # ------------------------------------------------------------------
    # 3. Identify supported legacy protocols
    # ------------------------------------------------------------------

    supported_legacy = [
        probe
        for probe in protocol_probes
        if probe.supported
        and probe.protocol in DEPRECATED_PROTOCOLS
    ]

    details["supported_legacy_protocols"] = [
        probe.protocol
        for probe in supported_legacy
    ]

    # ------------------------------------------------------------------
    # 4. Protocol-level UNSAFE findings
    # ------------------------------------------------------------------

    if supported_legacy:

        evidence = []

        for probe in supported_legacy:
            evidence.append(
                "Legacy protocol accepted: "
                f"{probe.protocol}"
                + (
                    f" with {probe.cipher}"
                    if probe.cipher
                    else ""
                )
            )

        return result(
            "UNSAFE",
            "The HTTPS service accepted one or more deprecated TLS protocol versions during controlled protocol negotiation.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # 5. Weak cipher findings from explicitly negotiated probes
    # ------------------------------------------------------------------

    cipher_findings: list[dict[str, Any]] = []

    for probe in protocol_probes:
        if not probe.supported or not probe.cipher:
            continue

        analysis = _classify_cipher(
            probe.negotiated_protocol,
            probe.cipher,
            probe.cipher_bits,
        )

        cipher_findings.append(
            analysis
        )

    details["cipher_findings"] = cipher_findings

    unsafe_ciphers = [
        finding
        for finding in cipher_findings
        if finding["classification"] == "UNSAFE"
    ]

    if unsafe_ciphers:
        evidence = [
            (
                f"{finding['protocol']} negotiated "
                f"{finding['cipher']}"
                + (
                    f" ({finding['bits']} bits)"
                    if finding["bits"] is not None
                    else ""
                )
            )
            for finding in unsafe_ciphers
        ]

        return result(
            "UNSAFE",
            "The HTTPS service negotiated a cipher suite classified as cryptographically weak or explicitly prohibited by the TC07 policy.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # 6. TLS compression
    # ------------------------------------------------------------------

    compression = baseline.get("compression")

    details["tls_compression"] = compression

    if compression:
        return result(
            "REVIEW REQUIRED",
            "The TLS connection reported negotiated compression. Review whether TLS compression is required and whether the deployment is exposed to compression-related risks.",
            details=details,
            evidence=[
                f"Negotiated TLS compression: {compression}",
            ],
        )

    # ------------------------------------------------------------------
    # 7. Certificate crypto metadata
    # ------------------------------------------------------------------

    certificate = _certificate_metadata(
        host,
        port,
        verify_tls=verify_tls,
        timeout=timeout,
    )

    details["certificate_crypto"] = certificate

    # We deliberately do not classify certificate expiry here.
    # TC09 owns certificate expiration/validity testing.

    signature = str(
        certificate.get(
            "signature_algorithm",
            "",
        )
    ).upper()

    weak_signature = any(
        item in signature
        for item in (
            "MD5",
            "SHA1",
        )
    )

    if weak_signature:
        return result(
            "UNSAFE",
            "The TLS certificate reports a legacy cryptographic signature algorithm that should be reviewed or replaced.",
            details=details,
            evidence=[
                "Certificate signature algorithm: "
                f"{certificate.get('signature_algorithm', '')}"
            ],
        )

    # ------------------------------------------------------------------
    # 8. Check whether any tests were impossible locally
    # ------------------------------------------------------------------

    locally_unavailable = [
        probe.protocol
        for probe in protocol_probes
        if probe.locally_unavailable
    ]

    details["locally_unavailable_protocol_tests"] = locally_unavailable

    protocol_labels = {
        "SSLv3": "SSL 3.0",
        "768": "SSL 3.0",
        "TLSv1": "TLS 1.0",
        "769": "TLS 1.0",
        "TLSv1.1": "TLS 1.1",
        "770": "TLS 1.1",
    }
    details["locally_unavailable_protocol_names"] = [
        protocol_labels.get(item, item)
        for item in locally_unavailable
    ]
    details["coverage_status"] = "PARTIAL" if locally_unavailable else "COMPLETE"

    # ------------------------------------------------------------------
    # 9. Review-level cipher findings
    # ------------------------------------------------------------------

    review_ciphers = [
        finding
        for finding in cipher_findings
        if finding["classification"] == "REVIEW REQUIRED"
    ]

    if review_ciphers:
        evidence = [
            (
                f"{finding['protocol']} negotiated "
                f"{finding['cipher']}"
            )
            for finding in review_ciphers
        ]

        return result(
            "REVIEW REQUIRED",
            "The service did not negotiate an explicitly prohibited cipher, but at least one negotiated cipher requires policy review. A dedicated TLS scanner should be used for exhaustive cipher-suite enumeration.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # 10. Incomplete coverage
    # ------------------------------------------------------------------

    if locally_unavailable:
        return result(
            "REVIEW REQUIRED",
            "No weak TLS configuration was confirmed, but one or more legacy protocol checks could not be performed because the local Python/OpenSSL environment does not expose those protocol capabilities. This must not be interpreted as proof that the server disables them.",
            details=details,
            evidence=[
                "Locally unavailable protocol checks: "
                + ", ".join(
                    details["locally_unavailable_protocol_names"]
                ),
                "This is a local scanner-environment limitation, not evidence that the target accepted those protocols.",
            ],
        )

    # ------------------------------------------------------------------
    # 11. Everything tested cleanly
    # ------------------------------------------------------------------

    return result(
        "SAFE",
        "The tested HTTPS endpoint negotiated modern TLS settings, no explicitly prohibited legacy protocol was accepted, and no clearly weak negotiated cipher or certificate signature algorithm was identified.",
        details=details,
    )