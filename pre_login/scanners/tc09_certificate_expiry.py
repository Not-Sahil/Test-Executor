from __future__ import annotations

import hashlib
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .common import (
    normalize_url,
    result,
    connection_result,
)


# ============================================================================
# Data model
# ============================================================================

@dataclass
class CertificateValidity:
    not_before: datetime | None
    not_after: datetime | None
    fingerprint_sha256: str
    subject: str
    issuer: str
    serial_number: str
    signature_algorithm: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "not_before": (
                self.not_before.isoformat()
                if self.not_before
                else None
            ),
            "not_after": (
                self.not_after.isoformat()
                if self.not_after
                else None
            ),
            "fingerprint_sha256": self.fingerprint_sha256,
            "subject": self.subject,
            "issuer": self.issuer,
            "serial_number": self.serial_number,
            "signature_algorithm": self.signature_algorithm,
        }


# ============================================================================
# Certificate parsing
# ============================================================================

def _parse_certificate(
    der_bytes: bytes,
) -> CertificateValidity:
    """
    Parse an X.509 certificate from DER.

    cryptography is used instead of relying on ssl.getpeercert(),
    because we need reliable certificate data even when normal TLS
    verification fails.
    """

    certificate = x509.load_der_x509_certificate(
        der_bytes
    )

    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc

    fingerprint = certificate.fingerprint(
        hashes.SHA256()
    ).hex()

    signature_algorithm = ""

    try:
        if certificate.signature_hash_algorithm:
            signature_algorithm = (
                certificate.signature_hash_algorithm.name
            )
    except Exception:
        signature_algorithm = ""

    return CertificateValidity(
        not_before=not_before,
        not_after=not_after,
        fingerprint_sha256=fingerprint,
        subject=certificate.subject.rfc4514_string(),
        issuer=certificate.issuer.rfc4514_string(),
        serial_number=format(
            certificate.serial_number,
            "x",
        ),
        signature_algorithm=signature_algorithm,
    )


# ============================================================================
# TLS certificate retrieval
# ============================================================================

def _fetch_presented_certificate(
    host: str,
    port: int,
    *,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """
    Retrieve the certificate actually presented by the server.

    When verify_tls=False, certificate verification is intentionally disabled
    so that certificates which are expired, self-signed, internally issued,
    etc. can still be inspected.

    This does NOT mean the certificate is considered trusted.
    """

    context = ssl.create_default_context()

    if not verify_tls:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    with socket.create_connection(
        (host, port),
        timeout=timeout,
    ) as raw_sock:

        with context.wrap_socket(
            raw_sock,
            server_hostname=host,
        ) as tls_sock:

            der = tls_sock.getpeercert(
                binary_form=True
            )

            if not der:
                raise RuntimeError(
                    "The TLS service did not return a peer certificate."
                )

            certificate = _parse_certificate(
                der
            )

            cipher = tls_sock.cipher()

            return {
                "certificate": certificate,
                "tls_version": (
                    tls_sock.version() or ""
                ),
                "cipher": (
                    cipher[0]
                    if cipher
                    else ""
                ),
                "cipher_bits": (
                    cipher[2]
                    if cipher and len(cipher) >= 3
                    else None
                ),
            }


# ============================================================================
# Verified connection
# ============================================================================

def _attempt_verified_connection(
    host: str,
    port: int,
    *,
    timeout: float,
) -> dict[str, Any]:

    context = ssl.create_default_context()

    try:
        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as raw_sock:

            with context.wrap_socket(
                raw_sock,
                server_hostname=host,
            ) as tls_sock:

                der = tls_sock.getpeercert(
                    binary_form=True
                )

                if not der:
                    return {
                        "success": False,
                        "error_type": (
                            "MissingCertificate"
                        ),
                        "error": (
                            "The TLS service did not "
                            "present a peer certificate."
                        ),
                    }

                certificate = _parse_certificate(
                    der
                )

                cipher = tls_sock.cipher()

                return {
                    "success": True,
                    "certificate": certificate,
                    "tls_version": (
                        tls_sock.version() or ""
                    ),
                    "cipher": (
                        cipher[0]
                        if cipher
                        else ""
                    ),
                    "cipher_bits": (
                        cipher[2]
                        if cipher and len(cipher) >= 3
                        else None
                    ),
                }

    except ssl.SSLCertVerificationError as exc:
        return {
            "success": False,
            "verification_failed": True,
            "error_type": type(exc).__name__,
            "error": str(exc)[:1000],
        }

    except (
        ssl.SSLError,
        socket.timeout,
        TimeoutError,
        ConnectionError,
        OSError,
    ) as exc:

        return {
            "success": False,
            "verification_failed": False,
            "error_type": type(exc).__name__,
            "error": str(exc)[:1000],
        }


# ============================================================================
# Verification-error analysis
# ============================================================================

def _categorize_verification_error(
    message: str,
) -> str:

    lower = message.lower()

    if "expired" in lower:
        return "expired"

    if (
        "not yet valid" in lower
        or "certificate is not yet valid" in lower
    ):
        return "not_yet_valid"

    if (
        "hostname mismatch" in lower
        or "doesn't match" in lower
        or "does not match" in lower
    ):
        return "hostname_mismatch"

    if (
        "self signed" in lower
        or "self-signed" in lower
    ):
        return "self_signed"

    if (
        "unable to get local issuer" in lower
        or "unknown ca" in lower
        or "certificate verify failed" in lower
    ):
        return "trust_or_chain"

    return "other"


# ============================================================================
# Validity calculation
# ============================================================================

def _calculate_validity(
    certificate: CertificateValidity,
    now: datetime,
    warning_days: int,
) -> dict[str, Any]:

    not_before = certificate.not_before
    not_after = certificate.not_after

    if not_before is None or not_after is None:
        return {
            "status": "unavailable",
            "days_remaining": None,
            "seconds_remaining": None,
            "not_yet_valid": False,
            "expired": False,
            "expires_soon": False,
            "invalid_interval": False,
        }

    if not_after <= not_before:
        return {
            "status": "invalid_interval",
            "days_remaining": None,
            "seconds_remaining": None,
            "not_yet_valid": False,
            "expired": False,
            "expires_soon": False,
            "invalid_interval": True,
        }

    if now < not_before:
        delta = not_before - now

        return {
            "status": "not_yet_valid",
            "days_until_valid": (
                delta.total_seconds() / 86400
            ),
            "days_remaining": (
                (not_after - now).total_seconds()
                / 86400
            ),
            "seconds_remaining": (
                (not_after - now).total_seconds()
            ),
            "not_yet_valid": True,
            "expired": False,
            "expires_soon": False,
            "invalid_interval": False,
        }

    if now > not_after:
        delta = now - not_after

        return {
            "status": "expired",
            "days_expired": (
                delta.total_seconds() / 86400
            ),
            "days_remaining": (
                (not_after - now).total_seconds()
                / 86400
            ),
            "seconds_remaining": (
                (not_after - now).total_seconds()
            ),
            "not_yet_valid": False,
            "expired": True,
            "expires_soon": False,
            "invalid_interval": False,
        }

    days_remaining = (
        not_after - now
    ).total_seconds() / 86400

    expires_soon = (
        days_remaining <= warning_days
    )

    return {
        "status": (
            "expires_soon"
            if expires_soon
            else "valid"
        ),
        "days_remaining": days_remaining,
        "seconds_remaining": (
            not_after - now
        ).total_seconds(),
        "not_yet_valid": False,
        "expired": False,
        "expires_soon": expires_soon,
        "invalid_interval": False,
    }


# ============================================================================
# Optional peer-chain inspection
# ============================================================================

def _get_peer_chain_expiry(
    host: str,
    port: int,
    *,
    timeout: float,
) -> list[dict[str, Any]]:

    observations: list[dict[str, Any]] = []

    context = ssl.create_default_context()

    try:

        with socket.create_connection(
            (host, port),
            timeout=timeout,
        ) as raw_sock:

            with context.wrap_socket(
                raw_sock,
                server_hostname=host,
            ) as tls_sock:

                # Python/OpenSSL availability differs by runtime.
                #
                # get_verified_chain() is used when available.
                get_chain = getattr(
                    tls_sock,
                    "get_verified_chain",
                    None,
                )

                if get_chain is None:
                    return observations

                chain = get_chain()

                for index, cert_obj in enumerate(chain):

                    try:
                        # Depending on Python/OpenSSL version, chain
                        # objects may expose public_bytes().
                        der = cert_obj.public_bytes(
                            __import__(
                                "cryptography.hazmat.primitives.serialization",
                                fromlist=["Encoding"],
                            ).Encoding.DER
                        )

                        certificate = (
                            _parse_certificate(der)
                        )

                        observations.append(
                            {
                                "chain_index": index,
                                **certificate.as_dict(),
                            }
                        )

                    except Exception as exc:
                        observations.append(
                            {
                                "chain_index": index,
                                "parse_error": str(
                                    exc
                                )[:500],
                            }
                        )

    except Exception:
        # Chain availability is supporting information and must not make
        # the entire testcase fail.
        return observations

    return observations


# ============================================================================
# Main scanner
# ============================================================================

def scan_certificate_expiry(
    url: str,
    verify_tls: bool = True,
    timeout: float = 12.0,
    warning_days: int = 60,
) -> dict:
    """
    TC09 - Certificate Expiry / Validity

    Tests:
        - certificate availability
        - notBefore
        - notAfter
        - expired certificate
        - not-yet-valid certificate
        - remaining validity period
        - configurable expiry warning
        - invalid validity interval
        - verified TLS behavior
        - certificate metadata
        - optional peer-chain validity

    This testcase does not own:
        - wildcard matching
        - hostname/SAN testing
        - weak cipher testing
        - general CA policy testing
    """

    target = normalize_url(url)
    parsed = urlparse(target)

    # ------------------------------------------------------------------
    # 1. Applicability
    # ------------------------------------------------------------------

    inferred_https = parsed.scheme.lower() == "http"
    if inferred_https:
        # A site URL supplied over HTTP can still expose HTTPS on the same host.
        # Try the same host/path over HTTPS rather than skipping TLS-specific tests.
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

    host = parsed.hostname
    port = parsed.port or 443

    if warning_days < 0:
        return result(
            "INCOMPLETE",
            "The certificate-expiry warning threshold cannot be negative.",
            details={
                "warning_days": warning_days,
            },
        )

    details: dict[str, Any] = {
        "target": target,
        "https_inferred_from_http_target": inferred_https,
        "hostname": host,
        "port": port,
        "warning_days": warning_days,
        "tls_verification_requested": verify_tls,
    }

    # ------------------------------------------------------------------
    # 2. First attempt a normal verified connection.
    #
    # This is important because an invalid certificate may cause handshake
    # failure. We want to know that independently from its actual dates.
    # ------------------------------------------------------------------

    verified = _attempt_verified_connection(
        host,
        port,
        timeout=timeout,
    )

    details["verified_connection"] = {
        "success": verified.get(
            "success",
            False,
        ),
        "verification_failed": verified.get(
            "verification_failed",
            False,
        ),
        "error_type": verified.get(
            "error_type",
            "",
        ),
        "error": verified.get(
            "error",
            "",
        ),
    }

    # ------------------------------------------------------------------
    # 3. Get the presented certificate.
    #
    # Even if verification failed, we need the actual certificate to
    # determine whether expiry is the reason.
    # ------------------------------------------------------------------

    presented: dict[str, Any] | None = None
    presented_error: Exception | None = None

    # If caller explicitly requested verification, first use the verified
    # connection result if it succeeded.
    if verified.get("success"):
        presented = verified

    else:
        try:
            presented = _fetch_presented_certificate(
                host,
                port,
                # Use the caller's requested verification behavior first.
                verify_tls=verify_tls,
                timeout=timeout,
            )
        except Exception as exc:
            presented_error = exc

    # If the verified connection failed and the configured verification
    # setting prevented certificate retrieval, perform a diagnostic
    # unverified connection. This is necessary to inspect an expired
    # certificate rather than merely reporting "TLS failed".
    if presented is None:

        try:
            presented = _fetch_presented_certificate(
                host,
                port,
                verify_tls=False,
                timeout=timeout,
            )

            details["diagnostic_certificate_connection"] = (
                True
            )

        except Exception as exc:

            details[
                "diagnostic_certificate_connection"
            ] = False

            details[
                "diagnostic_certificate_error"
            ] = {
                "type": type(exc).__name__,
                "message": str(exc)[:1000],
            }

            if presented_error:
                return connection_result(
                    presented_error,
                    target=target,
                )

            return connection_result(
                exc,
                target=target,
            )

    certificate: CertificateValidity = (
        presented["certificate"]
    )

    details["certificate"] = (
        certificate.as_dict()
    )

    details["tls_version"] = presented.get(
        "tls_version",
        "",
    )

    details["cipher"] = presented.get(
        "cipher",
        "",
    )

    details["cipher_bits"] = presented.get(
        "cipher_bits",
        None,
    )

    # ------------------------------------------------------------------
    # 4. Calculate validity
    # ------------------------------------------------------------------

    now = datetime.now(timezone.utc)

    validity = _calculate_validity(
        certificate,
        now,
        warning_days,
    )

    details["validity_analysis"] = validity
    details["checked_at_utc"] = now.isoformat()

    # ------------------------------------------------------------------
    # 5. Missing/malformed dates
    # ------------------------------------------------------------------

    if certificate.not_before is None or (
        certificate.not_after is None
    ):
        return result(
            "REVIEW REQUIRED",
            "The presented TLS certificate could not be evaluated because one or both certificate validity timestamps were unavailable.",
            details=details,
        )

    # ------------------------------------------------------------------
    # 6. Invalid validity interval
    # ------------------------------------------------------------------

    if validity["invalid_interval"]:

        return result(
            "UNSAFE",
            "The certificate has an invalid validity interval because its expiration time is not later than its start time.",
            details=details,
            evidence=[
                (
                    "notBefore: "
                    f"{certificate.not_before.isoformat()}"
                ),
                (
                    "notAfter: "
                    f"{certificate.not_after.isoformat()}"
                ),
            ],
        )

    # ------------------------------------------------------------------
    # 7. Not yet valid
    # ------------------------------------------------------------------

    if validity["not_yet_valid"]:

        return result(
            "UNSAFE",
            "The presented TLS certificate is not yet valid because its validity period starts in the future.",
            details=details,
            evidence=[
                (
                    "Certificate becomes valid at: "
                    f"{certificate.not_before.isoformat()}"
                ),
                (
                    "Current UTC time: "
                    f"{now.isoformat()}"
                ),
            ],
        )

    # ------------------------------------------------------------------
    # 8. Expired
    # ------------------------------------------------------------------

    if validity["expired"]:

        days_expired = validity.get(
            "days_expired",
            0,
        )

        return result(
            "UNSAFE",
            "The presented TLS certificate has expired.",
            details=details,
            evidence=[
                (
                    "Certificate expired at: "
                    f"{certificate.not_after.isoformat()}"
                ),
                (
                    f"Days expired: "
                    f"{round(days_expired, 2)}"
                ),
            ],
        )

    # ------------------------------------------------------------------
    # 9. Expiring soon
    # ------------------------------------------------------------------

    if validity["expires_soon"]:

        remaining = validity.get(
            "days_remaining",
            0,
        )

        return result(
            "REVIEW REQUIRED",
            (
                "The TLS certificate is currently valid but "
                f"expires within the configured {warning_days}-day "
                "warning window. Renew it before expiration to "
                "avoid service disruption."
            ),
            details=details,
            evidence=[
                (
                    "Certificate expires at: "
                    f"{certificate.not_after.isoformat()}"
                ),
                (
                    f"Days remaining: "
                    f"{round(remaining, 2)}"
                ),
            ],
        )

    # ------------------------------------------------------------------
    # 10. Optional chain inspection
    # ------------------------------------------------------------------

    chain = _get_peer_chain_expiry(
        host,
        port,
        timeout=timeout,
    )

    details["peer_chain"] = chain

    expired_chain_certificates = []

    not_yet_valid_chain_certificates = []

    chain_now = datetime.now(timezone.utc)

    for chain_certificate in chain:

        not_before_raw = chain_certificate.get(
            "not_before"
        )

        not_after_raw = chain_certificate.get(
            "not_after"
        )

        if not_before_raw and not_after_raw:

            try:
                chain_not_before = (
                    datetime.fromisoformat(
                        not_before_raw
                    )
                )

                chain_not_after = (
                    datetime.fromisoformat(
                        not_after_raw
                    )
                )

                if chain_now > chain_not_after:
                    expired_chain_certificates.append(
                        chain_certificate
                    )

                elif chain_now < chain_not_before:
                    not_yet_valid_chain_certificates.append(
                        chain_certificate
                    )

            except ValueError:
                continue

    details[
        "expired_peer_chain_certificates"
    ] = expired_chain_certificates

    details[
        "not_yet_valid_peer_chain_certificates"
    ] = not_yet_valid_chain_certificates

    if expired_chain_certificates:

        return result(
            "UNSAFE",
            "The presented TLS certificate chain contains an expired certificate.",
            details=details,
            evidence=[
                (
                    "Expired certificate in peer chain "
                    f"at chain index "
                    f"{item.get('chain_index')}: "
                    f"{item.get('subject', '')}"
                )
                for item in expired_chain_certificates
            ],
        )

    if not_yet_valid_chain_certificates:

        return result(
            "UNSAFE",
            "The presented TLS certificate chain contains a certificate that is not yet valid.",
            details=details,
            evidence=[
                (
                    "Not-yet-valid certificate in peer chain "
                    f"at chain index "
                    f"{item.get('chain_index')}: "
                    f"{item.get('subject', '')}"
                )
                for item in (
                    not_yet_valid_chain_certificates
                )
            ],
        )

    # ------------------------------------------------------------------
    # 11. Certificate validity is clean
    # ------------------------------------------------------------------

    remaining = validity.get(
        "days_remaining",
        0,
    )

    evidence = [
        (
            "Certificate valid from: "
            f"{certificate.not_before.isoformat()}"
        ),
        (
            "Certificate valid until: "
            f"{certificate.not_after.isoformat()}"
        ),
        (
            f"Days remaining: "
            f"{round(remaining, 2)}"
        ),
    ]

    # Add verification status as supporting information.
    if verified.get("success"):
        evidence.append(
            "Normal TLS certificate verification succeeded."
        )
    else:
        error_message = verified.get(
            "error",
            "",
        )

        if error_message:
            category = _categorize_verification_error(
                error_message
            )

            details[
                "certificate_verification_issue"
            ] = {
                "category": category,
                "message": error_message,
            }

            # A date-clean certificate can still have a CA trust or
            # hostname problem. Do not incorrectly call that SAFE.
            if category not in {
                "other",
                "",
            }:
                return result(
                    "REVIEW REQUIRED",
                    (
                        "The certificate is currently within "
                        "its validity period, but normal TLS "
                        "certificate verification did not "
                        "succeed. The issue appears to be "
                        f"'{category}', which is outside the "
                        "expiry-only condition and should be "
                        "reviewed separately."
                    ),
                    details=details,
                    evidence=evidence + [
                        (
                            "TLS verification result: "
                            f"{error_message}"
                        )
                    ],
                )

    return result(
        "SAFE",
        (
            "The presented TLS certificate is currently "
            "within its validity period and does not expire "
            f"within the configured {warning_days}-day warning "
            "window."
        ),
        details=details,
        evidence=evidence,
    )