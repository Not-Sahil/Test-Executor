from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

import requests


_TLS_ERROR_MARKERS = (
    "SSL",
    "TLS",
    "CERTIFICATE",
    "CERT_EXPIRED",
    "CERTIFICATE_VERIFY_FAILED",
    "CERTVERIFY",
    "SEC_E_CERT",
    "SSLERROR",
    "SSLCERTVERIFICATIONERROR",
)


def is_tls_verification_error(exc: BaseException | str) -> bool:
    """Return True when an exception or message is a TLS/certificate failure."""
    name = type(exc).__name__.upper() if isinstance(exc, BaseException) else ""
    text = str(exc).upper()
    haystack = f"{name} {text}"
    return any(marker in haystack for marker in _TLS_ERROR_MARKERS)


def effective_verify_tls(
    url: str,
    verify_tls: bool = True,
    *,
    timeout: float = 8.0,
) -> tuple[bool, str | None]:
    """
    Keep application tests running when an authorized target presents an
    untrusted or expired certificate.

    Certificate-specific scanners still inspect the presented certificate;
    this helper only decides whether ordinary HTTPS requests should verify.
    """
    if not verify_tls:
        return False, None

    raw = (url or "").strip()
    if not raw:
        return True, None
    if not raw.lower().startswith(("http://", "https://")):
        raw = "https://" + raw

    parsed = urlparse(raw)
    if parsed.scheme.lower() != "https":
        return True, None

    try:
        requests.get(
            raw,
            timeout=timeout,
            verify=True,
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
        )
        return True, None
    except Exception as exc:
        if is_tls_verification_error(exc):
            return False, (
                "The target TLS certificate failed verification. Remaining tests "
                "continued without certificate verification so application findings "
                "can still be produced. Certificate Expiry / Weak Cipher checks "
                "still inspect the presented certificate."
            )
        return True, None


DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_BODY = 100_000

USER_AGENT = "SecurityAssessmentScanner/1.0"


@dataclass
class HTTPSProbeResult:
    """
    Result of a lightweight HTTPS availability check.

    reachable:
        True when a TLS endpoint responded, even if the certificate
        could not be verified.

    verified:
        True when the TLS endpoint responded successfully with normal
        certificate verification enabled.

    status_code:
        HTTP status returned by the HTTPS endpoint, if available.

    final_url:
        URL actually tested/returned.

    certificate_error:
        Error produced by the verified TLS attempt, if any.

    error:
        Final error when the endpoint could not be reached even
        diagnostically.
    """

    reachable: bool
    verified: bool
    status_code: int | None = None
    final_url: str | None = None
    certificate_error: str | None = None
    error: str | None = None

    def as_dict(self) -> dict:
        return {
            "reachable": self.reachable,
            "verified": self.verified,
            "status_code": self.status_code,
            "final_url": self.final_url,
            "certificate_error": self.certificate_error,
            "error": self.error,
        }


def build_https_url(url: str) -> str:
    """
    Convert a supplied HTTP/HTTPS URL into its HTTPS counterpart.

    Examples:
        http://example.com       -> https://example.com
        http://example.com/test  -> https://example.com/test
        https://example.com      -> https://example.com
    """

    raw = (url or "").strip()

    if not raw:
        raise ValueError("Target URL is empty")

    if not raw.lower().startswith(
        ("http://", "https://")
    ):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if not parsed.netloc:
        raise ValueError(
            f"Invalid target URL: {url!r}"
        )

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            f"Unsupported URL scheme: {parsed.scheme!r}"
        )

    # Preserve:
    # - hostname
    # - explicit port
    # - path
    # - query
    # - fragment
    return parsed._replace(
        scheme="https"
    ).geturl()


def _request_https(
    url: str,
    *,
    verify_tls: bool,
    timeout: float,
    allow_redirects: bool,
) -> requests.Response:
    """
    Perform a lightweight HTTPS request.

    HEAD is preferred to reduce response size. Some applications
    do not implement HEAD correctly, so the caller can fall back
    to GET.
    """

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "*/*",
    }

    response = requests.request(
        "HEAD",
        url,
        timeout=timeout,
        verify=verify_tls,
        allow_redirects=allow_redirects,
        headers=headers,
    )

    # 405/501 commonly means HEAD isn't supported. Use GET.
    if response.status_code in {
        405,
        501,
    }:
        response = requests.request(
            "GET",
            url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=allow_redirects,
            headers=headers,
        )

    return response


def probe_https_endpoint(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    allow_redirects: bool = False,
) -> HTTPSProbeResult:
    """
    Determine whether an HTTPS/TLS endpoint exists.

    Important behavior:

    1. Try normal certificate verification first.
    2. If verification fails, retry without verification only to
       determine whether HTTPS/TLS itself is reachable.
    3. A certificate failure does NOT make the HTTPS endpoint
       NOT APPLICABLE.

    This is important for:
        TC07 - TLS protocol/cipher testing
        TC08 - wildcard certificate analysis
        TC09 - certificate expiry
    """

    https_url = build_https_url(
        url
    )

    verified_error: str | None = None

    # ========================================================
    # First attempt: normal TLS verification
    # ========================================================

    try:
        response = _request_https(
            https_url,
            verify_tls=verify_tls,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )

        return HTTPSProbeResult(
            reachable=True,
            verified=True,
            status_code=response.status_code,
            final_url=getattr(
                response,
                "url",
                https_url,
            ),
        )

    except requests.exceptions.SSLError as exc:
        verified_error = str(exc)

    except requests.exceptions.RequestException as exc:
        # A normal network failure may still be worth testing
        # diagnostically below.
        verified_error = str(exc)

    # ========================================================
    # Second attempt: diagnostic TLS connection
    #
    # Certificate validation is deliberately disabled only for
    # determining whether TLS is actually available.
    # ========================================================

    try:
        response = _request_https(
            https_url,
            verify_tls=False,
            timeout=timeout,
            allow_redirects=allow_redirects,
        )

        return HTTPSProbeResult(
            reachable=True,
            verified=False,
            status_code=response.status_code,
            final_url=getattr(
                response,
                "url",
                https_url,
            ),
            certificate_error=verified_error,
        )

    except requests.exceptions.RequestException as exc:
        return HTTPSProbeResult(
            reachable=False,
            verified=False,
            status_code=None,
            final_url=https_url,
            certificate_error=verified_error,
            error=str(exc),
        )


def https_available(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
) -> bool:
    """
    Convenience boolean wrapper.

    Returns True whenever an HTTPS endpoint can be reached,
    including cases where certificate verification fails.

    This function is intentionally suitable for testcase
    applicability decisions.
    """

    probe = probe_https_endpoint(
        url,
        timeout=timeout,
        verify_tls=verify_tls,
        allow_redirects=False,
    )

    return probe.reachable