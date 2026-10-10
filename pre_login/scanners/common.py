from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import warnings
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests
from urllib3.exceptions import InsecureRequestWarning


# ============================================================
# DEFAULT CONFIGURATION
# ============================================================

DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_BODY = 250_000

UA = "SecurityAssessmentScanner/1.0"


# ============================================================
# URL HELPERS
# ============================================================

def normalize_url(url: str) -> str:
    """
    Normalize and validate a target URL.

    Keeps the original path/query but removes trailing slashes.
    Adds HTTPS when a scheme is not supplied.
    """

    raw = (url or "").strip()

    if not raw:
        raise ValueError("Target URL is empty")

    # Add a default scheme.
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError(
            f"Unsupported URL scheme: {parsed.scheme!r}"
        )

    if not parsed.netloc:
        raise ValueError(
            f"Invalid target URL: {url!r}"
        )

    if not parsed.hostname:
        raise ValueError(
            f"Invalid target hostname: {url!r}"
        )

    # Reject obvious malformed whitespace/control characters.
    if any(
        ord(char) < 32
        for char in raw
    ):
        raise ValueError(
            "Target URL contains control characters"
        )

    # urlparse may accept malformed ports until .port is accessed.
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError(
            f"Invalid target port in URL: {url!r}"
        ) from exc

    return raw.rstrip("/")


def origin_root_url(url: str) -> str:
    """Normalize a target to the root of its HTTP(S) origin.

    Resource-discovery checks must not append absolute resource paths to a
    supplied deep URL such as /login.jsp. This helper keeps scheme, hostname,
    and port and intentionally scopes discovery paths from the origin root.
    """
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    return urlunparse((parsed.scheme, parsed.netloc, "/", "", "", "")).rstrip("/")


def effective_port(
    parsed_url,
) -> int | None:
    """
    Return the explicitly specified port or the default
    port for HTTP/HTTPS.
    """

    if parsed_url.port is not None:
        return parsed_url.port

    scheme = parsed_url.scheme.lower()

    if scheme == "http":
        return 80

    if scheme == "https":
        return 443

    return None


def same_origin(
    a: str,
    b: str,
) -> bool:
    """
    Compare two URLs using scheme, hostname and effective port.
    """

    try:
        x = urlparse(
            normalize_url(a)
        )
        y = urlparse(
            normalize_url(b)
        )
    except ValueError:
        return False

    return (
        x.scheme.lower(),
        (x.hostname or "").lower(),
        effective_port(x),
    ) == (
        y.scheme.lower(),
        (y.hostname or "").lower(),
        effective_port(y),
    )


def absolute(
    base: str,
    path: str,
) -> str:
    """
    Convert a relative path/reference into an absolute URL.
    """

    normalized_base = normalize_url(base)

    return urljoin(
        normalized_base + "/",
        (path or "").lstrip("/"),
    )


# ============================================================
# HTTP REQUEST HELPER
# ============================================================

def request(
    url: str,
    *,
    method: str = "GET",
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    allow_redirects: bool = True,
    max_body: int = DEFAULT_MAX_BODY,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> requests.Response:
    """
    Shared HTTP request helper.

    Important:
    - preserves existing scanner API
    - adds a consistent User-Agent
    - applies TLS verification only to HTTPS
    - optionally caps the retained response body
    - supports arbitrary requests parameters
    """

    target = str(url).strip()

    if not target:
        raise ValueError(
            "Request URL is empty"
        )

    parsed = urlparse(
        target
    )

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        raise ValueError(
            f"Unsupported request URL scheme: {parsed.scheme!r}"
        )

    merged_headers = {
        "User-Agent": UA,
        "Accept": "*/*",
    }

    if headers:
        merged_headers.update(
            headers
        )

    request_kwargs = dict(
        kwargs
    )

    # Let callers explicitly provide these if required,
    # but otherwise use our scanner defaults.
    request_kwargs.setdefault(
        "headers",
        merged_headers,
    )

    # If caller passed headers through kwargs, merge them.
    if "headers" in kwargs and kwargs["headers"]:
        combined = dict(
            merged_headers
        )
        combined.update(
            kwargs["headers"]
        )
        request_kwargs["headers"] = combined

    # Avoid applying certificate verification semantics to HTTP.
    request_kwargs.setdefault(
        "verify",
        verify_tls
        if parsed.scheme.lower() == "https"
        else False,
    )

    request_kwargs.setdefault(
        "allow_redirects",
        allow_redirects,
    )

    request_kwargs.setdefault(
        "timeout",
        timeout,
    )

    try:
        response = requests.request(
            method.upper(),
            target,
            **request_kwargs,
        )
    except requests.exceptions.SSLError:
        if (
            parsed.scheme.lower() != "https"
            or request_kwargs.get("verify") is False
        ):
            raise
        request_kwargs["verify"] = False
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", InsecureRequestWarning)
            response = requests.request(
                method.upper(),
                target,
                **request_kwargs,
            )

    # --------------------------------------------------------
    # Bound the retained response body.
    #
    # Note:
    # requests has already received the complete response at
    # this point. This limit prevents scanners from retaining
    # very large bodies, but it does not prevent network transfer.
    # --------------------------------------------------------

    if (
        max_body is not None
        and max_body >= 0
        and len(response.content) > max_body
    ):
        response._content = (
            response.content[:max_body]
        )

    return response


# ============================================================
# STANDARD RESULT HELPERS
# ============================================================

def result(
    status: str,
    summary: str,
    details: dict | None = None,
    evidence: list | None = None,
) -> dict:
    """
    Create a consistent scanner result.

    Accepts both positional and keyword arguments so older
    scanners remain compatible.
    """

    return {
        "status": status,
        "summary": summary,
        "details": details or {},
        "evidence": evidence or [],
    }


def connection_result(
    exc: Exception,
    *,
    target: str | None = None,
) -> dict:
    """
    Standard result for connectivity/request failures.
    """

    details = {
        "error": str(exc),
        "exception_type": type(exc).__name__,
    }

    if target:
        details["target"] = target

    return result(
        "INCOMPLETE",
        (
            "The target could not be contacted reliably, "
            "so this test did not complete."
        ),
        details=details,
        evidence=[
            f"{type(exc).__name__}: {exc}"
        ],
    )


# ============================================================
# TEXT / HTML HELPERS
# ============================================================

def clean_title(
    html: str,
) -> str | None:
    """
    Extract a normalized <title> from HTML.
    """

    match = re.search(
        r"<title\b[^>]*>(.*?)</title>",
        html or "",
        re.I | re.S,
    )

    if not match:
        return None

    text = re.sub(
        r"<[^>]+>",
        " ",
        match.group(1),
    )

    # Decode common HTML entities without introducing
    # another dependency.
    try:
        from html import unescape

        text = unescape(
            text
        )
    except Exception:
        pass

    return (
        re.sub(
            r"\s+",
            " ",
            text,
        ).strip()
        or None
    )


def text_sample(
    text: str,
    limit: int = 500,
) -> str:
    """
    Return a compact whitespace-normalized text sample.
    """

    if limit < 0:
        limit = 0

    return re.sub(
        r"\s+",
        " ",
        text or "",
    ).strip()[:limit]


def body_hash(
    text: str,
) -> str:
    """
    Stable normalized SHA-256 hash for response comparison.
    """

    normalized = re.sub(
        r"\s+",
        " ",
        text or "",
    ).strip().lower()

    return hashlib.sha256(
        normalized.encode(
            "utf-8",
            "replace",
        )
    ).hexdigest()


def looks_like_html(
    response: requests.Response,
) -> bool:
    """
    Determine whether a response appears to contain HTML.
    """

    content_type = (
        response.headers.get(
            "Content-Type"
        )
        or ""
    ).lower()

    sample = (
        response.text or ""
    )[:2000].lower()

    if "text/html" in content_type:
        return True

    if "application/xhtml+xml" in content_type:
        return True

    return (
        "<html" in sample
        or "<!doctype html" in sample
    )


# ============================================================
# HEADER HELPERS
# ============================================================

def get_header(
    response: requests.Response,
    name: str,
    default: str = "",
) -> str:
    """
    Safely retrieve one response header.
    """

    value = response.headers.get(
        name,
        default,
    )

    return (
        str(value).strip()
        if value is not None
        else default
    )


def get_all_header_values(
    response: requests.Response,
    name: str,
) -> list[str]:
    """
    Best-effort retrieval of all values for a header.

    requests' normal CaseInsensitiveDict may combine/collapse
    duplicate headers. When the underlying urllib3 response
    exposes getlist(), use it.

    Falls back to the ordinary header value.
    """

    target = name.lower()

    # urllib3 / requests raw header path.
    try:
        raw = response.raw

        original_headers = getattr(
            raw,
            "headers",
            None,
        )

        if original_headers is not None:

            # urllib3 HTTPHeaderDict supports getlist().
            getlist = getattr(
                original_headers,
                "getlist",
                None,
            )

            if callable(getlist):

                values = getlist(
                    name
                )

                if values:
                    return [
                        str(value).strip()
                        for value in values
                        if str(value).strip()
                    ]

    except Exception:
        pass

    # Fallback to requests' normal dictionary.
    value = response.headers.get(
        name
    )

    if value is None:
        return []

    return [
        part.strip()
        for part in str(value).split("\n")
        if part.strip()
    ]


def header_present(
    response: requests.Response,
    name: str,
) -> bool:
    """
    Check whether a response contains a header, including
    an intentionally empty header value.
    """

    return any(
        key.lower() == name.lower()
        for key in response.headers.keys()
    )


# ============================================================
# NETWORK / DNS HELPERS
# ============================================================

def resolve_host(
    host: str,
) -> list[str]:
    """
    Resolve IPv4/IPv6 addresses for a hostname.

    Returns unique addresses while preserving discovery order.
    """

    hostname = (
        (host or "").strip()
    )

    if not hostname:
        return []

    addresses: list[str] = []

    try:
        entries = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return []

    for entry in entries:

        sockaddr = entry[4]

        if not sockaddr:
            continue

        value = (
            str(sockaddr[0])
            .strip()
        )

        if value and value not in addresses:
            addresses.append(
                value
            )

    return addresses


def is_private_ip(
    value: str,
) -> bool:
    """
    Identify non-public/local address space.

    Includes:
    - RFC1918 private IPv4
    - IPv6 unique-local
    - loopback
    - link-local
    - unspecified
    - reserved
    - documentation/test ranges where ipaddress classifies them
      as non-globally-routable
    """

    try:
        ip = ipaddress.ip_address(
            value
        )
    except ValueError:
        return False

    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_unspecified
        or ip.is_reserved
    )


# ============================================================
# IP EXTRACTION
# ============================================================

_IPV4_PATTERN = re.compile(
    r"(?<![0-9])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![0-9])"
)


_IPV6_PATTERN = re.compile(
    r"""
    (?<![A-Za-z0-9:])

    (?:
        (?:[0-9A-Fa-f]{1,4}:){7}
            [0-9A-Fa-f]{1,4}
        |
        (?:[0-9A-Fa-f]{1,4}:){1,7}:
            |
        (?:[0-9A-Fa-f]{1,4}:){1,6}
            :[0-9A-Fa-f]{1,4}
        |
        (?:[0-9A-Fa-f]{1,4}:){1,5}
            (?:[:][0-9A-Fa-f]{1,4}){1,2}
        |
        (?:[0-9A-Fa-f]{1,4}:){1,4}
            (?:[:][0-9A-Fa-f]{1,4}){1,3}
        |
        (?:[0-9A-Fa-f]{1,4}:){1,3}
            (?:[:][0-9A-Fa-f]{1,4}){1,4}
        |
        (?:[0-9A-Fa-f]{1,4}:){1,2}
            (?:[:][0-9A-Fa-f]{1,4}){1,5}
        |
        [0-9A-Fa-f]{1,4}:
            (?:[:][0-9A-Fa-f]{1,4}){1,6}
        |
        :
            (?:[:][0-9A-Fa-f]{1,4}){1,7}
        |
        fe80:(?:[:][0-9A-Fa-f]{0,4}){0,4}
            %[\w.-]+
    )

    (?![A-Za-z0-9:])
    """,
    re.I | re.X,
)


def extract_ip_addresses(
    text: str,
) -> list[str]:
    """
    Extract private/local/reserved IP addresses from text.

    Supports IPv4 and common IPv6 representations.
    """

    candidates: set[str] = set()

    for match in _IPV4_PATTERN.finditer(
        text or ""
    ):
        candidates.add(
            match.group(0)
        )

    for match in _IPV6_PATTERN.finditer(
        text or ""
    ):
        candidates.add(
            match.group(0)
        )

    found: list[str] = []

    for value in candidates:

        clean = (
            value.strip()
            .strip("[]")
        )

        # Remove IPv6 zone identifier if present.
        if "%" in clean:
            clean = clean.split(
                "%",
                1,
            )[0]

        try:
            ip = ipaddress.ip_address(
                clean
            )
        except ValueError:
            continue

        if is_private_ip(
            str(ip)
        ):
            found.append(
                str(ip)
            )

    return sorted(
        set(found)
    )


# ============================================================
# HOSTNAME EXTRACTION
# ============================================================

_HOSTNAME_PATTERN = re.compile(
    r"""
    (?<![@A-Za-z0-9_-])

    (?:
        [A-Za-z0-9]
        (?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?
        \.
    )+

    [A-Za-z]{2,63}

    (?![A-Za-z0-9_-])
    """,
    re.I | re.X,
)


def extract_hostnames(
    text: str,
) -> list[str]:
    """
    Extract plausible DNS hostnames.

    This intentionally avoids:
    - localhost
    - IP literals
    - most single-label names
    """

    found: set[str] = set()

    for match in _HOSTNAME_PATTERN.finditer(
        text or ""
    ):

        hostname = (
            match.group(0)
            .lower()
            .rstrip(".")
        )

        if not hostname:
            continue

        try:
            ipaddress.ip_address(
                hostname
            )
            continue
        except ValueError:
            pass

        found.add(
            hostname
        )

    return sorted(
        found
    )


# ============================================================
# URL / REDIRECT HELPERS
# ============================================================

def redirect_target(
    response: requests.Response,
) -> str | None:
    """
    Safely obtain an absolute redirect target.
    """

    location = get_header(
        response,
        "Location",
    )

    if not location:
        return None

    current_url = getattr(
        response,
        "url",
        "",
    )

    return urljoin(
        current_url,
        location,
    )


def response_is_redirect(
    response: requests.Response,
) -> bool:
    return (
        300
        <= response.status_code
        < 400
    )


# ============================================================
# CONTENT TYPE HELPERS
# ============================================================

def content_type(
    response: requests.Response,
) -> str:
    """
    Return normalized MIME type without parameters.
    """

    raw = get_header(
        response,
        "Content-Type",
    )

    if not raw:
        return ""

    return (
        raw.split(
            ";",
            1,
        )[0]
        .strip()
        .lower()
    )


def is_textual_content(
    response: requests.Response,
) -> bool:

    mime = content_type(
        response
    )

    if (
        mime.startswith(
            "text/"
        )
    ):
        return True

    return mime in {
        "application/json",
        "application/xml",
        "application/javascript",
        "application/x-javascript",
        "application/xhtml+xml",
        "application/ld+json",
        "application/problem+json",
        "application/graphql-response+json",
    }


# ============================================================
# REDACT SENSITIVE VALUES
# ============================================================

def redact_value(
    value: str,
    visible: int = 4,
) -> str:
    """
    Redact potentially sensitive values before they enter
    evidence/reporting output.
    """

    value = str(
        value or ""
    ).strip()

    if not value:
        return "[REDACTED]"

    if len(value) <= (
        visible * 2
    ):
        return "[REDACTED]"

    return (
        value[:visible]
        + "*"
        * min(
            16,
            max(
                4,
                len(value) - (
                    visible * 2
                ),
            ),
        )
        + value[-visible:]
    )