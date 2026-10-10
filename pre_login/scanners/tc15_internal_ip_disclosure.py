from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlparse

from .common import normalize_url, request, result, connection_result


# ============================================================================
# Limits
# ============================================================================

MAX_BODY_BYTES = 200_000
MAX_JS_ASSETS = 12
MAX_IP_OCCURRENCES = 100
MAX_CONTEXT_CHARS = 220


# ============================================================================
# Context signals
# ============================================================================

STRONG_CONTEXT_MARKERS = (
    "backend",
    "upstream",
    "origin",
    "internal-api",
    "internal api",
    "internal server",
    "internal host",
    "private server",
    "private host",
    "database",
    "db host",
    "db_host",
    "redis",
    "memcached",
    "cluster",
    "intranet",
    "proxy",
    "gateway",
    "service host",
    "api server",
)

MEDIUM_CONTEXT_MARKERS = (
    "server",
    "host",
    "api",
    "service",
    "node",
    "internal",
    "private",
    "origin",
    "network",
)


PLACEHOLDER_CONTEXT_MARKERS = (
    "example",
    "example.com",
    "documentation",
    "docs",
    "sample",
    "test data",
    "demo",
    "tutorial",
    "placeholder",
    "dummy",
    "localhost example",
)


# ============================================================================
# Data model
# ============================================================================

@dataclass
class IPObservation:
    ip: str
    address_family: str
    category: str
    source_url: str
    source_location: str
    context: str
    context_score: int
    likely_placeholder: bool
    confidence: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "address_family": self.address_family,
            "category": self.category,
            "source_url": self.source_url,
            "source_location": self.source_location,
            "context": self.context,
            "context_score": self.context_score,
            "likely_placeholder": self.likely_placeholder,
            "confidence": self.confidence,
        }


# ============================================================================
# IP extraction
# ============================================================================

# Supports normal IPv4 and broad IPv6 textual representations.
#
# Actual validity is determined with ipaddress.ip_address(), so malformed
# matches are rejected.
IP_TOKEN_RE = re.compile(
    r"""
    (?<![A-Za-z0-9_.-])
    (
        (?:
            \d{1,3}(?:\.\d{1,3}){3}
        )
        |
        (?:
            [0-9A-Fa-f:]+:[0-9A-Fa-f:.%]+
        )
    )
    (?![A-Za-z0-9_.-])
    """,
    re.VERBOSE,
)


def _parse_ip(
    value: str,
) -> ipaddress._BaseAddress | None:

    value = value.strip(
        "[]()<>\"',; "
    )

    # IPv6 may appear with a zone identifier such as %eth0.
    if "%" in value:
        value = value.split(
            "%",
            1,
        )[0]

    try:
        return ipaddress.ip_address(
            value
        )
    except ValueError:
        return None


def _classify_ip(
    ip: ipaddress._BaseAddress,
) -> str:

    if ip.is_loopback:
        return "loopback"

    if ip.is_link_local:
        return "link_local"

    if ip.is_private:
        return "private_or_unique_local"

    if ip.is_reserved:
        return "reserved"

    if ip.is_unspecified:
        return "unspecified"

    if ip.is_multicast:
        return "multicast"

    # IPv4 shared CGN space isn't represented as is_private by every
    # Python version. Explicitly identify the RFC 6598 range.
    if isinstance(
        ip,
        ipaddress.IPv4Address,
    ):

        shared = ipaddress.ip_network(
            "100.64.0.0/10"
        )

        if ip in shared:
            return "shared_cgn"

    return "public"


def _address_family(
    ip: ipaddress._BaseAddress,
) -> str:

    if ip.version == 4:
        return "IPv4"

    return "IPv6"


# ============================================================================
# Context analysis
# ============================================================================

def _context_around(
    text: str,
    start: int,
    end: int,
) -> str:

    begin = max(
        0,
        start - MAX_CONTEXT_CHARS,
    )

    finish = min(
        len(text),
        end + MAX_CONTEXT_CHARS,
    )

    context = text[
        begin:finish
    ]

    return re.sub(
        r"\s+",
        " ",
        context,
    ).strip()


def _analyse_context(
    context: str,
) -> tuple[int, bool, str]:

    lower = context.lower()

    strong_hits = [
        marker
        for marker in STRONG_CONTEXT_MARKERS
        if marker in lower
    ]

    medium_hits = [
        marker
        for marker in MEDIUM_CONTEXT_MARKERS
        if marker in lower
    ]

    placeholder_hits = [
        marker
        for marker in PLACEHOLDER_CONTEXT_MARKERS
        if marker in lower
    ]

    score = (
        len(strong_hits) * 3
        + len(medium_hits)
        - len(placeholder_hits) * 2
    )

    likely_placeholder = (
        len(placeholder_hits) >= 1
        and not strong_hits
        and score <= 0
    )

    if strong_hits:
        confidence = "high"

    elif (
        medium_hits
        and not likely_placeholder
    ):
        confidence = "medium"

    elif not likely_placeholder:
        confidence = "low"

    else:
        confidence = "informational"

    return (
        score,
        likely_placeholder,
        confidence,
    )


# ============================================================================
# Source extraction
# ============================================================================

def _extract_script_urls(
    base_url: str,
    body: str,
) -> list[str]:

    urls: list[str] = []

    for match in re.finditer(
        r"""
        <script\b
        [^>]*?
        src\s*=\s*
        ["']([^"']+)["']
        """,
        body,
        flags=re.IGNORECASE | re.VERBOSE,
    ):

        raw_url = unescape(
            match.group(1)
        ).strip()

        absolute = urljoin(
            base_url,
            raw_url,
        )

        parsed = urlparse(
            absolute
        )

        base = urlparse(
            base_url
        )

        if (
            parsed.hostname
            and base.hostname
            and parsed.hostname.lower()
            != base.hostname.lower()
        ):
            continue

        if absolute not in urls:
            urls.append(
                absolute
            )

        if len(urls) >= MAX_JS_ASSETS:
            break

    return urls


def _extract_source_maps(
    body: str,
) -> list[str]:

    maps: list[str] = []

    for match in re.finditer(
        r"(?m)^\s*//#\s*sourceMappingURL\s*=\s*(.+?)\s*$",
        body,
        flags=re.IGNORECASE,
    ):

        value = match.group(1).strip()

        if value and value not in maps:
            maps.append(
                value
            )

    return maps[:10]


# ============================================================================
# Observation engine
# ============================================================================

def _extract_ip_observations(
    text: str,
    *,
    source_url: str,
    source_location: str,
) -> list[IPObservation]:

    observations: list[
        IPObservation
    ] = []

    seen_occurrences = 0

    for match in IP_TOKEN_RE.finditer(
        text
    ):

        if seen_occurrences >= MAX_IP_OCCURRENCES:
            break

        raw_ip = match.group(1)

        parsed = _parse_ip(
            raw_ip
        )

        if parsed is None:
            continue

        category = _classify_ip(
            parsed
        )

        # Public addresses are not this testcase's focus.
        if category == "public":
            continue

        context = _context_around(
            text,
            match.start(),
            match.end(),
        )

        (
            score,
            placeholder,
            confidence,
        ) = _analyse_context(
            context
        )

        observations.append(
            IPObservation(
                ip=str(parsed),
                address_family=_address_family(
                    parsed
                ),
                category=category,
                source_url=source_url,
                source_location=source_location,
                context=context,
                context_score=score,
                likely_placeholder=placeholder,
                confidence=confidence,
            )
        )

        seen_occurrences += 1

    return observations


# ============================================================================
# Header extraction
# ============================================================================

def _header_blob(
    response,
) -> str:

    lines = []

    for key, value in response.headers.items():

        lines.append(
            f"{key}: {value}"
        )

    return "\n".join(
        lines
    )


# ============================================================================
# Main scanner
# ============================================================================

def scan_internal_ip_disclosure(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
) -> dict:

    base = normalize_url(
        url
    )

    details: dict[str, Any] = {
        "target": base,
        "sources_tested": [],
        "findings": [],
        "limits": {
            "max_body_bytes": MAX_BODY_BYTES,
            "max_js_assets": MAX_JS_ASSETS,
            "max_ip_occurrences": MAX_IP_OCCURRENCES,
        },
    }

    observations: list[
        IPObservation
    ] = []

    failed_sources = 0
    completed_sources = 0

    # ========================================================================
    # 1. Primary page
    # ========================================================================

    primary_targets = (
        base,
        urljoin(
            base.rstrip("/") + "/",
            "robots.txt",
        ),
        urljoin(
            base.rstrip("/") + "/",
            "sitemap.xml",
        ),
    )

    fetched_pages: list[
        tuple[str, Any]
    ] = []

    for target in primary_targets:

        try:

            response = request(
                target,
                method="GET",
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=False,
                max_body=MAX_BODY_BYTES,
            )

            completed_sources += 1

            fetched_pages.append(
                (
                    target,
                    response,
                )
            )

        except Exception as exc:

            failed_sources += 1

            details[
                "sources_tested"
            ].append(
                {
                    "url": target,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                }
            )

            continue

        details[
            "sources_tested"
        ].append(
            {
                "url": target,
                "status_code": response.status_code,
                "content_type": response.headers.get(
                    "Content-Type",
                    "",
                ),
            }
        )

    # ========================================================================
    # 2. Analyze primary responses
    # ========================================================================

    js_urls: list[str] = []

    for target, response in fetched_pages:

        status = response.status_code

        # Analyze body even for redirect responses because some applications
        # place useful information in redirect pages.
        body = (
            response.text
            or ""
        )[:MAX_BODY_BYTES]

        # --------------------------------------------------------------
        # Body
        # --------------------------------------------------------------

        body_observations = (
            _extract_ip_observations(
                body,
                source_url=target,
                source_location="response_body",
            )
        )

        observations.extend(
            body_observations
        )

        # --------------------------------------------------------------
        # Headers
        # --------------------------------------------------------------

        header_text = _header_blob(
            response
        )

        header_observations = (
            _extract_ip_observations(
                header_text,
                source_url=target,
                source_location="response_headers",
            )
        )

        observations.extend(
            header_observations
        )

        # --------------------------------------------------------------
        # Redirect location
        # --------------------------------------------------------------

        location = response.headers.get(
            "Location",
            "",
        )

        if location:

            observations.extend(
                _extract_ip_observations(
                    location,
                    source_url=target,
                    source_location="location_header",
                )
            )

        # --------------------------------------------------------------
        # Extract same-origin JavaScript URLs from HTML
        # --------------------------------------------------------------

        content_type = response.headers.get(
            "Content-Type",
            "",
        ).lower()

        if (
            "html" in content_type
            or "<html" in body.lower()
            or "<script" in body.lower()
        ):

            js_urls.extend(
                _extract_script_urls(
                    response.url or target,
                    body,
                )
            )

            details.setdefault(
                "source_map_references",
                [],
            ).extend(
                _extract_source_maps(
                    body
                )
            )

    # Deduplicate JavaScript URLs.
    js_urls = list(
        dict.fromkeys(js_urls)
    )[:MAX_JS_ASSETS]

    details[
        "javascript_assets_discovered"
    ] = js_urls

    # ========================================================================
    # 3. Bounded JavaScript analysis
    # ========================================================================

    js_results: list[
        dict[str, Any]
    ] = []

    for js_url in js_urls:

        try:

            response = request(
                js_url,
                method="GET",
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=False,
                max_body=MAX_BODY_BYTES,
            )

            completed_sources += 1

            js_body = (
                response.text
                or ""
            )[:MAX_BODY_BYTES]

            js_observations = (
                _extract_ip_observations(
                    js_body,
                    source_url=js_url,
                    source_location=(
                        "same_origin_javascript"
                    ),
                )
            )

            observations.extend(
                js_observations
            )

            js_results.append(
                {
                    "url": js_url,
                    "status_code": response.status_code,
                    "content_type": response.headers.get(
                        "Content-Type",
                        "",
                    ),
                    "internal_ip_count": len(
                        js_observations
                    ),
                }
            )

        except Exception as exc:

            failed_sources += 1

            js_results.append(
                {
                    "url": js_url,
                    "error_type": type(exc).__name__,
                    "error": str(exc)[:500],
                }
            )

    details[
        "javascript_analysis"
    ] = js_results

    # ========================================================================
    # 4. Deduplicate observations
    # ========================================================================

    unique: dict[
        tuple[str, str, str, str],
        IPObservation,
    ] = {}

    for observation in observations:

        key = (
            observation.ip,
            observation.source_url,
            observation.source_location,
            observation.context,
        )

        unique[
            key
        ] = observation

    observations = list(
        unique.values()
    )

    # ========================================================================
    # 5. Sort strongest observations first
    # ========================================================================

    confidence_rank = {
        "high": 3,
        "medium": 2,
        "low": 1,
        "informational": 0,
    }

    observations.sort(
        key=lambda item: (
            confidence_rank.get(
                item.confidence,
                0,
            ),
            item.context_score,
        ),
        reverse=True,
    )

    details[
        "observations"
    ] = [
        item.as_dict()
        for item in observations
    ]

    # ========================================================================
    # 6. Strong / medium / weak findings
    # ========================================================================

    strong = [
        item
        for item in observations
        if (
            item.confidence == "high"
            and not item.likely_placeholder
            and item.category
            in {
                "private_or_unique_local",
                "loopback",
                "link_local",
                "shared_cgn",
                "reserved",
            }
        )
    ]

    medium = [
        item
        for item in observations
        if (
            item.confidence in {
                "medium",
                "low",
            }
            and not item.likely_placeholder
            and item.category
            in {
                "private_or_unique_local",
                "loopback",
                "link_local",
                "shared_cgn",
                "reserved",
            }
        )
    ]

    informational = [
        item
        for item in observations
        if item.likely_placeholder
    ]

    details[
        "strong_findings"
    ] = [
        item.as_dict()
        for item in strong
    ]

    details[
        "medium_findings"
    ] = [
        item.as_dict()
        for item in medium
    ]

    details[
        "informational_addresses"
    ] = [
        item.as_dict()
        for item in informational
    ]

    # ========================================================================
    # 7. Confirmed disclosure
    # ========================================================================

    if strong:

        evidence = []

        for item in strong[:20]:

            evidence.append(
                (
                    f"{item.ip} ({item.category}) "
                    f"disclosed in {item.source_location} "
                    f"at {item.source_url}; "
                    f"context indicates internal infrastructure."
                )
            )

        return result(
            "UNSAFE",
            "One or more non-public IP addresses were disclosed in publicly accessible content with strong infrastructure-related context.",
            details=details,
            evidence=evidence,
        )

    # ========================================================================
    # 8. Review-level disclosure
    # ========================================================================

    if medium:

        evidence = []

        for item in medium[:20]:

            evidence.append(
                (
                    f"Potential internal address "
                    f"{item.ip} observed in "
                    f"{item.source_location}; "
                    "context is insufficient for high-confidence "
                    "classification."
                )
            )

        return result(
            "REVIEW REQUIRED",
            "One or more private, local, link-local, shared, or reserved IP addresses were observed in public responses, but the scanner could not establish with high confidence that they represent sensitive production infrastructure.",
            details=details,
            evidence=evidence,
        )

    # ========================================================================
    # 9. Everything appears to be examples/placeholders
    # ========================================================================

    if informational and completed_sources > 0:

        return result(
            "SAFE",
            "Only addresses that appear to be examples, placeholders, or non-sensitive references were observed; no credible internal infrastructure disclosure was confirmed.",
            details=details,
        )

    # ========================================================================
    # 10. Nothing found
    # ========================================================================

    if completed_sources == 0:

        return result(
            "INCOMPLETE",
            "The configured public response sources could not be retrieved, so internal IP disclosure could not be assessed reliably.",
            details=details,
        )

    return result(
        "SAFE",
        "No credible private, local, link-local, shared, or reserved IP address disclosure was identified in the bounded response and same-origin JavaScript checks.",
        details=details,
    )