from __future__ import annotations

import re
from collections import Counter
from typing import Any
from urllib.parse import (
    parse_qsl,
    unquote,
    urljoin,
    urlparse,
)

from defusedxml import ElementTree as SafeET

from .common import (
    normalize_url,
    request,
    result,
    connection_result,
    same_origin,
)


# ============================================================
# CONFIGURATION
# ============================================================

DEFAULT_MAX_SITEMAPS = 10
DEFAULT_MAX_URLS = 5000
DEFAULT_MAX_SENSITIVE_ENTRIES = 100
DEFAULT_MAX_BODY = 5_000_000

DEFAULT_MAX_SENSITIVE_PROBES = 10


# ============================================================
# SENSITIVE PATH / PARAMETER SIGNALS
# ============================================================

SENSITIVE_PATH_HINTS = {
    "admin": 25,
    "administrator": 30,
    "private": 25,
    "internal": 30,
    "debug": 35,
    "backup": 35,
    "config": 30,
    "configuration": 30,
    "secret": 40,
    "staging": 30,
    "stage": 25,
    "dev": 20,
    "development": 25,
    "uat": 30,
    "test": 15,
    "testing": 20,
    "management": 20,
    "manage": 20,
    "console": 25,
    "dashboard": 15,
    "monitor": 20,
    "monitoring": 20,
    "actuator": 30,
    "phpinfo": 35,
    "server-status": 35,
    "server-info": 30,
    "internal-api": 35,
}

SENSITIVE_QUERY_HINTS = {
    "debug": 30,
    "admin": 25,
    "internal": 30,
    "secret": 40,
    "token": 40,
    "access_token": 50,
    "auth": 30,
    "password": 50,
    "passwd": 50,
    "api_key": 45,
    "apikey": 45,
    "key": 25,
    "config": 30,
    "redirect": 20,
    "url": 15,
    "path": 20,
}

PLACEHOLDER_HOSTS = {
    "example.com",
    "example.org",
    "example.net",
    "localhost",
}


# ============================================================
# XML NAMESPACE HELPERS
# ============================================================

def _local_name(tag: str) -> str:
    """
    Converts:
        {namespace}url
    into:
        url
    """
    if not tag:
        return ""

    if "}" in tag:
        return tag.rsplit("}", 1)[-1].lower()

    return tag.lower()


def _child_text(
    element,
    child_name: str,
) -> str | None:

    for child in list(element):
        if _local_name(child.tag) == child_name.lower():
            if child.text:
                return child.text.strip()

    return None


# ============================================================
# URL VALIDATION
# ============================================================

def _normalize_loc(
    raw_url: str,
    base_url: str,
) -> str | None:

    if not raw_url:
        return None

    value = unquote(raw_url.strip())

    # Reject obvious malformed control characters.
    if any(ord(ch) < 32 for ch in value):
        return None

    absolute = urljoin(base_url, value)

    parsed = urlparse(absolute)

    if parsed.scheme not in {"http", "https"}:
        return None

    if not parsed.netloc:
        return None

    return absolute


def _is_placeholder_url(url: str) -> bool:
    parsed = urlparse(url)

    hostname = (parsed.hostname or "").lower()

    if hostname in PLACEHOLDER_HOSTS:
        return True

    return False


# ============================================================
# SENSITIVE URL ANALYSIS
# ============================================================

def _analyze_url(url: str) -> dict[str, Any]:

    parsed = urlparse(url)

    path = unquote(parsed.path or "").lower()
    query = unquote(parsed.query or "").lower()

    score = 0
    signals: list[str] = []

    # --------------------------------------------------------
    # PATH ANALYSIS
    # --------------------------------------------------------

    path_parts = [
        part
        for part in re.split(r"[/._\-]+", path)
        if part
    ]

    for part in path_parts:

        weight = SENSITIVE_PATH_HINTS.get(part)

        if weight:
            score += weight
            signals.append(
                f"sensitive path term: {part}"
            )

    # Full path patterns.
    path_patterns = {
        r"/admin(?:/|$)": 25,
        r"/internal(?:/|$)": 30,
        r"/private(?:/|$)": 25,
        r"/debug(?:/|$)": 35,
        r"/backup(?:/|$)": 35,
        r"/staging(?:/|$)": 30,
        r"/(?:dev|development)(?:/|$)": 25,
        r"/uat(?:/|$)": 30,
        r"/actuator(?:/|$)": 30,
        r"/server-(?:status|info)(?:/|$)": 35,
    }

    for pattern, weight in path_patterns.items():

        if re.search(pattern, path, re.I):
            score += weight
            signals.append(
                f"sensitive path pattern: {pattern}"
            )

    # --------------------------------------------------------
    # QUERY ANALYSIS
    # --------------------------------------------------------

    query_items = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    for key, value in query_items:

        key_lower = unquote(key).lower()
        value_lower = unquote(value).lower()

        weight = SENSITIVE_QUERY_HINTS.get(
            key_lower
        )

        if weight:
            score += weight
            signals.append(
                f"sensitive query parameter: {key_lower}"
            )

        # Obvious credential-bearing parameter values.
        if key_lower in {
            "password",
            "passwd",
            "secret",
            "api_key",
            "apikey",
            "access_token",
            "auth_token",
            "refresh_token",
            "client_secret",
        }:
            if value_lower:
                score += 60
                signals.append(
                    f"credential-like query value: {key_lower}"
                )

    # --------------------------------------------------------
    # HOST ANALYSIS
    # --------------------------------------------------------

    hostname = (
        parsed.hostname or ""
    ).lower()

    if any(
        marker in hostname
        for marker in (
            "internal",
            "private",
            "staging",
            "stage",
            "dev",
            "test",
            "uat",
            "admin",
        )
    ):
        score += 30
        signals.append(
            f"sensitive-looking hostname: {hostname}"
        )

    # --------------------------------------------------------
    # FILE / EXTENSION ANALYSIS
    # --------------------------------------------------------

    suspicious_extensions = (
        ".bak",
        ".backup",
        ".old",
        ".orig",
        ".sql",
        ".dump",
        ".conf",
        ".config",
        ".env",
        ".log",
    )

    for extension in suspicious_extensions:

        if path.endswith(extension):
            score += 35
            signals.append(
                f"sensitive-looking file extension: {extension}"
            )

    # --------------------------------------------------------
    # CLASSIFICATION
    # --------------------------------------------------------

    if _is_placeholder_url(url):
        confidence = "LOW"
    elif score >= 70:
        confidence = "HIGH"
    elif score >= 35:
        confidence = "MEDIUM"
    elif score > 0:
        confidence = "LOW"
    else:
        confidence = "NONE"

    if score >= 70:
        classification = "HIGH"
    elif score >= 35:
        classification = "MEDIUM"
    elif score > 0:
        classification = "LOW"
    else:
        classification = "NONE"

    return {
        "url": url,
        "score": score,
        "classification": classification,
        "confidence": confidence,
        "signals": signals,
    }


# ============================================================
# SITEMAP DOCUMENT PARSER
# ============================================================

def _parse_sitemap(
    body: str,
) -> dict[str, Any]:

    try:
        root = SafeET.fromstring(
            body.encode("utf-8", errors="replace")
        )
    except Exception as exc:
        return {
            "valid": False,
            "error": str(exc),
            "type": None,
            "urls": [],
            "sitemaps": [],
        }

    root_name = _local_name(root.tag)

    if root_name == "urlset":
        sitemap_type = "urlset"

    elif root_name == "sitemapindex":
        sitemap_type = "sitemapindex"

    else:
        return {
            "valid": False,
            "error": (
                f"Unexpected root element: {root_name}"
            ),
            "type": root_name,
            "urls": [],
            "sitemaps": [],
        }

    urls: list[str] = []
    child_sitemaps: list[str] = []

    for element in root.iter():

        element_name = _local_name(
            element.tag
        )

        if element_name == "url":
            loc = _child_text(
                element,
                "loc",
            )

            if loc:
                urls.append(loc)

        elif element_name == "sitemap":
            loc = _child_text(
                element,
                "loc",
            )

            if loc:
                child_sitemaps.append(loc)

    return {
        "valid": True,
        "error": None,
        "type": sitemap_type,
        "urls": urls,
        "sitemaps": child_sitemaps,
    }


# ============================================================
# SITEMAP URL DISCOVERY
# ============================================================

def _extract_sitemap_references_from_robots(
    robots_text: str,
) -> list[str]:

    results: list[str] = []

    for line in (robots_text or "").splitlines():

        line = line.strip()

        if not line:
            continue

        if line.lower().startswith("sitemap:"):

            value = line.split(
                ":",
                1
            )[1].strip()

            if value:
                results.append(value)

    return results


def _discover_sitemap_locations(
    base_url: str,
    robots_text: str | None,
) -> list[str]:

    candidates = [
        urljoin(
            normalize_url(base_url) + "/",
            "sitemap.xml",
        ),
        urljoin(
            normalize_url(base_url) + "/",
            "sitemap_index.xml",
        ),
        urljoin(
            normalize_url(base_url) + "/",
            "sitemap-index.xml",
        ),
        urljoin(
            normalize_url(base_url) + "/",
            "sitemaps.xml",
        ),
    ]

    if robots_text:
        candidates.extend(
            _extract_sitemap_references_from_robots(
                robots_text
            )
        )

    output: list[str] = []
    seen: set[str] = set()

    for candidate in candidates:

        normalized = _normalize_loc(
            candidate,
            base_url,
        )

        if not normalized:
            continue

        if normalized in seen:
            continue

        seen.add(normalized)
        output.append(normalized)

    return output


# ============================================================
# FETCH ONE SITEMAP
# ============================================================

def _fetch_sitemap(
    url: str,
    verify_tls: bool,
    timeout: float,
    max_body: int,
):

    try:
        return request(
            url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
            max_body=max_body,
        )

    except Exception:
        return None


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_sitemap_xml(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
    max_sitemaps: int = DEFAULT_MAX_SITEMAPS,
    max_urls: int = DEFAULT_MAX_URLS,
    max_sensitive_entries: int = DEFAULT_MAX_SENSITIVE_ENTRIES,
) -> dict:

    base = normalize_url(url)

    # ========================================================
    # OPTIONAL ROBOTS DISCOVERY
    # ========================================================

    robots_text = None

    robots_url = urljoin(
        base + "/",
        "robots.txt",
    )

    try:
        robots_response = request(
            robots_url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
            max_body=500_000,
        )

        if (
            robots_response.status_code == 200
            and robots_response.text
        ):
            robots_text = robots_response.text

    except Exception:
        robots_text = None

    # ========================================================
    # DISCOVER SITEMAPS
    # ========================================================

    discovered_sitemaps = _discover_sitemap_locations(
        base,
        robots_text,
    )

    if not discovered_sitemaps:
        return result(
            "SAFE",
            "No standard or robots-declared sitemap location was identified.",
            details={
                "sitemaps_checked": [],
                "status": "not_found",
            },
        )

    queue: list[str] = list(
        discovered_sitemaps
    )

    visited: set[str] = set()

    sitemap_documents: list[dict[str, Any]] = []

    all_urls: list[str] = []

    external_sitemaps: list[str] = []

    parse_errors: list[dict[str, str]] = []

    sensitive_entries: list[dict[str, Any]] = []

    # ========================================================
    # BOUNDED SITEMAP TRAVERSAL
    # ========================================================

    while queue:

        if len(visited) >= max_sitemaps:
            break

        sitemap_url = queue.pop(0)

        if sitemap_url in visited:
            continue

        visited.add(sitemap_url)

        # --------------------------------------------
        # Only fetch HTTP(S).
        # --------------------------------------------

        parsed_sitemap_url = urlparse(
            sitemap_url
        )

        if parsed_sitemap_url.scheme not in {
            "http",
            "https",
        }:
            continue

        # --------------------------------------------
        # Fetch
        # --------------------------------------------

        response = _fetch_sitemap(
            sitemap_url,
            verify_tls=verify_tls,
            timeout=timeout,
            max_body=DEFAULT_MAX_BODY,
        )

        if response is None:
            sitemap_documents.append(
                {
                    "url": sitemap_url,
                    "status_code": None,
                    "state": "connection_failed",
                }
            )
            continue

        # --------------------------------------------
        # HTTP status handling
        # --------------------------------------------

        if response.status_code in {
            404,
            410,
        }:
            sitemap_documents.append(
                {
                    "url": sitemap_url,
                    "status_code": response.status_code,
                    "state": "not_found",
                }
            )
            continue

        if response.status_code != 200:
            sitemap_documents.append(
                {
                    "url": sitemap_url,
                    "status_code": response.status_code,
                    "state": "unexpected_status",
                    "content_type": response.headers.get(
                        "Content-Type"
                    ),
                }
            )
            continue

        body = response.text or ""

        # --------------------------------------------
        # XML parse
        # --------------------------------------------

        parsed = _parse_sitemap(body)

        if not parsed["valid"]:

            parse_errors.append(
                {
                    "url": sitemap_url,
                    "error": parsed["error"] or "unknown",
                }
            )

            sitemap_documents.append(
                {
                    "url": sitemap_url,
                    "status_code": 200,
                    "state": "invalid_xml",
                    "content_type": response.headers.get(
                        "Content-Type"
                    ),
                }
            )

            continue

        # --------------------------------------------
        # Record document
        # --------------------------------------------

        sitemap_documents.append(
            {
                "url": sitemap_url,
                "status_code": 200,
                "state": "parsed",
                "type": parsed["type"],
                "content_type": response.headers.get(
                    "Content-Type"
                ),
            }
        )

        # ====================================================
        # CHILD SITEMAPS
        # ====================================================

        for raw_child in parsed["sitemaps"]:

            child_url = _normalize_loc(
                raw_child,
                sitemap_url,
            )

            if not child_url:
                continue

            if child_url in visited:
                continue

            if not same_origin(
                base,
                child_url,
            ):
                external_sitemaps.append(
                    child_url
                )
                continue

            if (
                len(visited) + len(queue)
                >= max_sitemaps
            ):
                break

            queue.append(child_url)

        # ====================================================
        # URL ENTRIES
        # ====================================================

        for raw_url in parsed["urls"]:

            if len(all_urls) >= max_urls:
                break

            normalized_url = _normalize_loc(
                raw_url,
                sitemap_url,
            )

            if not normalized_url:
                continue

            all_urls.append(
                normalized_url
            )

            analysis = _analyze_url(
                normalized_url
            )

            if (
                analysis["classification"]
                != "NONE"
                and len(sensitive_entries)
                < max_sensitive_entries
            ):
                sensitive_entries.append(
                    analysis
                )

    # ========================================================
    # REMOVE DUPLICATE URL ENTRIES
    # ========================================================

    unique_urls = list(
        dict.fromkeys(all_urls)
    )

    duplicate_count = (
        len(all_urls)
        - len(unique_urls)
    )

    # ========================================================
    # HOST DISTRIBUTION
    # ========================================================

    host_counts = Counter()

    external_urls: list[str] = []

    same_origin_urls: list[str] = []

    for sitemap_entry in unique_urls:

        parsed = urlparse(
            sitemap_entry
        )

        host = (
            parsed.hostname
            or ""
        ).lower()

        if host:
            host_counts[host] += 1

        if same_origin(
            base,
            sitemap_entry,
        ):
            same_origin_urls.append(
                sitemap_entry
            )
        else:
            external_urls.append(
                sitemap_entry
            )

    # ========================================================
    # SEVERITY
    # ========================================================

    high_confidence = [
        item
        for item in sensitive_entries
        if item["confidence"] == "HIGH"
    ]

    medium_confidence = [
        item
        for item in sensitive_entries
        if item["confidence"] == "MEDIUM"
    ]

    findings = []

    for item in high_confidence:
        findings.append(
            (
                "High-confidence sensitive-looking "
                f"sitemap URL: {item['url']}"
            )
        )

    for item in medium_confidence:
        findings.append(
            (
                "Sensitive-looking sitemap URL requires "
                f"review: {item['url']}"
            )
        )

    # ========================================================
    # OVERALL CLASSIFICATION
    # ========================================================

    if high_confidence:
        overall_status = "REVIEW REQUIRED"

        summary = (
            "The sitemap exposes high-confidence "
            "administrative, internal, debugging, "
            "backup, configuration, or otherwise "
            "sensitive-looking application paths. "
            "The sitemap itself is not necessarily "
            "a vulnerability; the listed resources "
            "require manual validation."
        )

    elif medium_confidence:
        overall_status = "REVIEW REQUIRED"

        summary = (
            "The sitemap is accessible and contains "
            "paths that appear potentially sensitive. "
            "Review whether these URLs are intentionally "
            "public and whether they expose protected "
            "functionality."
        )

    elif parse_errors:
        overall_status = "REVIEW REQUIRED"

        summary = (
            "One or more discovered sitemap resources "
            "could not be parsed as valid sitemap XML."
        )

    elif not sitemap_documents:
        overall_status = "INCOMPLETE"

        summary = (
            "The scanner discovered sitemap locations "
            "but could not successfully retrieve any "
            "usable sitemap document."
        )

    else:
        overall_status = "SAFE"

        summary = (
            "Accessible sitemap resources were parsed "
            "successfully, and no obviously sensitive "
            "paths were identified within the bounded "
            "set of sitemap entries."
        )

    # ========================================================
    # DETAILS
    # ========================================================

    details: dict[str, Any] = {

        "base_url": base,

        "sitemaps_discovered": discovered_sitemaps,

        "sitemaps_checked": list(
            visited
        ),

        "sitemap_documents": sitemap_documents,

        "sitemap_count": len(
            visited
        ),

        "url_entry_count": len(
            all_urls
        ),

        "unique_url_count": len(
            unique_urls
        ),

        "duplicate_url_count": duplicate_count,

        "same_origin_url_count": len(
            same_origin_urls
        ),

        "external_url_count": len(
            external_urls
        ),

        "external_sitemaps": external_sitemaps,

        "host_distribution": dict(
            host_counts.most_common(50)
        ),

        "sensitive_entries": sensitive_entries,

        "parse_errors": parse_errors,

        "limits": {
            "max_sitemaps": max_sitemaps,
            "max_urls": max_urls,
            "max_sensitive_entries": (
                max_sensitive_entries
            ),
            "max_body": DEFAULT_MAX_BODY,
        },

        "robots_sitemap_discovery": (
            robots_text is not None
        ),
    }

    return result(
        overall_status,
        summary,
        details=details,
        evidence=findings[:100],
    )