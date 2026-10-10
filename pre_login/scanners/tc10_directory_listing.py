from __future__ import annotations

import json
import re
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlparse

from payloads.manager import load_lines, load_optional_sample, load_optional_lines

from .common import (
    absolute,
    normalize_url,
    origin_root_url,
    request,
    result,
    connection_result,
)


# ============================================================================
# Configuration
# ============================================================================

# These are discovery candidates, not guaranteed vulnerabilities.
# Active candidates are stored in the external, provenance-documented payload library.
# The sets are curated subsets of SecLists/FuzzDB resource-discovery themes.
def _directory_candidates(seed: str = "") -> tuple[str, ...]:
    curated = (
        load_lines("seclists/discovery/directory_candidates.txt", limit=48)
        + load_lines("fuzzdb/discovery/predictable_filepaths_curated.txt", limit=20)
    )
    upstream = (
        load_optional_sample(
            "upstream/SecLists/Discovery/Web-Content/raft-small-directories.txt",
            32, seed=f"{seed}:seclists-dirs"
        )
        + load_optional_sample(
            "upstream/SecLists/Discovery/Web-Content/api/api-endpoints.txt",
            12, seed=f"{seed}:seclists-api"
        )
        + load_optional_sample(
            "upstream/SecLists/Discovery/Web-Content/common.txt",
            12, seed=f"{seed}:seclists-common"
        )
        + load_optional_sample(
            "upstream/FuzzDB/discovery/predictable-filepaths/KitchensinkDirectories.txt",
            12, seed=f"{seed}:fuzzdb-dirs"
        )
    )
    return tuple(dict.fromkeys(curated + upstream))[:120]


MAX_DISCOVERED_DIRS = 50
MAX_PROBES = 40
MAX_BODY_ANALYSIS = 200_000


# ============================================================================
# Directory listing signatures
# ============================================================================

STRONG_HTML_MARKERS = (
    "index of /",
    "directory listing for",
    "directory listing",
    "parent directory",
    "apache autoindex",
    "nginx autoindex",
)

TITLE_MARKERS = (
    "index of",
    "directory listing",
    "parent directory",
)

DIRECTORY_ENTRY_HINTS = (
    "parent directory",
    "../",
    "last modified",
    "size",
    "description",
    "name",
    "filename",
)

SERVER_LISTING_SIGNATURES = {
    "apache": (
        "index of /",
        "apache autoindex",
    ),
    "nginx": (
        "index of",
        "nginx autoindex",
    ),
    "iis": (
        "directory listing",
    ),
}


# ============================================================================
# Helpers
# ============================================================================

def _extract_title(body: str) -> str:
    match = re.search(
        r"<title\b[^>]*>(.*?)</title>",
        body or "",
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return ""

    title = re.sub(
        r"<[^>]+>",
        " ",
        match.group(1),
    )

    return re.sub(
        r"\s+",
        " ",
        unescape(title),
    ).strip()[:300]


def _extract_links(body: str) -> list[str]:
    """
    Extract href values from HTML.

    This is intentionally lightweight. It is not intended to be a complete
    HTML parser.
    """

    links: list[str] = []

    for match in re.finditer(
        r"""<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']""",
        body or "",
        flags=re.IGNORECASE,
    ):
        href = unescape(match.group(1)).strip()

        if href:
            links.append(href)

    return links


def _looks_like_file_or_directory_href(
    href: str,
) -> bool:

    href_lower = href.lower().strip()

    if href_lower in {
        "../",
        "./",
        "/",
    }:
        return True

    parsed = urlparse(href)

    path = parsed.path.lower()

    if path.endswith("/"):
        return True

    # Common file extension indicator.
    if re.search(
        r"\.(txt|log|zip|gz|tar|tgz|bak|old|conf|cfg|json|xml|"
        r"csv|pdf|doc|docx|xls|xlsx|jpg|jpeg|png|gif|svg|css|js|"
        r"html?|php|asp|aspx|jsp)$",
        path,
        flags=re.IGNORECASE,
    ):
        return True

    return False


def _is_directory_like_url(
    base_url: str,
    candidate: str,
) -> bool:

    absolute_candidate = urljoin(
        base_url.rstrip("/") + "/",
        candidate,
    )

    parsed = urlparse(
        absolute_candidate
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
        return False

    return parsed.path.endswith("/")


def _extract_discovered_directories(
    base_url: str,
    body: str,
) -> list[str]:

    directories: list[str] = []

    for href in _extract_links(body):

        if not _is_directory_like_url(
            base_url,
            href,
        ):
            continue

        absolute_candidate = urljoin(
            base_url.rstrip("/") + "/",
            href,
        )

        parsed = urlparse(
            absolute_candidate
        )

        path = parsed.path or "/"

        if not path.startswith("/"):
            continue

        if path not in directories:
            directories.append(path)

    return directories


def _is_probable_spa_fallback(
    *,
    body: str,
    requested_path: str,
) -> bool:

    body_lower = body.lower()

    title = _extract_title(
        body
    ).lower()

    # Common SPA root/fallback signals.
    spa_script_signals = (
        "webpack",
        "__next_data__",
        "ng-version",
        "vite",
        "react",
        "angular",
        "vue",
    )

    script_tags = len(
        re.findall(
            r"<script\b",
            body,
            flags=re.IGNORECASE,
        )
    )

    has_app_shell = (
        any(
            signal in body_lower
            for signal in spa_script_signals
        )
        and script_tags >= 1
    )

    # Generic title plus application shell can be a catch-all.
    generic_title = title in {
        "",
        "home",
        "welcome",
        "application",
    }

    return (
        has_app_shell
        and generic_title
        and requested_path != "/"
    )


def _listing_analysis(
    body: str,
    headers: dict[str, str],
) -> dict[str, Any]:

    body_sample = (
        body[:MAX_BODY_ANALYSIS]
    )

    lower = re.sub(
        r"\s+",
        " ",
        body_sample,
    ).lower()

    title = _extract_title(
        body_sample
    )

    links = _extract_links(
        body_sample
    )

    directory_like_links = [
        href
        for href in links
        if _looks_like_file_or_directory_href(
            href
        )
    ]

    strong_matches = [
        marker
        for marker in STRONG_HTML_MARKERS
        if marker in lower
        or marker in title.lower()
    ]

    title_matches = [
        marker
        for marker in TITLE_MARKERS
        if marker in title.lower()
    ]

    entry_hints = [
        marker
        for marker in DIRECTORY_ENTRY_HINTS
        if marker in lower
    ]

    server_header = headers.get(
        "Server",
        "",
    ).lower()

    server_matches: dict[str, list[str]] = {}

    for server_name, markers in SERVER_LISTING_SIGNATURES.items():

        matched = [
            marker
            for marker in markers
            if marker in lower
        ]

        if matched:
            server_matches[
                server_name
            ] = matched

    parent_link = any(
        href.strip() in {
            "../",
            "..",
        }
        for href in links
    ) or "parent directory" in lower

    # Strong evidence:
    #
    #   a recognized listing marker
    #   + directory-like links
    #
    strong_listing = (
        len(strong_matches) >= 1
        and len(directory_like_links) >= 2
    )

    # Moderate evidence:
    #
    # Multiple table/listing hints and several entries.
    moderate_listing = (
        len(entry_hints) >= 2
        and len(directory_like_links) >= 3
        and (
            parent_link
            or len(links) >= 5
        )
    )

    return {
        "title": title,
        "link_count": len(links),
        "directory_like_link_count": (
            len(directory_like_links)
        ),
        "strong_markers": strong_matches,
        "title_markers": title_matches,
        "entry_hints": entry_hints,
        "server_signatures": server_matches,
        "parent_directory_link": parent_link,
        "strong_listing": strong_listing,
        "moderate_listing": moderate_listing,
        "sample_links": directory_like_links[:30],
    }


def _normalise_discovered_path(
    path: str,
) -> str | None:

    path = path.strip()

    if not path:
        return None

    parsed = urlparse(path)

    if parsed.scheme or parsed.netloc:
        return None

    if not path.startswith("/"):
        path = "/" + path

    if not path.endswith("/"):
        path += "/"

    return path


# ============================================================================
# Metadata-assisted discovery
# ============================================================================

def _discover_from_robots(
    base: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> list[str]:

    robots_url = absolute(
        base,
        "/robots.txt",
    )

    try:
        response = request(
            robots_url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )
    except Exception:
        return []

    if response.status_code != 200:
        return []

    paths: list[str] = []

    for raw_line in (
        response.text or ""
    ).splitlines():

        line = raw_line.split(
            "#",
            1,
        )[0].strip()

        if ":" not in line:
            continue

        key, value = (
            part.strip()
            for part in line.split(
                ":",
                1,
            )
        )

        if key.lower() not in {
            "allow",
            "disallow",
        }:
            continue

        candidate = _normalise_discovered_path(
            value
        )

        if candidate and candidate != "/":
            paths.append(candidate)

    return paths


def _discover_from_sitemap(
    base: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> list[str]:

    sitemap_url = absolute(
        base,
        "/sitemap.xml",
    )

    try:
        response = request(
            sitemap_url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )
    except Exception:
        return []

    if response.status_code != 200:
        return []

    body = response.text or ""

    paths: list[str] = []

    # Extract <loc> values.
    for match in re.finditer(
        r"<loc\b[^>]*>(.*?)</loc>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    ):

        location = unescape(
            match.group(1)
        ).strip()

        try:
            parsed = urlparse(
                location
            )
        except Exception:
            continue

        if not parsed.path:
            continue

        if parsed.hostname:
            base_host = urlparse(
                base
            ).hostname

            if (
                base_host
                and parsed.hostname.lower()
                != base_host.lower()
            ):
                continue

        path = parsed.path

        if not path.endswith("/"):
            continue

        if path not in paths:
            paths.append(path)

    return paths


# ============================================================================
# Main scanner
# ============================================================================

def scan_directory_listing(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
) -> dict:

    input_target = normalize_url(url)
    base = origin_root_url(input_target)
    payload_candidates = _directory_candidates(input_target)

    details: dict[str, Any] = {
        "input_target": input_target,
        "target": base,
        "configured_directories": list(
            payload_candidates
        ),
        "discovered_directories": [],
        "tested": [],
        "findings": [],
        "payload_library": {
            "sources": ["SecLists (curated subset)", "FuzzDB (curated subset)"],
            "files": ["payloads/seclists/discovery/directory_candidates.txt", "payloads/fuzzdb/discovery/predictable_filepaths_curated.txt"],
            "optional_upstream_files": ["payloads/upstream/SecLists/Discovery/Web-Content/raft-small-directories.txt", "payloads/upstream/FuzzDB/discovery/predictable-filepaths/KitchensinkDirectories.txt"],
            "candidate_count": len(payload_candidates),
        },
    }

    # ------------------------------------------------------------------
    # 1. Baseline root request
    # ------------------------------------------------------------------

    try:
        root_response = request(
            base,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )
    except Exception as exc:
        return connection_result(
            exc,
            target=base,
        )

    details["baseline"] = {
        "status_code": root_response.status_code,
        "final_url": root_response.url,
        "content_type": root_response.headers.get(
            "Content-Type",
            "",
        ),
    }

    # ------------------------------------------------------------------
    # 2. Build bounded discovery set
    # ------------------------------------------------------------------

    candidates: list[str] = []

    for path in payload_candidates:

        normalised = _normalise_discovered_path(
            path
        )

        if normalised:
            candidates.append(
                normalised
            )

    # robots.txt paths
    robots_paths = _discover_from_robots(
        base,
        timeout=timeout,
        verify_tls=verify_tls,
    )

    # sitemap.xml paths
    sitemap_paths = _discover_from_sitemap(
        base,
        timeout=timeout,
        verify_tls=verify_tls,
    )

    candidates.extend(
        robots_paths
    )

    candidates.extend(
        sitemap_paths
    )

    # Also use links found on the root page.
    root_body = root_response.text or ""

    root_discovered = (
        _extract_discovered_directories(
            root_response.url or base,
            root_body,
        )
    )

    candidates.extend(
        root_discovered
    )

    # De-duplicate while preserving order.
    candidates = list(
        dict.fromkeys(candidates)
    )[:MAX_DISCOVERED_DIRS]

    details["discovered_directories"] = candidates

    # ------------------------------------------------------------------
    # 3. Probe candidates
    # ------------------------------------------------------------------

    findings: list[dict[str, Any]] = []
    tested: list[dict[str, Any]] = []

    for index, path in enumerate(
        candidates
    ):

        if index >= MAX_PROBES:
            break

        target = absolute(
            base,
            path,
        )

        try:
            response = request(
                target,
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=True,
            )

        except Exception as exc:

            tested.append(
                {
                    "path": path,
                    "error": str(exc)[:500],
                    "error_type": type(exc).__name__,
                }
            )

            continue

        body = response.text or ""

        content_type = response.headers.get(
            "Content-Type",
            "",
        )

        # --------------------------------------------------------------
        # Analyze response
        # --------------------------------------------------------------

        analysis = {
            "strong": False,
            "moderate": False,
            "listing": None,
        }

        html_or_text = (
            "text/html" in content_type.lower()
            or "application/xhtml+xml"
            in content_type.lower()
            or content_type == ""
            or "json" in content_type.lower()
            or "xml" in content_type.lower()
        )

        if (
            200 <= response.status_code < 300
            and html_or_text
        ):

            # JSON directory-style response.
            json_listing = False
            json_entries: list[Any] = []

            if "json" in content_type.lower():

                try:
                    parsed_json = json.loads(
                        body[:MAX_BODY_ANALYSIS]
                    )

                    if isinstance(
                        parsed_json,
                        list,
                    ):
                        json_entries = (
                            parsed_json
                        )

                    elif isinstance(
                        parsed_json,
                        dict,
                    ):
                        for key in (
                            "files",
                            "entries",
                            "items",
                            "children",
                        ):
                            value = parsed_json.get(
                                key
                            )

                            if isinstance(
                                value,
                                list,
                            ):
                                json_entries = (
                                    value
                                )
                                break

                    json_listing = (
                        len(json_entries) >= 1
                    )

                except (
                    ValueError,
                    TypeError,
                ):
                    json_listing = False

            # XML directory-style response.
            xml_listing = False

            if "xml" in content_type.lower():

                lower_body = body.lower()

                xml_listing = (
                    (
                        "<file"
                        in lower_body
                    )
                    or (
                        "<directory"
                        in lower_body
                    )
                    or (
                        "<entry"
                        in lower_body
                    )
                )

            html_analysis = _listing_analysis(
                body,
                {
                    key: value
                    for key, value
                    in response.headers.items()
                },
            )

            spa_fallback = (
                _is_probable_spa_fallback(
                    body=body,
                    requested_path=path,
                )
            )

            strong = (
                (
                    html_analysis[
                        "strong_listing"
                    ]
                    and not spa_fallback
                )
                or json_listing
                or xml_listing
            )

            moderate = (
                (
                    html_analysis[
                        "moderate_listing"
                    ]
                    and not spa_fallback
                )
                and not strong
            )

            analysis = {
                "strong": strong,
                "moderate": moderate,
                "listing": html_analysis,
                "json_listing": json_listing,
                "json_entry_count": len(
                    json_entries
                ),
                "xml_listing": xml_listing,
                "spa_fallback": spa_fallback,
            }

        item = {
            "path": path,
            "requested_url": target,
            "status_code": response.status_code,
            "final_url": response.url,
            "content_type": content_type,
            "server": response.headers.get(
                "Server",
                "",
            ),
            "redirect_count": len(
                response.history
            ),
            "directory_listing": (
                analysis["strong"]
            ),
            "heuristic_candidate": (
                analysis["moderate"]
            ),
            "analysis": analysis,
        }

        tested.append(
            item
        )

        if analysis["strong"]:

            findings.append(
                item
            )

    details["tested"] = tested
    details["findings"] = findings

    # ------------------------------------------------------------------
    # 4. Strong findings
    # ------------------------------------------------------------------

    if findings:

        evidence = []

        for finding in findings:

            analysis = finding[
                "analysis"
            ]

            evidence.append(
                (
                    "Directory listing detected at "
                    f"{finding['path']} "
                    f"-> {finding['final_url']} "
                    f"(HTTP {finding['status_code']})"
                )
            )

            listing = analysis.get(
                "listing"
            ) or {}

            strong_markers = listing.get(
                "strong_markers",
                [],
            )

            if strong_markers:

                evidence.append(
                    "Listing markers: "
                    + ", ".join(
                        strong_markers[:10]
                    )
                )

            if analysis.get(
                "json_listing"
            ):

                evidence.append(
                    (
                        "Structured JSON directory "
                        f"entries detected: "
                        f"{analysis.get('json_entry_count', 0)}"
                    )
                )

            if analysis.get(
                "xml_listing"
            ):

                evidence.append(
                    "Structured XML directory listing indicators detected."
                )

        return result(
            "UNSAFE",
            "A publicly reachable directory-index response was detected on one or more tested web paths. Directory indexing can expose the names and locations of otherwise unreferenced files and directories.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # 5. Determine whether any useful probes completed
    # ------------------------------------------------------------------

    completed = [
        item
        for item in tested
        if "status_code" in item
    ]

    if not completed:
        return result(
            "INCOMPLETE",
            "None of the configured or discovered directory probes completed successfully, so directory indexing could not be assessed reliably.",
            details=details,
        )

    # ------------------------------------------------------------------
    # 6. Safe
    # ------------------------------------------------------------------

    # Heuristic/moderate similarity is deliberately NOT treated as a
    # security finding. A normal application page may contain generic
    # words such as "name", "size", or "description", directory-like
    # links, or a normal HTTP 200 response without exposing an actual
    # server-generated directory index.
    #
    # Only the strong-evidence path above is classified as UNSAFE.
    return result(
        "SAFE",
        "No publicly reachable directory listing was confirmed on the configured or bounded discovered directory paths. Heuristic directory-like content was not treated as a security finding.",
        details=details,
    )