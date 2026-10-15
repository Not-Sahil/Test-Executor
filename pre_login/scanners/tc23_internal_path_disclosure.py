from __future__ import annotations

import html
import ipaddress
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

from payloads.manager import load_lines

from .common import (
    normalize_url,
    origin_root_url,
    request,
    result,
    connection_result,
)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 750_000
MAX_PROBES = 16
MAX_EVIDENCE_ITEMS = 100
MAX_SNIPPET_LENGTH = 350


# ============================================================
# ERROR / PATH PROBES
#
# These are deliberately non-destructive. They request
# nonexistent or malformed paths only.
# ============================================================

ALL_PROBES = tuple(load_lines("fuzzdb/response_patterns/error_path_probes.txt"))
PROBES = ALL_PROBES[:MAX_PROBES]
MAX_FUZZDB_ERROR_SIGNATURES = 100
FUZZDB_ERROR_SIGNATURES = tuple(
    re.compile(re.escape(item), re.I)
    for item in load_lines(
        "upstream/FuzzDB/regex/errors.txt",
        limit=MAX_FUZZDB_ERROR_SIGNATURES,
    )
)


# ============================================================
# REGEX PATTERNS
# ============================================================

# ----------------------------
# Windows filesystem paths
# ----------------------------

WINDOWS_PATH_PATTERN = re.compile(
    r"""
    \b
    (?:
        [A-Za-z]:[\\/]
        |
        \\\\
        [A-Za-z0-9._-]+
        [\\\/]
    )
    (?:
        [^<>:"|?*\r\n]{1,180}
    )
    """,
    re.I | re.X,
)


WINDOWS_KNOWN_LOCATION_PATTERN = re.compile(
    r"""
    [A-Za-z]:[\\/]
    (?:
        Users
        |Windows
        |inetpub
        |Apache
        |Tomcat
        |xampp
        |wamp
        |Program Files
        |ProgramData
        |wwwroot
        |laragon
        |node_modules
    )
    [\\/]
    [^<>\r\n]{1,180}
    """,
    re.I | re.X,
)


# ----------------------------
# Unix filesystem paths
# ----------------------------

UNIX_PATH_PATTERN = re.compile(
    r"""
    (?:
        /
        (?:
            var/www
            |var/log
            |var/lib
            |var/cache
            |etc
            |opt
            |srv
            |home
            |usr/local
            |usr/src
            |tmp
            |app
            |workspace
            |www
            |data
            |mnt
            |root
        )
        /
        [^\s<>"']{1,220}
    )
    """,
    re.I | re.X,
)


# ----------------------------
# Source file locations
# ----------------------------

SOURCE_LOCATION_PATTERN = re.compile(
    r"""
    (?:
        [A-Za-z0-9_.\-/\\]+
        \.
        (?:
            py
            |pyw
            |java
            |kt
            |kts
            |cs
            |cshtml
            |php
            |inc
            |phtml
            |js
            |jsx
            |ts
            |tsx
            |rb
            |go
            |rs
            |swift
            |cpp
            |c
            |h
            |hpp
            |m
        )
        :
        \d+
        (?::\d+)?
    )
    """,
    re.I | re.X,
)


# ----------------------------
# Stack traces
# ----------------------------

STACK_TRACE_PATTERN = re.compile(
    r"""
    (?:
        Traceback\s*\(most\s+recent\s+call\s+last\)
        |
        stack\s+trace
        |
        exception\s+in\s+thread
        |
        caused\s+by:
        |
        at\s+[A-Za-z0-9_$.<>$]+\(
        |
        \b
        (?:
            NullPointerException
            |NumberFormatException
            |IllegalArgumentException
            |IllegalStateException
            |ClassNotFoundException
            |NoSuchMethodException
            |SQLException
            |SQLSyntaxErrorException
            |PDOException
            |TypeError
            |ReferenceError
            |RangeError
            |KeyError
            |IndexError
            |AttributeError
            |FileNotFoundError
            |PermissionError
            |FileExistsError
            |ConnectionRefusedError
            |OSError
        )
        \b
    )
    """,
    re.I | re.X,
)


# ----------------------------
# Database / SQL error leakage
# ----------------------------

DATABASE_ERROR_PATTERN = re.compile(
    r"""
    (?:
        SQL\s+syntax
        |
        SQLSTATE
        |
        syntax\s+error\s+at\s+or\s+near
        |
        mysql(?:_error| exception)?
        |
        PostgreSQL
        |
        PostgreSQL.*ERROR
        |
        pg_query
        |
        ORA-\d{4,}
        |
        SQLite(?:3)?::?
        |
        sqlite3?\.\w+
        |
        Mongo(?:DB)?.*(?:exception|error)
        |
        JDBC.*(?:SQLException|SQL)
        |
        database\s+exception
        |
        database\s+error
        |
        query\s+failed
        |
        unclosed\s+quotation
        |
        unterminated\s+string
    )
    """,
    re.I | re.X,
)


# ----------------------------
# Framework / runtime exception indicators
# ----------------------------

FRAMEWORK_ERROR_PATTERN = re.compile(
    r"""
    (?:
        Werkzeug
        |
        Django
        |
        Flask
        |
        Laravel
        |
        Symfony
        |
        Spring\s+Framework
        |
        Spring\s+Boot
        |
        Tomcat
        |
        Jetty
        |
        Undertow
        |
        ASP\.NET
        |
        Microsoft\.AspNetCore
        |
        Express
        |
        Node\.js
        |
        Ruby\s+on\s+Rails
        |
        Rack
        |
        Phoenix
        |
        Play\s+Framework
    )
    """,
    re.I | re.X,
)


# ----------------------------
# Debug / verbose error markers
# ----------------------------

DEBUG_ERROR_PATTERN = re.compile(
    r"""
    (?:
        DEBUG\s*(?:MODE|ERROR)?
        |
        DEBUGGER
        |
        detailed\s+error
        |
        detailed\s+exception
        |
        internal\s+server\s+error
        |
        error\s+details
        |
        exception\s+details
        |
        developer\s+exception
        |
        development\s+mode
        |
        environment\s+information
    )
    """,
    re.I | re.X,
)


# ----------------------------
# Internal package / namespace
# ----------------------------

PACKAGE_TRACE_PATTERN = re.compile(
    r"""
    (?:
        [A-Za-z_][A-Za-z0-9_]*\.
    ){2,}
    [A-Za-z_][A-Za-z0-9_$]*
    (?:
        \:
        \d+
        (?::\d+)?
    )?
    """,
    re.X,
)


# ----------------------------
# Line/column source references
# ----------------------------

LINE_COLUMN_PATTERN = re.compile(
    r"""
    \b
    (?:
        line
        |
        line_number
        |
        lineno
        |
        column
    )
    \s*[:=]?\s*\d+
    \b
    """,
    re.I | re.X,
)


# ----------------------------
# Internal host / backend URLs
# ----------------------------

INTERNAL_URL_PATTERN = re.compile(
    r"""
    https?://
    (?:
        localhost
        |
        127\.\d{1,3}\.\d{1,3}\.\d{1,3}
        |
        10\.\d{1,3}\.\d{1,3}\.\d{1,3}
        |
        192\.168\.\d{1,3}\.\d{1,3}
        |
        172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}
        |
        [a-z0-9-]+(?:\.internal|\.local|\.localhost)
    )
    (?::\d+)?
    (?:[/\?#][^\s<>"']*)?
    """,
    re.I | re.X,
)


# ----------------------------
# Source code disclosure
# ----------------------------

SOURCE_CODE_MARKER_PATTERN = re.compile(
    r"""
    (?:
        <?php
        |
        import\s+[A-Za-z0-9_.$]+
        |
        from\s+[A-Za-z0-9_./-]+\s+import
        |
        public\s+static\s+(?:final\s+)?class
        |
        namespace\s+[A-Za-z0-9_.\\]+
        |
        stacktrace
        |
        exception\.printStackTrace
        |
        System\.out\.println
    )
    """,
    re.I | re.X,
)


# ----------------------------
# Node / JS source locations
# ----------------------------

NODE_INTERNAL_STACK_PATTERN = re.compile(
    r"""
    at\s+
    (?:
        [A-Za-z0-9_$.\-]+
    )
    \s*
    \(
    (?:
        (?:https?|file):\/\/
        |
        /
        |
        [A-Za-z]:[\\/]
    )
    [^)]+\)
    """,
    re.I | re.X,
)


# ----------------------------
# PHP warnings/notices
# ----------------------------

PHP_PATH_ERROR_PATTERN = re.compile(
    r"""
    (?:
        Warning:
        |
        Notice:
        |
        Fatal\s+error:
        |
        Parse\s+error:
    )
    .{0,300}
    (?:
        in\s+
        [A-Za-z]:[\\/]
        |
        in\s+
        /
        |
        on\s+line\s+\d+
    )
    """,
    re.I | re.S | re.X,
)


# ----------------------------
# Java servlet/container errors
# ----------------------------

JAVA_STACK_PATTERN = re.compile(
    r"""
    \bat\s+
    [a-zA-Z_][a-zA-Z0-9_$]*(?:\.[a-zA-Z_][a-zA-Z0-9_$]*)+
    \(
    [A-Za-z0-9_$]+\.(?:java|kt):\d+
    \)
    """,
    re.I | re.X,
)


# ============================================================
# PATTERN REGISTRY
# ============================================================

PATTERNS: dict[str, re.Pattern[str]] = {
    "windows_filesystem_path":
        WINDOWS_PATH_PATTERN,

    "windows_known_location":
        WINDOWS_KNOWN_LOCATION_PATTERN,

    "unix_filesystem_path":
        UNIX_PATH_PATTERN,

    "source_file_location":
        SOURCE_LOCATION_PATTERN,

    "stack_trace":
        STACK_TRACE_PATTERN,

    "database_error":
        DATABASE_ERROR_PATTERN,

    "framework_error":
        FRAMEWORK_ERROR_PATTERN,

    "debug_error":
        DEBUG_ERROR_PATTERN,

    "package_or_namespace_trace":
        PACKAGE_TRACE_PATTERN,

    "line_or_column_reference":
        LINE_COLUMN_PATTERN,

    "internal_url":
        INTERNAL_URL_PATTERN,

    "source_code_marker":
        SOURCE_CODE_MARKER_PATTERN,

    "node_internal_stack":
        NODE_INTERNAL_STACK_PATTERN,

    "php_path_error":
        PHP_PATH_ERROR_PATTERN,

    "java_stack_trace":
        JAVA_STACK_PATTERN,
}


# ============================================================
# STATUS / SEVERITY GROUPS
# ============================================================

HIGH_CONFIDENCE_TYPES = {
    "windows_known_location",
    "unix_filesystem_path",
    "source_file_location",
    "stack_trace",
    "database_error",
    "node_internal_stack",
    "php_path_error",
    "java_stack_trace",
}

MEDIUM_CONFIDENCE_TYPES = {
    "windows_filesystem_path",
    "internal_url",
    "source_code_marker",
    "framework_error",
    "debug_error",
    "package_or_namespace_trace",
    "line_or_column_reference",
}


# ============================================================
# RESPONSE HELPERS
# ============================================================

def _response_text(response) -> str:
    try:
        return response.text or ""
    except Exception:
        return ""


def _response_location(
    response,
    fallback: str,
) -> str:

    value = getattr(
        response,
        "url",
        None,
    )

    return str(value or fallback)


def _get_header(
    response,
    name: str,
) -> str:
    return (
        response.headers.get(
            name,
            "",
        )
        or ""
    ).strip()


# ============================================================
# SNIPPET GENERATION
# ============================================================

def _normalize_text(
    text: str,
) -> str:

    text = html.unescape(
        text or ""
    )

    text = text.replace(
        "\r",
        "",
    )

    return text


def _build_snippet(
    text: str,
    start: int,
    end: int,
    radius: int = 120,
) -> str:

    left = max(
        0,
        start - radius,
    )

    right = min(
        len(text),
        end + radius,
    )

    snippet = text[
        left:right
    ]

    snippet = re.sub(
        r"\s+",
        " ",
        snippet,
    ).strip()

    if len(snippet) > MAX_SNIPPET_LENGTH:
        snippet = (
            snippet[:MAX_SNIPPET_LENGTH]
            + "..."
        )

    return snippet


# ============================================================
# INTERNAL IP VALIDATION
# ============================================================

def _is_private_or_internal_ip(
    value: str,
) -> bool:

    try:
        parsed = ipaddress.ip_address(
            value
        )

        return (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
        )

    except ValueError:
        return False


# ============================================================
# PATTERN ANALYSIS
# ============================================================

def _analyze_text(
    text: str,
) -> list[dict[str, Any]]:

    text = _normalize_text(
        text
    )

    findings: list[
        dict[str, Any]
    ] = []

    if not text:
        return findings

    for finding_type, pattern in PATTERNS.items():

        for match in pattern.finditer(
            text
        ):

            matched = match.group(
                0
            ).strip()

            if not matched:
                continue

            # Ignore obviously harmless line numbers unless
            # they occur in a stronger error context.
            if (
                finding_type
                == "line_or_column_reference"
            ):

                nearby = _build_snippet(
                    text,
                    match.start(),
                    match.end(),
                    radius=180,
                ).lower()

                if not any(
                    keyword in nearby
                    for keyword in (
                        "exception",
                        "error",
                        "trace",
                        "source",
                        "file",
                        "stack",
                    )
                ):
                    continue

            # Ignore generic framework names unless associated
            # with an error/debug response.
            if (
                finding_type
                == "framework_error"
            ):

                nearby = _build_snippet(
                    text,
                    match.start(),
                    match.end(),
                    radius=200,
                ).lower()

                if not any(
                    keyword in nearby
                    for keyword in (
                        "error",
                        "exception",
                        "trace",
                        "debug",
                        "stack",
                        "failed",
                    )
                ):
                    continue

            # Ignore generic package/namespace patterns unless
            # they have trace-like surrounding evidence.
            if (
                finding_type
                == "package_or_namespace_trace"
            ):

                nearby = _build_snippet(
                    text,
                    match.start(),
                    match.end(),
                    radius=160,
                ).lower()

                if not any(
                    keyword in nearby
                    for keyword in (
                        "exception",
                        "error",
                        "trace",
                        "stack",
                        "caused by",
                        "at ",
                    )
                ):
                    continue

            # Validate IP-looking matches where possible.
            if finding_type == "internal_url":

                host_match = re.search(
                    r"https?://"
                    r"([^/:?#]+)",
                    matched,
                    re.I,
                )

                if host_match:
                    host = host_match.group(
                        1
                    )

                    if not (
                        host.lower()
                        in {
                            "localhost",
                        }
                        or _is_private_or_internal_ip(
                            host
                        )
                        or host.lower().endswith(
                            (
                                ".internal",
                                ".local",
                                ".localhost",
                            )
                        )
                    ):
                        continue

            severity = (
                "HIGH"
                if finding_type
                in HIGH_CONFIDENCE_TYPES
                else "MEDIUM"
            )

            confidence = (
                "HIGH"
                if finding_type
                in HIGH_CONFIDENCE_TYPES
                else "MEDIUM"
            )

            findings.append(
                {
                    "type": finding_type,
                    "severity": severity,
                    "confidence": confidence,
                    "match": matched[
                        :300
                    ],
                    "snippet": _build_snippet(
                        text,
                        match.start(),
                        match.end(),
                    ),
                    "start": match.start(),
                    "end": match.end(),
                }
            )

    # FuzzDB signatures are supplemental response-analysis evidence. They are
    # intentionally LOW confidence here because an error string by itself does
    # not prove internal path disclosure; a filesystem/stack/database finding
    # remains necessary for an UNSAFE classification.
    fuzzdb_seen = 0
    for pattern in FUZZDB_ERROR_SIGNATURES:
        match = pattern.search(text)
        if not match:
            continue
        findings.append({
            "type": "fuzzdb_error_signature",
            "severity": "LOW",
            "confidence": "LOW",
            "match": match.group(0)[:300].strip(),
            "snippet": _build_snippet(text, match.start(), match.end()),
            "source": "FuzzDB regex/errors.txt",
            "start": match.start(),
            "end": match.end(),
        })
        fuzzdb_seen += 1
        if fuzzdb_seen >= 8:
            break

    return findings


# ============================================================
# FINDING DEDUPLICATION
# ============================================================

def _deduplicate_findings(
    findings: list[
        dict[str, Any]
    ],
) -> list[
    dict[str, Any]
]:

    seen: set[
        tuple[str, str, str]
    ] = set()

    unique = []

    for item in findings:

        key = (
            item.get(
                "type",
                "",
            ),
            item.get(
                "match",
                "",
            ).lower().strip(),
            item.get(
                "snippet",
                "",
            )[:100].lower(),
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


# ============================================================
# REDIRECT INSPECTION
# ============================================================

def _inspect_probe(
    target: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> tuple[
    dict[str, Any],
    list[dict[str, Any]],
]:

    current = target

    visited: set[str] = set()

    chain: list[
        dict[str, Any]
    ] = []

    all_findings: list[
        dict[str, Any]
    ] = []

    for hop in range(
        MAX_REDIRECTS + 1
    ):

        if current in visited:

            chain.append(
                {
                    "url": current,
                    "error": "redirect_loop",
                }
            )

            break

        visited.add(
            current
        )

        try:

            response = request(
                current,
                timeout=timeout,
                verify_tls=(
                    verify_tls
                    if urlparse(
                        current
                    ).scheme.lower()
                    == "https"
                    else False
                ),
                allow_redirects=False,
                max_body=MAX_BODY_BYTES,
            )

        except Exception as exc:

            chain.append(
                {
                    "url": current,
                    "error": str(exc),
                }
            )

            break

        body = _response_text(
            response
        )

        headers = {}

        for key, value in response.headers.items():

            lower = key.lower()

            if lower in {
                "location",
                "content-type",
                "server",
                "x-powered-by",
                "www-authenticate",
                "content-security-policy",
                "x-debug-token",
                "x-debug",
            }:

                headers[
                    key
                ] = value

        response_findings = (
            _analyze_text(body)
        )

        # Analyze selected header values too.
        for header_name, value in headers.items():

            if not value:
                continue

            header_findings = (
                _analyze_text(
                    str(value)
                )
            )

            for finding in header_findings:

                finding = dict(
                    finding
                )

                finding[
                    "source"
                ] = (
                    "response_header"
                )

                finding[
                    "header"
                ] = header_name

                all_findings.append(
                    finding
                )

        for finding in response_findings:

            finding = dict(
                finding
            )

            finding[
                "source"
            ] = "response_body"

            all_findings.append(
                finding
            )

        item = {
            "hop": hop,
            "url": current,
            "status_code": response.status_code,
            "content_type": _get_header(
                response,
                "Content-Type",
            ),
            "location": _get_header(
                response,
                "Location",
            ),
            "server": _get_header(
                response,
                "Server",
            ),
            "x_powered_by": _get_header(
                response,
                "X-Powered-By",
            ),
            "finding_types": sorted(
                {
                    finding[
                        "type"
                    ]
                    for finding
                    in response_findings
                }
            ),
        }

        chain.append(
            item
        )

        # Follow redirects only within our bounded chain.
        location = (
            item["location"]
        )

        if (
            300 <= response.status_code < 400
            and location
        ):

            next_url = urljoin(
                current,
                location,
            )

            current = next_url
            continue

        break

    return (
        {
            "chain": chain,
            "final_url": (
                chain[-1]["url"]
                if chain
                else target
            ),
            "final_status": (
                chain[-1].get(
                    "status_code"
                )
                if chain
                else None
            ),
        },
        all_findings,
    )


# ============================================================
# ERROR RESPONSE QUALITY ANALYSIS
# ============================================================

def _analyze_error_context(
    chain: list[
        dict[str, Any]
    ],
    findings: list[
        dict[str, Any]
    ],
) -> dict[str, Any]:

    status_codes = [
        item.get(
            "status_code"
        )
        for item in chain
        if item.get(
            "status_code"
        ) is not None
    ]

    error_statuses = [
        status
        for status in status_codes
        if isinstance(
            status,
            int,
        )
        and status >= 400
    ]

    finding_types = {
        item.get(
            "type"
        )
        for item in findings
    }

    stack_present = bool(
        {
            "stack_trace",
            "java_stack_trace",
            "node_internal_stack",
        }
        & finding_types
    )

    filesystem_present = bool(
        {
            "windows_known_location",
            "windows_filesystem_path",
            "unix_filesystem_path",
            "source_file_location",
            "php_path_error",
        }
        & finding_types
    )

    database_present = (
        "database_error"
        in finding_types
    )

    internal_host_present = (
        "internal_url"
        in finding_types
    )

    debug_present = bool(
        {
            "debug_error",
            "framework_error",
        }
        & finding_types
    )

    return {
        "error_statuses": error_statuses,
        "stack_trace": stack_present,
        "filesystem_disclosure": (
            filesystem_present
        ),
        "database_error": (
            database_present
        ),
        "internal_host_disclosure": (
            internal_host_present
        ),
        "debug_indicators": (
            debug_present
        ),
    }


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_internal_path_disclosure(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
    max_probes: int | None = None,
) -> dict:

    from payloads.manager import is_exhaustive_mode
    exhaustive = is_exhaustive_mode()
    input_target = normalize_url(url)
    base = origin_root_url(input_target)

    tested: list[
        dict[str, Any]
    ] = []

    global_findings: list[
        dict[str, Any]
    ] = []

    # --------------------------------------------------------
    # Bound probe count.
    # --------------------------------------------------------

    effective_max = max_probes if max_probes is not None else (len(ALL_PROBES) if exhaustive else MAX_PROBES)
    selected_probes = ALL_PROBES[:effective_max]

    # --------------------------------------------------------
    # Execute probes
    # --------------------------------------------------------

    for probe in selected_probes:

        target = urljoin(
            base + "/",
            probe.lstrip("/"),
        )

        try:

            chain_info, findings = (
                _inspect_probe(
                    target,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
            )

        except Exception as exc:

            tested.append(
                {
                    "probe": probe,
                    "target": target,
                    "error": str(exc),
                }
            )

            continue

        for finding in findings:

            enriched = dict(
                finding
            )

            enriched[
                "probe"
            ] = probe

            enriched[
                "target"
            ] = target

            global_findings.append(
                enriched
            )

        context = (
            _analyze_error_context(
                chain_info.get(
                    "chain",
                    [],
                ),
                findings,
            )
        )

        tested.append(
            {
                "probe": probe,
                "target": target,
                "redirect_chain": (
                    chain_info.get(
                        "chain",
                        [],
                    )
                ),
                "final_url": (
                    chain_info.get(
                        "final_url"
                    )
                ),
                "final_status": (
                    chain_info.get(
                        "final_status"
                    )
                ),
                "finding_types": sorted(
                    {
                        item.get(
                            "type"
                        )
                        for item
                        in findings
                    }
                ),
                "error_context": context,
            }
        )

    # --------------------------------------------------------
    # Deduplicate
    # --------------------------------------------------------

    global_findings = (
        _deduplicate_findings(
            global_findings
        )
    )

    # --------------------------------------------------------
    # Find strongest findings
    # --------------------------------------------------------

    high_confidence = [
        finding
        for finding
        in global_findings
        if finding.get(
            "confidence"
        ) == "HIGH"
    ]

    medium_confidence = [
        finding
        for finding
        in global_findings
        if finding.get(
            "confidence"
        ) == "MEDIUM"
    ]

    # --------------------------------------------------------
    # Categorize evidence
    # --------------------------------------------------------

    filesystem_findings = [
        item
        for item
        in global_findings
        if item.get("type")
        in {
            "windows_known_location",
            "windows_filesystem_path",
            "unix_filesystem_path",
            "source_file_location",
            "php_path_error",
        }
    ]

    stack_findings = [
        item
        for item
        in global_findings
        if item.get("type")
        in {
            "stack_trace",
            "java_stack_trace",
            "node_internal_stack",
        }
    ]

    database_findings = [
        item
        for item
        in global_findings
        if item.get("type")
        == "database_error"
    ]

    internal_url_findings = [
        item
        for item
        in global_findings
        if item.get("type")
        == "internal_url"
    ]

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    #
    # Strong disclosure:
    # actual filesystem/source/stack/database path details.
    #
    if (
        filesystem_findings
        or stack_findings
        or database_findings
    ):

        status = "UNSAFE"

        if filesystem_findings:

            summary = (
                "Error responses disclosed internal "
                "filesystem or source-code path information."
            )

        elif stack_findings:

            summary = (
                "Error responses exposed stack-trace or "
                "runtime execution details."
            )

        else:

            summary = (
                "Error responses exposed database error "
                "information that may reveal internal "
                "implementation details."
            )

    #
    # Internal backend URL or debug/framework information.
    #
    elif (
        internal_url_findings
        or medium_confidence
    ):

        status = "REVIEW REQUIRED"

        summary = (
            "Error responses contained technical or "
            "internal-looking information that may assist "
            "attackers in understanding application internals."
        )

    #
    # No findings.
    #
    elif tested:

        status = "SAFE"

        summary = (
            "The bounded malformed/nonexistent-path tests "
            "did not identify internal filesystem paths, "
            "source locations, stack traces, or similar "
            "technical path disclosure."
        )

    else:

        status = "INCOMPLETE"

        summary = (
            "The configured error probes could not be "
            "completed, so internal path disclosure could "
            "not be reliably assessed."
        )

    # --------------------------------------------------------
    # Evidence
    # --------------------------------------------------------

    evidence: list[str] = []

    for finding in global_findings[
        :MAX_EVIDENCE_ITEMS
    ]:

        probe = finding.get(
            "probe",
            "",
        )

        finding_type = finding.get(
            "type",
            "unknown",
        )

        evidence.append(
            (
                f"{probe} -> "
                f"{finding_type}"
            )
        )

    # --------------------------------------------------------
    # Details
    # --------------------------------------------------------

    details: dict[
        str,
        Any,
    ] = {

        "input_target": input_target,
        "target": base,

        "probes_tested": len(
            tested
        ),

        "probe_definitions": list(
            selected_probes
        ),
        "payload_library": {
            "source": "FuzzDB response-analysis dictionary plus project-curated non-destructive sentinels",
            "files": [
                "payloads/fuzzdb/response_patterns/error_path_probes.txt",
                "payloads/upstream/FuzzDB/regex/errors.txt",
            ],
            "probe_count": len(selected_probes),
            "response_signatures_loaded": len(FUZZDB_ERROR_SIGNATURES),
        },

        "tested": tested,

        "findings": global_findings[
            :MAX_EVIDENCE_ITEMS
        ],

        "finding_counts": {
            "total": len(
                global_findings
            ),
            "high_confidence": len(
                high_confidence
            ),
            "medium_confidence": len(
                medium_confidence
            ),
            "filesystem_disclosures": len(
                filesystem_findings
            ),
            "stack_trace_disclosures": len(
                stack_findings
            ),
            "database_error_disclosures": len(
                database_findings
            ),
            "internal_url_disclosures": len(
                internal_url_findings
            ),
        },

        "limits": {
            "max_redirects": MAX_REDIRECTS,
            "max_body_bytes": MAX_BODY_BYTES,
            "max_probes": len(selected_probes),
            "max_evidence_items": (
                MAX_EVIDENCE_ITEMS
            ),
        },

        "test_scope": [
            "nonexistent paths",
            "malformed URL encoding",
            "encoded path segments",
            "duplicate slash paths",
            "invalid path parameters",
            "extension-specific missing resources",
            "bounded redirect analysis",
            "error response body analysis",
            "selected error response header analysis",
            "filesystem path detection",
            "source-code location detection",
            "stack trace detection",
            "database error detection",
            "framework/debug disclosure detection",
            "internal URL detection",
        ],
    }

    return result(
        status,
        summary,
        details=details,
        evidence=evidence,
    )