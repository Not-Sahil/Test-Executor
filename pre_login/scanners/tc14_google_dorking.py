from __future__ import annotations

import re
import time
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import quote, unquote, urlparse

import requests

from .common import normalize_url


# ============================================================================
# Query categories
# ============================================================================

@dataclass(frozen=True)
class DorkQuery:
    category: str
    query: str
    purpose: str
    priority: str
    related_testcases: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# ============================================================================
# Domain helpers
# ============================================================================

def _normalise_host(host: str) -> str:
    """
    Normalize a hostname for query generation.
    """
    return (
        (host or "")
        .strip()
        .lower()
        .rstrip(".")
    )


def _base_domain(host: str) -> str:
    """
    Conservative domain extraction.

    This intentionally does NOT attempt full public-suffix-list
    resolution. The target host itself remains safe to use for
    site-scoped searches.

    Handles common second-level country-code suffixes such as:
        example.co.uk
        example.com.au
        example.co.in
        example.com.br
        example.co.jp
    """

    host = _normalise_host(host)

    if not host:
        return ""

    labels = [
        label
        for label in host.split(".")
        if label
    ]

    if len(labels) <= 2:
        return host

    # IMPORTANT:
    # Use tuples here, not lists. Lists are unhashable and cannot
    # be members of a set.
    common_cc_second_level_suffixes = {
        ("co", "uk"),
        ("com", "au"),
        ("co", "in"),
        ("com", "br"),
        ("co", "jp"),
    }

    if (
        len(labels) >= 3
        and tuple(labels[-2:])
        in common_cc_second_level_suffixes
    ):
        return ".".join(
            labels[-3:]
        )

    return ".".join(
        labels[-2:]
    )


# ============================================================================
# Query generator
# ============================================================================

def _build_queries(
    host: str,
    *,
    include_subdomain_scope: bool = True,
) -> list[DorkQuery]:

    domain = _normalise_host(
        host
    )

    if not domain:
        return []

    search_scope = (
        domain
        if include_subdomain_scope
        else host
    )

    queries: list[DorkQuery] = []

    def add(
        category: str,
        query: str,
        purpose: str,
        priority: str,
        related: tuple[str, ...],
    ) -> None:

        queries.append(
            DorkQuery(
                category=category,
                query=query,
                purpose=purpose,
                priority=priority,
                related_testcases=related,
            )
        )

    # ------------------------------------------------------------------
    # Baseline site discovery
    # ------------------------------------------------------------------

    add(
        "site_inventory",
        f"site:{search_scope}",
        "Identify pages currently indexed for the target domain.",
        "medium",
        ("TC14", "TC23"),
    )

    add(
        "indexed_directories",
        f'site:{search_scope} "index of /"',
        "Look for publicly indexed directory-listing pages.",
        "high",
        ("TC10", "TC13"),
    )

    # ------------------------------------------------------------------
    # Administrative interfaces
    # ------------------------------------------------------------------

    add(
        "administrative_interfaces",
        (
            f"site:{search_scope} "
            "(inurl:admin OR inurl:administrator OR "
            "inurl:dashboard OR inurl:manage)"
        ),
        "Find indexed administrative or management interfaces.",
        "high",
        ("TC14",),
    )

    add(
        "login_interfaces",
        (
            f"site:{search_scope} "
            "(inurl:login OR inurl:signin OR "
            "intitle:login)"
        ),
        "Find indexed authentication entry points.",
        "medium",
        ("TC14", "TC15"),
    )

    # ------------------------------------------------------------------
    # Development / staging / non-production
    # ------------------------------------------------------------------

    add(
        "non_production",
        (
            f"site:{search_scope} "
            "(staging OR stage OR dev OR development OR "
            "test OR testing OR uat OR beta)"
        ),
        "Identify indexed development, test, UAT, staging or beta environments.",
        "high",
        ("TC14", "TC17", "TC23"),
    )

    add(
        "subdomain_environment_names",
        (
            f"site:{search_scope} "
            "(inurl:dev OR inurl:staging OR inurl:test OR inurl:uat)"
        ),
        "Look for indexed non-production URLs and paths.",
        "high",
        ("TC14", "TC17"),
    )

    # ------------------------------------------------------------------
    # Backup / configuration
    # ------------------------------------------------------------------

    add(
        "backup_files",
        (
            f"site:{search_scope} "
            "(backup OR backups OR "
            "inurl:backup OR inurl:old OR inurl:archive)"
        ),
        "Find indexed backup or archived resources.",
        "high",
        ("TC13", "TC10"),
    )

    add(
        "configuration_files",
        (
            f"site:{search_scope} "
            "(config OR configuration OR "
            "\"application.properties\" OR "
            "\"web.config\" OR \"config.php\")"
        ),
        "Find indexed application/server configuration material.",
        "high",
        ("TC13", "TC23"),
    )

    # ------------------------------------------------------------------
    # Environment / secrets
    # ------------------------------------------------------------------

    add(
        "environment_files",
        (
            f"site:{search_scope} "
            '(".env" OR "DB_PASSWORD" OR '
            '"DATABASE_URL" OR "SECRET_KEY")'
        ),
        "Look for indexed environment/configuration information.",
        "critical",
        ("TC13", "TC19"),
    )

    add(
        "credentials",
        (
            f"site:{search_scope} "
            '("password" OR "passwd" OR '
            '"username" OR "api key" OR '
            '"secret key")'
        ),
        "Identify pages/documents potentially containing credential material.",
        "critical",
        ("TC13", "TC19"),
    )

    add(
        "private_keys",
        (
            f"site:{search_scope} "
            '("BEGIN PRIVATE KEY" OR '
            '"BEGIN RSA PRIVATE KEY" OR '
            '"BEGIN OPENSSH PRIVATE KEY")'
        ),
        "Look for indexed private-key material.",
        "critical",
        ("TC13", "TC19"),
    )

    # ------------------------------------------------------------------
    # Version control
    # ------------------------------------------------------------------

    add(
        "version_control",
        (
            f"site:{search_scope} "
            '(".git" OR ".git/HEAD" OR ".git/config" OR '
            '".svn" OR ".hg")'
        ),
        "Look for indexed version-control metadata.",
        "high",
        ("TC13",),
    )

    # ------------------------------------------------------------------
    # Sensitive documents
    # ------------------------------------------------------------------

    for filetype in (
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "csv",
        "txt",
        "log",
        "json",
        "xml",
    ):
        add(
            "sensitive_documents",
            f"site:{search_scope} filetype:{filetype}",
            f"Identify indexed {filetype.upper()} documents/resources.",
            "medium",
            ("TC14", "TC13"),
        )

    # ------------------------------------------------------------------
    # Internal infrastructure
    # ------------------------------------------------------------------

    add(
        "internal_information",
        (
            f"site:{search_scope} "
            '("internal" OR "intranet" OR '
            '"internal network" OR "network diagram" OR '
            '"topology")'
        ),
        "Look for indexed internal infrastructure/design information.",
        "high",
        ("TC14", "TC15"),
    )

    add(
        "server_information",
        (
            f"site:{search_scope} "
            '("server status" OR "server information" OR '
            '"phpinfo" OR "debug")'
        ),
        "Find indexed diagnostic/server-information pages.",
        "high",
        ("TC05", "TC13", "TC14"),
    )

    # ------------------------------------------------------------------
    # Error information
    # ------------------------------------------------------------------

    add(
        "error_messages",
        (
            f"site:{search_scope} "
            '("stack trace" OR "exception" OR '
            '"fatal error" OR "warning:" OR '
            '"debug mode")'
        ),
        "Look for indexed pages containing error/debug information.",
        "high",
        ("TC03", "TC14", "TC23"),
    )

    # ------------------------------------------------------------------
    # Logs
    # ------------------------------------------------------------------

    add(
        "logs",
        (
            f"site:{search_scope} "
            "(filetype:log OR inurl:log)"
        ),
        "Look for indexed application/server log files.",
        "high",
        ("TC13", "TC14", "TC23"),
    )

    # ------------------------------------------------------------------
    # API / documentation
    # ------------------------------------------------------------------

    add(
        "api_documentation",
        (
            f"site:{search_scope} "
            "(inurl:swagger OR inurl:openapi OR "
            "inurl:api-docs OR filetype:json)"
        ),
        "Identify indexed API documentation or schemas.",
        "medium",
        ("TC14", "TC23"),
    )

    # ------------------------------------------------------------------
    # File extension discovery
    # ------------------------------------------------------------------

    for extension in (
        "bak",
        "old",
        "orig",
        "save",
        "conf",
        "cfg",
    ):
        add(
            "backup_extensions",
            f"site:{search_scope} filetype:{extension}",
            f"Look for indexed resources using the {extension} extension.",
            "high",
            ("TC13", "TC14"),
        )

    return queries


# ============================================================================
# Search links
# ============================================================================

def _google_url(
    query: str,
) -> str:

    return (
        "https://www.google.com/search?q="
        + quote(
            query,
            safe="",
        )
    )


def _bing_url(
    query: str,
) -> str:

    return (
        "https://www.bing.com/search?q="
        + quote(
            query,
            safe="",
        )
    )


def _duckduckgo_url(
    query: str,
) -> str:

    return (
        "https://duckduckgo.com/?q="
        + quote(
            query,
            safe="",
        )
    )


# ============================================================================
# Search guidance
# ============================================================================

def _review_guidance(
    query: DorkQuery,
) -> list[str]:

    guidance: dict[str, list[str]] = {

        "site_inventory": [
            "Look for unexpected applications, hosts and paths.",
        ],

        "indexed_directories": [
            "Verify that the result is a real directory listing.",
            "Check whether file names reveal sensitive resources.",
        ],

        "administrative_interfaces": [
            "Determine whether the interface is intended to be public.",
            "Do not attempt authentication as part of this testcase.",
        ],

        "non_production": [
            "Verify whether the result belongs to development/staging/test infrastructure.",
            "Check whether it is publicly reachable.",
        ],

        "backup_files": [
            "Determine whether the result is a genuine backup/archive.",
            "Do not automatically download large backup files.",
        ],

        "configuration_files": [
            "Check whether configuration content is actually exposed.",
            "Redact any discovered secrets from reports.",
        ],

        "environment_files": [
            "Treat actual credentials/secrets as high-risk evidence.",
            "Do not store full secret values in scanner output.",
        ],

        "credentials": [
            "Distinguish documentation/examples from real credentials.",
            "Do not attempt authentication using discovered credentials automatically.",
        ],

        "private_keys": [
            "Verify that the indexed result contains actual private-key material.",
            "Do not reproduce the key contents in the report.",
        ],

        "version_control": [
            "Determine whether version-control metadata is genuinely indexed.",
        ],

        "sensitive_documents": [
            "Check whether the document is expected to be public.",
            "Review metadata for internal or confidential information.",
        ],

        "internal_information": [
            "Look for internal IPs, topology, hostnames or architecture details.",
        ],

        "server_information": [
            "Check for diagnostic/debug information or server-status content.",
        ],

        "error_messages": [
            "Look for stack traces, filesystem paths and environment details.",
        ],

        "logs": [
            "Check whether logs expose tokens, usernames, paths or internal infrastructure.",
        ],

        "api_documentation": [
            "Determine whether API documentation is intentionally public.",
        ],

        "backup_extensions": [
            "Verify whether the result is a genuine old/backup file rather than a normal document.",
        ],

        "login_interfaces": [
            "Determine whether the indexed login page is intended to be publicly reachable.",
        ],

        "subdomain_environment_names": [
            "Determine whether the result indicates a non-production environment.",
        ],
    }

    return guidance.get(
        query.category,
        [
            "Review the result manually for unintended information disclosure.",
        ],
    )


def _extract_ddg_hits(html: str, limit: int = 8) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for match in re.finditer(
        r'<a[^>]*class="[^"]*result__a[^"]*"[^>]*href="([^"]+)"[^>]*>(.*?)</a>',
        html or "",
        re.I | re.S,
    ):
        href = match.group(1).strip()
        title = re.sub(r"<[^>]+>", " ", match.group(2) or "")
        title = re.sub(r"\s+", " ", title).strip()
        parsed = urlparse(href)
        if "uddg" in (parsed.query or ""):
            for part in parsed.query.split("&"):
                if part.startswith("uddg="):
                    href = unquote(part.split("=", 1)[1])
                    break
        if href.startswith("//"):
            href = "https:" + href
        if href:
            hits.append({"title": title[:200], "url": href[:500]})
        if len(hits) >= limit:
            break
    return hits


def _search_duckduckgo(query: str, *, timeout: float = 10.0) -> dict[str, Any]:
    headers = {
        "User-Agent": "SecurityAssessmentTestExecutor-TC14-Dorking/1.0",
        "Accept": "text/html",
    }
    try:
        response = requests.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            headers=headers,
            timeout=timeout,
        )
        hits = _extract_ddg_hits(response.text or "")
        return {
            "ok": response.status_code < 500,
            "status_code": response.status_code,
            "hit_count": len(hits),
            "hits": hits,
            "error": "" if response.status_code < 500 else f"HTTP {response.status_code}",
        }
    except requests.RequestException as exc:
        return {
            "ok": False,
            "status_code": None,
            "hit_count": 0,
            "hits": [],
            "error": f"{type(exc).__name__}: {exc}",
        }


def _run_automated_dorks(queries: list[DorkQuery], *, max_queries: int = 6) -> dict[str, Any]:
    ranked = sorted(
        queries,
        key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(item.priority, 9),
    )
    selected = ranked[: max(1, min(max_queries, 8))]
    executed: list[dict[str, Any]] = []
    for index, query in enumerate(selected):
        result = _search_duckduckgo(query.query)
        executed.append({
            "category": query.category,
            "priority": query.priority,
            "query": query.query,
            "purpose": query.purpose,
            **result,
        })
        if index + 1 < len(selected):
            time.sleep(0.6)
    searched_ok = any(item.get("ok") for item in executed)
    hits = [item for item in executed if item.get("hit_count")]
    critical_hits = [item for item in hits if item.get("priority") == "critical"]
    return {
        "automated_search": searched_ok,
        "queries_executed": executed,
        "queries_with_hits": len(hits),
        "critical_hits": len(critical_hits),
        "engine": "duckduckgo_html",
        "payloads_used": [{"name": item["category"], "payload": item["query"], "kind": "dork"} for item in executed],
        "triggering_payload": (
            {
                "name": (critical_hits or hits)[0]["category"],
                "payload": (critical_hits or hits)[0]["query"],
                "reason": (
                    f"Automated DuckDuckGo search returned {(critical_hits or hits)[0]['hit_count']} "
                    f"indexed result(s) for this { (critical_hits or hits)[0]['priority'] }-priority dork."
                ),
                "verdict": "REVIEW REQUIRED",
            }
            if (critical_hits or hits) else None
        ),
    }


# ============================================================================
# Main scanner
# ============================================================================

def scan_google_dorking(
    url: str,
    *,
    include_subdomains: bool = True,
    **_,
) -> dict:

    # --------------------------------------------------------
    # Normalize / validate target
    # --------------------------------------------------------

    try:
        normalized = normalize_url(
            url
        )
    except Exception as exc:
        return {
            "status": "INCOMPLETE",
            "summary": (
                "The target URL could not be normalized, "
                "so search-engine reconnaissance queries "
                "could not be generated."
            ),
            "details": {
                "target": url,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            },
            "evidence": [],
        }

    # --------------------------------------------------------
    # Extract hostname
    # --------------------------------------------------------

    parsed = urlparse(
        normalized
    )

    host = _normalise_host(
        parsed.hostname or ""
    )

    if not host:

        return {
            "status": "INCOMPLETE",
            "summary": (
                "The target hostname could not be determined, "
                "so search-engine reconnaissance queries could "
                "not be generated."
            ),
            "details": {
                "target": normalized,
                "error": "invalid_hostname",
            },
            "evidence": [],
        }

    # --------------------------------------------------------
    # Conservative base-domain calculation
    # --------------------------------------------------------

    base_domain = _base_domain(
        host
    )

    # --------------------------------------------------------
    # Generate queries
    # --------------------------------------------------------

    queries = _build_queries(
        host,
        include_subdomain_scope=(
            include_subdomains
        ),
    )

    # --------------------------------------------------------
    # Deduplicate query strings
    # --------------------------------------------------------

    unique_queries: list[DorkQuery] = []

    seen: set[str] = set()

    for query in queries:

        query_text = (
            query.query
            .strip()
        )

        if not query_text:
            continue

        if query_text in seen:
            continue

        seen.add(
            query_text
        )

        unique_queries.append(
            query
        )

    # --------------------------------------------------------
    # Build manual links
    # --------------------------------------------------------

    query_records: list[
        dict[str, Any]
    ] = []

    for query in unique_queries:

        query_records.append(
            {
                **query.as_dict(),

                "manual_links": {
                    "google": _google_url(
                        query.query
                    ),

                    "bing": _bing_url(
                        query.query
                    ),

                    "duckduckgo": _duckduckgo_url(
                        query.query
                    ),
                },

                "review_guidance": (
                    _review_guidance(
                        query
                    )
                ),
            }
        )

    # --------------------------------------------------------
    # Priority summary
    # --------------------------------------------------------

    priority_counts: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
    }

    for query in unique_queries:

        priority = (
            query.priority
            .strip()
            .lower()
        )

        if priority in priority_counts:
            priority_counts[
                priority
            ] += 1

    # --------------------------------------------------------
    # Category summary
    # --------------------------------------------------------

    categories: dict[str, int] = {}

    for query in unique_queries:

        category = (
            query.category
            .strip()
        )

        categories[
            category
        ] = (
            categories.get(
                category,
                0,
            )
            + 1
        )

    # --------------------------------------------------------
    # Important limitation disclosure
    # --------------------------------------------------------

    limitations = [
        (
            "A search result is not automatically a confirmed vulnerability; "
            "exposed content must still be opened and verified by an operator."
        ),
        (
            "Search-engine indexes can differ and may be "
            "stale, incomplete, personalized, or regional."
        ),
        (
            "No credentials discovered through search results "
            "are automatically tested."
        ),
        (
            "Large backup/archive results should not be "
            "automatically downloaded by this testcase."
        ),
    ]

    automated = _run_automated_dorks(unique_queries)
    for record in query_records:
        executed = next(
            (item for item in automated.get("queries_executed") or [] if item.get("query") == record.get("query")),
            None,
        )
        if executed:
            record["automated_hits"] = executed.get("hits") or []
            record["automated_hit_count"] = executed.get("hit_count") or 0

    evidence = [
        f"Generated {len(query_records)} categorized search-engine queries.",
        f"Automatically queried DuckDuckGo HTML for {len(automated.get('queries_executed') or [])} high-priority dorks.",
    ]
    if automated.get("queries_with_hits"):
        status = "REVIEW REQUIRED"
        summary = (
            "Automated search-engine reconnaissance returned indexed results for one or more "
            "sensitive dorks. An operator should open the linked hits and confirm whether "
            "the exposed content is a real disclosure."
        )
        evidence.append(
            f"{automated['queries_with_hits']} dork(s) returned indexed hits, including "
            f"{automated.get('critical_hits') or 0} critical-priority hit set(s)."
        )
        operator_action = (
            "Review the automated DuckDuckGo hits and the generated Google/Bing links. "
            "Confirm whether indexed files, credentials, or admin interfaces are actually exposed."
        )
        assessment_state = "REVIEW_REQUIRED"
    elif automated.get("automated_search"):
        status = "SAFE"
        summary = (
            "Automated DuckDuckGo reconnaissance did not return indexed hits for the bounded "
            "high-priority dork set. Search indexes can be incomplete, so the generated Google/Bing "
            "links remain available for a manual spot-check."
        )
        evidence.append("No indexed hits were returned by the automated DuckDuckGo pass.")
        operator_action = (
            "Optional: spot-check the generated Google/Bing links if DuckDuckGo coverage is a concern."
        )
        assessment_state = "NOT_A_FINDING"
    else:
        status = "REVIEW REQUIRED"
        summary = (
            "Domain-scoped reconnaissance queries were generated, but the automated search-engine "
            "query did not complete. Manual review of the Google/Bing/DuckDuckGo links is required."
        )
        evidence.append("Automated DuckDuckGo queries did not complete; falling back to operator review.")
        operator_action = "Open the generated Google/Bing/DuckDuckGo links and review any indexed sensitive content."
        assessment_state = "MANUAL_REVIEW_PENDING"

    return {
        "status": status,
        "summary": summary,
        "details": {
            "target": normalized,
            "target_host": host,
            "base_domain": base_domain,
            "include_subdomains": include_subdomains,
            "automated_search": bool(automated.get("automated_search")),
            "finding_confirmed": False,
            "assessment_state": assessment_state,
            "query_count": len(query_records),
            "priority_counts": priority_counts,
            "categories": categories,
            "queries": query_records,
            "payloads_used": automated.get("payloads_used") or [],
            "triggering_payload": automated.get("triggering_payload"),
            "automated_results": automated,
            "operator_action": operator_action,
            "limitations": limitations,
        },
        "evidence": evidence,
    }