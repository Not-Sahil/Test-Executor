from __future__ import annotations

import hashlib
import re
import secrets
from html import unescape
from typing import Any
from urllib.parse import urljoin, urlparse

from .common import normalize_url, request, result, connection_result


# ============================================================================
# Configuration
# ============================================================================

FORWARDED_HOST_HEADERS = (
    "X-Forwarded-Host",
    "X-Host",
    "Forwarded",
)

MAX_BODY_SAMPLE = 150_000
MAX_TEXT_EVIDENCE = 500


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


def _normalise_text(value: str) -> str:
    return re.sub(
        r"\s+",
        " ",
        value or "",
    ).strip()


def _body_fingerprint(body: str) -> str:
    """
    Create a coarse content fingerprint.

    This is not intended to uniquely identify pages; it is simply useful
    for comparing normal vs. manipulated-host responses.
    """

    normalized = _normalise_text(
        body[:MAX_BODY_SAMPLE]
    )

    # Remove the injected marker so reflection doesn't create a false
    # impression of an otherwise different application response.
    normalized = re.sub(
        r"TC12-[A-Za-z0-9_-]+",
        "<HOST_MARKER>",
        normalized,
    )

    return hashlib.sha256(
        normalized.encode(
            "utf-8",
            errors="replace",
        )
    ).hexdigest()


def _extract_locations(
    response,
) -> list[str]:

    locations: list[str] = []

    raw = response.headers.get(
        "Location",
        "",
    )

    if raw:
        locations.append(
            raw.strip()
        )

    refresh = response.headers.get(
        "Refresh",
        "",
    )

    if refresh:
        locations.append(
            refresh.strip()
        )

    return locations


def _extract_absolute_urls(
    body: str,
) -> list[str]:

    urls: list[str] = []

    # Basic absolute-URL detection.
    for match in re.findall(
        r"""https?://[^\s"'<>]+""",
        body[:MAX_BODY_SAMPLE],
        flags=re.IGNORECASE,
    ):

        cleaned = match.rstrip(
            ".,);]}>\"'"
        )

        if cleaned:
            urls.append(
                cleaned
            )

    return list(
        dict.fromkeys(urls)
    )[:50]


def _extract_html_host_context(
    body: str,
    test_host: str,
) -> dict[str, Any]:

    lower = body.lower()
    host_lower = test_host.lower()

    canonical_matches = re.findall(
        r"""<link\b[^>]*rel=["']?canonical["']?[^>]*href=["']([^"']+)["']""",
        body,
        flags=re.IGNORECASE,
    )

    og_matches = re.findall(
        r"""<meta\b[^>]*property=["']og:url["'][^>]*content=["']([^"']+)["']""",
        body,
        flags=re.IGNORECASE,
    )

    scripts = re.findall(
        r"""<(?:script|link)\b[^>]*(?:src|href)=["']([^"']+)["']""",
        body,
        flags=re.IGNORECASE,
    )

    return {
        "host_reflected_in_body": (
            host_lower in lower
        ),
        "canonical_urls": canonical_matches[:20],
        "canonical_reflects_test_host": any(
            host_lower in value.lower()
            for value in canonical_matches
        ),
        "og_urls": og_matches[:20],
        "og_reflects_test_host": any(
            host_lower in value.lower()
            for value in og_matches
        ),
        "resource_urls": scripts[:30],
        "resource_urls_reflect_test_host": any(
            host_lower in value.lower()
            for value in scripts
        ),
        "absolute_urls": _extract_absolute_urls(
            body
        ),
    }


def _cookie_host_influence(
    response,
    test_host: str,
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    # requests combines Set-Cookie headers into its cookie jar, so for
    # reliable raw-header inspection we inspect the response headers where
    # available.
    set_cookie_headers: list[str] = []

    try:
        raw_headers = response.raw.headers

        get_all = getattr(
            raw_headers,
            "get_all",
            None,
        )

        if get_all:
            values = get_all(
                "Set-Cookie"
            )

            if values:
                set_cookie_headers.extend(
                    values
                )

    except Exception:
        pass

    if not set_cookie_headers:

        single = response.headers.get(
            "Set-Cookie",
            "",
        )

        if single:
            set_cookie_headers.append(
                single
            )

    for cookie in set_cookie_headers:

        item = {
            "set_cookie": cookie[:2000],
            "test_host_reflected": (
                test_host.lower()
                in cookie.lower()
            ),
        }

        if item["test_host_reflected"]:
            findings.append(
                item
            )

    return findings


def _response_summary(
    response,
    *,
    test_host: str,
    requested_url: str,
) -> dict[str, Any]:

    body = response.text or ""

    body_context = _extract_html_host_context(
        body,
        test_host,
    )

    return {
        "requested_url": requested_url,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "content_length": len(body),
        "title": _extract_title(body),
        "server": response.headers.get(
            "Server",
            "",
        ),
        "location": response.headers.get(
            "Location",
            "",
        ),
        "refresh": response.headers.get(
            "Refresh",
            "",
        ),
        "content_location": response.headers.get(
            "Content-Location",
            "",
        ),
        "body_fingerprint": _body_fingerprint(
            body
        ),
        "body_context": body_context,
        "cookie_influence": _cookie_host_influence(
            response,
            test_host,
        ),
    }


def _safe_request(
    url: str,
    *,
    verify_tls: bool,
    timeout: float,
    headers: dict[str, str] | None = None,
):
    return request(
        url,
        method="GET",
        timeout=timeout,
        verify_tls=verify_tls,
        allow_redirects=False,
        headers=headers or {},
    )


def _location_contains_test_host(
    response,
    test_host: str,
) -> bool:

    location = response.headers.get(
        "Location",
        "",
    )

    refresh = response.headers.get(
        "Refresh",
        "",
    )

    return (
        test_host.lower() in location.lower()
        or test_host.lower() in refresh.lower()
    )


def _material_response_difference(
    normal: dict[str, Any],
    injected: dict[str, Any],
) -> dict[str, Any]:

    differences: list[str] = []

    if normal["status_code"] != injected[
        "status_code"
    ]:
        differences.append(
            "status_code"
        )

    if normal["content_type"] != injected[
        "content_type"
    ]:
        differences.append(
            "content_type"
        )

    if normal["body_fingerprint"] != injected[
        "body_fingerprint"
    ]:
        differences.append(
            "body_content"
        )

    if normal["title"] != injected[
        "title"
    ]:
        differences.append(
            "title"
        )

    return {
        "material_difference": bool(
            differences
        ),
        "differences": differences,
    }


def _forwarded_header_value(
    header: str,
    test_host: str,
) -> str:

    if header.lower() == "forwarded":
        return (
            f"host={test_host};proto=https"
        )

    return test_host


# ============================================================================
# Main scanner
# ============================================================================

def scan_host_header(
    url: str,
    verify_tls: bool = True,
    timeout: float = 12.0,
) -> dict:

    target = normalize_url(
        url
    )

    parsed = urlparse(
        target
    )

    if not parsed.hostname:

        return result(
            "INCOMPLETE",
            "The scanner could not determine the target hostname.",
            details={
                "target": target,
                "error": "invalid_hostname",
            },
        )

    original_host = parsed.hostname

    # Random marker prevents accidental matching with ordinary page content.
    token = secrets.token_hex(8)

    test_host = (
        f"tc12-{token}.invalid"
    )

    details: dict[str, Any] = {
        "target": target,
        "original_host": original_host,
        "test_host": test_host,
        "redirects_followed": False,
        "tests": [],
    }

    # ========================================================================
    # 1. Baseline request
    # ========================================================================

    try:

        normal_response = _safe_request(
            target,
            verify_tls=verify_tls,
            timeout=timeout,
        )

    except Exception as exc:

        return connection_result(
            exc,
            target=target,
        )

    normal = _response_summary(
        normal_response,
        test_host=test_host,
        requested_url=target,
    )

    details["normal"] = normal

    # ========================================================================
    # 2. Direct Host injection
    # ========================================================================

    try:

        injected_response = _safe_request(
            target,
            verify_tls=verify_tls,
            timeout=timeout,
            headers={
                "Host": test_host,
            },
        )

    except Exception as exc:

        return result(
            "INCOMPLETE",
            "The normal request succeeded, but the controlled Host-header request failed, so the injection test could not be completed.",
            details={
                **details,
                "host_test_error": {
                    "type": type(exc).__name__,
                    "message": str(exc)[:1000],
                },
            },
        )

    injected = _response_summary(
        injected_response,
        test_host=test_host,
        requested_url=target,
    )

    details["host_injection"] = injected

    # ========================================================================
    # 3. Analyze direct Host influence
    # ========================================================================

    direct_location_reflection = (
        _location_contains_test_host(
            injected_response,
            test_host,
        )
    )

    direct_body_reflection = (
        injected["body_context"][
            "host_reflected_in_body"
        ]
    )

    direct_absolute_url_reflection = any(
        test_host.lower()
        in value.lower()
        for value in injected[
            "body_context"
        ]["absolute_urls"]
    )

    direct_canonical_reflection = (
        injected[
            "body_context"
        ]["canonical_reflects_test_host"]
    )

    direct_og_reflection = (
        injected[
            "body_context"
        ]["og_reflects_test_host"]
    )

    direct_resource_reflection = (
        injected[
            "body_context"
        ]["resource_urls_reflect_test_host"]
    )

    direct_cookie_reflection = bool(
        injected[
            "cookie_influence"
        ]
    )

    details[
        "direct_host_analysis"
    ] = {
        "location_or_refresh_reflection": (
            direct_location_reflection
        ),
        "body_reflection": (
            direct_body_reflection
        ),
        "absolute_url_reflection": (
            direct_absolute_url_reflection
        ),
        "canonical_reflection": (
            direct_canonical_reflection
        ),
        "og_url_reflection": (
            direct_og_reflection
        ),
        "resource_url_reflection": (
            direct_resource_reflection
        ),
        "cookie_reflection": (
            direct_cookie_reflection
        ),
    }

    # ========================================================================
    # 4. Safe host variants
    #
    # Test port-bearing and case variation. These are still controlled,
    # non-destructive values.
    # ========================================================================

    variant_results: list[dict[str, Any]] = []

    variants = (
        (
            "host_with_port",
            f"{test_host}:{parsed.port or (443 if parsed.scheme == 'https' else 80)}",
        ),
        (
            "uppercase_host",
            test_host.upper(),
        ),
    )

    for variant_name, variant_host in variants:

        try:

            response = _safe_request(
                target,
                verify_tls=verify_tls,
                timeout=timeout,
                headers={
                    "Host": variant_host,
                },
            )

            variant = _response_summary(
                response,
                test_host=variant_host,
                requested_url=target,
            )

            variant_results.append(
                {
                    "variant": variant_name,
                    "host": variant_host,
                    "response": variant,
                    "location_reflection": (
                        _location_contains_test_host(
                            response,
                            variant_host,
                        )
                    ),
                    "body_reflection": (
                        variant[
                            "body_context"
                        ][
                            "host_reflected_in_body"
                        ]
                    ),
                }
            )

        except Exception as exc:

            variant_results.append(
                {
                    "variant": variant_name,
                    "host": variant_host,
                    "error": str(exc)[:500],
                    "error_type": type(exc).__name__,
                }
            )

    details["host_variants"] = variant_results

    # ========================================================================
    # 5. X-Forwarded-Host bypass check
    # ========================================================================

    forwarded_results: list[dict[str, Any]] = []

    for header_name in FORWARDED_HOST_HEADERS:

        try:

            response = _safe_request(
                target,
                verify_tls=verify_tls,
                timeout=timeout,
                headers={
                    header_name: _forwarded_header_value(
                        header_name,
                        test_host,
                    )
                },
            )

            observation = _response_summary(
                response,
                test_host=test_host,
                requested_url=target,
            )

            location_reflection = (
                _location_contains_test_host(
                    response,
                    test_host,
                )
            )

            body_reflection = (
                observation[
                    "body_context"
                ][
                    "host_reflected_in_body"
                ]
            )

            absolute_reflection = any(
                test_host.lower()
                in value.lower()
                for value in observation[
                    "body_context"
                ]["absolute_urls"]
            )

            forwarded_results.append(
                {
                    "header": header_name,
                    "response": observation,
                    "location_reflection": (
                        location_reflection
                    ),
                    "body_reflection": (
                        body_reflection
                    ),
                    "absolute_url_reflection": (
                        absolute_reflection
                    ),
                }
            )

        except Exception as exc:

            forwarded_results.append(
                {
                    "header": header_name,
                    "error": str(exc)[:500],
                    "error_type": type(exc).__name__,
                }
            )

    details[
        "forwarded_host_tests"
    ] = forwarded_results

    # ========================================================================
    # 6. Compare normal vs injected behavior
    # ========================================================================

    direct_difference = (
        _material_response_difference(
            normal,
            injected,
        )
    )

    details[
        "normal_vs_injected_difference"
    ] = direct_difference

    # ========================================================================
    # 7. Check alternate likely application paths
    #
    # We keep this very small. The objective is to see whether Host handling
    # changes security-relevant behavior beyond the root page, not to crawl.
    # ========================================================================

    secondary_paths = (
        "/",
        "/robots.txt",
    )

    path_comparisons: list[dict[str, Any]] = []

    for path in secondary_paths:

        path_url = urljoin(
            target.rstrip("/") + "/",
            path.lstrip("/"),
        )

        try:

            normal_path_response = _safe_request(
                path_url,
                verify_tls=verify_tls,
                timeout=timeout,
            )

            injected_path_response = _safe_request(
                path_url,
                verify_tls=verify_tls,
                timeout=timeout,
                headers={
                    "Host": test_host,
                },
            )

            normal_path = _response_summary(
                normal_path_response,
                test_host=test_host,
                requested_url=path_url,
            )

            injected_path = _response_summary(
                injected_path_response,
                test_host=test_host,
                requested_url=path_url,
            )

            path_comparisons.append(
                {
                    "path": path,
                    "normal": normal_path,
                    "injected": injected_path,
                    "difference": (
                        _material_response_difference(
                            normal_path,
                            injected_path,
                        )
                    ),
                    "location_reflection": (
                        _location_contains_test_host(
                            injected_path_response,
                            test_host,
                        )
                    ),
                }
            )

        except Exception as exc:

            path_comparisons.append(
                {
                    "path": path,
                    "error": str(exc)[:500],
                    "error_type": type(exc).__name__,
                }
            )

    details[
        "secondary_path_comparisons"
    ] = path_comparisons

    # ========================================================================
    # 8. Classification
    # ========================================================================

    def _is_host_rejection(response_summary: dict[str, Any]) -> bool:
        """Identify a likely server-side rejection of the manipulated Host."""
        status = response_summary.get("status_code")
        title = (response_summary.get("title") or "").lower()
        server = (response_summary.get("server") or "").lower()

        if not isinstance(status, int) or status < 400:
            return False

        rejection_titles = {
            "bad request",
            "service unavailable",
            "forbidden",
            "not found",
            "method not allowed",
            "invalid host",
            "invalid hostname",
        }
        return title in rejection_titles or "microsoft-httpapi" in server

    injected_host_rejected = _is_host_rejection(injected)
    details["injected_host_rejected"] = injected_host_rejected

    evidence: list[str] = []

    # ------------------------------------------------------------------------
    # Strongest finding: attacker-controlled redirect destination
    # ------------------------------------------------------------------------

    if direct_location_reflection:

        location = injected_response.headers.get(
            "Location",
            "",
        )

        evidence.append(
            (
                "Injected Host value influenced "
                f"Location/Refresh: {location[:1000]}"
            )
        )

        return result(
            "UNSAFE",
            "The application used the controlled Host value when generating a redirect, demonstrating security-sensitive host-header influence.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------------
    # X-Forwarded-Host redirect influence
    # ------------------------------------------------------------------------

    forwarded_redirects = [
        item
        for item in forwarded_results
        if item.get(
            "location_reflection",
            False,
        )
    ]

    if forwarded_redirects:

        evidence.extend(
            [
                (
                    f"{item['header']} influenced "
                    "the redirect destination."
                )
                for item in forwarded_redirects
            ]
        )

        return result(
            "UNSAFE",
            "A forwarded-host header influenced a redirect destination. This indicates that upstream host metadata may be trusted without sufficient validation.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------------
    # Security-sensitive generated URL reflections
    # ------------------------------------------------------------------------

    if (
        direct_canonical_reflection
        or direct_og_reflection
        or direct_resource_reflection
        or direct_absolute_url_reflection
    ):

        if direct_canonical_reflection:
            evidence.append(
                "Injected Host appeared in a canonical URL."
            )

        if direct_og_reflection:
            evidence.append(
                "Injected Host appeared in an OpenGraph URL."
            )

        if direct_resource_reflection:
            evidence.append(
                "Injected Host appeared in a generated resource URL."
            )

        if direct_absolute_url_reflection:
            evidence.append(
                "Injected Host appeared in an absolute URL in the response."
            )

        return result(
            "REVIEW REQUIRED",
            "The application used the controlled Host value when generating absolute URLs or page metadata. This may become security-sensitive depending on how those URLs are consumed.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------------
    # Cookie influence
    # ------------------------------------------------------------------------

    if direct_cookie_reflection:

        evidence.append(
            "The controlled Host value appeared in a Set-Cookie response."
        )

        return result(
            "REVIEW REQUIRED",
            "The controlled Host value influenced cookie-related response data. Review whether cookie domain or other security-sensitive cookie attributes are derived from an untrusted Host value.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------------
    # Explicit Host rejection
    # ------------------------------------------------------------------------

    if (
        direct_difference["material_difference"]
        and injected_host_rejected
        and not direct_location_reflection
        and not direct_body_reflection
        and not direct_absolute_url_reflection
        and not direct_canonical_reflection
        and not direct_og_reflection
        and not direct_resource_reflection
        and not direct_cookie_reflection
    ):
        return result(
            "SAFE",
            "The manipulated Host value was rejected by the server, and no security-sensitive Host-derived redirect, URL, cookie, or body reflection was observed.",
            details=details,
            evidence=[
                f"Injected Host returned HTTP {injected.get('status_code')} with a rejection response: {injected.get('title') or 'server rejection'}."
            ],
        )

    # ------------------------------------------------------------------------
    # Virtual-host response switching
    # ------------------------------------------------------------------------

    if direct_difference[
        "material_difference"
    ]:

        evidence.append(
            "Normal and Host-injected responses differed materially: "
            + ", ".join(
                direct_difference[
                    "differences"
                ]
            )
        )

        return result(
            "REVIEW REQUIRED",
            "Changing the Host header caused materially different application behavior. This may indicate virtual-host routing based on an unvalidated Host value and should be investigated.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------------
    # Body reflection only
    # ------------------------------------------------------------------------

    if direct_body_reflection:

        evidence.append(
            (
                f"The controlled Host value "
                f"{test_host} was reflected in the response body."
            )
        )

        return result(
            "REVIEW REQUIRED",
            "The controlled Host value was reflected in the response body, but no security-sensitive redirect or generated URL was confirmed automatically.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------------
    # Forwarded-host non-sensitive reflection
    # ------------------------------------------------------------------------

    forwarded_reflections = [
        item
        for item in forwarded_results
        if (
            item.get(
                "body_reflection",
                False,
            )
            or item.get(
                "absolute_url_reflection",
                False,
            )
        )
    ]

    if forwarded_reflections:

        return result(
            "REVIEW REQUIRED",
            "A forwarded-host header influenced response content or generated URLs. Review whether the deployment trusts proxy-supplied host metadata without adequate validation.",
            details=details,
            evidence=[
                (
                    f"{item['header']} influenced "
                    "response content."
                )
                for item in forwarded_reflections
            ],
        )

    # ------------------------------------------------------------------------
    # No finding
    # ------------------------------------------------------------------------

    return result(
        "SAFE",
        "The controlled Host-header tests did not identify a security-sensitive redirect, generated-URL influence, cookie-domain influence, or clear virtual-host switching.",
        details=details,
    )