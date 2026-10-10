from __future__ import annotations

import hashlib
import secrets
from typing import Any

from .common import normalize_url, request, result, connection_result


# ============================================================================
# Configuration
# ============================================================================

SAFE_METHODS = (
    "GET",
    "HEAD",
    "OPTIONS",
)

DIAGNOSTIC_METHODS = (
    "TRACE",
    "TRACK",
)

# RFC 9110 / common HTTP methods that may legitimately be used by APIs.
STATE_CHANGING_METHODS = (
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
)

# Small set of request methods useful for detecting incorrect routing of
# unknown verbs. This is deliberately harmless and non-destructive.
UNKNOWN_METHODS = (
    "X-SECURITY-TEST",
)

METHOD_OVERRIDE_HEADERS = (
    "X-HTTP-Method",
    "X-HTTP-Method-Override",
    "X-Method-Override",
)

MAX_RESPONSE_SAMPLE = 100_000


# ============================================================================
# Helpers
# ============================================================================

def _parse_allow(value: str | None) -> set[str]:
    """
    Parse an HTTP Allow header into normalized method names.
    """

    return {
        part.strip().upper()
        for part in (value or "").split(",")
        if part.strip()
    }


def _status_category(status_code: int) -> str:
    if 200 <= status_code < 300:
        return "2xx"

    if 300 <= status_code < 400:
        return "3xx"

    if 400 <= status_code < 500:
        return "4xx"

    if 500 <= status_code < 600:
        return "5xx"

    return "other"


def _sample_headers(response) -> dict[str, str]:
    important = (
        "Allow",
        "Location",
        "Content-Type",
        "Content-Length",
        "Server",
        "Via",
    )

    return {
        name: response.headers.get(name, "")[:1000]
        for name in important
        if response.headers.get(name) is not None
    }


def _marker_found(
    response,
    marker: str,
) -> dict[str, Any]:
    """
    Determine whether a controlled marker was reflected in the response
    body or headers.
    """

    body = (response.text or "")[
        :MAX_RESPONSE_SAMPLE
    ]

    body_reflected = marker in body

    header_reflected = any(
        marker in str(value)
        for value in response.headers.values()
    )

    return {
        "body": body_reflected,
        "headers": header_reflected,
        "any": (
            body_reflected
            or header_reflected
        ),
    }


def _body_fingerprint(response) -> str:
    """Create a compact response-body fingerprint for baseline comparison."""
    body = (response.text or "")[:MAX_RESPONSE_SAMPLE]
    return hashlib.sha256(
        body.encode("utf-8", errors="replace")
    ).hexdigest()


def _method_result_item(
    method: str,
    response,
    *,
    marker: str | None = None,
) -> dict[str, Any]:

    item = {
        "method": method,
        "status_code": response.status_code,
        "status_category": _status_category(
            response.status_code
        ),
        "url": response.url,
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "content_length": len(response.content or b""),
        "body_fingerprint": _body_fingerprint(response),
        "allow": response.headers.get(
            "Allow",
            "",
        ),
        "location": response.headers.get(
            "Location",
            "",
        ),
        "headers": _sample_headers(
            response
        ),
    }

    if marker:
        item["marker_reflection"] = _marker_found(
            response,
            marker,
        )

    return item


def _compare_allow_with_observed(
    advertised: set[str],
    observed: dict[str, dict[str, Any]],
) -> dict[str, Any]:

    mismatches: list[dict[str, Any]] = []

    for method, item in observed.items():

        if method in advertised:
            advertised_present = True
        else:
            advertised_present = False

        status = item.get(
            "status_code"
        )

        appears_accepted = (
            isinstance(status, int)
            and 200 <= status < 300
        )

        if advertised_present and not appears_accepted:
            if status not in {
                401,
                403,
                404,
                405,
                501,
            }:
                mismatches.append(
                    {
                        "method": method,
                        "issue": (
                            "advertised_but_probe_did_not_return_2xx"
                        ),
                        "status_code": status,
                    }
                )

        elif (
            not advertised_present
            and appears_accepted
            and method not in {
                "HEAD",
                "OPTIONS",
            }
        ):
            mismatches.append(
                {
                    "method": method,
                    "issue": (
                        "accepted_but_not_advertised"
                    ),
                    "status_code": status,
                }
            )

    return {
        "mismatches": mismatches,
        "count": len(mismatches),
    }


# ============================================================================
# Main scanner
# ============================================================================

def scan_http_arbitrary_methods(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
) -> dict:
    """
    TC11 - HTTP Methods

    Safe pre-login assessment of HTTP method handling.

    Tests:
        - OPTIONS / Allow discovery
        - GET baseline
        - HEAD behavior
        - TRACE
        - TRACK
        - unknown/custom method rejection
        - marker reflection through diagnostic methods
        - Allow/probe consistency
        - advertised state-changing methods

    Intentionally does NOT issue destructive PUT/PATCH/DELETE/POST requests
    against unknown live targets.
    """

    target = normalize_url(
        url
    )

    details: dict[str, Any] = {
        "target": target,
        "tests": [],
        "warnings": [],
    }

    # ------------------------------------------------------------------
    # 1. GET baseline
    # ------------------------------------------------------------------

    try:
        baseline = request(
            target,
            method="GET",
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
        )
    except Exception as exc:

        return connection_result(
            exc,
            target=target,
        )

    details["baseline"] = (
        _method_result_item(
            "GET",
            baseline,
        )
    )

    # ------------------------------------------------------------------
    # 2. OPTIONS
    # ------------------------------------------------------------------

    try:
        options = request(
            target,
            method="OPTIONS",
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
        )
    except Exception as exc:

        return connection_result(
            exc,
            target=target,
        )

    allow_raw = options.headers.get(
        "Allow",
        "",
    )

    advertised = _parse_allow(
        allow_raw
    )

    details["options"] = {
        **_method_result_item(
            "OPTIONS",
            options,
        ),
        "allow_raw": allow_raw,
        "allow": sorted(advertised),
    }

    # ------------------------------------------------------------------
    # 3. HEAD
    # ------------------------------------------------------------------

    observed: dict[str, dict[str, Any]] = {}

    try:
        head = request(
            target,
            method="HEAD",
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
        )

        head_item = _method_result_item(
            "HEAD",
            head,
        )

        observed["HEAD"] = head_item
        details["tests"].append(
            head_item
        )

    except Exception as exc:

        details["tests"].append(
            {
                "method": "HEAD",
                "error": str(exc)[:500],
                "error_type": type(exc).__name__,
            }
        )

    # ------------------------------------------------------------------
    # 4. TRACE / TRACK
    # ------------------------------------------------------------------

    diagnostic_marker = (
        "SECURITY-TC11-"
        + secrets.token_hex(8)
    )

    diagnostic_results: list[dict[str, Any]] = []

    for method in DIAGNOSTIC_METHODS:

        try:

            response = request(
                target,
                method=method,
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=False,
                headers={
                    "X-Security-Test-Trace": (
                        diagnostic_marker
                    ),
                },
            )

            item = _method_result_item(
                method,
                response,
                marker=diagnostic_marker,
            )

            diagnostic_results.append(
                item
            )

            observed[method] = item

            details["tests"].append(
                item
            )

        except Exception as exc:

            item = {
                "method": method,
                "error": str(exc)[:500],
                "error_type": type(exc).__name__,
            }

            diagnostic_results.append(
                item
            )

            details["tests"].append(
                item
            )

    details["diagnostic_methods"] = (
        diagnostic_results
    )

    # ------------------------------------------------------------------
    # 5. Unknown method
    # ------------------------------------------------------------------

    unknown_results: list[dict[str, Any]] = []

    for method in UNKNOWN_METHODS:

        try:

            response = request(
                target,
                method=method,
                timeout=timeout,
                verify_tls=verify_tls,
                allow_redirects=False,
            )

            item = _method_result_item(
                method,
                response,
            )

            unknown_results.append(
                item
            )

            observed[method] = item

            details["tests"].append(
                item
            )

        except Exception as exc:

            unknown_results.append(
                {
                    "method": method,
                    "error": str(exc)[:500],
                    "error_type": type(exc).__name__,
                }
            )

    details["unknown_method_tests"] = (
        unknown_results
    )

    # ------------------------------------------------------------------
    # 6. Identify diagnostic reflection
    # ------------------------------------------------------------------

    reflected = [
        item
        for item in diagnostic_results
        if item.get(
            "marker_reflection",
            {},
        ).get(
            "any",
            False,
        )
    ]

    details["diagnostic_reflection"] = reflected

    # ------------------------------------------------------------------
    # 7. Identify accepted TRACE/TRACK
    # ------------------------------------------------------------------

    accepted_diagnostic = [
        item
        for item in diagnostic_results
        if isinstance(
            item.get("status_code"),
            int,
        )
        and 200 <= item["status_code"] < 300
    ]

    details[
        "accepted_diagnostic_methods"
    ] = [
        item["method"]
        for item in accepted_diagnostic
    ]

    # ------------------------------------------------------------------
    # 8. State-changing methods advertised
    # ------------------------------------------------------------------

    advertised_state_changing = sorted(
        advertised
        & set(
            STATE_CHANGING_METHODS
        )
    )

    details[
        "advertised_state_changing_methods"
    ] = advertised_state_changing

    # ------------------------------------------------------------------
    # 9. Explain why destructive methods were not automatically invoked
    # ------------------------------------------------------------------

    details[
        "destructive_methods_probed"
    ] = []

    details[
        "destructive_method_policy"
    ] = (
        "POST, PUT, PATCH and DELETE are not automatically "
        "executed against arbitrary live resources because "
        "they may legitimately change application state. "
        "Their advertisement is recorded for review instead."
    )

    # ------------------------------------------------------------------
    # 10. Compare Allow header to observed safe methods
    # ------------------------------------------------------------------

    details[
        "allow_probe_comparison"
    ] = _compare_allow_with_observed(
        advertised,
        observed,
    )

    # ------------------------------------------------------------------
    # 11. Analyze unexpected unknown-method behavior
    # ------------------------------------------------------------------

    accepted_unknown = [
        item
        for item in unknown_results
        if isinstance(
            item.get("status_code"),
            int,
        )
        and 200 <= item["status_code"] < 300
    ]

    # 501 means method isn't implemented.
    # 405 means method is recognized but not allowed.
    # Both are normal/expected rejection behavior.
    details[
        "unknown_method_rejection_statuses"
    ] = [
        item.get("status_code")
        for item in unknown_results
    ]

    # ------------------------------------------------------------------
    # 12. Classification — highest confidence first
    # ------------------------------------------------------------------

    # TRACE/TRACK marker reflection is strongest diagnostic finding.
    if reflected:

        evidence = []

        for item in reflected:

            reflection = item[
                "marker_reflection"
            ]

            places = []

            if reflection.get("body"):
                places.append("response body")

            if reflection.get("headers"):
                places.append(
                    "response headers"
                )

            evidence.append(
                (
                    f"{item['method']} reflected "
                    f"the controlled marker in "
                    f"{' and '.join(places)}"
                )
            )

        return result(
            "REVIEW REQUIRED",
            "A diagnostic HTTP method reflected a unique controlled marker in the response. This indicates that the method is actively processed and may expose request information; review whether TRACE/TRACK is required and whether it is safely restricted.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # 13. TRACE/TRACK accepted without reflection
    # ------------------------------------------------------------------

    if accepted_diagnostic:
        generic_diagnostic = [
            item
            for item in accepted_diagnostic
            if (
                item.get("body_fingerprint")
                == details["baseline"].get("body_fingerprint")
                and item.get("content_type", "")
                == details["baseline"].get("content_type", "")
                and not item.get("marker_reflection", {}).get("any", False)
            )
        ]
        meaningful_diagnostic = [
            item for item in accepted_diagnostic
            if item not in generic_diagnostic
        ]

        if meaningful_diagnostic:
            return result(
                "REVIEW REQUIRED",
                "TRACE/TRACK was accepted and produced behavior materially different from the GET baseline without reflecting the controlled marker. Review whether the method is intentionally handled by the application or an intermediary.",
                details=details,
                evidence=[
                    f"{item['method']} returned HTTP {item['status_code']} with behavior different from the GET baseline."
                    for item in meaningful_diagnostic
                ],
            )

        details["diagnostic_method_assessment"] = (
            "TRACE/TRACK returned a generic response matching the GET baseline "
            "and did not reflect the controlled marker."
        )

    # ------------------------------------------------------------------
    # 14. Unknown method accepted

    # ------------------------------------------------------------------

    if accepted_unknown:
        generic_unknown = [
            item
            for item in accepted_unknown
            if (
                item.get("body_fingerprint")
                == details["baseline"].get("body_fingerprint")
                and item.get("content_type", "")
                == details["baseline"].get("content_type", "")
            )
        ]
        meaningful_unknown = [
            item for item in accepted_unknown
            if item not in generic_unknown
        ]

        if meaningful_unknown:
            return result(
                "REVIEW REQUIRED",
                "An unknown HTTP method received a successful response that differed from the normal GET behavior. This may indicate permissive method routing and should be reviewed.",
                details=details,
                evidence=[
                    f"Unknown method {item['method']} returned HTTP {item['status_code']} with behavior different from the GET baseline."
                    for item in meaningful_unknown
                ],
            )

        details["unknown_method_assessment"] = (
            "The unknown method received a generic response matching the GET baseline; "
            "this is not treated as evidence of a distinct method-handling vulnerability."
        )

    # ------------------------------------------------------------------
    # 15. State-changing methods advertised

    # ------------------------------------------------------------------

    if advertised_state_changing:

        return result(
            "REVIEW REQUIRED",
            "The target advertises one or more state-changing HTTP methods. Their presence is not inherently a vulnerability because APIs may legitimately require them, but their authorization and endpoint-specific behavior should be reviewed. This scanner intentionally does not execute destructive requests against arbitrary live resources.",
            details=details,
            evidence=[
                (
                    f"Allow header advertises "
                    f"{method}"
                )
                for method in (
                    advertised_state_changing
                )
            ],
        )

    # ------------------------------------------------------------------
    # 16. Allow/probe inconsistency
    # ------------------------------------------------------------------

    mismatches = details[
        "allow_probe_comparison"
    ]["mismatches"]

    if mismatches:
        details["allow_probe_assessment"] = (
            "Allow/probe mismatches are retained as diagnostic evidence only. "
            "They do not independently change the security verdict unless "
            "material method-specific behavior is also observed."
        )

    # ------------------------------------------------------------------
    # 17. Normal/safe behavior

    # ------------------------------------------------------------------

    return result(
        "SAFE",
        "No security-sensitive TRACE/TRACK reflection or materially different diagnostic/unknown-method behavior was identified on the tested endpoint.",
        details=details,
    )