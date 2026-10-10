from __future__ import annotations

import re
from typing import Any

from .common import (
    normalize_url,
    request,
    result,
    connection_result,
)


# ---------------------------------------------------------------------------
# ETag syntax
# ---------------------------------------------------------------------------

ETAG_PATTERN = re.compile(
    r'^(W/)?"([^"]*)"$',
    flags=re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Heuristic patterns
#
# IMPORTANT:
# These are only indicators. An ETag is opaque by HTTP semantics, so the
# scanner must NOT claim that an inode/timestamp leak is proven merely from
# an unusual-looking value.
# ---------------------------------------------------------------------------

STRUCTURED_ETAG_PATTERNS = (
    # Common hex/decimal resource metadata-looking layouts.
    re.compile(r"^[0-9a-f]+-[0-9a-f]+$", re.IGNORECASE),
    re.compile(r"^[0-9a-f]+-[0-9a-f]+-[0-9a-f]+$", re.IGNORECASE),
    re.compile(r"^\d+-\d+$"),
    re.compile(r"^\d+-\d+-\d+$"),

    # Explicitly descriptive forms.
    re.compile(r".*(inode|mtime|mtime|size|timestamp).*", re.IGNORECASE),
)


def _parse_etag(value: str | None) -> dict[str, Any]:
    """
    Parse an ETag without attempting to interpret its opaque value.
    """
    if not value:
        return {
            "present": False,
            "raw": None,
            "valid": False,
            "weak": False,
            "opaque_value": None,
        }

    value = value.strip()

    match = ETAG_PATTERN.match(value)

    if not match:
        return {
            "present": True,
            "raw": value,
            "valid": False,
            "weak": value.startswith("W/"),
            "opaque_value": None,
        }

    weak = bool(match.group(1))
    opaque = match.group(2)

    return {
        "present": True,
        "raw": value,
        "valid": True,
        "weak": weak,
        "opaque_value": opaque,
    }


def _looks_structured(opaque_value: str | None) -> bool:
    if not opaque_value:
        return False

    return any(
        pattern.search(opaque_value)
        for pattern in STRUCTURED_ETAG_PATTERNS
    )


def _safe_header_value(response, name: str) -> str:
    value = response.headers.get(name, "")
    return value[:1000]


def _response_metadata(response) -> dict[str, Any]:
    return {
        "status_code": response.status_code,
        "url": response.url,
        "etag": response.headers.get("ETag", ""),
        "last_modified": _safe_header_value(
            response,
            "Last-Modified",
        ),
        "cache_control": _safe_header_value(
            response,
            "Cache-Control",
        ),
        "expires": _safe_header_value(
            response,
            "Expires",
        ),
        "vary": _safe_header_value(
            response,
            "Vary",
        ),
        "content_type": _safe_header_value(
            response,
            "Content-Type",
        ),
        "content_length": _safe_header_value(
            response,
            "Content-Length",
        ),
        "content_encoding": _safe_header_value(
            response,
            "Content-Encoding",
        ),
        "last_modified": _safe_header_value(
            response,
            "Last-Modified",
        ),
    }


def _is_successful_representation(response) -> bool:
    """
    We primarily care about actual representations.

    2xx responses are generally useful.
    304 is a validator response and should be handled separately.
    """
    return 200 <= response.status_code < 300


def _normalise_etag_for_comparison(value: str | None) -> str | None:
    if not value:
        return None

    return value.strip()


def _compare_resources(
    first_etag: str | None,
    second_etag: str | None,
) -> dict[str, Any]:
    first = _normalise_etag_for_comparison(first_etag)
    second = _normalise_etag_for_comparison(second_etag)

    return {
        "first_etag": first,
        "second_etag": second,
        "same": (
            first is not None
            and second is not None
            and first == second
        ),
    }


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan_etag_header(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
) -> dict:
    """
    TC06 - ETag Header

    Purpose:
        Determine whether ETag behavior exposes potentially useful
        implementation/resource metadata or behaves unexpectedly.

    Important:
        Presence of an ETag or stability across requests is NOT itself
        considered a vulnerability.
    """

    target = normalize_url(url)

    details: dict[str, Any] = {
        "requested_url": target,
    }

    # ------------------------------------------------------------------
    # 1. Baseline request
    # ------------------------------------------------------------------

    try:
        first = request(
            target,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )
    except Exception as exc:
        return connection_result(
            exc,
            target=target,
        )

    first_metadata = _response_metadata(first)

    details["baseline"] = first_metadata
    details["final_url"] = first.url

    etag = first.headers.get("ETag")

    # ------------------------------------------------------------------
    # 2. No ETag
    # ------------------------------------------------------------------

    if not etag:
        return result(
            "SAFE",
            "No ETag header was returned by the tested response.",
            details=details,
        )

    parsed_first = _parse_etag(etag)

    details["etag_analysis"] = parsed_first

    # ------------------------------------------------------------------
    # 3. Invalid ETag syntax
    # ------------------------------------------------------------------

    if not parsed_first["valid"]:
        return result(
            "REVIEW REQUIRED",
            "An ETag header was returned, but its value does not match normal HTTP entity-tag syntax. This appears to be an implementation anomaly rather than proof of a security vulnerability.",
            details=details,
            evidence=[
                f"Malformed-looking ETag observed: {etag}",
            ],
        )

    # ------------------------------------------------------------------
    # 4. Determine whether the value looks unusually structured
    # ------------------------------------------------------------------

    structured = _looks_structured(
        parsed_first["opaque_value"]
    )

    details["looks_structured"] = structured

    # ------------------------------------------------------------------
    # 5. Repeat request
    # ------------------------------------------------------------------

    try:
        second = request(
            target,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )
    except Exception as exc:
        details["repeat_request_error"] = str(exc)

        if structured:
            return result(
                "REVIEW REQUIRED",
                "The target exposes a syntactically valid ETag with a structured-looking value, but repeated-request verification could not be completed.",
                details=details,
                evidence=[
                    f"Structured-looking ETag: {etag}",
                    f"Repeat request error: {exc}",
                ],
            )

        return result(
            "REVIEW REQUIRED",
            "An ETag was observed, but repeated-request verification could not be completed.",
            details=details,
            evidence=[
                f"ETag observed: {etag}",
                f"Repeat request error: {exc}",
            ],
        )

    second_etag = second.headers.get("ETag")

    details["repeat"] = _response_metadata(second)

    details["etag_stable"] = (
        second_etag == etag
    )

    # ------------------------------------------------------------------
    # 6. Conditional request using If-None-Match
    # ------------------------------------------------------------------

    conditional_status: int | None = None
    conditional_etag: str | None = None
    conditional_error: str | None = None

    try:
        conditional = request(
            target,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=False,
            headers={
                "If-None-Match": etag,
            },
        )

        conditional_status = conditional.status_code
        conditional_etag = conditional.headers.get("ETag")

        details["conditional_request"] = {
            "status_code": conditional_status,
            "etag": conditional_etag,
            "content_length": _safe_header_value(
                conditional,
                "Content-Length",
            ),
            "cache_control": _safe_header_value(
                conditional,
                "Cache-Control",
            ),
            "location": _safe_header_value(
                conditional,
                "Location",
            ),
        }

    except Exception as exc:
        conditional_error = str(exc)
        details["conditional_request_error"] = conditional_error

    # ------------------------------------------------------------------
    # 7. Test validator behavior
    # ------------------------------------------------------------------

    validator_behaviour = "not_tested"

    if conditional_status == 304:
        validator_behaviour = "validated_304"

    elif conditional_status == first.status_code:
        validator_behaviour = "returned_representation"

    elif conditional_status is not None:
        validator_behaviour = (
            f"unexpected_status_{conditional_status}"
        )

    details["validator_behaviour"] = validator_behaviour

    # ------------------------------------------------------------------
    # 8. Compare a second safe public resource
    #
    # We use robots.txt because:
    #   - it is normally a harmless GET
    #   - it does not require guessing application routes
    #   - it is already part of your pre-login assessment suite
    #
    # This is correlation evidence only.
    # ------------------------------------------------------------------

    parsed_target = target.rstrip("/")

    related_url = f"{parsed_target}/robots.txt"

    cross_resource: dict[str, Any] = {
        "url": related_url,
        "tested": False,
    }

    try:
        related = request(
            related_url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
        )

        related_etag = related.headers.get("ETag")

        cross_resource.update(
            {
                "tested": True,
                "status_code": related.status_code,
                "etag": related_etag,
                "content_type": related.headers.get(
                    "Content-Type",
                    "",
                ),
                "same_as_baseline": (
                    related_etag == etag
                    if related_etag and etag
                    else False
                ),
            }
        )

        parsed_related = _parse_etag(related_etag)

        cross_resource["etag_analysis"] = parsed_related

        if related_etag:
            cross_resource["looks_structured"] = (
                _looks_structured(
                    parsed_related["opaque_value"]
                )
            )

            cross_resource["comparison"] = (
                _compare_resources(
                    etag,
                    related_etag,
                )
            )

    except Exception as exc:
        cross_resource["error"] = str(exc)

    details["cross_resource"] = cross_resource

    # ------------------------------------------------------------------
    # 9. Classification
    # ------------------------------------------------------------------

    evidence: list[str] = []

    if parsed_first["weak"]:
        evidence.append(
            "The server returned a weak ETag validator."
        )
    else:
        evidence.append(
            "The server returned a strong ETag validator."
        )

    if details.get("etag_stable"):
        evidence.append(
            "The ETag remained stable across repeated requests."
        )

    if conditional_status == 304:
        evidence.append(
            "If-None-Match using the observed ETag produced "
            "HTTP 304 Not Modified."
        )

    if structured:
        evidence.append(
            "The ETag contains a structured-looking value that "
            "may warrant review for implementation-specific metadata."
        )

    if (
        cross_resource.get("tested")
        and cross_resource.get("etag")
        and cross_resource.get("looks_structured")
    ):
        evidence.append(
            "A second public resource also returned a "
            "structured-looking ETag."
        )

    # ------------------------------------------------------------------
    # 10. Stronger review condition
    # ------------------------------------------------------------------
    #
    # Presence alone = SAFE.
    #
    # Stable ETag alone = SAFE.
    #
    # Valid 304 behavior = SAFE.
    #
    # Structured-looking ETag = REVIEW because it may deserve manual
    # verification, but we cannot prove what an opaque ETag encodes.
    # ------------------------------------------------------------------

    if structured:
        return result(
            "REVIEW REQUIRED",
            "The target exposes a syntactically valid ETag whose opaque value has a structured format that may reflect implementation or resource metadata. ETag usage itself is normal and this scanner cannot prove what the value encodes, so manual verification is required.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # 11. Unexpected conditional behavior
    # ------------------------------------------------------------------

    if (
        conditional_status is not None
        and conditional_status not in {
            304,
            first.status_code,
            200,
            206,
        }
    ):
        return result(
            "REVIEW REQUIRED",
            "The observed ETag produced an unexpected response to an If-None-Match conditional request. Review the server's cache-validation behavior.",
            details=details,
            evidence=evidence
            + [
                f"If-None-Match response: HTTP {conditional_status}",
            ],
        )

    # ------------------------------------------------------------------
    # 12. Normal ETag behavior
    # ------------------------------------------------------------------

    return result(
        "SAFE",
        "The target uses a syntactically valid ETag as a normal HTTP resource validator. No clear ETag-based information disclosure was identified by the automated checks.",
        details=details,
        evidence=evidence,
    )