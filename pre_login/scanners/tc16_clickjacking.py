from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse
from .common import (
    normalize_url,
    request,
    result,
    connection_result,
)


# ============================================================================
# Configuration
# ============================================================================

MAX_POLICY_LENGTH = 20_000


# ============================================================================
# Data structures
# ============================================================================

@dataclass
class FramePolicy:
    source: str
    enforced: bool
    directive: str = ""
    values: list[str] | None = None
    raw: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "enforced": self.enforced,
            "directive": self.directive,
            "values": self.values or [],
            "raw": self.raw,
        }


# ============================================================================
# Header helpers
# ============================================================================

def _get_all_headers(
    response,
    name: str,
) -> list[str]:
    """
    Retrieve all occurrences of a response header where the underlying
    requests/urllib3 object exposes them.

    Falls back to the merged header value if necessary.
    """

    values: list[str] = []

    try:
        raw_headers = response.raw.headers

        get_all = getattr(
            raw_headers,
            "get_all",
            None,
        )

        if get_all:
            raw_values = get_all(name)

            if raw_values:
                values.extend(
                    str(value)
                    for value in raw_values
                )

    except Exception:
        pass

    if not values:

        value = response.headers.get(
            name,
            "",
        )

        if value:
            values.append(
                value
            )

    return values


def _normalise_policy(
    value: str,
) -> str:
    return re.sub(
        r"\s+",
        " ",
        value.strip(),
    )


# ============================================================================
# CSP parsing
# ============================================================================

def _parse_csp_policy(
    policy: str,
) -> dict[str, Any]:
    """
    Parse only the portions relevant to clickjacking.

    The scanner intentionally does not attempt to implement the entire CSP
    grammar.
    """

    policy = _normalise_policy(
        policy[:MAX_POLICY_LENGTH]
    )

    directives: list[dict[str, Any]] = []

    for raw_directive in policy.split(";"):

        directive = raw_directive.strip()

        if not directive:
            continue

        parts = directive.split()

        if not parts:
            continue

        name = parts[0].lower()
        values = [
            part.strip()
            for part in parts[1:]
            if part.strip()
        ]

        directives.append(
            {
                "name": name,
                "values": values,
                "raw": directive,
            }
        )

    frame_ancestors = [
        directive
        for directive in directives
        if directive["name"]
        == "frame-ancestors"
    ]

    return {
        "raw": policy,
        "directives": directives,
        "frame_ancestors": frame_ancestors,
    }


def _parse_csp_headers(
    response,
) -> dict[str, Any]:

    enforced_headers = _get_all_headers(
        response,
        "Content-Security-Policy",
    )

    report_only_headers = _get_all_headers(
        response,
        "Content-Security-Policy-Report-Only",
    )

    enforced_policies = [
        _parse_csp_policy(
            value
        )
        for value in enforced_headers
    ]

    report_only_policies = [
        _parse_csp_policy(
            value
        )
        for value in report_only_headers
    ]

    enforced_frame_ancestors = []

    for policy in enforced_policies:

        for directive in policy[
            "frame_ancestors"
        ]:

            enforced_frame_ancestors.append(
                {
                    "policy": policy["raw"],
                    "values": directive[
                        "values"
                    ],
                    "raw": directive[
                        "raw"
                    ],
                }
            )

    report_only_frame_ancestors = []

    for policy in report_only_policies:

        for directive in policy[
            "frame_ancestors"
        ]:

            report_only_frame_ancestors.append(
                {
                    "policy": policy["raw"],
                    "values": directive[
                        "values"
                    ],
                    "raw": directive[
                        "raw"
                    ],
                }
            )

    return {
        "enforced_headers": enforced_headers,
        "report_only_headers": report_only_headers,
        "enforced_policies": enforced_policies,
        "report_only_policies": report_only_policies,
        "enforced_frame_ancestors": (
            enforced_frame_ancestors
        ),
        "report_only_frame_ancestors": (
            report_only_frame_ancestors
        ),
    }


# ============================================================================
# X-Frame-Options
# ============================================================================

def _parse_xfo_headers(
    response,
) -> dict[str, Any]:

    values = _get_all_headers(
        response,
        "X-Frame-Options",
    )

    parsed: list[dict[str, Any]] = []

    for raw_value in values:

        normalized = _normalise_policy(
            raw_value
        )

        upper = normalized.upper()

        if upper == "DENY":

            classification = (
                "effective_restrictive"
            )

        elif upper == "SAMEORIGIN":

            classification = (
                "effective_restrictive"
            )

        elif upper.startswith(
            "ALLOW-FROM "
        ):

            classification = (
                "obsolete_allow_from"
            )

        else:

            classification = (
                "invalid_or_unknown"
            )

        parsed.append(
            {
                "raw": raw_value,
                "normalized": normalized,
                "classification": classification,
            }
        )

    return {
        "headers": values,
        "parsed": parsed,
    }


# ============================================================================
# Frame-policy evaluation
# ============================================================================

def _evaluate_csp_frame_ancestors(
    csp_info: dict[str, Any],
) -> dict[str, Any]:

    directives = csp_info[
        "enforced_frame_ancestors"
    ]

    if not directives:

        return {
            "present": False,
            "classification": (
                "not_present"
            ),
            "effective": False,
            "allows_everyone": False,
            "values": [],
            "reason": (
                "No enforced frame-ancestors "
                "directive was observed."
            ),
        }

    # Multiple enforced policies should not simply be collapsed into one.
    #
    # For automated classification, any policy containing a restrictive
    # frame-ancestors directive is useful evidence, while conflicting
    # policies are surfaced for review.
    all_values = [
        tuple(item["values"])
        for item in directives
    ]

    unique_value_sets = {
        values
        for values in all_values
    }

    # Determine whether ANY policy explicitly allows everyone.
    allows_everyone = any(
        "*" in item["values"]
        for item in directives
    )

    restrictive_none = any(
        "'none'" in {
            value.lower()
            for value in item["values"]
        }
        for item in directives
    )

    restrictive_self = any(
        "'self'" in {
            value.lower()
            for value in item["values"]
        }
        and "*" not in {
            value.lower()
            for value in item["values"]
        }
        for item in directives
    )

    if allows_everyone:

        return {
            "present": True,
            "classification": (
                "unrestricted"
            ),
            "effective": True,
            "allows_everyone": True,
            "values": [
                item["values"]
                for item in directives
            ],
            "conflicting_policy_count": (
                len(unique_value_sets)
            ),
            "reason": (
                "At least one enforced "
                "frame-ancestors policy allows "
                "all framing sources."
            ),
        }

    if restrictive_none:

        return {
            "present": True,
            "classification": (
                "deny_all"
            ),
            "effective": True,
            "allows_everyone": False,
            "values": [
                item["values"]
                for item in directives
            ],
            "conflicting_policy_count": (
                len(unique_value_sets)
            ),
            "reason": (
                "At least one enforced "
                "frame-ancestors policy uses "
                "'none'."
            ),
        }

    if restrictive_self:

        return {
            "present": True,
            "classification": (
                "same_origin"
            ),
            "effective": True,
            "allows_everyone": False,
            "values": [
                item["values"]
                for item in directives
            ],
            "conflicting_policy_count": (
                len(unique_value_sets)
            ),
            "reason": (
                "The enforced frame-ancestors "
                "policy restricts embedding rather "
                "than allowing arbitrary origins."
            ),
        }

    # Explicit host/scheme allowlists.
    explicit_values = [
        value
        for item in directives
        for value in item["values"]
    ]

    return {
        "present": True,
        "classification": (
            "restricted_allowlist"
        ),
        "effective": True,
        "allows_everyone": False,
        "values": [
            item["values"]
            for item in directives
        ],
        "explicit_sources": explicit_values,
        "conflicting_policy_count": (
            len(unique_value_sets)
        ),
        "reason": (
            "The enforced frame-ancestors "
            "policy restricts embedding to explicit "
            "source expressions."
        ),
    }


def _evaluate_xfo(
    xfo_info: dict[str, Any],
) -> dict[str, Any]:

    parsed = xfo_info[
        "parsed"
    ]

    if not parsed:

        return {
            "present": False,
            "classification": (
                "not_present"
            ),
            "effective": False,
            "restrictive": False,
        }

    restrictive = [
        item
        for item in parsed
        if item["classification"]
        == "effective_restrictive"
    ]

    obsolete = [
        item
        for item in parsed
        if item["classification"]
        == "obsolete_allow_from"
    ]

    invalid = [
        item
        for item in parsed
        if item["classification"]
        == "invalid_or_unknown"
    ]

    if restrictive and not obsolete and not invalid:

        # More than one different restrictive value is ambiguous.
        normalized_values = {
            item["normalized"].upper()
            for item in restrictive
        }

        if len(normalized_values) > 1:

            return {
                "present": True,
                "classification": (
                    "conflicting_restrictive"
                ),
                "effective": False,
                "restrictive": True,
            }

        return {
            "present": True,
            "classification": (
                "restrictive"
            ),
            "effective": True,
            "restrictive": True,
            "value": next(
                iter(
                    normalized_values
                )
            ),
        }

    if obsolete:

        return {
            "present": True,
            "classification": (
                "obsolete_allow_from"
            ),
            "effective": False,
            "restrictive": False,
            "values": [
                item["normalized"]
                for item in obsolete
            ],
        }

    return {
        "present": True,
        "classification": (
            "invalid_or_ambiguous"
        ),
        "effective": False,
        "restrictive": False,
        "values": [
            item["normalized"]
            for item in invalid
        ],
    }


# ============================================================================
# HTML/resource analysis
# ============================================================================

def _is_frameable_content_type(
    content_type: str,
) -> bool:

    normalized = (
        content_type or ""
    ).lower()

    if not normalized:
        # Unknown content type: don't exclude the response from analysis.
        return True

    frameable = (
        "text/html",
        "application/xhtml+xml",
        "application/pdf",
        "image/",
    )

    return normalized.startswith(
        frameable
    )


def _extract_meta_frame_policies(
    body: str,
) -> dict[str, Any]:

    meta_policies: list[str] = []

    for match in re.finditer(
        r"""
        <meta\b[^>]*?
        http-equiv\s*=\s*
        ["']?content-security-policy["']?
        [^>]*?
        content\s*=\s*
        ["']([^"']+)["']
        """,
        body,
        flags=re.IGNORECASE | re.VERBOSE,
    ):

        meta_policies.append(
            match.group(1).strip()
        )

    return {
        "count": len(
            meta_policies
        ),
        "policies": meta_policies,
        "frame_ancestors_present": any(
            re.search(
                r"\bframe-ancestors\b",
                policy,
                flags=re.IGNORECASE,
            )
            for policy in meta_policies
        ),
    }


# ============================================================================
# Optional browser test
# ============================================================================

def _browser_framing_test(
    target: str,
    timeout_ms: int = 12_000,
) -> dict[str, Any]:
    """
    Optional browser-based validation.

    This intentionally does not attempt any clickjacking action. It only
    determines whether a target document can be embedded into a page hosted
    on a different origin.

    A browser implementation/environment may prevent a fully deterministic
    classification, so this is supporting evidence rather than the sole
    source of the final verdict.
    """

    try:
        from playwright.sync_api import (
            Error as PlaywrightError,
            TimeoutError as PlaywrightTimeoutError,
            sync_playwright,
        )
    except ImportError:
        return {
            "available": False,
            "classification": (
                "playwright_not_installed"
            ),
        }

    result_data: dict[str, Any] = {
        "available": True,
        "classification": (
            "not_tested"
        ),
        "target": target,
    }

    try:

        with sync_playwright() as playwright:

            browser = playwright.chromium.launch(
                headless=True
            )

            context = browser.new_context()

            page = context.new_page()

            # Use a data URL / unique local document as the framing page.
            attacker_page = """
            <!doctype html>
            <html>
            <body>
                <iframe
                    id="tc16-frame"
                    src="TARGET_PLACEHOLDER"
                    style="width:800px;height:600px"
                ></iframe>
            </body>
            </html>
            """.replace(
                "TARGET_PLACEHOLDER",
                target.replace(
                    '"',
                    "&quot;",
                ),
            )

            frame_url = (
                "data:text/html,"
                + attacker_page
            )

            blocked = False
            console_messages: list[str] = []

            def on_console(message) -> None:
                try:
                    console_messages.append(
                        message.text[:1000]
                    )
                except Exception:
                    pass

            page.on(
                "console",
                on_console,
            )

            try:
                page.goto(
                    frame_url,
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )

            except PlaywrightTimeoutError:
                result_data[
                    "classification"
                ] = "browser_timeout"

                browser.close()

                return result_data

            frame = page.locator(
                "#tc16-frame"
            )

            try:
                frame.wait_for(
                    state="attached",
                    timeout=3_000,
                )
            except PlaywrightError:
                pass

            # Give browser security checks a short time to settle.
            page.wait_for_timeout(
                min(2_000, timeout_ms)
            )

            # Inspect browser console for well-known framing-block messages.
            security_console = [
                message
                for message in console_messages
                if any(
                    marker in message.lower()
                    for marker in (
                        "refused to display",
                        "frame-ancestors",
                        "x-frame-options",
                        "refused to connect",
                    )
                )
            ]

            if security_console:
                blocked = True

            result_data[
                "console_security_messages"
            ] = security_console[:10]

            # A child frame may disappear or have an unexpected URL when
            # browser framing is denied.
            try:

                child_frames = [
                    child
                    for child in page.frames
                    if child.parent_frame is not None
                ]

                result_data[
                    "child_frame_count"
                ] = len(
                    child_frames
                )

                target_host = (
                    urlparse(
                        target
                    ).netloc
                )

                target_frames = [
                    child
                    for child in child_frames
                    if target_host
                    and target_host.lower()
                    in child.url.lower()
                ]

                result_data[
                    "target_frame_count"
                ] = len(
                    target_frames
                )

            except Exception:
                pass

            if blocked:

                result_data[
                    "classification"
                ] = "browser_blocked"

            elif result_data.get(
                "target_frame_count",
                0,
            ) > 0:

                result_data[
                    "classification"
                ] = "browser_frame_detected"

            else:

                result_data[
                    "classification"
                ] = "inconclusive"

            browser.close()

            return result_data

    except Exception as exc:

        return {
            "available": True,
            "classification": (
                "browser_error"
            ),
            "error_type": type(exc).__name__,
            "error": str(exc)[:1000],
            "target": target,
        }


# ============================================================================
# Main scanner
# ============================================================================

def scan_clickjacking(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
    browser_validate: bool = False,
) -> dict:
    """
    TC16 - Clickjacking

    Checks:
        - X-Frame-Options
        - CSP frame-ancestors
        - CSP Report-Only
        - conflicting/duplicate policies
        - redirects
        - frameable content
        - meta-tag misuse
        - optional browser validation

    Does not attempt actual clickjacking, credential actions, or user
    interaction.
    """

    target = normalize_url(
        url
    )

    details: dict[str, Any] = {
        "target": target,
        "browser_validation_requested": (
            browser_validate
        ),
    }

    # ========================================================================
    # 1. Baseline response
    # ========================================================================

    try:

        response = request(
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

    content_type = response.headers.get(
        "Content-Type",
        "",
    )

    details["response"] = {
        "status_code": response.status_code,
        "requested_url": target,
        "final_url": response.url,
        "content_type": content_type,
        "content_length": response.headers.get(
            "Content-Length",
            "",
        ),
        "redirect_count": len(
            response.history
        ),
        "redirect_chain": [
            {
                "status_code": item.status_code,
                "url": item.url,
                "location": item.headers.get(
                    "Location",
                    "",
                ),
            }
            for item in response.history
        ],
    }

    # ========================================================================
    # 2. If not a usable document response
    # ========================================================================

    if response.status_code in {
        401,
        403,
        404,
        410,
    }:

        # A blocked/missing resource can't be confidently assessed as a
        # publicly frameable application page.
        return result(
            "REVIEW REQUIRED",
            "The tested URL did not return a normal publicly accessible document, so clickjacking protection could not be evaluated conclusively for the target resource.",
            details=details,
        )

    if response.status_code >= 500:

        return result(
            "REVIEW REQUIRED",
            "The target returned a server error, so clickjacking protection could not be evaluated reliably.",
            details=details,
        )

    # ========================================================================
    # 3. CSP
    # ========================================================================

    csp_info = _parse_csp_headers(
        response
    )

    details["csp"] = {
        "enforced_headers": csp_info[
            "enforced_headers"
        ],
        "report_only_headers": csp_info[
            "report_only_headers"
        ],
        "enforced_frame_ancestors": (
            csp_info[
                "enforced_frame_ancestors"
            ]
        ),
        "report_only_frame_ancestors": (
            csp_info[
                "report_only_frame_ancestors"
            ]
        ),
    }

    csp_evaluation = (
        _evaluate_csp_frame_ancestors(
            csp_info
        )
    )

    details[
        "csp_frame_ancestors_evaluation"
    ] = csp_evaluation

    # ========================================================================
    # 4. X-Frame-Options
    # ========================================================================

    xfo_info = _parse_xfo_headers(
        response
    )

    details["x_frame_options"] = (
        xfo_info
    )

    xfo_evaluation = _evaluate_xfo(
        xfo_info
    )

    details[
        "x_frame_options_evaluation"
    ] = xfo_evaluation

    # ========================================================================
    # 5. HTML/meta information
    # ========================================================================

    body = (
        response.text
        or ""
    )[:150_000]

    if (
        "html" in content_type.lower()
        or "<html" in body.lower()
    ):

        meta_frame_policy = (
            _extract_meta_frame_policies(
                body
            )
        )

    else:

        meta_frame_policy = {
            "count": 0,
            "policies": [],
            "frame_ancestors_present": False,
        }

    details[
        "meta_csp"
    ] = meta_frame_policy

    # Important: CSP in a meta element does not implement frame-ancestors.
    # MDN explicitly states that frame-ancestors is not supported in <meta>.
    if meta_frame_policy[
        "frame_ancestors_present"
    ]:

        details[
            "warnings"
        ] = [
            (
                "frame-ancestors was found in a "
                "meta CSP policy; it is not an effective "
                "frame-ancestors enforcement mechanism."
            )
        ]

    # ========================================================================
    # 6. Determine effective protection
    # ========================================================================

    csp_classification = csp_evaluation[
        "classification"
    ]

    xfo_classification = xfo_evaluation[
        "classification"
    ]

    details[
        "effective_protection_analysis"
    ] = {
        "csp_frame_ancestors": (
            csp_classification
        ),
        "x_frame_options": (
            xfo_classification
        ),
    }

    # ========================================================================
    # 7. Optional browser validation
    # ========================================================================

    if browser_validate:

        browser_result = (
            _browser_framing_test(
                response.url or target,
                timeout_ms=int(
                    timeout * 1000
                ),
            )
        )

        details[
            "browser_validation"
        ] = browser_result

    # ========================================================================
    # 8. High-confidence unrestricted framing
    # ========================================================================

    if csp_evaluation[
        "allows_everyone"
    ]:

        return result(
            "UNSAFE",
            "The enforced Content-Security-Policy contains frame-ancestors with an unrestricted '*' source, allowing arbitrary framing origins.",
            details=details,
            evidence=[
                "CSP frame-ancestors contains '*'."
            ],
        )

    # ========================================================================
    # 9. CSP explicitly denies/restricts framing
    # ========================================================================

    if csp_classification in {
        "deny_all",
        "same_origin",
        "restricted_allowlist",
    }:

        # Conflicting policies are worth flagging for review.
        if (
            csp_evaluation.get(
                "conflicting_policy_count",
                1,
            ) > 1
        ):

            return result(
                "REVIEW REQUIRED",
                "An enforced CSP frame-ancestors policy restricts framing, but multiple distinct frame-ancestors policies were observed. Review the combined policy behavior to ensure it matches the intended embedding model.",
                details=details,
                evidence=[
                    (
                        "Multiple enforced "
                        "frame-ancestors policies "
                        "were observed."
                    )
                ],
            )

        return result(
            "SAFE",
            "The tested resource has an enforced CSP frame-ancestors policy that restricts which origins may embed it.",
            details=details,
            evidence=[
                (
                    "CSP frame-ancestors: "
                    + "; ".join(
                        " ".join(
                            item["values"]
                        )
                        for item in csp_info[
                            "enforced_frame_ancestors"
                        ]
                    )
                )
            ],
        )

    # ========================================================================
    # 10. X-Frame-Options protection where CSP doesn't define policy
    # ========================================================================

    if xfo_classification == "restrictive":

        return result(
            "SAFE",
            "The tested resource does not expose an enforced CSP frame-ancestors policy, but it does provide a restrictive X-Frame-Options header.",
            details=details,
            evidence=[
                (
                    "X-Frame-Options: "
                    f"{xfo_evaluation.get('value', '')}"
                )
            ],
        )

    # ========================================================================
    # 11. Obsolete ALLOW-FROM
    # ========================================================================

    if xfo_classification in {
        "obsolete_allow_from",
        "invalid_or_ambiguous",
        "conflicting_restrictive",
    }:

        return result(
            "REVIEW REQUIRED",
            "The target's X-Frame-Options configuration is obsolete, ambiguous, or conflicting and does not provide a clean modern clickjacking protection policy.",
            details=details,
            evidence=[
                (
                    "X-Frame-Options configuration: "
                    + str(
                        xfo_info.get(
                            "headers",
                            [],
                        )
                    )
                )
            ],
        )

    # ========================================================================
    # 12. Report-Only CSP without enforced protection
    # ========================================================================

    if csp_info[
        "report_only_frame_ancestors"
    ]:

        return result(
            "UNSAFE",
            "The response contains only a report-only frame-ancestors policy without an enforced clickjacking protection policy.",
            details=details,
            evidence=[
                (
                    "CSP Report-Only contains "
                    "frame-ancestors, but "
                    "Report-Only policies are not "
                    "enforcement."
                )
            ],
        )

    # ========================================================================
    # 13. No protection
    # ========================================================================

    if (
        not csp_evaluation["present"]
        and not xfo_evaluation["present"]
    ):

        return result(
            "UNSAFE",
            "No effective X-Frame-Options or enforced CSP frame-ancestors policy was identified on the tested resource, so cross-origin framing may be permitted.",
            details=details,
            evidence=[
                "No enforced frame-ancestors directive found.",
                "No effective restrictive X-Frame-Options header found.",
            ],
        )

    # ========================================================================
    # 14. Final conservative review
    # ========================================================================

    return result(
        "REVIEW REQUIRED",
        "The response contains clickjacking-related policy information, but the scanner could not establish a clean effective framing policy with high confidence.",
        details=details,
    )