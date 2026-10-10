from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

from .common import (
    normalize_url,
    request,
    result,
    connection_result,
    looks_like_html,
)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_REDIRECTS = 8
MAX_BODY = 1_000_000
MAX_REFERENCED_RESOURCES = 40

SENSITIVE_COOKIE_NAMES = (
    "session",
    "sess",
    "sid",
    "sessionid",
    "auth",
    "authorization",
    "token",
    "access_token",
    "refresh_token",
    "jwt",
    "id_token",
    "remember",
    "rememberme",
)

HTTP_SENSITIVE_PATH_HINTS = (
    "/login",
    "/signin",
    "/auth",
    "/authenticate",
    "/oauth",
    "/token",
    "/session",
    "/account",
    "/profile",
    "/password",
    "/reset",
    "/checkout",
    "/payment",
    "/admin",
)

ACTIVE_RESOURCE_TAGS = {
    "script": "src",
    "iframe": "src",
    "object": "data",
    "embed": "src",
    "link": "href",
}

FORM_TAG = "form"


# ============================================================
# HTML RESOURCE PARSER
# ============================================================

class HTMLResourceParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()

        self.resources: list[dict[str, str]] = []
        self.forms: list[dict[str, str]] = []
        self.canonicals: list[str] = []
        self.metas: list[dict[str, str]] = []

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:

        tag = tag.lower()
        attributes = {
            str(k).lower(): (v or "")
            for k, v in attrs
        }

        if tag in ACTIVE_RESOURCE_TAGS:

            attribute = ACTIVE_RESOURCE_TAGS[tag]
            value = attributes.get(attribute)

            if value:
                self.resources.append(
                    {
                        "tag": tag,
                        "attribute": attribute,
                        "url": value,
                    }
                )

        elif tag == FORM_TAG:

            action = attributes.get(
                "action",
                "",
            )

            self.forms.append(
                {
                    "action": action,
                    "method": attributes.get(
                        "method",
                        "GET",
                    ).upper(),
                }
            )

        elif tag == "link":

            rel = attributes.get(
                "rel",
                "",
            ).lower()

            href = attributes.get(
                "href",
                "",
            )

            if (
                href
                and "canonical" in rel
            ):
                self.canonicals.append(
                    href
                )

        elif tag == "meta":

            self.metas.append(
                attributes
            )


# ============================================================
# URL HELPERS
# ============================================================

def _replace_scheme(
    url: str,
    scheme: str,
) -> str:
    parsed = urlparse(
        normalize_url(url)
    )

    return parsed._replace(
        scheme=scheme
    ).geturl()


def _is_http_url(
    value: str,
) -> bool:
    return value.lower().startswith(
        "http://"
    )


def _is_https_url(
    value: str,
) -> bool:
    return value.lower().startswith(
        "https://"
    )


def _same_origin(
    base: str,
    candidate: str,
) -> bool:
    a = urlparse(base)
    b = urlparse(candidate)

    return (
        a.scheme.lower() == b.scheme.lower()
        and (a.hostname or "").lower()
        == (b.hostname or "").lower()
        and (a.port or (
            443 if a.scheme == "https" else 80
        )) == (b.port or (
            443 if b.scheme == "https" else 80
        ))
    )


# ============================================================
# COOKIE ANALYSIS
# ============================================================

def _split_set_cookie(header_value: str) -> list[str]:
    """
    Split a combined Set-Cookie header conservatively.

    Avoids splitting on commas that are likely part of an
    Expires attribute.
    """
    if not header_value:
        return []

    cookies = []
    current = []
    in_expires = False

    parts = re.split(r"(,)(?=\s*[^;,=\s]+)", header_value)

    for part in parts:
        if part == ",":
            if in_expires:
                current.append(part)
            else:
                cookie = "".join(current).strip()

                if cookie:
                    cookies.append(cookie)

                current = []
        else:
            current.append(part)

            if re.search(
                r"\bexpires\s*=",
                part,
                re.I,
            ):
                in_expires = True

            if re.search(
                r"\b(?:path|domain|secure|httponly|samesite)\b",
                part,
                re.I,
            ):
                # Keep current state conservative. An Expires value
                # normally ends before the next cookie begins.
                pass

    final_cookie = "".join(current).strip()

    if final_cookie:
        cookies.append(final_cookie)

    return cookies


def _cookie_analysis(
    set_cookie: str,
) -> list[dict[str, Any]]:

    findings: list[dict[str, Any]] = []

    for raw_cookie in _split_set_cookie(
        set_cookie
    ):

        parts = [
            item.strip()
            for item in raw_cookie.split(";")
        ]

        if not parts:
            continue

        name_value = parts[0]

        if "=" not in name_value:
            continue

        cookie_name = (
            name_value.split(
                "=",
                1,
            )[0]
            .strip()
        )

        cookie_name_lower = cookie_name.lower()

        attributes = {
            part.lower()
            for part in parts[1:]
        }

        secure = (
            "secure" in attributes
        )

        httponly = (
            "httponly" in attributes
        )

        samesite = None

        for attribute in parts[1:]:
            if attribute.lower().startswith(
                "samesite="
            ):
                samesite = attribute.split(
                    "=",
                    1,
                )[1].strip().lower()

        sensitive_name = any(
            hint in cookie_name_lower
            for hint in SENSITIVE_COOKIE_NAMES
        )

        findings.append(
            {
                "name": cookie_name,
                "secure": secure,
                "httponly": httponly,
                "samesite": samesite,
                "sensitive_name": sensitive_name,
            }
        )

    return findings


# ============================================================
# APPLICATION CONTENT DETECTION
# ============================================================

def _looks_like_application(
    response,
) -> bool:

    if looks_like_html(
        response
    ):
        return bool(
            (response.text or "").strip()
        )

    content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
        .lower()
    )

    if any(
        token in content_type
        for token in (
            "application/json",
            "application/xml",
            "application/javascript",
            "text/plain",
        )
    ):
        return bool(
            (response.text or "").strip()
        )

    # Successful binary data can still be a legitimate
    # application resource.
    return (
        response.status_code in range(200, 300)
        and bool(
            response.content
        )
    )


# ============================================================
# RESPONSE SNAPSHOT
# ============================================================

def _snapshot(
    response,
) -> dict[str, Any]:

    return {
        "status_code": response.status_code,
        "url": getattr(
            response,
            "url",
            "",
        ),
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "content_length": len(
            response.content or b""
        ),
        "server": response.headers.get(
            "Server",
            "",
        ),
        "location": response.headers.get(
            "Location",
            "",
        ),
        "hsts": response.headers.get(
            "Strict-Transport-Security",
            "",
        ),
        "set_cookie": response.headers.get(
            "Set-Cookie",
            "",
        ),
        "cache_control": response.headers.get(
            "Cache-Control",
            "",
        ),
        "served_application_content": (
            _looks_like_application(
                response
            )
        ),
    }


# ============================================================
# REDIRECT CHAIN
# ============================================================

def _inspect_redirect_chain(
    start_url: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> tuple[dict[str, Any], list[str]]:

    current = start_url
    visited: set[str] = set()

    chain: list[dict[str, Any]] = []
    evidence: list[str] = []

    for hop in range(
        MAX_REDIRECTS + 1
    ):

        if current in visited:

            chain.append(
                {
                    "url": current,
                    "error": "redirect_loop_detected",
                }
            )

            return (
                {
                    "chain": chain,
                    "final_url": current,
                    "final_scheme": urlparse(
                        current
                    ).scheme.lower(),
                    "loop": True,
                    "response": None,
                },
                evidence,
            )

        visited.add(current)

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
                max_body=MAX_BODY,
            )

        except Exception as exc:

            chain.append(
                {
                    "url": current,
                    "error": str(exc),
                }
            )

            return (
                {
                    "chain": chain,
                    "final_url": current,
                    "final_scheme": urlparse(
                        current
                    ).scheme.lower(),
                    "loop": False,
                    "response": None,
                },
                evidence,
            )

        item = _snapshot(
            response
        )

        item["url"] = current
        item["hop"] = hop

        chain.append(
            item
        )

        status = (
            response.status_code
        )

        location = (
            response.headers.get(
                "Location",
                "",
            )
            .strip()
        )

        if (
            300 <= status < 400
            and location
        ):

            next_url = urljoin(
                current,
                location,
            )

            if next_url in visited:
                continue

            current = next_url
            continue

        if (
            300 <= status < 400
            and not location
        ):

            evidence.append(
                f"HTTP {status} returned without Location"
            )

        return (
            {
                "chain": chain,
                "final_url": current,
                "final_scheme": urlparse(
                    current
                ).scheme.lower(),
                "loop": False,
                "response": response,
            },
            evidence,
        )

    evidence.append(
        "Maximum redirect depth reached."
    )

    return (
        {
            "chain": chain,
            "final_url": current,
            "final_scheme": urlparse(
                current
            ).scheme.lower(),
            "loop": False,
            "response": None,
        },
        evidence,
    )


# ============================================================
# HTTP CONTENT / PAGE ANALYSIS
# ============================================================

def _analyze_http_content(
    *,
    http_url: str,
    response,
) -> dict[str, Any]:

    output: dict[str, Any] = {
        "http_resource": [],
        "http_forms": [],
        "http_canonicals": [],
        "http_mixed_content": [],
        "sensitive_http_paths": [],
    }

    body = response.text or ""

    content_type = (
        response.headers.get(
            "Content-Type",
            "",
        )
        .lower()
    )

    if (
        "html" not in content_type
        and "<html" not in body.lower()
        and "<form" not in body.lower()
    ):
        return output

    parser = HTMLResourceParser()

    try:
        parser.feed(
            body
        )
    except Exception:
        return output

    page_origin = http_url

    # --------------------------------------------------------
    # Referenced resources
    # --------------------------------------------------------

    for resource in parser.resources[
        :MAX_REFERENCED_RESOURCES
    ]:

        raw = resource["url"]

        absolute = urljoin(
            page_origin,
            raw,
        )

        parsed = urlparse(
            absolute
        )

        if (
            parsed.scheme.lower()
            == "http"
        ):

            output[
                "http_mixed_content"
            ].append(
                {
                    "tag": resource["tag"],
                    "url": absolute,
                }
            )

        output[
            "http_resource"
        ].append(
            {
                "tag": resource["tag"],
                "url": absolute,
                "scheme": parsed.scheme,
            }
        )

    # --------------------------------------------------------
    # Forms
    # --------------------------------------------------------

    for form in parser.forms[
        :MAX_REFERENCED_RESOURCES
    ]:

        action = form[
            "action"
        ]

        absolute = urljoin(
            page_origin,
            action or page_origin,
        )

        if _is_http_url(
            absolute
        ):

            output[
                "http_forms"
            ].append(
                {
                    "method": form[
                        "method"
                    ],
                    "action": absolute,
                }
            )

    # --------------------------------------------------------
    # Canonical links
    # --------------------------------------------------------

    for canonical in parser.canonicals:

        absolute = urljoin(
            page_origin,
            canonical,
        )

        if _is_http_url(
            absolute
        ):

            output[
                "http_canonicals"
            ].append(
                absolute
            )

    # --------------------------------------------------------
    # Sensitive-looking endpoint
    # --------------------------------------------------------

    parsed_page = urlparse(
        http_url
    )

    path = (
        parsed_page.path
        or "/"
    ).lower()

    for hint in HTTP_SENSITIVE_PATH_HINTS:

        if (
            hint in path
        ):

            output[
                "sensitive_http_paths"
            ].append(
                hint
            )

    return output


# ============================================================
# HTTPS COMPARISON
# ============================================================

def _compare_http_https(
    http_response,
    https_response,
) -> dict[str, Any]:

    if (
        http_response is None
        or https_response is None
    ):
        return {
            "comparable": False
        }

    http_type = (
        http_response.headers.get(
            "Content-Type",
            "",
        )
        .split(";")[0]
        .strip()
        .lower()
    )

    https_type = (
        https_response.headers.get(
            "Content-Type",
            "",
        )
        .split(";")[0]
        .strip()
        .lower()
    )

    http_body = (
        http_response.text or ""
    )

    https_body = (
        https_response.text or ""
    )

    return {
        "comparable": True,

        "status_equal": (
            http_response.status_code
            == https_response.status_code
        ),

        "content_type_equal": (
            http_type == https_type
        ),

        "same_body": (
            http_body[:100_000]
            == https_body[:100_000]
        ),

        "http_status": (
            http_response.status_code
        ),

        "https_status": (
            https_response.status_code
        ),

        "http_content_type": http_type,

        "https_content_type": https_type,
    }


# ============================================================
# MAIN SCANNER
# ============================================================

def scan_application_running_on_http(
    url: str,
    verify_tls: bool = True,
    timeout: float = 10.0,
) -> dict:

    base = normalize_url(
        url
    )

    parsed = urlparse(
        base
    )

    if (
        parsed.scheme.lower()
        not in {
            "http",
            "https",
        }
        or not parsed.netloc
    ):

        return result(
            "INCOMPLETE",
            (
                "The supplied target URL is invalid, "
                "so HTTP exposure could not be assessed."
            ),
            details={
                "target": base
            },
        )

    input_scheme = (
        parsed.scheme.lower()
    )

    http_url = _replace_scheme(
        base,
        "http",
    )

    https_url = _replace_scheme(
        base,
        "https",
    )

    details: dict[str, Any] = {

        "target": base,

        "input_scheme": input_scheme,

        "http_url_tested": http_url,

        "https_url_tested": https_url,

        "http_redirect_chain": [],

        "https_check": None,

        "http_cookie_analysis": [],

        "http_content_analysis": {},

        "http_https_comparison": {},

        "findings": [],
    }

    evidence: list[str] = []

    # ========================================================
    # HTTP
    # ========================================================

    try:

        http_info, chain_notes = (
            _inspect_redirect_chain(
                http_url,
                timeout=timeout,
                verify_tls=verify_tls,
            )
        )

    except Exception as exc:

        return connection_result(
            exc,
            target=http_url,
        )

    details[
        "http_redirect_chain"
    ] = http_info[
        "chain"
    ]

    details[
        "http_final_url"
    ] = http_info[
        "final_url"
    ]

    details[
        "http_final_scheme"
    ] = http_info[
        "final_scheme"
    ]

    details[
        "redirect_loop"
    ] = http_info[
        "loop"
    ]

    evidence.extend(
        chain_notes
    )

    chain = http_info[
        "chain"
    ]

    if not chain:

        return result(
            "INCOMPLETE",
            (
                "No HTTP response was obtained, "
                "so HTTP enforcement could not "
                "be reliably assessed."
            ),
            details=details,
            evidence=evidence,
        )

    first = chain[0]

    first_status = int(
        first.get(
            "status_code",
            0,
        )
        or 0
    )

    final_scheme = (
        http_info[
            "final_scheme"
        ]
        or ""
    ).lower()

    final_response = http_info.get(
        "response"
    )

    first_application = bool(
        first.get(
            "served_application_content"
        )
    )

    final_application = bool(
        chain[-1].get(
            "served_application_content"
        )
    )

    # ========================================================
    # COOKIE ANALYSIS
    # ========================================================

    set_cookie = (
        first.get(
            "set_cookie"
        )
        or ""
    )

    cookie_results = _cookie_analysis(
        set_cookie
    )

    details[
        "http_cookie_analysis"
    ] = cookie_results

    weak_http_cookies = [
        cookie
        for cookie in cookie_results
        if not cookie["secure"]
    ]

    sensitive_weak_http_cookies = [
        cookie
        for cookie in weak_http_cookies
        if cookie["sensitive_name"]
    ]

    # ========================================================
    # HTTP CONTENT ANALYSIS
    # ========================================================

    if (
        final_response is not None
        and final_scheme == "http"
    ):

        details[
            "http_content_analysis"
        ] = _analyze_http_content(
            http_url=http_url,
            response=final_response,
        )

    # ========================================================
    # FINDING: REDIRECT TO HTTPS
    # ========================================================

    if final_scheme == "https":

        # HTTPS enforcement succeeded.
        details[
            "https_enforced_by_redirect"
        ] = True

        if input_scheme == "https":
            return result(
                "SAFE",
                (
                    "The HTTP counterpart redirects to HTTPS "
                    "before the application is ultimately served."
                ),
                details=details,
                evidence=[
                    f"HTTP endpoint: {http_url}",
                    (
                        "HTTP redirect chain terminates at HTTPS: "
                        f"{http_info['final_url']}"
                    ),
                ],
            )

        # If the operator supplied HTTP, still analyze the
        # counterpart below when useful.
        evidence.append(
            "HTTP is redirected to HTTPS."
        )

    # ========================================================
    # FINDING: HTTP REDIRECT LOOP
    # ========================================================

    if http_info["loop"]:

        details[
            "findings"
        ].append(
            "HTTP redirect loop"
        )

        return result(
            "REVIEW REQUIRED",
            (
                "The HTTP endpoint contains a redirect loop, "
                "so HTTPS enforcement could not be reliably "
                "confirmed."
            ),
            details=details,
            evidence=[
                "Redirect loop detected."
            ],
        )

    # ========================================================
    # FINDING: DIRECT HTTP APPLICATION CONTENT
    # ========================================================

    if (
        final_scheme == "http"
        and final_application
    ):

        details[
            "findings"
        ].append(
            "application_served_over_http"
        )

        evidence.append(
            (
                "Application content was served from the "
                f"HTTP endpoint: {http_info['final_url']}"
            )
        )

        # Continue collecting additional evidence instead
        # of immediately returning.

    elif (
        200 <= first_status < 300
        and first_application
        and final_scheme == "http"
    ):

        details[
            "findings"
        ].append(
            "application_served_directly_over_http"
        )

        evidence.append(
            (
                f"HTTP {first_status} returned application "
                "content directly."
            )
        )

    # ========================================================
    # COOKIE FINDINGS
    # ========================================================

    if sensitive_weak_http_cookies:

        details[
            "findings"
        ].append(
            "sensitive_cookie_without_secure"
        )

        evidence.append(
            (
                "One or more session/authentication-like "
                "cookies were returned without the Secure "
                "attribute over HTTP."
            )
        )

    elif weak_http_cookies:

        details[
            "findings"
        ].append(
            "cookie_without_secure"
        )

        evidence.append(
            (
                "One or more cookies were returned over "
                "HTTP without the Secure attribute."
            )
        )

    # ========================================================
    # AUTH CHALLENGE OVER HTTP
    # ========================================================

    if (
        final_response is not None
        and final_scheme == "http"
    ):

        www_authenticate = (
            final_response.headers.get(
                "WWW-Authenticate",
                "",
            )
        )

        if (
            "basic" in
            www_authenticate.lower()
        ):

            details[
                "findings"
            ].append(
                "basic_auth_over_http"
            )

            evidence.append(
                (
                    "The HTTP response exposes a Basic "
                    "Authentication challenge."
                )
            )

    # ========================================================
    # SENSITIVE HTTP PATH
    # ========================================================

    content_analysis = details.get(
        "http_content_analysis",
        {},
    )

    sensitive_paths = content_analysis.get(
        "sensitive_http_paths",
        [],
    )

    if sensitive_paths:

        details[
            "sensitive_http_path"
        ] = True

        evidence.append(
            (
                "The tested HTTP URL appears related to a "
                "sensitive endpoint: "
                + ", ".join(
                    sensitive_paths
                )
            )
        )

        # Serving such a sensitive route over HTTP is
        # stronger evidence than an ordinary public page.
        if (
            final_scheme == "http"
            and final_application
        ):
            details[
                "findings"
            ].append(
                "sensitive_application_route_over_http"
            )

    # ========================================================
    # HTTP PAGE SELF-REFERENCES
    # ========================================================

    mixed_content = content_analysis.get(
        "http_mixed_content",
        [],
    )

    http_forms = content_analysis.get(
        "http_forms",
        [],
    )

    http_canonicals = content_analysis.get(
        "http_canonicals",
        [],
    )

    details[
        "http_mixed_content"
    ] = mixed_content

    details[
        "http_forms"
    ] = http_forms

    details[
        "http_canonicals"
    ] = http_canonicals

    if mixed_content:

        details[
            "findings"
        ].append(
            "http_page_references_http_resources"
        )

        evidence.append(
            (
                "The HTTP document references one or more "
                "resources using HTTP URLs."
            )
        )

    if http_forms:

        details[
            "findings"
        ].append(
            "form_submits_over_http"
        )

        evidence.append(
            (
                "The HTTP page contains form actions "
                "targeting HTTP URLs."
            )
        )

    if http_canonicals:

        details[
            "findings"
        ].append(
            "http_canonical_reference"
        )

    # ========================================================
    # HTTPS COUNTERPART
    # ========================================================

    try:

        https_response = request(
            https_url,
            timeout=timeout,
            verify_tls=verify_tls,
            allow_redirects=True,
            max_body=MAX_BODY,
        )

        details[
            "https_check"
        ] = {
            "reachable": True,
            "status_code": (
                https_response.status_code
            ),
            "final_url": getattr(
                https_response,
                "url",
                https_url,
            ),
            "content_type": (
                https_response.headers.get(
                    "Content-Type",
                    "",
                )
            ),
            "hsts": (
                https_response.headers.get(
                    "Strict-Transport-Security",
                    "",
                )
            ),
            "served_application_content": (
                _looks_like_application(
                    https_response
                )
            ),
        }

        details[
            "http_https_comparison"
        ] = _compare_http_https(
            final_response
            if final_response is not None
            and final_scheme == "http"
            else None,
            https_response,
        )

    except Exception as exc:

        details[
            "https_check"
        ] = {
            "reachable": False,
            "error": str(exc),
        }

    # ========================================================
    # HTTPS AVAILABILITY
    # ========================================================

    https_info = details[
        "https_check"
    ]

    if (
        https_info
        and https_info.get(
            "reachable"
        )
    ):

        if (
            not https_info.get(
                "hsts"
            )
        ):

            details[
                "findings"
            ].append(
                "https_missing_hsts"
            )

            evidence.append(
                (
                    "HTTPS was reachable but did not return "
                    "a Strict-Transport-Security header. "
                    "This is related transport-hardening evidence; "
                    "HSTS itself is assessed separately by TC18."
                )
            )

    # ========================================================
    # CLASSIFY
    # ========================================================

    findings = details[
        "findings"
    ]

    # Strong finding:
    # actual application exposed over HTTP.
    if any(
        item in findings
        for item in (
            "application_served_over_http",
            "application_served_directly_over_http",
        )
    ):

        return result(
            "UNSAFE",
            (
                "The application is accessible over unencrypted "
                "HTTP instead of being consistently enforced over HTTPS."
            ),
            details=details,
            evidence=evidence,
        )

    # Sensitive cookie over HTTP.
    if (
        "sensitive_cookie_without_secure"
        in findings
    ):

        return result(
            "UNSAFE",
            (
                "A sensitive/session-like cookie was returned "
                "over HTTP without the Secure attribute."
            ),
            details=details,
            evidence=evidence,
        )

    # HTTP remains available but isn't clearly serving
    # application content.
    if (
        final_scheme == "http"
        and (
            http_forms
            or mixed_content
            or sensitive_paths
        )
    ):

        return result(
            "REVIEW REQUIRED",
            (
                "The HTTP endpoint remains accessible and "
                "contains security-relevant HTTP references, "
                "but direct application exposure could not "
                "be established with high confidence."
            ),
            details=details,
            evidence=evidence,
        )

    if (
        weak_http_cookies
    ):

        return result(
            "REVIEW REQUIRED",
            (
                "Cookies were returned over HTTP without "
                "the Secure attribute, but they were not "
                "identified as clearly session/authentication "
                "cookies."
            ),
            details=details,
            evidence=evidence,
        )

    if (
        first_status in {
            401,
            403,
        }
        and final_scheme == "http"
    ):

        return result(
            "REVIEW REQUIRED",
            (
                f"The HTTP endpoint returned HTTP {first_status} "
                "without clearly enforcing HTTPS. Access was "
                "blocked, so application exposure could not "
                "be conclusively established."
            ),
            details=details,
            evidence=evidence,
        )

    if (
        first_status in {
            404,
            410,
        }
        and final_scheme == "http"
    ):

        return result(
            "REVIEW REQUIRED",
            (
                "The HTTP endpoint did not expose the requested "
                "resource, so HTTPS enforcement could not be "
                "confirmed from this URL alone."
            ),
            details=details,
            evidence=evidence,
        )

    if (
        first_status >= 500
        and final_scheme == "http"
    ):

        return result(
            "REVIEW REQUIRED",
            (
                "The HTTP endpoint returned a server-side error "
                "without clearly enforcing HTTPS."
            ),
            details=details,
            evidence=evidence,
        )

    if (
        final_scheme == "https"
    ):

        return result(
            "SAFE",
            (
                "The HTTP endpoint redirects to HTTPS before "
                "the application is ultimately served."
            ),
            details=details,
            evidence=evidence,
        )

    # Default uncertain state.
    return result(
        "REVIEW REQUIRED",
        (
            "The HTTP endpoint responded, but the scanner "
            "could not conclusively determine whether "
            "unencrypted application access is possible."
        ),
        details=details,
        evidence=evidence,
    )