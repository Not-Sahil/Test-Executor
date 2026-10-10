from __future__ import annotations

import re
from html import unescape
from urllib.parse import urljoin, urlparse

from .common import (
    normalize_url,
    request,
    result,
    connection_result,
)


# ---------------------------------------------------------------------------
# Default-page signatures
# ---------------------------------------------------------------------------
#
# These are deliberately specific. A generic word such as "welcome" is not
# sufficient to declare a default server page.
#
# Each server has:
#   - strong markers: highly characteristic phrases
#   - title markers: useful supporting indicators
#   - asset/path markers: useful supporting indicators
#
# The scanner combines multiple indicators before declaring UNSAFE.
# ---------------------------------------------------------------------------

DEFAULT_PAGE_SIGNATURES: dict[str, dict[str, tuple[str, ...]]] = {
    "apache": {
        "strong": (
            "apache2 debian default page",
            "apache http server test page",
            "it works! apache",
            "it works! the apache http server",
            "apache2 ubuntu default page",
        ),
        "title": (
            "apache2 debian default page",
            "apache http server test page",
            "it works!",
        ),
        "asset": (
            "/icons/apache_pb2.gif",
            "/apache2-default/",
        ),
    },
    "nginx": {
        "strong": (
            "welcome to nginx!",
            "welcome to nginx",
            "if you see this page, the nginx web server is successfully installed",
        ),
        "title": (
            "welcome to nginx!",
            "welcome to nginx",
        ),
        "asset": (
            "/nginx-logo.png",
            "/poweredby.png",
        ),
    },
    "iis": {
        "strong": (
            "internet information services",
            "iis windows server",
            "iis windows server default",
        ),
        "title": (
            "internet information services",
            "iis",
        ),
        "asset": (
            "/iisstart.htm",
            "/iisstart.png",
        ),
    },
    "tomcat": {
        "strong": (
            "if you're seeing this, you've successfully installed tomcat",
            "if you're seeing this, you've successfully installed apache tomcat",
            "apache tomcat welcome",
        ),
        "title": (
            "apache tomcat",
            "tomcat",
        ),
        "asset": (
            "/tomcat.svg",
            "/tomcat.css",
        ),
    },
    "jetty": {
        "strong": (
            "powered by jetty",
            "jetty default",
            "welcome to jetty",
        ),
        "title": (
            "jetty",
        ),
        "asset": (
            "/jetty.css",
        ),
    },
    "lighttpd": {
        "strong": (
            "lighttpd test page",
            "powered by lighttpd",
        ),
        "title": (
            "lighttpd",
        ),
        "asset": (),
    },
    "caddy": {
        "strong": (
            "welcome to caddy",
            "caddy works",
        ),
        "title": (
            "welcome to caddy",
        ),
        "asset": (),
    },
    "openlitespeed": {
        "strong": (
            "openlitespeed",
            "congratulations! you have successfully installed openlitespeed",
            "welcome to openlitespeed",
        ),
        "title": (
            "openlitespeed",
        ),
        "asset": (),
    },
}


# ---------------------------------------------------------------------------
# Generic indicators
# ---------------------------------------------------------------------------

GENERIC_DEFAULT_INDICATORS = (
    "this is the default page",
    "default web page",
    "test page",
    "test server",
    "server test page",
    "welcome to your web server",
    "welcome to the web server",
    "installation successful",
    "successfully installed",
    "web server is successfully installed",
)


# Phrases that commonly indicate a real application rather than a generic
# server landing page.
#
# These are supporting signals only; they should not by themselves prove that
# a site is safe.
APPLICATION_INDICATORS = (
    "sign in",
    "sign up",
    "login",
    "log in",
    "dashboard",
    "checkout",
    "cart",
    "products",
    "pricing",
    "contact us",
    "about us",
    "my account",
    "forgot password",
)


# ---------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------

def _extract_title(body: str) -> str:
    match = re.search(
        r"<title\b[^>]*>(.*?)</title>",
        body,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if not match:
        return ""

    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:300]


def _visible_text(body: str) -> str:
    """
    Produce a lightweight text representation of HTML.

    This is intentionally not a full HTML parser because the scanner only
    needs broad page-content indicators.
    """
    text = re.sub(
        r"(?is)<(script|style|noscript|template).*?>.*?</\1>",
        " ",
        body,
    )

    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = unescape(text)
    text = re.sub(r"\s+", " ", text).strip()

    return text[:250_000]


def _same_origin(base_url: str, candidate_url: str) -> bool:
    try:
        base = urlparse(base_url)
        candidate = urlparse(candidate_url)

        return (
            candidate.scheme in {"http", "https"}
            and candidate.hostname is not None
            and base.hostname is not None
            and candidate.hostname.lower() == base.hostname.lower()
        )
    except Exception:
        return False


def _content_type_is_html(content_type: str) -> bool:
    content_type = content_type.lower()

    return (
        "text/html" in content_type
        or "application/xhtml+xml" in content_type
        or content_type == ""
    )


# ---------------------------------------------------------------------------
# Signature analysis
# ---------------------------------------------------------------------------

def _analyse_signature(
    server_name: str,
    body_lower: str,
    title_lower: str,
) -> dict:
    signature = DEFAULT_PAGE_SIGNATURES[server_name]

    strong_matches = [
        marker
        for marker in signature["strong"]
        if marker in body_lower
    ]

    title_matches = [
        marker
        for marker in signature["title"]
        if marker in title_lower
    ]

    asset_matches = [
        marker
        for marker in signature["asset"]
        if marker in body_lower
    ]

    return {
        "strong_matches": strong_matches,
        "title_matches": title_matches,
        "asset_matches": asset_matches,
    }


def _detect_default_page(
    *,
    body: str,
    title: str,
    server_header: str,
) -> dict:
    body_lower = body.lower()
    title_lower = title.lower()
    server_lower = server_header.lower()

    findings: list[dict] = []

    # ------------------------------------------------------------------
    # Server-specific analysis
    # ------------------------------------------------------------------

    for server_name in DEFAULT_PAGE_SIGNATURES:
        analysis = _analyse_signature(
            server_name,
            body_lower,
            title_lower,
        )

        strong = analysis["strong_matches"]
        title_matches = analysis["title_matches"]
        asset_matches = analysis["asset_matches"]

        if not strong and not title_matches and not asset_matches:
            continue

        server_header_matches = server_name in server_lower

        # High-confidence case:
        #
        # A strong page signature is already enough to strongly suspect a
        # default installation page. We record all supporting indicators.
        if strong:
            confidence = "high"

        # Medium confidence:
        #
        # Title + server identity, or multiple supporting indicators.
        elif (
            len(title_matches) >= 1
            and server_header_matches
        ) or (
            len(title_matches) + len(asset_matches) >= 2
        ):
            confidence = "medium"

        else:
            confidence = "low"

        findings.append(
            {
                "server_type": server_name,
                "confidence": confidence,
                "strong_matches": strong,
                "title_matches": title_matches,
                "asset_matches": asset_matches,
                "server_header_matches": server_header_matches,
            }
        )

    # ------------------------------------------------------------------
    # Generic indicators
    # ------------------------------------------------------------------

    generic_matches = [
        marker
        for marker in GENERIC_DEFAULT_INDICATORS
        if marker in body_lower
    ]

    return {
        "server_specific": findings,
        "generic_matches": generic_matches,
    }


# ---------------------------------------------------------------------------
# Application-content detection
# ---------------------------------------------------------------------------

def _detect_application_indicators(
    body: str,
    title: str,
) -> list[str]:
    combined = f"{title} {body}".lower()

    return [
        indicator
        for indicator in APPLICATION_INDICATORS
        if indicator in combined
    ]


# ---------------------------------------------------------------------------
# Redirect analysis
# ---------------------------------------------------------------------------

def _analyse_redirect_history(response) -> list[dict]:
    history: list[dict] = []

    for previous in response.history:
        history.append(
            {
                "status_code": previous.status_code,
                "url": previous.url,
                "location": previous.headers.get("Location", ""),
            }
        )

    return history


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan_default_server_page(
    url: str,
    verify_tls: bool = True,
    timeout: float = 12.0,
) -> dict:
    """
    TC05 - Default Server Page

    Determine whether the target is exposing a generic/default web-server
    installation landing page instead of the intended application.

    This testcase intentionally does NOT perform directory brute forcing or
    arbitrary file discovery. Those belong to other testcases such as
    sensitive-file exposure and directory enumeration.
    """

    target = normalize_url(url)

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

    body = response.text or ""

    # Limit analysis to a reasonable amount of data.
    analysis_body = body[:250_000]

    title = _extract_title(analysis_body)

    server_header = response.headers.get("Server", "")
    powered_by = response.headers.get("X-Powered-By", "")
    content_type = response.headers.get("Content-Type", "")

    final_url = response.url or target

    redirect_history = _analyse_redirect_history(response)

    details: dict = {
        "requested_url": target,
        "final_url": final_url,
        "status_code": response.status_code,
        "content_type": content_type,
        "server": server_header,
        "x_powered_by": powered_by,
        "title": title,
        "content_length": len(body),
        "redirect_count": len(response.history),
        "redirect_history": redirect_history,
    }

    # ------------------------------------------------------------------
    # HTTP status handling
    # ------------------------------------------------------------------

    if response.status_code in {404, 410}:
        return result(
            "SAFE",
            "The target root returned a not-found response; no publicly reachable default server landing page was identified.",
            details=details,
        )

    if response.status_code in {401, 403}:
        return result(
            "SAFE",
            "The target root is access-controlled and did not expose a default server landing page.",
            details=details,
        )

    if response.status_code in {301, 302, 303, 307, 308}:
        # Normally requests with allow_redirects=True should end on another
        # response. This branch is defensive.
        return result(
            "REVIEW REQUIRED",
            "The target returned a redirect that could not be evaluated as a final application response.",
            details=details,
        )

    if response.status_code >= 500:
        return result(
            "REVIEW REQUIRED",
            f"The target returned HTTP {response.status_code}; a default server page could not be classified reliably.",
            details=details,
        )

    if not (200 <= response.status_code < 300):
        return result(
            "REVIEW REQUIRED",
            f"The target returned HTTP {response.status_code}; the default-server-page condition could not be evaluated confidently.",
            details=details,
        )

    # ------------------------------------------------------------------
    # Content type
    # ------------------------------------------------------------------

    html_response = _content_type_is_html(content_type)

    details["is_html_response"] = html_response

    # A PDF/image/JSON/etc. at the root is not normally a generic web-server
    # landing page.
    if not html_response:
        return result(
            "SAFE",
            "The target root did not return an HTML document, so no generic default web-server landing page was identified.",
            details=details,
        )

    # ------------------------------------------------------------------
    # Signature detection
    # ------------------------------------------------------------------

    detection = _detect_default_page(
        body=analysis_body,
        title=title,
        server_header=server_header,
    )

    details["server_specific_signatures"] = detection["server_specific"]
    details["generic_default_indicators"] = detection["generic_matches"]

    # ------------------------------------------------------------------
    # Application indicators
    # ------------------------------------------------------------------

    application_indicators = _detect_application_indicators(
        analysis_body,
        title,
    )

    details["application_indicators"] = application_indicators

    # ------------------------------------------------------------------
    # Strong evidence
    # ------------------------------------------------------------------

    high_confidence = [
        finding
        for finding in detection["server_specific"]
        if finding["confidence"] == "high"
    ]

    if high_confidence:
        evidence: list[str] = []

        for finding in high_confidence:
            server_name = finding["server_type"]

            if finding["strong_matches"]:
                evidence.append(
                    f"{server_name} default-page marker matched: "
                    f"{', '.join(finding['strong_matches'][:5])}"
                )

            if finding["title_matches"]:
                evidence.append(
                    f"{server_name} default-page title marker matched: "
                    f"{', '.join(finding['title_matches'][:5])}"
                )

            if finding["server_header_matches"]:
                evidence.append(
                    f"Server header is consistent with {server_name}."
                )

            if finding["asset_matches"]:
                evidence.append(
                    f"{server_name} default-page asset/path marker matched: "
                    f"{', '.join(finding['asset_matches'][:5])}"
                )

        return result(
            "UNSAFE",
            "A recognizable generic/default web-server landing page is publicly reachable at the target root, indicating that the intended application may not be deployed or that the server is still using its default installation page.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Medium-confidence case
    # ------------------------------------------------------------------

    medium_confidence = [
        finding
        for finding in detection["server_specific"]
        if finding["confidence"] == "medium"
    ]

    if medium_confidence:
        # If strong application indicators are present, avoid declaring a
        # default server page automatically.
        if application_indicators:
            return result(
                "SAFE",
                "The response contains some default-server-like indicators, but application-specific content is also present; no default server landing page was confirmed.",
                details=details,
            )

        evidence = []

        for finding in medium_confidence:
            evidence.append(
                f"Possible {finding['server_type']} default-page indicators detected."
            )

        return result(
            "REVIEW REQUIRED",
            "The target contains indicators resembling a default web-server landing page, but the available evidence is not strong enough to declare the condition conclusively.",
            details=details,
            evidence=evidence,
        )

    # ------------------------------------------------------------------
    # Generic default-page detection
    # ------------------------------------------------------------------

    generic_matches = detection["generic_matches"]

    if len(generic_matches) >= 2:
        if application_indicators:
            return result(
                "REVIEW REQUIRED",
                "Generic default-page language was detected, but application-specific content is also present. Manual review is recommended to determine whether the page is actually a server default page.",
                details=details,
                evidence=[
                    f"Generic default-page indicators: {', '.join(generic_matches[:10])}",
                    f"Application indicators: {', '.join(application_indicators[:10])}",
                ],
            )

        return result(
            "UNSAFE",
            "Multiple independent generic default-page indicators were found at the target root, suggesting that the server may still be exposing its default landing page.",
            details=details,
            evidence=[
                f"Generic default-page indicators: {', '.join(generic_matches[:10])}",
            ],
        )

    if len(generic_matches) == 1:
        return result(
            "REVIEW REQUIRED",
            "A generic default-page indicator was detected, but there is insufficient evidence to confirm that the target is serving a default web-server installation page.",
            details=details,
            evidence=[
                f"Possible default-page indicator: {generic_matches[0]}",
            ],
        )

    # ------------------------------------------------------------------
    # No evidence
    # ------------------------------------------------------------------

    return result(
        "SAFE",
        "No recognizable generic default-server landing page was detected at the target root.",
        details=details,
    )