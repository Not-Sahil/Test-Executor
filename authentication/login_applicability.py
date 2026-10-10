from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

import requests


# ---------------------------------------------------------------------------
# Public Identity Provider hosts
# ---------------------------------------------------------------------------

_PUBLIC_IDP_HOST_SUFFIXES = (
    "login.microsoftonline.com",
    "microsoftonline.com",
    "login.microsoft.com",
    "login.windows.net",
    "sts.windows.net",
    "login.live.com",
    "ciamlogin.com",
    "okta.com",
    "oktapreview.com",
    "okta-emea.com",
    "auth0.com",
    "onelogin.com",
    "pingidentity.com",
    "pingone.com",
    "accounts.google.com",
    "login.salesforce.com",
    "appleid.apple.com",
    "amazoncognito.com",
)


# ---------------------------------------------------------------------------
# OAuth / OIDC indicators
# ---------------------------------------------------------------------------

_OAUTH_PATH_MARKERS = (
    "/oauth2/",
    "/oauth/authorize",
    "/adfs/",
    "/protocol/openid-connect/",
    "/connect/authorize",
    "/as/authorization.oauth2",
    "/authorize.ping",
)

_OAUTH_QUERY_KEYS = {
    "client_id",
    "response_type",
    "redirect_uri",
}


# ---------------------------------------------------------------------------
# HTML indicators
# ---------------------------------------------------------------------------

_PASSWORD_INPUT_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]password['\"]",
    re.IGNORECASE,
)

_CAPTCHA_HTML_MARKERS = (
    "g-recaptcha",
    "grecaptcha",
    "recaptcha/api.js",
    "google.com/recaptcha",
    "gstatic.com/recaptcha",
    "h-captcha",
    "hcaptcha.com",
    "cf-turnstile",
    "challenges.cloudflare.com/turnstile",
)

_CAPTCHA_URL_MARKERS = (
    "captcha=fail",
    "captcha=required",
    "captcha_fail",
    "captcha-required",
)

_IDP_HTML_MARKERS = (
    "login.microsoftonline.com",
    "login.windows.net",
    "login.microsoft.com",
    "sts.windows.net",
    "getcredentialtype",
    "ms-ests",
    "convergedlogin",
    "okta-signin",
    "okta.com/oauth2",
    "auth0-lock",
    "auth0.com/authorize",
    "accounts.google.com",
    "amazoncognito.com",
    "pingone.com",
    "onelogin.com",
)


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def hostname(url: str) -> str:
    """
    Return the normalized hostname from a URL.

    Supports URLs with or without an explicit scheme.
    """
    raw = (url or "").strip()

    if raw and "://" not in raw:
        raw = "https://" + raw

    return (urlparse(raw).hostname or "").lower().rstrip(".")


def absolute_login_url(target: str, login_input: str) -> str:
    """
    Resolve a login path or absolute login URL against the target.
    """
    raw = (login_input or "/login").strip()

    parsed = urlparse(raw)

    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return raw

    return urljoin(
        target.rstrip("/") + "/",
        raw.lstrip("/"),
    )


def _host_matches_suffix(host: str, suffix: str) -> bool:
    """
    Match an exact hostname or a subdomain of the supplied suffix.
    """
    host = (host or "").lower().rstrip(".")
    suffix = (suffix or "").lower().rstrip(".")

    return host == suffix or host.endswith("." + suffix)


def is_public_idp_host(host: str) -> bool:
    """
    Determine whether a hostname belongs to a known public identity provider.
    """
    return any(
        _host_matches_suffix(host, suffix)
        for suffix in _PUBLIC_IDP_HOST_SUFFIXES
    )


# ---------------------------------------------------------------------------
# OAuth / OIDC detection
# ---------------------------------------------------------------------------

def looks_like_oauth_authorize(url: str) -> bool:
    """
    Detect common OAuth/OIDC authorization endpoints.
    """
    parsed = urlparse(url or "")

    query_keys = {
        key.lower()
        for key in parse_qs(
            parsed.query,
            keep_blank_values=True,
        )
    }

    hits = query_keys & _OAUTH_QUERY_KEYS

    return (
        any(
            marker in (parsed.path or "").lower()
            for marker in _OAUTH_PATH_MARKERS
        )
        or len(hits) >= 2
    )


def classify_login_url(url: str) -> str | None:
    """
    Classify a login URL as a hosted identity provider or OAuth/OIDC endpoint.

    Returns:
        hosted_identity_provider
        oauth_oidc_authorize
        None
    """
    host = hostname(url)

    if is_public_idp_host(host):
        return "hosted_identity_provider"

    if looks_like_oauth_authorize(url):
        return "oauth_oidc_authorize"

    return None


# ---------------------------------------------------------------------------
# CAPTCHA detection
# ---------------------------------------------------------------------------

def captcha_marker_from_html(html: str) -> str | None:
    """
    Return the first recognized CAPTCHA marker found in HTML.
    """
    lowered = (html or "").lower()

    return next(
        (
            marker
            for marker in _CAPTCHA_HTML_MARKERS
            if marker in lowered
        ),
        None,
    )


def captcha_marker_from_url(url: str) -> str | None:
    """
    Return the first recognized CAPTCHA marker found in a URL.
    """
    lowered = (url or "").lower()

    return next(
        (
            marker
            for marker in _CAPTCHA_URL_MARKERS
            if marker in lowered
        ),
        None,
    )


# ---------------------------------------------------------------------------
# Identity-provider HTML detection
# ---------------------------------------------------------------------------

def html_indicates_hosted_idp(html: str) -> str | None:
    """
    Detect identity-provider indicators in returned HTML.

    If a normal password input exists, the HTML is not automatically
    classified as an IDP page because many first-party login pages
    legitimately contain strings referencing identity providers.
    """
    raw = html or ""

    if _PASSWORD_INPUT_RE.search(raw):
        return None

    lowered = raw.lower()

    return next(
        (
            marker
            for marker in _IDP_HTML_MARKERS
            if marker in lowered
        ),
        None,
    )


# ---------------------------------------------------------------------------
# Classification reason
# ---------------------------------------------------------------------------

def _reason(classification: str) -> str:
    """
    Convert a classification into a human-readable reason.
    """
    if classification == "hosted_identity_provider":
        return (
            "the login flow uses a hosted identity-provider sign-in page"
        )

    if classification == "oauth_oidc_authorize":
        return (
            "the login flow is an OAuth/OpenID Connect authorization endpoint"
        )

    return (
        "the login flow appears to use federated authentication"
    )


# Compatibility name used by older versions of the authentication layer.
reason_for_classification = _reason


# ---------------------------------------------------------------------------
# Not-applicable result formatting
# ---------------------------------------------------------------------------

def format_not_applicable_summary(
    test_name: str,
    skip: dict,
) -> str:
    """
    Build the standardized summary used by the assessment orchestrator
    when an authentication testcase is not applicable because the target
    uses federated authentication.
    """
    reason = (
        skip.get("reason")
        or "federated authentication is in use"
    )

    return (
        f"Not applicable: {reason}. "
        f"{test_name} was skipped because this check only applies "
        "to a username/password login form hosted by the target "
        "application. Submitting default credentials or username "
        "probes to an identity provider is not a valid test of "
        "the target."
    )


def skip_evidence(skip: dict) -> list[str]:
    """
    Build structured evidence for a skipped/not-applicable authentication
    testcase.
    """
    reason = (
        skip.get("reason")
        or "federated authentication is in use"
    )

    final_url = (
        skip.get("final_url")
        or skip.get("matched_url")
        or skip.get("login_url")
    )

    items = [
        f"not_applicable classification={skip.get('classification')}",
        f"login_url={skip.get('login_url')}",
        f"target_host={skip.get('target_host') or '(none)'}",
        f"login_host={skip.get('login_host') or '(none)'}",
        f"reason={reason}",
    ]

    if final_url and final_url != skip.get("login_url"):
        items.append(
            f"identity_provider_url={final_url}"
        )

    hops = skip.get("redirect_hops") or []

    if hops:
        items.append(
            "redirect_hops=" + " -> ".join(str(h) for h in hops)
        )

    if skip.get("html_marker"):
        items.append(
            f"html_marker={skip.get('html_marker')}"
        )

    return items


# ---------------------------------------------------------------------------
# Federated login detection
# ---------------------------------------------------------------------------

def federated_login_skip(
    target: str,
    login_input: str,
    probe: bool = True,
) -> dict | None:
    """
    Determine whether a login flow is hosted by or redirected to an
    external identity provider.

    This function performs only bounded GET/redirect inspection.
    It does not submit credentials.
    """
    login_url = absolute_login_url(
        target,
        login_input,
    )

    target_host = hostname(target)
    login_host = hostname(login_url)

    # ---------------------------------------------------------------
    # 1. Direct URL classification
    # ---------------------------------------------------------------

    classification = classify_login_url(login_url)

    if classification:
        return {
            "classification": classification,
            "reason": _reason(classification),
            "login_url": login_url,
            "target_host": target_host,
            "login_host": login_host,
        }

    # ---------------------------------------------------------------
    # 2. Optional network probe
    # ---------------------------------------------------------------

    if not probe:
        return None

    session = requests.Session()

    current = login_url
    hops = [login_url]

    # Hard limit prevents an unexpected redirect loop.
    for _ in range(8):
        try:
            response = session.get(
                current,
                timeout=8,
                allow_redirects=False,
            )
        except requests.RequestException:
            # A failed probe is not enough evidence to classify the
            # login flow as federated.
            return None

        location = response.headers.get("Location")

        # -----------------------------------------------------------
        # Redirect handling
        # -----------------------------------------------------------

        if (
            300 <= response.status_code < 400
            and location
        ):
            current = urljoin(
                current,
                location,
            )

            hops.append(current)

            classification = classify_login_url(
                current
            )

            if classification:
                return {
                    "classification": classification,
                    "reason": _reason(classification),
                    "login_url": login_url,
                    "target_host": target_host,
                    "login_host": login_host,
                    "final_url": current,
                    "redirect_hops": hops,
                }

            continue

        # -----------------------------------------------------------
        # Final response / HTML inspection
        # -----------------------------------------------------------

        final_url = response.url or current

        classification = classify_login_url(
            final_url
        )

        marker = html_indicates_hosted_idp(
            response.text or ""
        )

        if classification or marker:
            classification = (
                classification
                or "hosted_identity_provider"
            )

            return {
                "classification": classification,
                "reason": _reason(classification),
                "login_url": login_url,
                "target_host": target_host,
                "login_host": login_host,
                "final_url": final_url,
                "redirect_hops": hops + [str(final_url)],
                "html_marker": marker,
            }

        # No evidence of federated authentication.
        return None

    # Redirect limit reached without enough evidence.
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "hostname",
    "absolute_login_url",
    "is_public_idp_host",
    "looks_like_oauth_authorize",
    "classify_login_url",
    "captcha_marker_from_html",
    "captcha_marker_from_url",
    "html_indicates_hosted_idp",
    "reason_for_classification",
    "format_not_applicable_summary",
    "skip_evidence",
    "federated_login_skip",
]