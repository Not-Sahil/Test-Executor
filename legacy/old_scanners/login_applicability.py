"""Detect when form-based auth checks are not applicable.

Classifies hosted identity-provider / OAuth-OIDC sign-in from the configured
URL, HTTP redirects, or page HTML. Does not special-case customer hosts.
"""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import parse_qs, urljoin, urlparse

import requests

# Public identity-provider platforms (not customer application hosts).
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

_OAUTH_PATH_MARKERS = (
    "/oauth2/",
    "/oauth/authorize",
    "/adfs/",
    "/protocol/openid-connect/",
    "/connect/authorize",
    "/as/authorization.oauth2",
    "/authorize.ping",
)

_OAUTH_QUERY_KEYS = {"client_id", "response_type", "redirect_uri"}

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


def hostname(url: str) -> str:
    raw = (url or "").strip()
    if raw and "://" not in raw:
        raw = "https://" + raw
    return (urlparse(raw).hostname or "").lower().rstrip(".")


def absolute_login_url(target: str, login_input: str) -> str:
    raw = (login_input or "").strip() or "/login"
    parsed = urlparse(raw)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return raw
    if raw.startswith("//") and "/" in raw[2:]:
        scheme = urlparse(target).scheme or "https"
        return f"{scheme}:{raw}"
    if not raw.startswith("/"):
        raw = "/" + raw
    return urljoin((target or "").rstrip("/") + "/", raw.lstrip("/"))


def _host_matches_suffix(host: str, suffix: str) -> bool:
    host = (host or "").lower().rstrip(".")
    suffix = (suffix or "").lower().rstrip(".")
    if not host or not suffix:
        return False
    return host == suffix or host.endswith("." + suffix)


def is_public_idp_host(host: str) -> bool:
    return any(_host_matches_suffix(host, suffix) for suffix in _PUBLIC_IDP_HOST_SUFFIXES)


def looks_like_oauth_authorize(url: str) -> bool:
    parsed = urlparse(url or "")
    path = (parsed.path or "").lower()
    query_keys = {key.lower() for key in parse_qs(parsed.query, keep_blank_values=True)}
    oauth_hits = query_keys & _OAUTH_QUERY_KEYS
    if any(marker in path for marker in _OAUTH_PATH_MARKERS):
        return True
    return len(oauth_hits) >= 2


def classify_login_url(url: str) -> Optional[str]:
    host = hostname(url)
    if is_public_idp_host(host):
        return "hosted_identity_provider"
    if looks_like_oauth_authorize(url):
        return "oauth_oidc_authorize"
    return None


def captcha_marker_from_html(html: str) -> Optional[str]:
    lowered = (html or "").lower()
    for marker in _CAPTCHA_HTML_MARKERS:
        if marker in lowered:
            return marker
    return None


def captcha_marker_from_url(url: str) -> Optional[str]:
    lowered = (url or "").lower()
    for marker in _CAPTCHA_URL_MARKERS:
        if marker in lowered:
            return marker
    return None


def html_indicates_hosted_idp(html: str) -> Optional[str]:
    raw = html or ""
    if _PASSWORD_INPUT_RE.search(raw):
        return None
    lowered = raw.lower()
    for marker in _IDP_HTML_MARKERS:
        if marker in lowered:
            return marker
    return None


def reason_for_classification(classification: str) -> str:
    if classification == "hosted_identity_provider":
        return (
            "the login flow uses a hosted identity-provider sign-in page "
            "(federated SSO), not an application HTML username/password form"
        )
    if classification == "oauth_oidc_authorize":
        return (
            "the login flow is an OAuth / OpenID Connect authorization endpoint, "
            "not a local application login form"
        )
    return (
        "the login page is a federated identity-provider sign-in "
        "(identifier-first SSO), not a local username/password form"
    )


def format_not_applicable_summary(test_name: str, skip: dict) -> str:
    reason = skip.get("reason") or "federated authentication is in use"
    return (
        f"Not applicable: {reason}. {test_name} was skipped because this check only "
        "applies to a username/password login form hosted by the target application. "
        "Submitting default credentials or username probes to an identity provider "
        "is not a valid test of the target."
    )


def skip_evidence(skip: dict) -> list[str]:
    reason = skip.get("reason") or "federated authentication is in use"
    final_url = skip.get("final_url") or skip.get("matched_url") or skip.get("login_url")
    items = [
        f"not_applicable classification={skip.get('classification')}",
        f"login_url={skip.get('login_url')}",
        f"target_host={skip.get('target_host') or '(none)'}",
        f"login_host={skip.get('login_host') or '(none)'}",
        f"reason={reason}",
    ]
    if final_url and final_url != skip.get("login_url"):
        items.append(f"identity_provider_url={final_url}")
    hops = skip.get("redirect_hops") or []
    if hops:
        items.append("redirect_hops=" + " -> ".join(str(h) for h in hops))
    if skip.get("html_marker"):
        items.append(f"html_marker={skip.get('html_marker')}")
    return items


def probe_login_for_idp(login_url: str) -> Optional[dict]:
    """Follow redirects and inspect HTML for hosted identity-provider login."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
    })
    current = login_url
    hops: list[str] = [login_url]
    verify = True

    for _ in range(8):
        try:
            resp = session.get(
                current,
                timeout=10,
                allow_redirects=False,
                verify=verify,
            )
        except requests.exceptions.SSLError:
            if verify:
                verify = False
                continue
            return None
        except requests.RequestException:
            return None

        location = resp.headers.get("Location") or resp.headers.get("location")
        if 300 <= resp.status_code < 400 and location:
            nxt = urljoin(current, location)
            hops.append(nxt)
            kind = classify_login_url(nxt)
            if kind:
                return {
                    "classification": kind,
                    "matched_url": nxt,
                    "final_url": nxt,
                    "hops": hops,
                    "http_status": resp.status_code,
                }
            current = nxt
            continue

        hops.append(str(resp.url or current))
        kind = classify_login_url(str(resp.url or current))
        if kind:
            return {
                "classification": kind,
                "matched_url": str(resp.url or current),
                "final_url": str(resp.url or current),
                "hops": hops,
                "http_status": resp.status_code,
            }
        marker = html_indicates_hosted_idp(resp.text or "")
        if marker:
            return {
                "classification": "hosted_identity_provider",
                "matched_url": str(resp.url or current),
                "final_url": str(resp.url or current),
                "hops": hops,
                "http_status": resp.status_code,
                "html_marker": marker,
            }
        return None

    return None


def federated_login_skip(
    target: str,
    login_input: str,
    probe: bool = True,
) -> Optional[dict]:
    """Return skip metadata when form-based auth tests are not applicable."""
    login_url = absolute_login_url(target, login_input)
    target_host = hostname(target)
    login_host = hostname(login_url)

    kind = classify_login_url(login_url)
    if kind:
        return {
            "classification": kind,
            "reason": reason_for_classification(kind),
            "login_url": login_url,
            "target_host": target_host,
            "login_host": login_host,
        }

    if not probe:
        return None

    probed = probe_login_for_idp(login_url)
    if not probed:
        return None

    classification = str(probed.get("classification") or "hosted_identity_provider")
    return {
        "classification": classification,
        "reason": reason_for_classification(classification),
        "login_url": login_url,
        "target_host": target_host,
        "login_host": login_host,
        "final_url": probed.get("final_url"),
        "matched_url": probed.get("matched_url"),
        "redirect_hops": probed.get("hops") or [],
        "html_marker": probed.get("html_marker"),
    }
