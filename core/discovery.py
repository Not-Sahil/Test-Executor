"""Dynamic Application and Authentication Flow Discovery Engine.

Combines HTTP baseline probing and Playwright browser observation to discover
application origins, external Identity Providers, OAuth/OIDC flows, client-side
routing, and DOM authentication controls.
"""
from __future__ import annotations

import logging
import re
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

import requests

from core.browser import discover_browser_flow
from core.evidence import is_soft_404_or_spa_fallback, sanitize_url_parameters
from core.models import (
    AuthFlowMetadata,
    AuthProtocolHint,
    DiscoveredTargetModel,
    LoginFormControls,
    ScopeStatus,
)
from core.scope import ScopeValidator, extract_hostname, normalize_origin
from core.target_policy import TargetPolicy, validate_target_url

logger = logging.getLogger(__name__)

# Known public Identity Provider domains
PUBLIC_IDP_HOST_SUFFIXES = (
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

# OAuth / OIDC markers in URL paths
OAUTH_PATH_MARKERS = (
    "/protocol/openid-connect/auth",
    "/protocol/openid-connect/",
    "/oauth2/v2.0/authorize",
    "/oauth2/authorize",
    "/oauth/authorize",
    "/connect/authorize",
    "/as/authorization.oauth2",
    "/adfs/oauth2/authorize",
)

OAUTH_QUERY_KEYS = {"client_id", "response_type", "redirect_uri"}

# Common login path candidates
COMMON_LOGIN_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/user/login",
    "/login.jsp",
    "/login.html",
    "/login.php",
)


def _is_public_idp_host(host: str) -> bool:
    host_clean = (host or "").lower().rstrip(".")
    return any(host_clean == s or host_clean.endswith("." + s) for s in PUBLIC_IDP_HOST_SUFFIXES)


class _SimpleFormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current_form: dict | None = None
        self.login_links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._current_form = {
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self._current_form)
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "type": attr_dict.get("type", "text").lower(),
                "name": attr_dict.get("name", ""),
                "id": attr_dict.get("id", ""),
            })
        elif tag == "a":
            href = attr_dict.get("href", "")
            if href:
                href_lower = href.lower()
                if any(t in href_lower for t in ("login", "signin", "sign-in", "auth")):
                    self.login_links.append(href)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


def analyze_auth_flow(
    all_observed_urls: list[str],
    html_content: str = "",
) -> AuthFlowMetadata:
    """Analyze observed URLs, redirects, and HTML to infer authentication protocol hints."""
    evidence: list[str] = []
    
    # 1. Inspect each observed URL for OIDC / OAuth indicators
    for url in all_observed_urls:
        if not url:
            continue
        parsed = urlparse(url)
        path_lower = (parsed.path or "").lower()
        query_params = {k.lower(): v for k, v in parse_qs(parsed.query).items()}

        # Check OIDC Authorization Code Flow
        is_oidc_path = any(marker in path_lower for marker in OAUTH_PATH_MARKERS)
        has_client_id = "client_id" in query_params
        has_redirect_uri = "redirect_uri" in query_params
        response_type = query_params.get("response_type", [""])[0].lower()
        scope_vals = query_params.get("scope", [""])[0].lower()

        if is_oidc_path or (has_client_id and has_redirect_uri):
            callback = query_params.get("redirect_uri", [None])[0]
            sanitized_url = sanitize_url_parameters(url)

            if "openid" in scope_vals or "/protocol/openid-connect/" in path_lower:
                evidence.append(f"Observed OpenID Connect authorization endpoint: {sanitized_url}")
                if "code" in response_type:
                    evidence.append("Authorization request specifies response_type=code")
                return AuthFlowMetadata(
                    protocol_hint=AuthProtocolHint.OIDC_AUTHORIZATION_CODE.value,
                    confidence="high",
                    evidence=evidence,
                    confirmed=False,
                    idp_host=parsed.hostname,
                    authorization_endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    callback_url=callback,
                )

            # Generic OAuth 2.0 flow
            evidence.append(f"Observed OAuth 2.0 authorization endpoint: {sanitized_url}")
            return AuthFlowMetadata(
                protocol_hint=AuthProtocolHint.OAUTH2_AUTHORIZATION_FLOW.value,
                confidence="high",
                evidence=evidence,
                confirmed=False,
                idp_host=parsed.hostname,
                authorization_endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                callback_url=callback,
            )

        # Check SAML indicators
        if "samlrequest" in query_params or "/saml2/" in path_lower or "/adfs/ls/" in path_lower:
            evidence.append("Observed SAML protocol parameter or endpoint.")
            return AuthFlowMetadata(
                protocol_hint=AuthProtocolHint.SAML_SSO.value,
                confidence="medium",
                evidence=evidence,
                confirmed=False,
                idp_host=parsed.hostname,
                authorization_endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            )

        # Check for known public Identity Provider host
        if _is_public_idp_host(parsed.hostname or ""):
            evidence.append(f"Observed redirect to centralized Identity Provider: {parsed.hostname}")
            return AuthFlowMetadata(
                protocol_hint=AuthProtocolHint.CENTRALIZED_IDP.value,
                confidence="high",
                evidence=evidence,
                confirmed=False,
                idp_host=parsed.hostname,
                authorization_endpoint=f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
            )

    # 2. Check for traditional password form in HTML
    if bool(re.search(r"<input\b[^>]*type\s*=\s*['\"]password['\"]", html_content or "", re.I)):
        evidence.append("Observed traditional HTML login form with password input.")
        return AuthFlowMetadata(
            protocol_hint=AuthProtocolHint.TRADITIONAL_FORM.value,
            confidence="high",
            evidence=evidence,
            confirmed=False,
        )

    return AuthFlowMetadata(
        protocol_hint=AuthProtocolHint.UNKNOWN_OR_UNRESOLVED.value,
        confidence="low",
        evidence=["No conclusive authentication protocol signature observed."],
        confirmed=False,
    )


def discover_application_and_auth_flow(
    target_url: str,
    login_path_hint: str = "/login",
    additional_in_scope_origins: list[str] | None = None,
    verify_tls: bool = True,
    use_browser: bool = True,
    timeout: float = 12.0,
) -> DiscoveredTargetModel:
    """Execute unified application and authentication flow discovery.

    Combines initial target validation, HTTP baseline probing, redirect analysis,
    and Playwright browser discovery.
    """
    # Phase A: Initial Target Validation
    policy = TargetPolicy.from_environment()
    valid_target = validate_target_url(target_url, policy=policy)
    app_origin = normalize_origin(valid_target)

    scope_validator = ScopeValidator(
        primary_target=valid_target,
        additional_in_scope_origins=additional_in_scope_origins,
        allow_subdomains=False,
        policy=policy,
    )

    discovery_evidence: list[str] = [f"Initial target validated: {valid_target} (Origin: {app_origin})"]
    observed_urls: list[str] = [valid_target]
    redirect_chain: list[str] = []
    discovered_login_url: str | None = None
    discovered_idp_origin: str | None = None
    callback_url: str | None = None
    controls = LoginFormControls()
    spa_fallback = False
    waf_detected = False
    html_sample = ""

    # Phase B: HTTP-Based Initial Discovery
    try:
        session = requests.Session()
        resp = session.get(
            valid_target,
            timeout=timeout,
            verify=verify_tls,
            headers={"User-Agent": "Mozilla/5.0 TestExecutor-SecurityScanner/2.0"},
            allow_redirects=True,
        )
        final_http_url = resp.url
        observed_urls.append(final_http_url)

        # Capture HTTP redirect chain
        if resp.history:
            for r in resp.history:
                redirect_chain.append(r.url)
                observed_urls.append(r.url)
                discovery_evidence.append(f"HTTP Redirect: {r.status_code} -> {r.headers.get('Location', '')}")

        html_sample = resp.text or ""

        # Check soft-404 / SPA / WAF
        spa_fallback = is_soft_404_or_spa_fallback(resp.content, resp.status_code)
        if "request rejected" in html_sample.lower() or "attention required! | cloudflare" in html_sample.lower():
            waf_detected = True
            discovery_evidence.append("WAF or rejection signature detected in HTTP baseline response.")

        # Parse forms and login links in HTML
        parser = _SimpleFormParser()
        parser.feed(html_sample)
        for form in parser.forms:
            has_pwd = any(inp["type"] == "password" for inp in form["inputs"])
            if has_pwd:
                controls.has_form = True
                controls.action_url = form["action"]
                controls.method = form["method"]
                controls.password_field = next((inp["name"] for inp in form["inputs"] if inp["type"] == "password"), "password")
                controls.username_field = next((inp["name"] for inp in form["inputs"] if inp["type"] in ("text", "email")), "username")
                discovered_login_url = final_http_url
                discovery_evidence.append(f"HTTP discovery found password form on: {final_http_url}")
                break

        if not controls.has_form and login_path_hint:
            if login_path_hint.lower().startswith(("http://", "https://")):
                hint_url = login_path_hint
            else:
                hint_url = urljoin(valid_target + "/", login_path_hint.lstrip("/"))
            try:
                hint_resp = session.get(
                    hint_url,
                    timeout=timeout,
                    verify=verify_tls,
                    headers={"User-Agent": "Mozilla/5.0 TestExecutor-SecurityScanner/2.0"},
                    allow_redirects=True,
                )
                observed_urls.append(hint_resp.url)
                hint_parser = _SimpleFormParser()
                hint_parser.feed(hint_resp.text or "")
                for form in hint_parser.forms:
                    if any(inp["type"] == "password" for inp in form["inputs"]):
                        controls.has_form = True
                        controls.action_url = form["action"]
                        controls.method = form["method"]
                        controls.password_field = next((inp["name"] for inp in form["inputs"] if inp["type"] == "password"), "password")
                        controls.username_field = next((inp["name"] for inp in form["inputs"] if inp["type"] in ("text", "email")), "username")
                        discovered_login_url = hint_resp.url
                        discovery_evidence.append(f"HTTP discovery confirmed login form via hint URL: {hint_resp.url}")
                        break
            except Exception:
                pass

    except Exception as exc:
        discovery_evidence.append(f"HTTP baseline probe encountered exception: {exc}")

    # Phase C: Browser-Based Discovery (Playwright)
    if use_browser:
        browser_res = discover_browser_flow(
            target_url=valid_target,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        observed_urls.append(browser_res.settled_url)
        for redir in browser_res.redirect_chain:
            if redir not in redirect_chain:
                redirect_chain.append(redir)
            observed_urls.append(redir)

        discovery_evidence.extend(browser_res.evidence)

        # If browser discovered form controls, update controls
        if browser_res.controls.has_form:
            controls = browser_res.controls
            discovered_login_url = browser_res.settled_url
            discovery_evidence.append(f"Browser discovery resolved login form at: {browser_res.settled_url}")
        elif not discovered_login_url and browser_res.settled_url != valid_target:
            discovered_login_url = browser_res.settled_url

    # Analyze Authentication Protocol Hint
    auth_flow = analyze_auth_flow(observed_urls, html_content=html_sample)
    if auth_flow.idp_host:
        discovered_idp_origin = f"https://{auth_flow.idp_host}"
    if auth_flow.callback_url:
        callback_url = auth_flow.callback_url

    # Resolve Login Origin
    login_origin = None
    if discovered_login_url:
        try:
            login_origin = normalize_origin(discovered_login_url)
        except Exception:
            login_origin = app_origin
    elif discovered_idp_origin:
        login_origin = discovered_idp_origin

    # Build Centralized Scope Map for All Discovered Origins
    scope_map: dict[str, str] = {}
    origins_to_check = {app_origin}
    if login_origin:
        origins_to_check.add(login_origin)
    if discovered_idp_origin:
        origins_to_check.add(discovered_idp_origin)
    if callback_url:
        try:
            callback_origin = normalize_origin(callback_url)
            origins_to_check.add(callback_origin)
        except Exception:
            pass

    for org in origins_to_check:
        status, _ = scope_validator.validate_scope(org)
        scope_map[org] = status.value

    callback_origin_val = None
    if callback_url:
        try:
            callback_origin_val = normalize_origin(callback_url)
        except Exception:
            pass

    return DiscoveredTargetModel(
        original_url=valid_target,
        application_origin=app_origin,
        login_url=discovered_login_url,
        login_origin=login_origin,
        identity_provider_origin=discovered_idp_origin,
        callback_url=callback_url,
        callback_origin=callback_origin_val,
        additional_in_scope_origins=list(additional_in_scope_origins or []),
        scope_map=scope_map,
        auth_flow=auth_flow,
        login_controls=controls,
        redirect_chain=redirect_chain,
        spa_fallback_detected=spa_fallback,
        waf_detected=waf_detected,
        discovery_evidence=discovery_evidence,
    )
