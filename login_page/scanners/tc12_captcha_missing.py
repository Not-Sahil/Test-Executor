"""TC12 - CAPTCHA Missing / Missing CAPTCHA enforcement.

Additive login-page scanner. It detects whether a local username/password
login flow exposes no CAPTCHA and, when explicitly enabled, performs a very
small bounded set of synthetic failed-login probes to see whether a CAPTCHA
appears after failures.

The scanner never solves, bypasses, OCRs, or calls CAPTCHA-solving services.
It never uses discovered credentials. Browser automation is optional.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from html import unescape
from typing import Any, Callable, Optional
from urllib.parse import urljoin, urlparse
import re
import time

try:
    import requests
except Exception:  # pragma: no cover
    requests = None  # type: ignore


CAPTCHA_MARKERS = (
    "recaptcha", "g-recaptcha", "grecaptcha", "hcaptcha", "h-captcha",
    "turnstile", "cf-turnstile", "captcha", "arkose", "funcaptcha",
    "friendly-challenge", "geetest", "cloudflare turnstile",
)

CAPTCHA_RESPONSE_FIELDS = (
    "g-recaptcha-response", "h-captcha-response", "cf-turnstile-response",
    "captcha-response", "captcha_token", "captcha-token", "captchaToken",
)

SSO_MARKERS = (
    "oauth", "oidc", "openid", "saml", "microsoftonline", "okta",
    "auth0", "accounts.google.com", "login.microsoftonline.com",
    "cognito", "pingidentity",
)

SUCCESS_MARKERS = (
    "logout", "sign out", "dashboard", "my account", "welcome",
)

ERROR_MARKERS = (
    "invalid", "incorrect", "failed", "authentication failed",
    "wrong password", "invalid credentials", "try again",
)


@dataclass(frozen=True)
class TC12Config:
    login_path: str = "/login"
    timeout: float = 8.0
    verify_tls: bool = True
    max_failed_probes: int = 3
    probe_delay_seconds: float = 0.35
    allow_browser_fallback: bool = True
    include_failed_login_probes: bool = True
    screenshot_evidence: bool = False
    synthetic_username: str = "tc12-captcha-missing-invalid-user"
    synthetic_password: str = "TC12-Synthetic-Invalid-Password-7F3A"


@dataclass
class TC12Result:
    status: str
    summary: str
    details: dict[str, Any]
    evidence: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _normalize_target(target: str, login_path: str) -> str:
    target = (target or "").strip()
    if not target:
        raise ValueError("target URL is required")
    if not re.match(r"^https?://", target, re.I):
        target = "https://" + target
    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError("target URL has no hostname")
    if parsed.path and parsed.path not in ("/", ""):
        return target
    return urljoin(target.rstrip("/") + "/", login_path.lstrip("/"))


def _html_text(html: str) -> str:
    text = re.sub(r"<script\b[^>]*>.*?</script>", " ", html, flags=re.I | re.S)
    text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", unescape(text)).strip()


def detect_captcha(html: str, url: str = "") -> dict[str, Any]:
    source = (html or "").lower()
    url_lower = (url or "").lower()
    markers = sorted({m for m in CAPTCHA_MARKERS if m in source or m in url_lower})
    fields = []
    for field in CAPTCHA_RESPONSE_FIELDS:
        if field.lower() in source:
            fields.append(field)
    provider = "unknown"
    if any(x in source for x in ("recaptcha", "g-recaptcha", "grecaptcha")):
        provider = "reCAPTCHA"
    elif "hcaptcha" in source or "h-captcha" in source:
        provider = "hCaptcha"
    elif "turnstile" in source or "cf-turnstile" in source:
        provider = "Cloudflare Turnstile"
    elif "arkose" in source or "funcaptcha" in source:
        provider = "Arkose/FunCaptcha"
    elif "geetest" in source:
        provider = "GeeTest"
    elif markers:
        provider = "generic/other"
    return {
        "present": bool(markers or fields),
        "markers": markers,
        "response_fields": fields,
        "provider": provider,
    }


def detect_local_login_form(html: str) -> dict[str, Any]:
    source = html or ""
    lower = source.lower()
    forms = re.findall(r"<form\b[^>]*>(.*?)</form>", source, flags=re.I | re.S)
    password_fields = re.findall(
        r"<input\b[^>]*type\s*=\s*['\"]?password['\"]?[^>]*>",
        source, flags=re.I,
    )
    username_fields = re.findall(
        r"<input\b[^>]*(?:type\s*=\s*['\"]?(?:text|email)['\"]?|name\s*=\s*['\"][^'\"]*(?:user|email|login)[^'\"]*['\"])[^>]*>",
        source, flags=re.I,
    )
    sso = any(marker in lower for marker in SSO_MARKERS)
    return {
        "forms": len(forms),
        "password_fields": len(password_fields),
        "username_fields": len(username_fields),
        "local_password_login": bool(password_fields),
        "federated_markers": sorted({m for m in SSO_MARKERS if m in lower}),
        "likely_federated": sso and not password_fields,
    }


def _response_signature(resp: Any) -> dict[str, Any]:
    text = getattr(resp, "text", "") or ""
    return {
        "status_code": getattr(resp, "status_code", None),
        "final_url": getattr(resp, "url", ""),
        "content_length": len(text),
        "captcha": detect_captcha(text, getattr(resp, "url", "")),
        "success_markers": [m for m in SUCCESS_MARKERS if m in text.lower()],
        "error_markers": [m for m in ERROR_MARKERS if m in text.lower()],
    }


def _find_form(html: str) -> Optional[dict[str, Any]]:
    match = re.search(r"<form\b([^>]*)>(.*?)</form>", html or "", flags=re.I | re.S)
    if not match:
        return None
    attrs, body = match.group(1), match.group(2)
    action_m = re.search(r"action\s*=\s*['\"]([^'\"]*)", attrs, re.I)
    method_m = re.search(r"method\s*=\s*['\"]?([^\s'\"]+)", attrs, re.I)
    action = action_m.group(1) if action_m else ""
    method = (method_m.group(1) if method_m else "POST").upper()
    inputs = []
    for tag in re.findall(r"<input\b[^>]*>", body, flags=re.I):
        name_m = re.search(r"name\s*=\s*['\"]([^'\"]*)", tag, re.I)
        type_m = re.search(r"type\s*=\s*['\"]?([^\s'\"]+)", tag, re.I)
        value_m = re.search(r"value\s*=\s*['\"]([^'\"]*)", tag, re.I)
        if name_m:
            inputs.append({
                "name": name_m.group(1),
                "type": (type_m.group(1).lower() if type_m else "text"),
                "value": value_m.group(1) if value_m else "",
            })
    return {"action": action, "method": method, "inputs": inputs}


def _form_payload(form: dict[str, Any], username: str, password: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for item in form["inputs"]:
        name = item["name"]
        typ = item["type"]
        if typ in {"submit", "button", "image", "reset", "file"}:
            continue
        lname = name.lower()
        if typ == "password" or "pass" in lname:
            payload[name] = password
        elif any(x in lname for x in ("user", "email", "login", "identifier")):
            payload[name] = username
        else:
            # Preserve non-secret hidden/auxiliary fields exactly as supplied.
            payload[name] = item.get("value", "")
    return payload


def _classify(
    *,
    local_login: dict[str, Any],
    initial_captcha: dict[str, Any],
    post_probe_captchas: list[dict[str, Any]],
    attempted_probes: int,
    rate_limited: bool,
    browser_available: bool,
    probe_error: Optional[str],
) -> tuple[str, str]:
    if local_login["likely_federated"]:
        return "NOT_ASSESSED", "Federated authentication was detected without a local password form."
    if not local_login["local_password_login"]:
        return "NOT_ASSESSED", "No local username/password login form was identified."
    if initial_captcha["present"]:
        return "SAFE", "A CAPTCHA control is present on the login flow; this testcase found no missing CAPTCHA condition."
    if rate_limited:
        return "REVIEW REQUIRED", "The bounded failed-login probes were rate-limited before CAPTCHA appearance could be established."
    if probe_error and attempted_probes == 0:
        return "REVIEW REQUIRED", "The login page was inspected, but dynamic CAPTCHA enforcement could not be verified."
    if attempted_probes == 0 and not browser_available:
        return "REVIEW REQUIRED", "No CAPTCHA was visible initially, but dynamic post-failure enforcement was not tested."
    if post_probe_captchas and any(item.get("present") for item in post_probe_captchas):
        return "SAFE", "A CAPTCHA appeared during the bounded failed-login sequence."
    if attempted_probes > 0 and not any(item.get("present") for item in post_probe_captchas):
        return "UNSAFE", "No CAPTCHA was observed on the local login flow, including after bounded failed-login probes."
    return "REVIEW REQUIRED", "CAPTCHA enforcement could not be conclusively classified from the available evidence."


def _http_scan(target_url: str, config: TC12Config) -> TC12Result:
    if requests is None:
        return TC12Result("ERROR", "The requests library is unavailable.", {}, [])

    session = requests.Session()
    session.headers.update({"User-Agent": "SecurityAssessmentTestExecutor/TC12"})
    evidence: list[str] = []
    details: dict[str, Any] = {"target": target_url, "lane": "http", "probes": []}

    try:
        resp = session.get(target_url, timeout=config.timeout, verify=config.verify_tls, allow_redirects=True)
    except Exception as exc:
        return TC12Result("ERROR", "Login-page retrieval failed.", {"error": str(exc)}, ["GET failed"])

    html = resp.text or ""
    local_login = detect_local_login_form(html)
    initial_captcha = detect_captcha(html, resp.url)
    details["initial_response"] = {
        "status_code": resp.status_code,
        "final_url": resp.url,
        "content_length": len(html),
    }
    details["local_login"] = local_login
    details["initial_captcha"] = initial_captcha

    if local_login["likely_federated"]:
        return TC12Result("NOT_ASSESSED", "Federated authentication flow detected; local CAPTCHA enforcement is not applicable.", details, ["Federated authentication detected"])
    if not local_login["local_password_login"]:
        return TC12Result("NOT_ASSESSED", "No local username/password login form was identified.", details, ["No local password field detected"])
    if initial_captcha["present"] or not config.include_failed_login_probes:
        status, summary = _classify(local_login=local_login, initial_captcha=initial_captcha,
            post_probe_captchas=[], attempted_probes=0, rate_limited=False,
            browser_available=False, probe_error=None)
        return TC12Result(status, summary, details, ["CAPTCHA detected on initial login page"] if initial_captcha["present"] else ["Dynamic probing disabled"])

    form = _find_form(html)
    if not form:
        return TC12Result("REVIEW REQUIRED", "A password field was detected, but no usable login form could be parsed for bounded verification.", details, ["Login form parsing failed"])

    action = urljoin(resp.url, form["action"] or resp.url)
    post_probe_captchas: list[dict[str, Any]] = []
    rate_limited = False
    probe_error: Optional[str] = None
    for index in range(max(0, min(config.max_failed_probes, 3))):
        payload = _form_payload(form, config.synthetic_username, config.synthetic_password)
        try:
            if form["method"] == "GET":
                probe = session.get(action, params=payload, timeout=config.timeout, verify=config.verify_tls, allow_redirects=True)
            else:
                probe = session.post(action, data=payload, timeout=config.timeout, verify=config.verify_tls, allow_redirects=True)
            sig = _response_signature(probe)
            sig["attempt"] = index + 1
            post_probe_captchas.append(sig["captcha"])
            details["probes"].append(sig)
            if probe.status_code in (429, 403) and "captcha" not in (probe.text or "").lower():
                rate_limited = True
                break
            if sig["captcha"]["present"]:
                break
        except Exception as exc:
            probe_error = str(exc)
            break
        if config.probe_delay_seconds:
            time.sleep(min(config.probe_delay_seconds, 1.0))

    status, summary = _classify(
        local_login=local_login,
        initial_captcha=initial_captcha,
        post_probe_captchas=post_probe_captchas,
        attempted_probes=len(post_probe_captchas),
        rate_limited=rate_limited,
        browser_available=False,
        probe_error=probe_error,
    )
    evidence.append(f"Initial CAPTCHA present: {initial_captcha['present']}")
    evidence.append(f"Bounded failed-login probes: {len(post_probe_captchas)}")
    if any(item.get("present") for item in post_probe_captchas):
        evidence.append("CAPTCHA appeared during the bounded probe sequence")
    else:
        evidence.append("No CAPTCHA observed during the bounded probe sequence")
    if probe_error:
        evidence.append("A probe error occurred; see structured details")
        details["probe_error"] = probe_error
    return TC12Result(status, summary, details, evidence)


def _browser_scan(target_url: str, config: TC12Config) -> Optional[TC12Result]:
    if not config.allow_browser_fallback:
        return None
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return None

    details: dict[str, Any] = {"target": target_url, "lane": "browser", "probes": []}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=not config.verify_tls)
            page = context.new_page()
            page.goto(target_url, wait_until="domcontentloaded", timeout=int(config.timeout * 1000))
            html = page.content()
            local_login = detect_local_login_form(html)
            initial_captcha = detect_captcha(html, page.url)
            details["local_login"] = local_login
            details["initial_captcha"] = initial_captcha
            if local_login["likely_federated"]:
                browser.close()
                return TC12Result("NOT_ASSESSED", "Federated authentication flow detected; local CAPTCHA enforcement is not applicable.", details, ["Federated authentication detected"])
            if not local_login["local_password_login"]:
                browser.close()
                return TC12Result("NOT_ASSESSED", "No local username/password login form was identified.", details, ["No local password field detected"])
            if initial_captcha["present"]:
                browser.close()
                return TC12Result("SAFE", "A CAPTCHA control is present on the login flow; this testcase found no missing CAPTCHA condition.", details, ["CAPTCHA detected in rendered login page"])
            if not config.include_failed_login_probes:
                browser.close()
                return TC12Result("REVIEW REQUIRED", "No CAPTCHA was visible initially; dynamic enforcement was not tested.", details, ["Dynamic probing disabled"])

            # Fill only synthetic invalid credentials. Never use stored/discovered credentials.
            password = page.locator("input[type='password']").first
            username = page.locator("input[type='email'], input[name*='user' i], input[name*='login' i], input[name*='email' i], input[type='text']").first
            submit = page.locator("button[type='submit'], input[type='submit'], button").first
            if password.count() == 0 or submit.count() == 0:
                browser.close()
                return TC12Result("REVIEW REQUIRED", "The rendered login form could not be safely exercised with synthetic invalid credentials.", details, ["Browser form controls incomplete"])

            seen = []
            for attempt in range(max(0, min(config.max_failed_probes, 3))):
                if username.count() > 0:
                    username.fill(config.synthetic_username)
                password.fill(config.synthetic_password)
                submit.click()
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=int(config.timeout * 1000))
                except Exception:
                    pass
                time.sleep(min(config.probe_delay_seconds, 1.0))
                current = detect_captcha(page.content(), page.url)
                seen.append(current)
                details["probes"].append({"attempt": attempt + 1, "captcha": current, "url": page.url})
                if current["present"]:
                    break

            browser.close()
            status, summary = _classify(
                local_login=local_login,
                initial_captcha=initial_captcha,
                post_probe_captchas=seen,
                attempted_probes=len(seen),
                rate_limited=False,
                browser_available=True,
                probe_error=None,
            )
            evidence = [f"Initial CAPTCHA present: {initial_captcha['present']}", f"Bounded browser probes: {len(seen)}"]
            evidence.append("CAPTCHA appeared during browser probe" if any(x.get("present") for x in seen) else "No CAPTCHA observed during browser probe")
            return TC12Result(status, summary, details, evidence)
    except Exception as exc:
        return TC12Result("REVIEW REQUIRED", "Browser verification could not be completed; see details.", {**details, "error": str(exc)}, ["Browser lane failed"])


def scan_captcha_missing(
    target: str,
    *,
    config: Optional[TC12Config] = None,
    progress: Optional[Callable[[str], None]] = None,
) -> dict[str, Any]:
    """Run TC12. HTTP lane is primary; browser lane is used only when HTTP is inconclusive."""
    config = config or TC12Config()
    from authentication.auth_discovery import login_page_candidates
    if progress:
        progress("TC12: inspecting login page for CAPTCHA enforcement")
    http_result = None
    target_url = _normalize_target(target, config.login_path)
    for candidate in login_page_candidates(target, config.login_path)[:6] or [target_url]:
        current = _http_scan(candidate, config)
        http_result = current
        target_url = candidate
        if "No local username/password login form was identified" in (current.summary or ""):
            continue
        if current.status in {"SAFE", "UNSAFE", "NOT_ASSESSED", "ERROR"}:
            return current.as_dict()
        break
    if http_result is None:
        http_result = _http_scan(target_url, config)
    if http_result.status in {"SAFE", "UNSAFE", "NOT_ASSESSED", "ERROR"}:
        return http_result.as_dict()
    browser_result = _browser_scan(target_url, config)
    if browser_result is not None:
        return browser_result.as_dict()
    return http_result.as_dict()


def scan(target: str, **kwargs: Any) -> dict[str, Any]:
    return scan_captcha_missing(target, **kwargs)
