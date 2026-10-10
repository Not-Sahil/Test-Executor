from __future__ import annotations

"""
TC10 - Remember Me / Session Persistence

Additive login-page testcase.

This testcase evaluates whether an application's explicit "Remember Me"
functionality creates a persistent authentication state and whether that state
is invalidated appropriately on logout.

It deliberately does not modify or invoke TC01-TC09 scanners.

Key rules:
- Requires explicitly authorized credentials because an authenticated state
  must be established to test persistence.
- Does not report the remember-me checkbox itself as a finding.
- Does not report an ordinary session cookie as a finding merely because it
  lacks an Expires/Max-Age attribute.
- Does not expose cookie values or credentials in evidence.
- Does not attempt password guessing, enumeration, lockout testing, or CAPTCHA
  bypass.
- Uses a browser lane when Playwright is available because persistence across
  browser contexts cannot be reliably established with a single requests
  session.
- Falls back to an HTTP cookie inspection lane only when the application is
  sufficiently conventional.
"""

from dataclasses import dataclass, asdict
from html.parser import HTMLParser
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from authentication.auth_discovery import login_page_candidates

import requests

try:
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover
    sync_playwright = None


STATUS_SAFE = "SAFE"
STATUS_UNSAFE = "UNSAFE"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_ASSESSED = "NOT ASSESSED"


@dataclass
class RememberMeControl:
    selector_hint: str
    name: str
    value: str
    checked: bool
    label: str
    form_action: str
    form_method: str
    source_url: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class LoginPageParser(HTMLParser):
    def __init__(self, source_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.source_url = source_url
        self.controls: list[RememberMeControl] = []
        self._form: dict[str, Any] | None = None
        self._labels: list[tuple[str, str]] = []
        self._current_label_for: str = ""
        self._label_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        d = {str(k).lower(): (v or "") for k, v in attrs}

        if tag == "form":
            action = urljoin(self.source_url, d.get("action", "") or self.source_url)
            self._form = {
                "action": action,
                "method": (d.get("method", "POST") or "POST").upper(),
            }
            return

        if tag == "label":
            self._current_label_for = d.get("for", "").strip()
            self._label_text = []
            return

        if tag == "input":
            input_type = d.get("type", "text").strip().lower()
            if input_type != "checkbox":
                return

            name = d.get("name", "").strip()
            value = d.get("value", "1").strip()
            input_id = d.get("id", "").strip()
            aria = d.get("aria-label", "").strip()
            autocomplete = d.get("autocomplete", "").strip().lower()

            prior_label_text = " ".join(
                label_text for label_for, label_text in self._labels
                if label_for and label_for in {input_id, name}
            )
            joined = " ".join(
                x for x in (name, input_id, aria, value, autocomplete, prior_label_text) if x
            ).lower()

            if not _looks_like_remember_me(joined):
                return

            selector = (
                f"#{input_id}" if input_id
                else f'input[name="{name}"]' if name
                else "input[type=checkbox]"
            )

            self.controls.append(
                RememberMeControl(
                    selector_hint=selector,
                    name=name,
                    value=value,
                    checked="checked" in d,
                    label="",
                    form_action=(self._form or {}).get("action", self.source_url),
                    form_method=(self._form or {}).get("method", "POST"),
                    source_url=self.source_url,
                )
            )

    def handle_data(self, data: str) -> None:
        if self._current_label_for:
            self._label_text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "label" and self._current_label_for:
            label = " ".join(" ".join(self._label_text).split())
            if label:
                self._labels.append((self._current_label_for, label))
            for control in self.controls:
                if control.selector_hint == f"#{self._current_label_for}":
                    control.label = label
            self._current_label_for = ""
            self._label_text = []


def _looks_like_remember_me(text: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", " ", text.lower()).strip()
    compact = normalized.replace(" ", "")
    phrases = (
        "remember me",
        "remember login",
        "remember this device",
        "keep me signed in",
        "keep me logged in",
        "stay signed in",
        "stay logged in",
        "persistent login",
        "persist login",
    )
    return any(p in normalized for p in phrases) or any(
        p in compact
        for p in ("rememberme", "rememberlogin", "rememberdevice", "keepsignedin")
    )


def _normalize_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target URL is empty")
    if "://" not in raw:
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme.lower() not in {"http", "https"} or not p.netloc:
        raise ValueError("target must be a valid http:// or https:// URL")
    return p._replace(fragment="").geturl()


def _cookie_meta(cookie: requests.cookies.create_cookie) -> dict[str, Any]:
    # Never return cookie.value.
    expires = cookie.expires
    return {
        "name": cookie.name,
        "domain": cookie.domain,
        "path": cookie.path,
        "secure": bool(cookie.secure),
        "httponly": bool(cookie._rest.get("HttpOnly") or cookie._rest.get("httponly")),
        "samesite": cookie._rest.get("SameSite") or cookie._rest.get("samesite"),
        "persistent": expires is not None,
        "has_expires": expires is not None,
        "expires_present": expires is not None,
    }


def _response_cookie_meta(response: requests.Response) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    jar = getattr(response, "cookies", [])
    try:
        iterator = iter(jar)
    except TypeError:
        return records
    for cookie in iterator:
        try:
            records.append(_cookie_meta(cookie))
        except Exception:
            # Test doubles and nonstandard response wrappers may omit cookie fields.
            continue
    return records


def _fetch_login_page(
    target: str,
    login_path: str,
    timeout: float,
    verify_tls: bool,
) -> tuple[requests.Response | None, list[str], str]:
    base = _normalize_target(target)
    evidence: list[str] = []
    last_url = urljoin(base.rstrip("/") + "/", (login_path or "/login").lstrip("/"))
    last_error = ""
    for url in login_page_candidates(base, login_path):
        try:
            response = requests.get(
                url,
                timeout=timeout,
                verify=verify_tls,
                allow_redirects=True,
                headers={
                    "User-Agent": "TestExecutor-TC10/1.0",
                    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
                },
            )
        except requests.RequestException as exc:
            last_error = str(exc)
            last_url = url
            continue
        evidence.append(f"login_page_status={response.status_code}")
        evidence.append(f"login_page_url={response.url}")
        last_url = response.url
        controls = _parse_remember_controls(response)
        if controls or "password" in (response.text or "").lower():
            return response, evidence, response.url
    if last_error:
        evidence.append(f"login_page_request_error={last_error}")
        return None, evidence, last_url
    try:
        response = requests.get(
            last_url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=True,
            headers={
                "User-Agent": "TestExecutor-TC10/1.0",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
        )
        evidence.append(f"login_page_status={response.status_code}")
        evidence.append(f"login_page_url={response.url}")
        return response, evidence, response.url
    except requests.RequestException as exc:
        evidence.append(f"login_page_request_error={exc}")
        return None, evidence, last_url


def _parse_remember_controls(response: requests.Response | None) -> list[RememberMeControl]:
    if response is None:
        return []

    parser = LoginPageParser(response.url)
    try:
        parser.feed((response.text or "")[:1_500_000])
        parser.close()
    except Exception:
        pass
    return parser.controls


def _has_captcha_or_sso(html: str, url: str) -> tuple[bool, str]:
    lower = (html or "").lower()
    if any(
        marker in lower or marker in url.lower()
        for marker in (
            "recaptcha",
            "hcaptcha",
            "turnstile",
            "captcha",
        )
    ):
        return True, "captcha_detected"

    if any(
        marker in lower or marker in url.lower()
        for marker in (
            "oauth",
            "openid",
            "oidc",
            "saml",
            "accounts.google.com",
            "login.microsoftonline.com",
        )
    ):
        return True, "federated_or_external_auth_detected"

    return False, ""


def _redact_username(username: str) -> str:
    if not username:
        return ""
    if "@" in username:
        local, domain = username.split("@", 1)
        return (local[:1] + "***@" + domain) if local else "***@" + domain
    return username[:1] + "***"


def _safe_cookie_names(cookies: list[dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(c.get("name", ""))
            for c in cookies
            if c.get("name")
        }
    )


def _looks_like_auth_cookie(name: str) -> bool:
    n = name.lower()
    return any(
        token in n
        for token in (
            "session",
            "sess",
            "auth",
            "token",
            "jwt",
            "refresh",
            "remember",
            "login",
        )
    )


def _classify_cookie_persistence(
    cookies: list[dict[str, Any]],
) -> dict[str, Any]:
    auth = [
        c for c in cookies
        if _looks_like_auth_cookie(str(c.get("name", "")))
    ]
    persistent_auth = [
        c for c in auth
        if bool(c.get("persistent"))
    ]
    return {
        "all_cookie_names": _safe_cookie_names(cookies),
        "auth_cookie_names": _safe_cookie_names(auth),
        "persistent_auth_cookie_names": _safe_cookie_names(persistent_auth),
        "persistent_auth_cookie_count": len(persistent_auth),
        "auth_cookie_count": len(auth),
    }


def _browser_scan(
    target: str,
    login_path: str,
    username: str,
    password: str,
    *,
    timeout_ms: int,
    verify_tls: bool,
    protected_urls: tuple[str, ...],
) -> dict[str, Any]:
    if sync_playwright is None:
        return {
            "available": False,
            "status": STATUS_REVIEW,
            "reason": "playwright_unavailable",
            "evidence": ["browser_lane_unavailable"],
        }

    base = _normalize_target(target)
    login_url = urljoin(
        base.rstrip("/") + "/",
        (login_path or "/login").lstrip("/"),
    )

    evidence: list[str] = []
    snapshots: dict[str, Any] = {}

    def inspect_context(context, page, label: str) -> dict[str, Any]:
        cookies = context.cookies()
        safe_cookies = [
            {
                "name": c.get("name"),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "secure": bool(c.get("secure")),
                "httpOnly": bool(c.get("httpOnly")),
                "sameSite": c.get("sameSite"),
                "expires": c.get("expires"),
                "persistent": bool(c.get("expires", 0) not in (0, -1)),
            }
            for c in cookies
        ]
        return {
            "label": label,
            "url": page.url,
            "cookies": safe_cookies,
            "cookie_names": sorted({c["name"] for c in safe_cookies if c["name"]}),
        }

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)

        # Context A: Remember Me CHECKED.
        context_a = browser.new_context(ignore_https_errors=not verify_tls)
        page_a = context_a.new_page()
        try:
            page_a.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page_a.wait_for_timeout(300)

            controls = page_a.locator(
                'input[type="checkbox"]'
            )
            remember_indexes: list[int] = []

            for i in range(min(controls.count(), 50)):
                el = controls.nth(i)
                try:
                    text = (
                        (el.get_attribute("name") or "")
                        + " "
                        + (el.get_attribute("id") or "")
                        + " "
                        + (el.get_attribute("aria-label") or "")
                        + " "
                        + (el.get_attribute("value") or "")
                    )
                    parent_text = ""
                    try:
                        parent_text = el.locator("xpath=..").inner_text(timeout=500)
                    except Exception:
                        pass
                    if _looks_like_remember_me(text + " " + parent_text):
                        remember_indexes.append(i)
                except Exception:
                    continue

            if not remember_indexes:
                return {
                    "available": True,
                    "status": STATUS_NOT_ASSESSED,
                    "reason": "remember_me_control_not_found",
                    "evidence": ["no_remember_me_control_detected"],
                    "browser": True,
                }

            checkbox = controls.nth(remember_indexes[0])
            if not checkbox.is_checked():
                checkbox.check()

            # Discover username/password inputs without assuming names.
            user_candidates = page_a.locator(
                'input:not([type="hidden"]):not([type="password"])'
            )
            pass_candidates = page_a.locator('input[type="password"]')

            if pass_candidates.count() == 0 or user_candidates.count() == 0:
                return {
                    "available": True,
                    "status": STATUS_REVIEW,
                    "reason": "credential_fields_not_found",
                    "evidence": ["browser_credential_fields_not_found"],
                    "browser": True,
                }

            user_input = user_candidates.nth(0)
            pass_input = pass_candidates.nth(0)

            user_input.fill(username)
            pass_input.fill(password)

            submit = page_a.locator(
                'button[type="submit"], input[type="submit"]'
            )
            if submit.count() == 0:
                submit = page_a.locator(
                    'button:has-text("Sign in"), '
                    'button:has-text("Login"), '
                    'button:has-text("Log in"), '
                    'button:has-text("Sign In")'
                )

            if submit.count() == 0:
                return {
                    "available": True,
                    "status": STATUS_REVIEW,
                    "reason": "submit_control_not_found",
                    "evidence": ["browser_submit_control_not_found"],
                    "browser": True,
                }

            submit.nth(0).click()
            page_a.wait_for_timeout(700)

            first = inspect_context(context_a, page_a, "remember_me_checked_after_login")
            snapshots["checked_after_login"] = first

            # Verify the authenticated state using protected URLs if configured.
            protected_results: list[dict[str, Any]] = []
            for path in protected_urls[:5]:
                if not path:
                    continue
                p = page_a if path.startswith("http") else page_a
                url = path if path.startswith("http") else urljoin(
                    base.rstrip("/") + "/", path.lstrip("/")
                )
                try:
                    response = p.request.get(url, timeout=timeout_ms)
                    protected_results.append({
                        "url": url,
                        "status": response.status,
                        "final_url": response.url,
                    })
                except Exception as exc:
                    protected_results.append({
                        "url": url,
                        "error": str(exc),
                    })

            snapshots["protected_access"] = protected_results

            # Close the first browser context. This is the critical persistence
            # boundary: cookies/storage from Context A are not copied to B.
            context_a.close()

            # Context B: fresh browser context, same profile-free browser.
            context_b = browser.new_context(ignore_https_errors=not verify_tls)
            page_b = context_b.new_page()
            page_b.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
            page_b.wait_for_timeout(300)

            before = inspect_context(context_b, page_b, "fresh_context_before_relogin")
            snapshots["fresh_context_before_relogin"] = before

            # A persistent remember-me implementation should make the
            # authenticated state available without another password submission.
            persisted = False

            for path in protected_urls[:5]:
                if not path:
                    continue
                url = path if path.startswith("http") else urljoin(
                    base.rstrip("/") + "/", path.lstrip("/")
                )
                try:
                    response = page_b.request.get(url, timeout=timeout_ms)
                    if response.status in (200, 204):
                        body = (response.text() or "").lower()
                        if not any(
                            marker in body
                            for marker in (
                                "login",
                                "sign in",
                                "signin",
                                "authentication required",
                            )
                        ):
                            persisted = True
                            break
                except Exception:
                    continue

            after = inspect_context(context_b, page_b, "fresh_context_after_protected_probe")
            snapshots["fresh_context_after_protected_probe"] = after

            # If no protected URL was supplied, a fresh context cookie check is
            # insufficient to prove authentication persistence. Do not infer it.
            if not protected_urls:
                context_b.close()
                browser.close()
                return {
                    "available": True,
                    "status": STATUS_REVIEW,
                    "reason": "protected_url_required_for_persistence_confirmation",
                    "evidence": [
                        "remember_me_checked_login_completed",
                        "fresh_browser_context_created",
                        "no_protected_url_configured",
                    ],
                    "snapshots": snapshots,
                    "browser": True,
                }

            if persisted:
                evidence.append("authenticated_state_persisted_in_fresh_browser_context")
                result = STATUS_SAFE
                reason = "Remember Me persistence was observed without resubmitting credentials."
            else:
                evidence.append("fresh_browser_context_did_not_retain_authenticated_state")
                result = STATUS_REVIEW
                reason = (
                    "Remember Me was exercised, but the fresh browser context did not provide "
                    "sufficient evidence of persistent authentication."
                )

            # Logout invalidation check is deliberately performed only when
            # persistence was actually demonstrated.
            logout_verified = None
            if persisted:
                logout_controls = page_b.locator(
                    'a:has-text("Logout"), '
                    'a:has-text("Log out"), '
                    'button:has-text("Logout"), '
                    'button:has-text("Log out")'
                )
                if logout_controls.count():
                    logout_controls.nth(0).click()
                    page_b.wait_for_timeout(500)

                    context_c = browser.new_context(
                        ignore_https_errors=not verify_tls
                    )
                    page_c = context_c.new_page()
                    page_c.goto(login_url, wait_until="domcontentloaded", timeout=timeout_ms)
                    page_c.wait_for_timeout(250)

                    logout_access = []
                    for path in protected_urls[:5]:
                        url = path if path.startswith("http") else urljoin(
                            base.rstrip("/") + "/", path.lstrip("/")
                        )
                        try:
                            response = page_c.request.get(url, timeout=timeout_ms)
                            logout_access.append({
                                "url": url,
                                "status": response.status,
                                "final_url": response.url,
                            })
                        except Exception as exc:
                            logout_access.append({
                                "url": url,
                                "error": str(exc),
                            })

                    logout_verified = not any(
                        r.get("status") in (200, 204)
                        for r in logout_access
                    )
                    snapshots["post_logout_fresh_context"] = logout_access
                    context_c.close()

                    if logout_verified:
                        evidence.append("logout_invalidated_persistent_authentication")
                    else:
                        evidence.append("logout_invalidation_not_confirmed")
                        result = STATUS_REVIEW
                        reason = (
                            "Remember Me persistence was observed, but logout invalidation "
                            "could not be reliably confirmed."
                        )

            context_b.close()
            browser.close()

            return {
                "available": True,
                "status": result,
                "reason": reason,
                "evidence": evidence,
                "snapshots": snapshots,
                "logout_invalidation_verified": logout_verified,
                "browser": True,
            }

        except Exception as exc:
            try:
                context_a.close()
            except Exception:
                pass
            try:
                browser.close()
            except Exception:
                pass
            return {
                "available": True,
                "status": STATUS_REVIEW,
                "reason": f"browser_exception:{type(exc).__name__}",
                "evidence": [f"browser_error={exc}"],
                "snapshots": snapshots,
                "browser": True,
            }


def _http_fallback(
    target: str,
    login_path: str,
    username: str,
    password: str,
    timeout: float,
    verify_tls: bool,
) -> dict[str, Any]:
    """
    Conservative non-browser fallback.

    This does not claim persistence across a real browser restart. It only
    reports whether the login response creates a persistent-looking auth cookie
    and whether the page exposes a remember-me control.
    """
    response, evidence, login_url = _fetch_login_page(
        target,
        login_path,
        timeout,
        verify_tls,
    )

    if response is None:
        return {
            "status": STATUS_INCOMPLETE,
            "reason": "login_page_unreachable",
            "evidence": evidence,
        }

    controls = _parse_remember_controls(response)
    if not controls:
        return {
            "status": STATUS_NOT_ASSESSED,
            "reason": "remember_me_control_not_found",
            "evidence": evidence + ["remember_me_control_not_found"],
        }

    # We intentionally do not submit credentials in the HTTP fallback.
    # A requests-only lane cannot reliably reproduce browser storage semantics
    # or prove cross-context persistence.
    cookies = _response_cookie_meta(response)
    cookie_analysis = _classify_cookie_persistence(cookies)

    return {
        "status": STATUS_REVIEW,
        "reason": "browser_lane_required_for_persistence_confirmation",
        "evidence": evidence + [
            "http_fallback_did_not_submit_credentials",
            "cross_browser_context_persistence_not_testable_with_static_http",
        ],
        "controls": [c.as_dict() for c in controls],
        "cookie_analysis": cookie_analysis,
    }


def _result(
    target: str,
    status: str,
    summary: str,
    evidence: list[str],
    details: dict[str, Any],
) -> dict[str, Any]:
    assessment = {
        STATUS_UNSAFE: "CONFIRMED",
        STATUS_SAFE: "NOT_A_FINDING",
        STATUS_REVIEW: "REVIEW_REQUIRED",
        STATUS_INCOMPLETE: "INCOMPLETE",
        STATUS_NOT_ASSESSED: "NOT_ASSESSED",
    }.get(status, "REVIEW_REQUIRED")

    return {
        "key": "tc10_remember_me",
        "name": "Remember Me",
        "status": status,
        "assessment_state": assessment,
        "severity": None,
        "risk_score": None,
        "severity_rationale": "",
        "severity_components": {},
        "severity_metrics": {},
        "summary": summary,
        "target": target,
        "raw_output": "",
        "evidence": evidence,
        "details": details,
    }


def scan_remember_me(
    target: str,
    *,
    login_path: str = "/login",
    authorized_username: str | None = None,
    authorized_password: str | None = None,
    protected_urls: tuple[str, ...] = (),
    timeout: float = 10.0,
    timeout_ms: int = 15_000,
    verify_tls: bool = True,
    allow_browser: bool = True,
) -> dict[str, Any]:
    """
    Execute TC10.

    Persistence across logout requires an authorized account. The scanner still
    inspects the login page first so a missing Remember Me control is completed
    as not applicable instead of incomplete.
    """
    try:
        normalized = _normalize_target(target)
    except Exception as exc:
        return _result(
            target,
            STATUS_INCOMPLETE,
            "TC10 could not normalize the target URL.",
            [f"{type(exc).__name__}: {exc}"],
            {"finding_confirmed": False},
        )

    response, page_evidence, final_url = _fetch_login_page(
        normalized,
        login_path,
        timeout,
        verify_tls,
    )

    if response is None:
        return _result(
            normalized,
            STATUS_INCOMPLETE,
            "TC10 could not reach the configured login page.",
            page_evidence,
            {"finding_confirmed": False},
        )

    blocked, reason = _has_captcha_or_sso(response.text or "", final_url)
    if blocked:
        status = STATUS_NOT_ASSESSED if reason == "federated_or_external_auth_detected" else STATUS_REVIEW
        return _result(
            normalized,
            status,
            (
                "TC10 is not applicable to a federated authentication flow."
                if reason == "federated_or_external_auth_detected"
                else "TC10 requires manual interaction because the login route is protected by CAPTCHA."
            ),
            page_evidence + [reason],
            {
                "finding_confirmed": False,
                "credentials_submitted": False,
            },
        )

    controls = _parse_remember_controls(response)
    if not controls:
        return _result(
            normalized,
            STATUS_NOT_ASSESSED,
            "No Remember Me control was identified on the configured login page.",
            page_evidence + ["remember_me_control_not_found"],
            {
                "finding_confirmed": False,
                "credentials_submitted": False,
                "controls": [],
            },
        )

    if not authorized_username or authorized_password is None or authorized_password == "":
        default_checked = any(c.checked for c in controls)
        status = STATUS_UNSAFE if default_checked else STATUS_REVIEW
        summary = (
            "A Remember Me control is present and checked by default, which can persist credentials in the browser."
            if default_checked else
            "A Remember Me control is present. Persistence after login was not tested because no authorized "
            "account was supplied; provide a test account to complete that check."
        )
        return _result(
            normalized,
            status,
            summary,
            page_evidence + ["remember_me_control_found", "missing_authorized_credentials_for_persistence_lane"],
            {
                "finding_confirmed": default_checked,
                "credentials_submitted": False,
                "controls": [c.as_dict() for c in controls],
                "operator_action": (
                    "Supply an authorized test account to verify whether Remember Me creates a persistent session."
                ),
            },
        )

    details: dict[str, Any] = {
        "finding_confirmed": False,
        "credentials_submitted": False,
        "authorized_username": _redact_username(authorized_username),
        "remember_me_controls": [c.as_dict() for c in controls],
        "protected_urls": list(protected_urls),
        "scope_boundaries": [
            "TC10 evaluates Remember Me/session persistence.",
            "TC01 evaluates autocomplete metadata.",
            "TC07 evaluates browser memory retention.",
            "TC08/TC09 evaluate transport security.",
            "TC17 evaluates lockout/rate limiting.",
            "TC10 does not test password guessing or session fixation.",
        ],
    }

    if allow_browser and sync_playwright is not None:
        browser_result = _browser_scan(
            normalized,
            login_path,
            authorized_username,
            authorized_password,
            timeout_ms=timeout_ms,
            verify_tls=verify_tls,
            protected_urls=protected_urls,
        )
        details["browser_result"] = {
            k: v for k, v in browser_result.items()
            if k not in {"password", "authorized_password"}
        }

        return _result(
            normalized,
            browser_result["status"],
            browser_result.get("reason", "TC10 browser assessment completed."),
            page_evidence + list(browser_result.get("evidence") or []),
            details,
        )

    fallback = _http_fallback(
        normalized,
        login_path,
        authorized_username,
        authorized_password,
        timeout,
        verify_tls,
    )
    details["http_fallback"] = fallback

    return _result(
        normalized,
        fallback["status"],
        fallback["reason"],
        page_evidence + list(fallback.get("evidence") or []),
        details,
    )


scan = scan_remember_me


__all__ = [
    "RememberMeControl",
    "LoginPageParser",
    "scan_remember_me",
    "scan",
]
