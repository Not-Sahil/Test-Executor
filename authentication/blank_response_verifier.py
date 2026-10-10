from __future__ import annotations

import json
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import requests

from .evidence import normalize_text
from .models import AuthMechanism


FAILURE_MARKERS = (
    "invalid credentials",
    "invalid username",
    "invalid password",
    "incorrect password",
    "wrong password",
    "login failed",
    "authentication failed",
    "access denied",
    "unable to sign in",
    "unauthorized",
    "required field",
    "field is required",
    "username is required",
    "password is required",
    "credentials are required",
)
CAPTCHA_MARKERS = (
    "g-recaptcha",
    "grecaptcha",
    "hcaptcha",
    "cf-turnstile",
    "captcha required",
    "verify you are human",
)
MFA_MARKERS = (
    "two-factor",
    "two factor",
    "multi-factor",
    "multifactor",
    "verification code",
    "authenticator app",
    "one-time password",
    "enter the code",
)
PASSWORD_CHANGE_MARKERS = (
    "change your password",
    "change password",
    "password expired",
    "must change password",
    "reset your password",
)
SUCCESS_MARKERS = (
    "logout",
    "log out",
    "sign out",
    "sign off",
    "welcome",
    "my account",
    "dashboard",
)


@dataclass(frozen=True)
class VerificationResult:
    state: str
    authenticated: bool
    mfa_required: bool = False
    password_change_required: bool = False
    captcha_blocked: bool = False
    reason: str = ""
    evidence: tuple[str, ...] = ()


def _has_login_path(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(token in path for token in ("login", "signin", "sign-in"))


def _json_success(response: requests.Response) -> bool:
    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError):
        return False
    if not isinstance(data, dict):
        return False
    if any(data.get(k) is True for k in ("authenticated", "isAuthenticated", "logged_in", "loggedIn")):
        return True
    for key in ("token", "access_token", "id_token", "session", "sessionId"):
        value = data.get(key)
        if value:
            return True
    status = str(data.get("status") or data.get("result") or "").lower()
    return status in {"authenticated", "success", "logged_in", "ok"}



def has_explicit_authentication_signal(response: requests.Response | None) -> bool:
    """Return True only when the auth endpoint itself explicitly reports authentication success."""
    if response is None:
        return False
    try:
        data = response.json()
    except (ValueError, json.JSONDecodeError):
        data = None
    if isinstance(data, dict):
        if any(data.get(k) is True for k in ("authenticated", "isAuthenticated", "logged_in", "loggedIn")):
            return True
        for key in ("token", "access_token", "id_token", "session", "sessionId"):
            value = data.get(key)
            if value:
                return True
    return False

def verify_blank_response(
    response: requests.Response | None,
    mechanism: AuthMechanism,
) -> VerificationResult:
    if response is None:
        return VerificationResult("ERROR", False, reason="no HTTP response was produced")

    try:
        body = response.text[:30000]
    except Exception:
        body = ""
    normalized = normalize_text(body, limit=30000).lower()
    location = response.headers.get("Location", "")

    if response.status_code in {420, 423, 429} or any(
        marker in normalized for marker in ("too many requests", "rate limit", "temporarily blocked", "account locked", "locked out")
    ):
        return VerificationResult("RATE_LIMITED", False, reason="rate limiting or lockout signal detected")

    if any(marker in normalized for marker in CAPTCHA_MARKERS):
        return VerificationResult("CAPTCHA_BLOCKED", False, captcha_blocked=True, reason="CAPTCHA/challenge signal detected")

    if any(marker in normalized for marker in MFA_MARKERS):
        return VerificationResult(
            "MFA_REQUIRED",
            False,
            mfa_required=True,
            reason="primary authentication may have advanced to a second factor, but full authentication is not proven",
        )

    if any(marker in normalized for marker in PASSWORD_CHANGE_MARKERS):
        return VerificationResult(
            "PASSWORD_CHANGE_REQUIRED",
            False,
            password_change_required=True,
            reason="authentication flow requires a password change before normal account use",
        )

    if any(marker in normalized for marker in FAILURE_MARKERS):
        return VerificationResult("REJECTED", False, reason="explicit authentication failure/validation marker detected")

    if mechanism.type == "http_basic":
        if response.status_code in {401, 403}:
            return VerificationResult("REJECTED", False, reason=f"HTTP Basic returned HTTP {response.status_code}")
        if 200 <= response.status_code < 300:
            return VerificationResult("CANDIDATE_SUCCESS", False, reason="HTTP Basic returned a successful response; protected-resource verification is still required")
        return VerificationResult("AMBIGUOUS", False, reason=f"HTTP Basic returned HTTP {response.status_code}")

    if mechanism.type == "json_api":
        if _json_success(response):
            return VerificationResult(
                "CANDIDATE_SUCCESS",
                False,
                reason="JSON response contained an authentication/session success signal; independent protected-resource verification is still required",
            )
        if response.status_code in {400, 401, 403, 422}:
            return VerificationResult("REJECTED", False, reason=f"JSON authentication rejected with HTTP {response.status_code}")
        if 300 <= response.status_code < 400 and location and not _has_login_path(location):
            return VerificationResult("CANDIDATE_SUCCESS", False, reason="JSON authentication redirected away from login; protected-resource verification is still required")
        return VerificationResult("AMBIGUOUS", False, reason="JSON response lacked a decisive authentication signal")

    # HTML/form behavior.
    if any(marker in normalized for marker in SUCCESS_MARKERS) and not _has_login_path(response.url):
        return VerificationResult("CANDIDATE_SUCCESS", False, reason="post-login marker found outside the login page; protected-resource verification is still required")

    if 300 <= response.status_code < 400 and location:
        if _has_login_path(location):
            return VerificationResult("REJECTED", False, reason="redirected back to the login flow")
        return VerificationResult("CANDIDATE_SUCCESS", False, reason="redirected away from the login flow; protected-resource verification is still required")

    if _has_login_path(response.url) or re.search(r'<input[^>]+type=["\']password', body, re.I):
        return VerificationResult("REJECTED", False, reason="response remained on or returned to a login/password form")

    if response.status_code in {400, 401, 403, 422}:
        return VerificationResult("REJECTED", False, reason=f"HTTP {response.status_code} authentication rejection")

    return VerificationResult("AMBIGUOUS", False, reason="response lacked a strong authentication success/failure signal")


def verify_protected_access(
    session: requests.Session,
    base_url: str,
    protected_urls: tuple[str, ...],
    *,
    timeout: float = 6.0,
) -> tuple[bool, str, list[str]]:
    """Require a configured protected endpoint before confirming an HTTP success signal."""
    evidence: list[str] = []
    if not protected_urls:
        return False, "not_configured", ["No protected URL was configured for independent authentication verification."]

    for path in protected_urls:
        target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        try:
            response = session.get(target, timeout=timeout, allow_redirects=True)
        except requests.RequestException as exc:
            evidence.append(f"protected verification failed for {target}: {exc}")
            continue

        body = ""
        try:
            body = normalize_text(response.text[:20000], limit=20000).lower()
        except Exception:
            pass

        login_redirect = _has_login_path(response.url)
        authenticated_marker = any(marker in body for marker in SUCCESS_MARKERS)
        accessible = 200 <= response.status_code < 300 and not login_redirect and (authenticated_marker or response.url.rstrip("/") != target.rstrip("/"))

        evidence.append(
            f"protected verification {target}: status={response.status_code} final={response.url} "
            f"login_redirect={login_redirect} authenticated_marker={authenticated_marker}"
        )
        if accessible:
            return True, "protected_resource_access_confirmed", evidence

    return False, "protected_resource_access_not_confirmed", evidence
