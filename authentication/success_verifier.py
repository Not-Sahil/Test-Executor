from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

from .evidence import normalize_text
from .models import AuthMechanism, AuthenticationVerification


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
)
MFA_MARKERS = (
    "two-factor",
    "two factor",
    "multi-factor",
    "multifactor",
    "verification code",
    "authenticator app",
    "one-time password",
    "otp",
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


def _has_login_path(url: str) -> bool:
    path = (urlparse(url).path or "").lower()
    return any(token in path for token in ("login", "signin", "sign-in"))


def _json_auth_success(response: requests.Response) -> bool:
    try:
        data = response.json()
    except ValueError:
        return False
    if not isinstance(data, dict):
        return False
    lower_keys = {str(k).lower() for k in data.keys()}
    if "token" in lower_keys or "access_token" in lower_keys or "id_token" in lower_keys:
        return True
    for key in ("authenticated", "isAuthenticated", "logged_in", "loggedIn"):
        if data.get(key) is True:
            return True
    return False


def verify_authentication(
    response: requests.Response | None,
    mechanism: AuthMechanism,
    baseline_url: str = "",
) -> AuthenticationVerification:
    if response is None:
        return AuthenticationVerification(
            state="AMBIGUOUS",
            confirmed=False,
            reason="authentication request produced no response",
        )

    try:
        body = response.text[:20000]
    except Exception:
        body = ""
    normalized = normalize_text(body, limit=20000).lower()
    location = response.headers.get("Location", "")

    rate_signals = ("too many requests", "rate limit", "temporarily blocked", "account locked")
    if response.status_code == 429 or any(marker in normalized for marker in rate_signals):
        return AuthenticationVerification("RATE_LIMITED", False, reason="rate limiting/lockout response")

    if any(marker in normalized for marker in MFA_MARKERS):
        # MFA may mean primary credentials were accepted, but full authentication is not proven.
        return AuthenticationVerification(
            state="MFA_REQUIRED",
            confirmed=False,
            mfa_required=True,
            reason="response indicates a second authentication factor is required",
        )

    if any(marker in normalized for marker in PASSWORD_CHANGE_MARKERS):
        return AuthenticationVerification(
            state="PASSWORD_CHANGE_REQUIRED",
            confirmed=False,
            password_change_required=True,
            reason="response requires password change before normal account use",
        )

    if any(marker in normalized for marker in FAILURE_MARKERS):
        return AuthenticationVerification(
            state="REJECTED",
            confirmed=False,
            reason="explicit authentication failure marker detected",
        )

    if mechanism.type == "http_basic":
        if response.status_code in {401, 403}:
            return AuthenticationVerification("REJECTED", False, reason=f"HTTP {response.status_code} authentication rejection")
        if 200 <= response.status_code < 400:
            return AuthenticationVerification("AUTHENTICATED", True, reason="HTTP Basic challenge accepted")
        return AuthenticationVerification("AMBIGUOUS", False, reason=f"unexpected HTTP status {response.status_code}")

    if mechanism.type == "json_api":
        if _json_auth_success(response):
            return AuthenticationVerification("AUTHENTICATED", True, reason="JSON response contained an authentication/token success signal")
        if response.status_code in {401, 403, 422}:
            return AuthenticationVerification("REJECTED", False, reason=f"JSON login rejected with HTTP {response.status_code}")
        if 300 <= response.status_code < 400 and location and not _has_login_path(location):
            return AuthenticationVerification("AUTHENTICATED", True, reason="redirected away from login endpoint")
        return AuthenticationVerification("AMBIGUOUS", False, reason="JSON response did not provide a strong success or failure signal")

    # HTML form.
    explicit_logout = any(marker in normalized for marker in ("logout", "log out", "sign out", "sign off"))
    if explicit_logout:
        return AuthenticationVerification("AUTHENTICATED", True, reason="explicit post-login logout marker found")

    if 300 <= response.status_code < 400 and location:
        if _has_login_path(location):
            return AuthenticationVerification("REJECTED", False, reason="redirected back to login endpoint")
        return AuthenticationVerification("AUTHENTICATED", True, reason="redirected away from login endpoint")

    # Returning to the login page or rendering a password field is strong rejection evidence.
    if _has_login_path(response.url) or re.search(r'<input[^>]+type=["\']password', body, re.I):
        return AuthenticationVerification("REJECTED", False, reason="response remained on/login form")

    if any(marker in normalized for marker in ("welcome", "my account", "dashboard")) and not _has_login_path(response.url):
        return AuthenticationVerification("AUTHENTICATED", True, reason="post-login account/dashboard marker found outside login endpoint")

    if response.status_code in {401, 403, 422}:
        return AuthenticationVerification("REJECTED", False, reason=f"HTTP {response.status_code} authentication rejection")

    return AuthenticationVerification("AMBIGUOUS", False, reason="HTML response lacked a strong authentication success/failure signal")
