from __future__ import annotations

import re
from typing import Iterable


AUTH_FAILURE_MARKERS = (
    "invalid credentials",
    "invalid username",
    "invalid password",
    "incorrect password",
    "wrong password",
    "password is incorrect",
    "password is wrong",
    "login failed",
    "authentication failed",
    "unable to sign in",
    "access denied",
    "authentication error",
    "credentials are incorrect",
)

MFA_MARKERS = (
    "two-factor",
    "two factor",
    "multi-factor",
    "multifactor",
    "verification code",
    "authenticator app",
    "one-time password",
    "one time password",
    "otp",
    "enter the code",
    "security code",
)

PASSWORD_CHANGE_MARKERS = (
    "change your password",
    "change password",
    "password expired",
    "must change password",
    "reset your password",
)

CAPTCHA_MARKERS = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "turnstile",
    "challenge required",
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


def normalize_body(text: str) -> str:
    return " ".join(re.sub(r"\s+", " ", str(text or "").lower()).split())


def contains_any(text: str, markers: Iterable[str]) -> bool:
    value = normalize_body(text)
    return any(marker.lower() in value for marker in markers)


def detect_failure_marker(text: str) -> str | None:
    body = normalize_body(text)
    for marker in AUTH_FAILURE_MARKERS:
        if marker in body:
            return marker
    return None


def detect_mfa_marker(text: str) -> str | None:
    body = normalize_body(text)
    for marker in MFA_MARKERS:
        if marker in body:
            return marker
    return None


def detect_password_change_marker(text: str) -> str | None:
    body = normalize_body(text)
    for marker in PASSWORD_CHANGE_MARKERS:
        if marker in body:
            return marker
    return None


def detect_captcha_marker(text: str) -> str | None:
    body = normalize_body(text)
    for marker in CAPTCHA_MARKERS:
        if marker in body:
            return marker
    return None


def detect_success_marker(text: str) -> str | None:
    body = normalize_body(text)
    for marker in SUCCESS_MARKERS:
        if marker in body:
            return marker
    return None


def redact_password_for_evidence(password: str) -> str:
    if password == "":
        return "<empty>"
    return "*" * min(max(len(password), 8), 16)
