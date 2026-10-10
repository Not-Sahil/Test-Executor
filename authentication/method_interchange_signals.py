from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from urllib.parse import urljoin, urlparse

FAILURE_MARKERS = (
    "invalid username",
    "invalid password",
    "invalid credentials",
    "incorrect password",
    "wrong password",
    "login failed",
    "authentication failed",
    "access denied",
    "unauthorized",
    "sign in failed",
    "sign-in failed",
    "incorrect login",
)

AUTH_MARKERS = (
    "logout",
    "log out",
    "sign out",
    "dashboard",
    "my account",
    "account overview",
    "welcome",
)

RATE_LIMIT_MARKERS = (
    "too many requests",
    "rate limit",
    "temporarily blocked",
    "try again later",
    "account locked",
    "locked out",
    "too many login attempts",
)

CSRF_MARKERS = (
    "csrf",
    "xsrf",
    "invalid authenticity token",
    "invalid verification token",
    "invalid token",
)

METHOD_REJECTION_STATUSES = {405, 501}

def normalize_url(base: str, path_or_url: str) -> str:
    candidate = path_or_url.strip()
    if candidate.startswith(("http://", "https://")):
        return candidate
    return urljoin(base.rstrip("/") + "/", candidate.lstrip("/"))

def same_origin(base: str, candidate: str) -> bool:
    a = urlparse(base)
    b = urlparse(candidate)
    if a.scheme not in {"http", "https"} or b.scheme not in {"http", "https"}:
        return False
    return (a.scheme, a.netloc.lower()) == (b.scheme, b.netloc.lower())

def normalize_body(text: str) -> str:
    if not text:
        return ""
    body = text.lower()
    body = re.sub(
        r'(?i)(csrf|xsrf|nonce|token|state|request[_-]?id|session(?:id)?)[=:]\s*["\']?[^"\'\s>&]+',
        r"\1=<dynamic>",
        body,
    )
    body = re.sub(r"\b\d{10,18}\b", "<number>", body)
    body = re.sub(r"\b[a-f0-9]{16,}\b", "<hex>", body)
    body = re.sub(r"\s+", " ", body)
    return body.strip()

def body_fingerprint(text: str) -> str:
    return hashlib.sha256(normalize_body(text).encode("utf-8", "ignore")).hexdigest()

def body_contains(text: str, markers: tuple[str, ...]) -> bool:
    lower = text.lower()
    return any(marker in lower for marker in markers)

def classify_response(
    *,
    status_code: int | None,
    final_url: str,
    body: str,
    expected_login_url: str,
    response_headers: Mapping[str, str] | None = None,
) -> dict:
    headers = {str(k).lower(): str(v) for k, v in (response_headers or {}).items()}
    location = headers.get("location", "")
    rate_limited = (
        status_code == 429
        or body_contains(body, RATE_LIMIT_MARKERS)
        or "retry-after" in headers
    )
    csrf_rejected = body_contains(body, CSRF_MARKERS)
    rejected = (
        status_code in {400, 401, 403, 422}
        or status_code in METHOD_REJECTION_STATUSES
        or body_contains(body, FAILURE_MARKERS)
        or csrf_rejected
    )

    parsed_expected = urlparse(expected_login_url)
    parsed_final = urlparse(final_url)
    left_login_path = (
        parsed_final.path.rstrip("/") != parsed_expected.path.rstrip("/")
    )
    redirect_away = bool(location) and not location.endswith(parsed_expected.path)

    authenticated_signal = (
        not rejected
        and not rate_limited
        and (
            body_contains(body, AUTH_MARKERS)
            or left_login_path
            or redirect_away
            or status_code in {302, 303, 307, 308}
        )
    )

    return {
        "authenticated_signal": authenticated_signal,
        "rejected_signal": rejected,
        "rate_limited": rate_limited,
        "csrf_rejected": csrf_rejected,
        "left_login_path": left_login_path,
        "redirect_away": redirect_away,
        "location": location,
        "body_fingerprint": body_fingerprint(body),
        "normalized_length": len(normalize_body(body)),
    }

def infer_auth_cookies(
    cookies: Mapping[str, str] | None,
    hints: tuple[str, ...],
) -> list[str]:
    names: list[str] = []
    for name in (cookies or {}).keys():
        lower = str(name).lower()
        if any(hint.lower() in lower for hint in hints):
            names.append(str(name))
    return sorted(set(names))

def compact_method_evidence(
    method: str,
    status_code: int | None,
    final_url: str,
    signals: dict,
) -> str:
    return (
        f"{method}: status={status_code}, final_url={final_url}, "
        f"authenticated_signal={signals['authenticated_signal']}, "
        f"rejected_signal={signals['rejected_signal']}, "
        f"rate_limited={signals['rate_limited']}, "
        f"csrf_rejected={signals['csrf_rejected']}"
    )
