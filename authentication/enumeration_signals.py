from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher
from urllib.parse import urlparse


INVALID_USERNAME_MARKERS = (
    "invalid username",
    "username is invalid",
    "unknown user",
    "user not found",
    "user does not exist",
    "user doesn't exist",
    "account not found",
    "account does not exist",
    "no such user",
    "unrecognized user",
    "invalid userid",
    "invalid user id",
    "unknown account",
)

INVALID_PASSWORD_MARKERS = (
    "invalid password",
    "password is invalid",
    "wrong password",
    "incorrect password",
    "password incorrect",
    "password does not match",
    "password doesn't match",
    "bad password",
    "credentials are invalid",
)

GENERIC_FAILURE_MARKERS = (
    "invalid credentials",
    "invalid credential",
    "username or password",
    "user or password",
    "userid or password",
    "login failed",
    "authentication failed",
    "sign in failed",
    "unable to sign in",
    "access denied",
)

RATE_LIMIT_MARKERS = (
    "too many requests",
    "rate limit",
    "rate-limit",
    "temporarily blocked",
    "try again later",
    "slow down",
    "request limit",
    "account locked",
    "account lock",
    "locked out",
    "captcha required",
)

EXPLICIT_DISCLOSURE_PATTERNS = (
    r"\baccount(?:\s+[^\s<]{1,128})?\s+(?:exists|found)\b",
    r"\buser(?:\s+[^\s<]{1,128})?\s+(?:exists|found)\b",
    r"\busername(?:\s+[^\s<]{1,128})?\s+(?:exists|found)\b",
    r"\baccount\s+with\s+that\s+(?:username|email)\b",
    r"\buser\s+is\s+registered\b",
    r"\bemail\s+is\s+registered\b",
)


def normalize_dynamic_content(body: str, *, limit: int = 20000) -> str:
    text = str(body or "")[:limit].lower()
    if not text:
        return ""

    text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.I | re.S)

    dynamic_key = (
        r"csrf|xsrf|nonce|authenticity[_-]?token|verification[_-]?token|"
        r"session(?:id)?|sid|request[_-]?id|trace[_-]?id|correlation[_-]?id|"
        r"timestamp|token|state"
    )
    text = re.sub(
        rf'(?i)({dynamic_key})\s*=\s*["\']?[^"\'\s>&]+',
        r"\1=<dynamic>",
        text,
    )
    text = re.sub(
        rf"(?i)({dynamic_key})=([^&\s\"']+)",
        r"\1=<dynamic>",
        text,
    )
    text = re.sub(
        r"\b\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?\b",
        "<timestamp>",
        text,
    )
    text = re.sub(r"\b\d{10,18}\b", "<number>", text)
    text = re.sub(r"\b[a-f0-9]{16,}\b", "<hex>", text)
    return " ".join(text.split())


def normalized_digest(body: str) -> str:
    normalized = normalize_dynamic_content(body)
    return hashlib.sha256(normalized.encode("utf-8", "ignore")).hexdigest()


def classify_message(body: str) -> str:
    text = normalize_dynamic_content(body)
    if not text:
        return "none"
    if any(marker in text for marker in INVALID_USERNAME_MARKERS):
        return "invalid_username"
    if any(marker in text for marker in INVALID_PASSWORD_MARKERS):
        return "invalid_password"
    if any(marker in text for marker in GENERIC_FAILURE_MARKERS):
        return "generic_failure"
    return "other"


def has_password_step(body: str) -> bool:
    text = body or ""
    return bool(
        re.search(
            r'<input\b[^>]*\btype\s*=\s*["\']password["\']',
            text,
            re.I,
        )
        or re.search(r'"password"\s*:', text, re.I)
    )


def normalize_path(url: str) -> str:
    try:
        return urlparse(url or "").path or "/"
    except Exception:
        return "/"


def explicit_username_disclosure(body: str, username: str) -> bool:
    text = normalize_dynamic_content(body)
    candidate = str(username or "").strip().lower()
    if not candidate:
        return False
    if candidate not in text:
        return False
    return any(re.search(pattern, text, re.I) for pattern in EXPLICIT_DISCLOSURE_PATTERNS)


def body_similarity(a: str, b: str, *, max_chars: int = 10000) -> float:
    a_norm = normalize_dynamic_content(a)[:max_chars]
    b_norm = normalize_dynamic_content(b)[:max_chars]
    if not a_norm and not b_norm:
        return 1.0
    if not a_norm or not b_norm:
        return 0.0
    return round(SequenceMatcher(None, a_norm, b_norm, autojunk=False).ratio(), 4)


def is_rate_limited(status: int | None, body: str) -> bool:
    if status in {420, 423, 429}:
        return True
    lowered = normalize_dynamic_content(body)
    return any(marker in lowered for marker in RATE_LIMIT_MARKERS)
