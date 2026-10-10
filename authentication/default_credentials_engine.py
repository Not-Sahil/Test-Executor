"""
default_creds_lane.py
WSTG-ATHN-02 : Testing for Default Credentials
WSTG-IDNT-04 : Username enumeration (HttpDefaultCredChecker.enumerate_usernames)

Execution-layer module for credential-mcp-server. Deterministic dispatch:
  - HTTP(S) targets  -> form/basic-auth aware checker (this file)
  - non-HTTP services -> Hydra via subprocess, dormant unless opted in
    (HYDRA_ENABLED = True, or --enable-hydra on the runner)

Design constraints honored:
  - No LLM in the execution path. This module only produces structured
    JSON results; rationale/labeling (if any) stays upstream/downstream
    of this module, not inside it.
  - Optional lockout guard: backoff between attempts; no attempt cap unless
    the caller sets one. Independent of any tool-reported state.
  - Output schema aligned with your existing test-case/result schema
    (test_case_id, wstg_category, target, result, evidence).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from html import unescape
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urlparse, urlsplit

import requests

from .login_applicability import (
    federated_login_skip,
    format_not_applicable_summary,
    skip_evidence,
)

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError
except ImportError:  # Optional dependency; HTTP scanner still works without it.
    sync_playwright = None
    PlaywrightTimeoutError = Exception


# ---------------------------------------------------------------------------
# Scanner safety/performance limits
# ---------------------------------------------------------------------------
# These are deliberately conservative so a single slow target cannot stall the
# whole assessment. Callers can override them through HttpDefaultCredChecker.
DEFAULT_HTTP_TIMEOUT = 3.5
DEFAULT_AUTH_BUDGET_SECONDS = 45.0
DEFAULT_ENUM_BUDGET_SECONDS = 30.0


def _mask_secret(value: str) -> str:
    """Keep credentials out of scanner evidence/logs."""
    if value is None:
        return ""
    if value == "":
        return "<empty>"
    return "*" * min(max(len(value), 8), 16)


def _safe_pair(username: str, password: str) -> str:
    return f"{username}:{_mask_secret(password)}"


def _apply_federated_skip(result, skip: dict, test_name: str) -> None:
    result.result = ResultStatus.SKIPPED
    if hasattr(result, "auth_mechanism"):
        result.auth_mechanism = str(skip.get("classification") or "federated_idp")
    result.evidence.extend(skip_evidence(skip))
    result.summary = format_not_applicable_summary(test_name, skip)
    result.client_status = _client_status(result.result)
    result.finished_at = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Authorized credential input
# ---------------------------------------------------------------------------

def load_cred_pairs(path: Optional[str] = None) -> list[CredPair]:
    """Load authorized credential pairs from JSON.

    No built-in credentials are silently injected.  The caller must provide
    the JSON file containing credential pairs it is authorized to test.

    Expected format:
      [
        {"username": "admin", "password": "admin"},
        {"username": "operator", "password": "secret", "product_hint": "generic"}
      ]
    """
    if not path:
        return []

    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    if not isinstance(raw, list):
        raise ValueError("Credential JSON must contain a top-level array.")

    pairs: list[CredPair] = []
    for index, item in enumerate(raw, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"Credential entry {index} must be an object.")
        if "username" not in item or "password" not in item:
            raise ValueError(
                f"Credential entry {index} must contain username and password."
            )
        pairs.append(
            CredPair(
                str(item["username"]),
                str(item["password"]),
                item.get("product_hint"),
            )
        )
    return pairs


# ---------------------------------------------------------------------------
# Result schema# ---------------------------------------------------------------------------
# Result schema
# ---------------------------------------------------------------------------

class ResultStatus(str, Enum):
    VULNERABLE = "vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    LOCKOUT_ABORTED = "lockout_aborted"
    UNRESOLVED = "unresolved"       # couldn't determine auth mechanism
    ERROR = "error"
    SKIPPED = "skipped"             # present but not executed (e.g. Hydra dormant)


# Adaptive login discovery is deliberately allow-listed rather than a crawler.
COMMON_LOGIN_PATHS = (
    "/login",
    "/login.html",
    "/signin",
    "/signin.html",
    "/sign-in",
    "/auth/login",
    "/account/login",
)


def is_absolute_http_url(value: str) -> bool:
    parsed = urlparse((value or "").strip())
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def resolve_login_url(base_url: str, login_input: str) -> str:
    """Accept a full login URL or a path and return an absolute request URL."""
    raw = (login_input or "").strip() or "/login"
    if is_absolute_http_url(raw):
        return raw
    if raw.startswith("//") and "/" in raw[2:]:
        scheme = urlparse(base_url).scheme or "https"
        return f"{scheme}:{raw}"
    if not raw.startswith("/"):
        raw = "/" + raw
    return urljoin((base_url or "").rstrip("/") + "/", raw.lstrip("/"))

_RATE_LIMIT_STATUS_CODES = (420, 429)
_RATE_LIMIT_MARKERS = (
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

def _client_status(result: ResultStatus) -> str:
    if result == ResultStatus.VULNERABLE:
        return "UNSAFE"
    if result == ResultStatus.NOT_VULNERABLE:
        return "SAFE"
    return "REVIEW"

def _apply_auth_verdict(result: "DefaultCredResult") -> None:
    """Set vulnerable/not_vulnerable after credential attempts.

    A confirmed pair always wins. Lockout, error, skipped, and explicit
    unresolved outcomes (missing mechanism, baseline failure, budget)
    stay unchanged when no pair authenticated.
    """
    if result.successful_pairs:
        result.result = ResultStatus.VULNERABLE
        return
    if result.result in (
        ResultStatus.LOCKOUT_ABORTED,
        ResultStatus.ERROR,
        ResultStatus.UNRESOLVED,
        ResultStatus.SKIPPED,
    ):
        return
    result.result = ResultStatus.NOT_VULNERABLE


def _default_cred_summary(result) -> str:
    if result.result == ResultStatus.VULNERABLE:
        return "A supplied authorized credential pair was confirmed to authenticate successfully."
    if result.result == ResultStatus.NOT_VULNERABLE:
        return "No supplied credential pair was confirmed to authenticate successfully."
    if result.result == ResultStatus.LOCKOUT_ABORTED:
        return "Testing stopped because the target showed lockout or rate-limit behavior."
    if result.result == ResultStatus.UNRESOLVED:
        joined = " ".join(str(item) for item in (result.evidence or []))
        mechanism = str(getattr(result, "auth_mechanism", "") or "")
        if (
            mechanism in {"", "unresolved"}
            or "authentication mechanism could not be resolved" in joined
        ) and "discovered form" not in joined:
            return (
                "Login discovery did not find a usable authentication form or mechanism "
                "at the configured path. This is not a SAFE finding. "
                "Enter the correct login page path and rerun."
            )
        if "budget exhausted" in joined:
            return (
                "The authentication check did not finish within the time budget. "
                "This is not a SAFE finding."
            )
        return (
            "The authentication check could not be completed reliably. "
            "This is not a SAFE finding."
        )
    if result.result == ResultStatus.ERROR:
        return "The authentication check could not be completed reliably; manual review is required."
    if result.result == ResultStatus.SKIPPED:
        for item in result.evidence or []:
            text = str(item)
            if text.startswith("reason="):
                return format_not_applicable_summary("Default Credentials", {"reason": text[7:]})
        return "The default-credential check was skipped."
    return "The authentication check was not executed."

def _enum_summary(result) -> str:
    likely = [c.username for c in result.candidates if c.classification == "likely_valid"]
    inconclusive = [c.username for c in result.candidates if c.classification == "inconclusive"]
    disclosed = [
        c.username for c in result.candidates
        if c.classification == "likely_valid" and (c.signals or {}).get("page_disclosure")
    ]
    if disclosed:
        return (
            f"The login page disclosed {len(disclosed)} account identifier(s). "
            "This is username enumeration / information disclosure."
        )
    if likely:
        return (
            f"Potential username-enumeration differences were observed for "
            f"{len(likely)} candidate(s); manual verification is recommended."
        )
    if result.result == ResultStatus.NOT_VULNERABLE:
        return "No reliable username-enumeration difference was identified by the configured comparison signals."
    if result.result == ResultStatus.LOCKOUT_ABORTED:
        return "Enumeration testing stopped because the target showed lockout or rate-limit behavior."
    if inconclusive:
        return "Some username probes were inconclusive; the scanner did not treat them as confirmed enumeration."
    if result.result == ResultStatus.UNRESOLVED:
        return (
            "Login discovery did not find a usable login form for user enumeration. "
            "This is not a SAFE finding. Enter the correct login page path and rerun."
        )
    if result.result == ResultStatus.SKIPPED:
        for item in result.evidence or []:
            text = str(item)
            if text.startswith("reason="):
                return format_not_applicable_summary("User Enumeration", {"reason": text[7:]})
        return "The user-enumeration check was skipped."
    return "Username enumeration could not be determined reliably; manual review is required."


@dataclass
class AttemptResult:
    username: str
    password: str
    success: bool
    http_status: Optional[int] = None
    evidence: str = ""
    failure_reason: Optional[str] = None
    alert: Optional[str] = None


@dataclass
class DefaultCredResult:
    test_case_id: str
    wstg_category: str = "WSTG-ATHN-02"
    target: str = ""
    auth_mechanism: str = "unresolved"
    result: ResultStatus = ResultStatus.UNRESOLVED
    attempts_made: int = 0
    successful_pairs: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    client_status: str = "REVIEW"
    summary: str = "Authentication result requires review."

    def to_json(self) -> str:
        d = asdict(self)
        d["result"] = self.result.value
        return json.dumps(d, indent=2)


# ---------------------------------------------------------------------------
# WSTG-IDNT-04 — username enumeration (failure-reason classifier)
# ---------------------------------------------------------------------------

_USER_NOT_FOUND_MARKERS = (
    "user invalid",
    "username is invalid",
    "username invalid",
    "userid is invalid",
    "userid invalid",
    "invalid username",
    "invalid userid",
    "invalid user",
    "no such user",
    "unknown user",
    "user not found",
    "user does not exist",
    "user doesn't exist",
    "username not found",
    "account not found",
    "account does not exist",
    "unrecognized user",
)

_WRONG_PASSWORD_MARKERS = (
    "password invalid",
    "password is invalid",
    "invalid password",
    "incorrect password",
    "wrong password",
    "password is incorrect",
    "password incorrect",
    "bad password",
    "password does not match",
    "password doesn't match",
)

_GENERIC_CREDENTIAL_MARKERS = (
    "username or password",
    "user or password",
    "userid or password",
    "username/password",
    "user/password",
    "invalid credentials",
    "login failed",
)

_JS_ALERT_RE = re.compile(
    r"""(?:window\s*\.\s*)?alert\s*\(\s*(['"])(?P<msg>.*?)\1\s*\)""",
    re.IGNORECASE | re.DOTALL,
)


class _AlertTextParser(HTMLParser):
    """Visible text from error/alert/message elements (not a JS alert() only)."""

    _HINTS = ("alert", "error", "message", "errmsg", "fail", "warning")

    def __init__(self) -> None:
        super().__init__()
        self._depth = 0
        self._skip = 0
        self._buf: list[str] = []
        self.texts: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
            return
        if self._skip:
            return
        attrs_d = {k.lower(): (v or "").lower() for k, v in attrs}
        blob = f"{attrs_d.get('id', '')} {attrs_d.get('class', '')} {attrs_d.get('role', '')}"
        if any(hint in blob for hint in self._HINTS):
            if self._depth == 0:
                self._buf = []
            self._depth += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
            return
        if self._depth:
            self._depth -= 1
            if self._depth == 0:
                text = " ".join("".join(self._buf).split())
                if text:
                    self.texts.append(text)

    def handle_data(self, data):
        if self._skip == 0 and self._depth:
            self._buf.append(data)


_VALIDATION_ALERT_MARKERS = (
    "you must enter",
    "please enter",
    "field is required",
    "required field",
)


def _extract_login_alert(html: str) -> Optional[str]:
    """Grab the post-login error text.

    Prefer the visible on-page message (Altoro's Login Failed span) over
    alert() strings that live in page JavaScript (e.g. confirminput).
    """
    if not html:
        return None

    page_texts: list[str] = []
    parser = _AlertTextParser()
    try:
        parser.feed(html)
        parser.close()
        page_texts = parser.texts
    except Exception:
        page_texts = []

    js_alerts: list[str] = []
    for match in _JS_ALERT_RE.finditer(html):
        msg = " ".join(match.group("msg").replace("\\n", " ").split())
        if msg:
            js_alerts.append(msg)

    def _is_failure_text(text: str) -> bool:
        lower = text.lower()
        if any(v in lower for v in _VALIDATION_ALERT_MARKERS):
            return False
        return any(word in lower for word in (
            "fail", "invalid", "incorrect", "wrong", "not found",
            "denied", "sorry", "does not exist", "doesn't exist",
        ))

    for text in page_texts:
        if _is_failure_text(text):
            return text
    for text in js_alerts:
        if _is_failure_text(text):
            return text
    if page_texts:
        return page_texts[0]
    return js_alerts[0] if js_alerts else None


def _classify_failure_reason(body_lower: str, baseline_body_lower: Optional[str]) -> str:
    """Classify from the login alert/error text. Username phrases win over password phrases."""
    body = body_lower or ""
    if any(marker in body for marker in _GENERIC_CREDENTIAL_MARKERS):
        return "indistinguishable"
    user_hit = any(marker in body for marker in _USER_NOT_FOUND_MARKERS)
    pass_hit = any(marker in body for marker in _WRONG_PASSWORD_MARKERS)
    if user_hit and pass_hit:
        return "both_invalid"
    if user_hit:
        return "invalid_username"
    if pass_hit:
        return "invalid_password"
    if baseline_body_lower is not None and body != baseline_body_lower:
        return "unknown_but_differs_from_baseline"
    return "unknown"


@dataclass
class EnumerationCandidate:
    username: str
    classification: str  # "likely_valid" | "likely_invalid" | "inconclusive"
    signals: dict = field(default_factory=dict)
    evidence: str = ""


@dataclass
class EnumerationResult:
    test_case_id: str
    wstg_category: str = "WSTG-IDNT-04"
    target: str = ""
    signal_used: str = ""
    candidates: list[EnumerationCandidate] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    result: ResultStatus = ResultStatus.UNRESOLVED
    client_status: str = "REVIEW"
    summary: str = "Username enumeration result requires review."

    def to_json(self) -> str:
        d = asdict(self)
        d["result"] = self.result.value
        return json.dumps(d, indent=2)


_PROBE_WRONG_PASSWORD = "__wrong_password_idnt04__"
_FACTOR_LENGTH_SLOP = 15


def _normalize_dynamic_content(body: str) -> str:
    """Normalize common per-request values before comparing auth responses."""
    if not body:
        return ""
    text = body.lower()

    # Dynamic JS/CSS commonly contains build IDs and per-request values.
    text = re.sub(r"<script\b[^>]*>.*?</script>", " ", text, flags=re.I | re.S)
    text = re.sub(r"<style\b[^>]*>.*?</style>", " ", text, flags=re.I | re.S)

    # Common CSRF/session/token attributes and query-style values.
    token_key = (
        r"csrf|xsrf|nonce|authenticity_token|verification[_-]?token|"
        r"session(?:id)?|sid|token|state|request[_-]?id"
    )
    text = re.sub(
        rf'(?i)({token_key})\s*=\s*["\']?[^"\'\s>&]+',
        r"\1=<dynamic>",
        text,
    )
    text = re.sub(
        rf"(?i)({token_key})=([^&\s\"']+)",
        r"\1=<dynamic>",
        text,
    )

    text = re.sub(
        r"\b\d{4}-\d{2}-\d{2}[tT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:z|[+-]\d{2}:?\d{2})?\b",
        "<timestamp>",
        text,
    )
    text = re.sub(r"\b\d{10,16}\b", "<number>", text)
    text = re.sub(r"\b[a-f0-9]{16,}\b", "<hex>", text)
    return " ".join(text.split())


def _is_rate_limited_response(resp: Optional[requests.Response]) -> bool:
    if resp is None:
        return False
    if resp.status_code in _RATE_LIMIT_STATUS_CODES:
        return True

    headers = {str(k).lower(): str(v).lower() for k, v in resp.headers.items()}
    if "retry-after" in headers:
        return True
    if headers.get("x-ratelimit-remaining", "").strip() in {"0", "0.0"}:
        return True

    body = (resp.text or "").lower()
    return any(marker in body for marker in _RATE_LIMIT_MARKERS)


def _fingerprint_response(resp: Optional[requests.Response]) -> Optional[dict]:
    if resp is None:
        return None
    body = resp.text or ""
    normalized = _normalize_dynamic_content(body)
    alert = _extract_login_alert(body) or ""
    return {
        "status": resp.status_code,
        "url": (resp.url or "").rstrip("/"),
        "path": urlsplit(resp.url or "").path.rstrip("/").lower(),
        "length": len(normalized),
        "digest": hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()[:16],
        "marker": _classify_failure_reason(normalized, None),
        "message": _normalize_dynamic_content(alert),
        "rate_limited": _is_rate_limited_response(resp),
    }


def _same_fingerprint(
    a: Optional[dict],
    b: Optional[dict],
    length_slop: int = _FACTOR_LENGTH_SLOP,
) -> bool:
    if a is None or b is None:
        return a is b
    if a.get("rate_limited") or b.get("rate_limited"):
        return False
    if a.get("digest") and a.get("digest") == b.get("digest"):
        return True
    if (
        a.get("marker") in ("invalid_username", "invalid_password", "indistinguishable")
        and a.get("marker") == b.get("marker")
    ):
        return True
    if a.get("message") and a.get("message") == b.get("message"):
        return a.get("status") == b.get("status") and a.get("path") == b.get("path")
    return (
        a.get("status") == b.get("status")
        and a.get("path") == b.get("path")
        and abs(int(a.get("length") or 0) - int(b.get("length") or 0)) <= length_slop
    )


def _form_response_success(
    resp: requests.Response,
    posted_url: str,
    login_page_url: str,
    failure_markers: tuple[str, ...],
) -> bool:
    """Conservative form-auth success candidate detector."""
    body_lower = (resp.text or "").lower()
    alert = _extract_login_alert(resp.text or "")
    alert_lower = (alert or "").lower()

    explicit_failure = any(marker.lower() in body_lower for marker in failure_markers)
    alert_failure = any(
        marker in alert_lower
        for marker in (
            "wrong", "invalid", "incorrect", "failed", "denied",
            "not found", "does not exist", "doesn't exist",
            "unauthorized", "authentication error", "try again",
        )
    )
    if explicit_failure or alert_failure or _is_rate_limited_response(resp):
        return False
    if resp.status_code in (401, 403, 404, 405, 429, 501):
        return False

    def identity(value: str) -> tuple[str, str, str]:
        parsed = urlsplit(value or "")
        return (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path.rstrip("/").lower(),
        )

    final_id = identity(resp.url)
    posted_id = identity(posted_url)
    login_id = identity(login_page_url)

    same_as_login = (
        bool(login_page_url)
        and final_id[0] == login_id[0]
        and final_id[1] == login_id[1]
        and final_id[2] == login_id[2]
    )
    login_words = ("login", "signin", "sign-in", "authenticate")
    looks_like_login = (
        same_as_login
        or any(word in final_id[2] for word in login_words)
        or 'type="password"' in body_lower
        or "type='password'" in body_lower
        or ("<form" in body_lower and "password" in body_lower)
    )
    if looks_like_login:
        return False

    positive_hit = any(marker in body_lower for marker in _SUCCESS_MARKERS)
    redirected_to_non_login = (
        final_id != posted_id and not same_as_login and not looks_like_login
    )
    return bool(positive_hit or redirected_to_non_login)


def _map_failure_reason_to_factor(reason: Optional[str], success: bool) -> Optional[str]:
    """Collapse classifier output into the username/password/both/indistinguishable set."""
    if success:
        return None
    if reason == "unknown":
        return "indistinguishable"
    if reason == "unknown_but_differs_from_baseline":
        return "invalid_password"
    return reason


@dataclass
class LoginFactorResult:
    """Verdict for one username/password pair: which half (if either) is wrong."""
    test_case_id: str
    wstg_category: str = "WSTG-IDNT-04"
    target: str = ""
    username: str = ""
    verdict: str = ""  # both_valid | invalid_username | invalid_password | both_invalid | indistinguishable
    username_valid: Optional[bool] = None
    password_valid: Optional[bool] = None
    site_behavior: str = ""  # distinguishes | indistinguishable | unknown
    evidence: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


@dataclass
class LoginFactorReport:
    """One or more pair verdicts plus whether the login form distinguishes the three failures."""
    test_case_id: str
    wstg_category: str = "WSTG-IDNT-04"
    target: str = ""
    site_behavior: str = ""
    verdicts: list[dict] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2)


# ---------------------------------------------------------------------------
# Lockout guard — deterministic, independent of tool output
# ---------------------------------------------------------------------------

class LockoutGuard:
    """Enforces backoff between requests. Attempt cap is optional: pass
    max_attempts to stop early, or leave it None to walk the full wordlist.
    """

    def __init__(self, max_attempts: Optional[int] = None, min_delay_seconds: float = 0.25):
        self.max_attempts = max_attempts
        self.min_delay_seconds = min_delay_seconds
        self._count = 0
        self._last_ts = 0.0

    def can_proceed(self) -> bool:
        if self.max_attempts is None:
            return True
        return self._count < self.max_attempts

    def record_attempt(self) -> None:
        self._count += 1
        now = time.monotonic()
        elapsed = now - self._last_ts
        if elapsed < self.min_delay_seconds:
            time.sleep(self.min_delay_seconds - elapsed)
        self._last_ts = time.monotonic()


# ---------------------------------------------------------------------------
# Login-form discovery (field names + POST action, not guesswork)
# ---------------------------------------------------------------------------

_USER_FIELD_HINTS = ("uid", "user", "username", "login", "email", "userid", "user_name", "j_username")
_PASS_FIELD_HINTS = ("passw", "password", "passwd", "pass", "pwd", "j_password")
_SUCCESS_MARKERS = ("sign off", "signoff", "log off", "logoff", "logout", "log out", "welcome")


@dataclass
class DiscoveredForm:
    action_url: str
    user_field: str = "username"
    pass_field: str = "password"
    extra_fields: dict = field(default_factory=dict)
    method: str = "post"
    stepped: bool = False


class _LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._current: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        attrs_d = dict(attrs)
        if tag == "form":
            if self._current is not None:
                self.forms.append(self._current)
            self._current = {
                "action": attrs_d.get("action", "") or "",
                "method": (attrs_d.get("method") or "get").lower(),
                "inputs": [],
            }
        elif tag in ("input", "button") and self._current is not None:
            self._current["inputs"].append({
                "name": attrs_d.get("name") or "",
                "type": (attrs_d.get("type") or "text").lower(),
                "value": attrs_d.get("value") or "",
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self):
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None
        super().close()


def _pick_field(inputs: list[dict], hints: tuple[str, ...], type_names: tuple[str, ...]) -> Optional[str]:
    typed = [i for i in inputs if i["name"] and i["type"] in type_names]
    for hint in hints:
        for item in typed:
            if item["name"].lower() == hint or hint in item["name"].lower():
                return item["name"]
    return typed[0]["name"] if typed else None


def discover_login_form(page_url: str, html: str) -> Optional[DiscoveredForm]:
    """
    Discover a conventional HTML login form.

    Some scan-me applications expose the login controls in markup that is
    awkward for a strict <form>-only parser (for example, a hidden username
    input populated by JavaScript). Therefore this function first parses
    normal forms and then falls back to page-wide input discovery.

    The fallback does not execute JavaScript; it only uses names/types already
    present in the returned HTML.
    """
    parser = _LoginFormParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        parser.forms = []

    candidates = []

    for form in parser.forms:
        inputs = form["inputs"]

        pass_field = _pick_field(
            inputs,
            _PASS_FIELD_HINTS,
            ("password",)
        )
        if not pass_field:
            user_named = _pick_field(
                inputs,
                _USER_FIELD_HINTS,
                ("text", "email", "username"),
            )
            maybe_pass = _pick_field(
                inputs,
                _PASS_FIELD_HINTS,
                ("text",)
            )
            if maybe_pass and maybe_pass != user_named:
                pass_field = maybe_pass

        if not pass_field:
            continue

        user_field = _pick_field(
            inputs,
            _USER_FIELD_HINTS,
            ("text", "email", "username", "hidden")
        )

        extra = {
            i["name"]: i["value"]
            for i in inputs
            if i["name"]
            and i["type"] in ("hidden", "submit")
            and i["name"] != user_field
        }

        action_url = (
            urljoin(page_url, form["action"])
            if form["action"]
            else page_url
        )

        candidates.append(
            DiscoveredForm(
                action_url,
                user_field or "username",
                pass_field,
                extra,
                method=form.get("method") or "post",
            )
        )

    if candidates:
        return candidates[0]

    # ----------------------------------------------------------
    # Fallback: discover login controls anywhere in the page.
    # ----------------------------------------------------------

    fallback_parser = _LoginFormParser()

    try:
        # Wrap loose inputs in a synthetic form so the same parser can
        # safely inspect pages whose login markup is not inside <form>.
        synthetic_html = "<form>" + html + "</form>"
        fallback_parser.feed(synthetic_html)
        fallback_parser.close()
    except Exception:
        return None

    if not fallback_parser.forms:
        return None

    inputs = fallback_parser.forms[0]["inputs"]

    pass_field = _pick_field(
        inputs,
        _PASS_FIELD_HINTS,
        ("password",)
    )
    if not pass_field:
        user_named = _pick_field(
            inputs,
            _USER_FIELD_HINTS,
            ("text", "email", "username"),
        )
        maybe_pass = _pick_field(
            inputs,
            _PASS_FIELD_HINTS,
            ("text",)
        )
        if maybe_pass and maybe_pass != user_named:
            pass_field = maybe_pass

    if not pass_field:
        return None

    user_field = _pick_field(
        inputs,
        _USER_FIELD_HINTS,
        ("text", "email", "username", "hidden")
    )

    extra = {
        i["name"]: i["value"]
        for i in inputs
        if i["name"]
        and i["type"] in ("hidden", "submit")
        and i["name"] != user_field
    }

    return DiscoveredForm(
        page_url,
        user_field or "username",
        pass_field,
        extra,
        method="post",
    )


def _form_extras(inputs: list[dict], skip_name: str) -> dict:
    return {
        i["name"]: i["value"]
        for i in inputs
        if i["name"]
        and i["type"] in ("hidden", "submit")
        and i["name"] != skip_name
    }


def discover_username_step_form(page_url: str, html: str) -> Optional[DiscoveredForm]:
    """Discover a username-only first step (no password field on this page)."""
    parser = _LoginFormParser()
    try:
        parser.feed(html)
        parser.close()
    except Exception:
        parser.forms = []

    def _from_inputs(inputs: list[dict], action: str, method: str) -> Optional[DiscoveredForm]:
        if _pick_field(inputs, _PASS_FIELD_HINTS, ("password",)):
            return None
        user_field = _pick_field(
            inputs,
            _USER_FIELD_HINTS,
            ("text", "email", "username"),
        )
        if not user_field:
            return None
        return DiscoveredForm(
            urljoin(page_url, action) if action else page_url,
            user_field,
            "",
            _form_extras(inputs, user_field),
            method=method or "post",
            stepped=True,
        )

    for form in parser.forms:
        found = _from_inputs(
            form["inputs"],
            form.get("action") or "",
            form.get("method") or "post",
        )
        if found:
            return found

    try:
        fallback = _LoginFormParser()
        fallback.feed("<form>" + html + "</form>")
        fallback.close()
    except Exception:
        return None
    if not fallback.forms:
        return None
    return _from_inputs(fallback.forms[0]["inputs"], "", "post")


_DISCLOSED_USER_STOPWORDS = {
    "username", "user", "password", "passwd", "login", "log", "sign",
    "email", "account", "submit", "continue", "next", "enter", "please",
    "here", "your", "name", "field", "button", "form", "text", "value",
    "label", "input", "required", "optional", "remember", "forgot",
}


def _visible_login_text(html: str) -> str:
    text = re.sub(r"(?is)<script[^>]*>.*?</script>", " ", html or "")
    text = re.sub(r"(?is)<style[^>]*>.*?</style>", " ", text)
    text = re.sub(r"(?is)<!--.*?-->", " ", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = unescape(text)
    return re.sub(r"\s+", " ", text).strip()


def extract_disclosed_usernames(html: str) -> list[str]:
    """Find account identifiers published in login-page HTML. Site-agnostic."""
    if not html:
        return []
    visible = _visible_login_text(html)
    found: list[str] = []
    patterns = (
        r"(?i)\buser(?:\s*name)?\s*[:\-]\s*([A-Za-z][A-Za-z0-9._@-]{2,63})",
        r"(?i)\buser(?:name)?\s+([A-Za-z][A-Za-z0-9._@-]{2,63})\b",
        r"(?i)\b(?:log\s*in|sign\s*in)\s+as\s+([A-Za-z][A-Za-z0-9._@-]{2,63})",
        r"(?i)\btry\s+(?:the\s+)?(?:user(?:name)?\s+)?([A-Za-z][A-Za-z0-9._@-]{2,63})",
        r"(?i)\bdemo\s+(?:user(?:name)?|account)\s*[:\-]?\s*([A-Za-z][A-Za-z0-9._@-]{2,63})",
    )
    for pattern in patterns:
        for match in re.finditer(pattern, visible):
            token = match.group(1).strip(".,;:()[]")
            lowered = token.lower()
            if lowered in _DISCLOSED_USER_STOPWORDS:
                continue
            if token not in found:
                found.append(token)
    return found


def _html_has_password_field(html: str) -> bool:
    page = (html or "").lower()
    return (
        'type="password"' in page
        or "type='password'" in page
        or 'name="password"' in page
    )


# ---------------------------------------------------------------------------
# Username-enumeration control comparator
# ---------------------------------------------------------------------------

def _enum_control_match(a: Optional[dict], b: Optional[dict]) -> bool:
    """Compare two login responses strictly enough for IDNT-04 controls.

    A status/path/length match alone is intentionally NOT sufficient because
    many applications return different error messages with the same response
    size. Prefer exact normalized-body digest, then exact message + routing,
    then a meaningful failure marker + routing.
    """
    if a is None or b is None:
        return False
    if a.get("rate_limited") or b.get("rate_limited"):
        return False

    if a.get("digest") and a.get("digest") == b.get("digest"):
        return True

    same_route = (
        a.get("status") == b.get("status")
        and a.get("path") == b.get("path")
    )

    if same_route and a.get("message") and a.get("message") == b.get("message"):
        return True

    meaningful_markers = {"invalid_username", "invalid_password", "both_invalid", "indistinguishable"}
    if (
        same_route
        and a.get("marker") in meaningful_markers
        and a.get("marker") == b.get("marker")
    ):
        return True

    return False


# ---------------------------------------------------------------------------
# HTTP-native checker (form-based + HTTP Basic)
# ---------------------------------------------------------------------------

class HttpDefaultCredChecker:
    def __init__(
        self,
        base_url: str,
        timeout: float = DEFAULT_HTTP_TIMEOUT,
        auth_budget_seconds: float = DEFAULT_AUTH_BUDGET_SECONDS,
        enum_budget_seconds: float = DEFAULT_ENUM_BUDGET_SECONDS,
        verify_tls: bool = True,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = max(0.5, float(timeout))
        self.auth_budget_seconds = max(5.0, float(auth_budget_seconds))
        self.enum_budget_seconds = max(5.0, float(enum_budget_seconds))
        self.verify_tls = bool(verify_tls)
        self.session = requests.Session()
        self.session.verify = self.verify_tls
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            )
        })
        self._deadline: Optional[float] = None
        self._last_request_error: Optional[str] = None
        self._last_response: Optional[requests.Response] = None
        self._last_discovered_login_path: Optional[str] = None
        self._last_login_html: str = ""
        self._last_login_url: str = ""

    def _start_budget(self, seconds: float) -> None:
        self._deadline = time.monotonic() + max(1.0, seconds)

    def _clear_budget(self) -> None:
        self._deadline = None

    def _remaining_timeout(self) -> float:
        """Return a request timeout that never exceeds the active scan budget."""
        if self._deadline is None:
            return self.timeout
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            return 0.0
        return min(self.timeout, remaining)

    def _budget_exhausted(self) -> bool:
        return self._deadline is not None and time.monotonic() >= self._deadline

    def detect_mechanism(self, login_path: str) -> str:
        """Deterministic probe, not an LLM judgment call."""
        url = resolve_login_url(self.base_url, login_path)
        timeout = self._remaining_timeout()
        if timeout <= 0:
            self._last_request_error = "scan_budget_exhausted"
            return "unresolved"
        try:
            resp = self.session.get(url, timeout=timeout, allow_redirects=True)
            self._last_request_error = None
        except requests.Timeout as exc:
            self._last_request_error = f"request_timeout:{exc}"
            return "unresolved"
        except requests.RequestException as exc:
            self._last_request_error = f"request_error:{exc}"
            return "unresolved"

        if resp.status_code == 401 and "www-authenticate" in {k.lower() for k in resp.headers}:
            return "http_basic"
        if "<form" in resp.text.lower() and (
            "password" in resp.text.lower() or 'type="password"' in resp.text.lower()
        ):
            return "form"
        if discover_username_step_form(url, resp.text):
            return "form"
        return "unresolved"

    def _probe_login_page(
        self,
        login_path: str,
    ) -> tuple[str, str, Optional[DiscoveredForm]]:
        """Discover the requested login endpoint, then a short allow-list."""
        requested = (login_path or "/login").strip()
        if is_absolute_http_url(requested) or requested.startswith("//"):
            candidates = [requested]
        else:
            if not requested.startswith("/"):
                requested = "/" + requested
            candidates = [requested]
            candidates.extend(p for p in COMMON_LOGIN_PATHS if p not in candidates)

        last_error = "no supported login mechanism detected"

        for candidate in candidates:
            url = resolve_login_url(self.base_url, candidate)
            timeout = self._remaining_timeout()
            if timeout <= 0:
                self._last_request_error = "scan_budget_exhausted"
                return "unresolved", url, None
            try:
                resp = self.session.get(url, timeout=timeout, allow_redirects=True)
                self._last_request_error = None
            except requests.Timeout as exc:
                last_error = f"request_timeout:{exc}"
                continue
            except requests.exceptions.SSLError as exc:
                last_error = f"tls_verification_failed:{exc}"
                continue
            except requests.RequestException as exc:
                last_error = f"request_error:{exc}"
                continue

            page_url = str(resp.url)
            self._last_login_html = resp.text or ""
            self._last_login_url = page_url
            headers = {k.lower(): v for k, v in resp.headers.items()}

            if resp.status_code == 401 and "www-authenticate" in headers:
                self._last_discovered_login_path = candidate
                return "http_basic", page_url, None

            form = discover_login_form(page_url, resp.text)
            has_password = _html_has_password_field(resp.text)
            if form:
                self._last_discovered_login_path = candidate
                return "form", page_url, form
            if has_password:
                self._last_discovered_login_path = candidate
                return (
                    "form",
                    page_url,
                    DiscoveredForm(page_url, "username", "password", {}),
                )

            stepped = discover_username_step_form(page_url, resp.text)
            if stepped:
                self._last_discovered_login_path = candidate
                return "form", page_url, stepped

            # JavaScript-driven fallback.
            if sync_playwright is not None:
                remaining = self._remaining_timeout()
                if remaining <= 0:
                    self._last_request_error = "scan_budget_exhausted"
                    return "unresolved", page_url, None
                try:
                    with sync_playwright() as pw:
                        browser = pw.chromium.launch(
                            headless=True,
                            timeout=max(250, int(min(self.timeout, remaining) * 1000)),
                        )
                        context = browser.new_context(ignore_https_errors=not self.verify_tls)
                        page = context.new_page()
                        page.goto(
                            page_url,
                            wait_until="domcontentloaded",
                            timeout=max(250, int(min(self.timeout, remaining) * 1000)),
                        )
                        page.wait_for_timeout(min(500, max(100, int(remaining * 250))))
                        rendered = page.content() or ""
                        self._last_login_html = rendered
                        password_count = page.locator(
                            'input[type="password"], input[name="password"]'
                        ).count()
                        username_count = page.locator(
                            'input[name="username"], input[name="user"], '
                            'input[name="login"], input[type="email"]'
                        ).count()
                        browser.close()
                        if password_count and username_count:
                            self._last_discovered_login_path = candidate
                            return "browser_form", page_url, None
                        stepped_js = discover_username_step_form(page_url, rendered)
                        if stepped_js or (username_count and not password_count):
                            self._last_discovered_login_path = candidate
                            return (
                                "form",
                                page_url,
                                stepped_js
                                or DiscoveredForm(
                                    page_url, "username", "", {},
                                    stepped=True,
                                ),
                            )
                except Exception as exc:
                    last_error = f"browser_discovery_error:{type(exc).__name__}"

        self._last_request_error = last_error
        return "unresolved", resolve_login_url(self.base_url, requested), None


    def _browser_login_attempt(
        self,
        login_url: str,
        cred: CredPair,
    ) -> AttemptResult:
        """
        Browser-based fallback for JavaScript-driven login pages.

        This is intentionally conservative: one browser context is created
        for the individual credential attempt, the page's own form/CSRF
        handling is used, and the result is verified by the final URL/page
        state. It is only used when the normal HTTP detector cannot resolve
        the login mechanism.
        """
        pair = _safe_pair(cred.username, cred.password)

        if sync_playwright is None:
            return AttemptResult(
                cred.username,
                cred.password,
                False,
                evidence=(
                    f"{pair} browser_fallback_unavailable: "
                    "Playwright is not installed"
                ),
                failure_reason="browser_dependency_missing",
            )

        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=not self.verify_tls)
                page = context.new_page()

                timeout = self._remaining_timeout()
                if timeout <= 0:
                    browser.close()
                    return AttemptResult(
                        cred.username, cred.password, False,
                        evidence=f"{pair} auth_budget_exhausted",
                        failure_reason="scan_budget_exhausted",
                    )

                page.goto(
                    login_url,
                    wait_until="domcontentloaded",
                    timeout=max(250, int(timeout * 1000)),
                )

                # Allow page JavaScript to finish populating hidden fields.
                page.wait_for_timeout(1000)

                password_locator = page.locator(
                    'input[type="password"], input[name="password"]'
                ).first

                if password_locator.count() == 0:
                    browser.close()
                    return AttemptResult(
                        cred.username,
                        cred.password,
                        False,
                        evidence=f"{pair} browser_form_not_found",
                        failure_reason="login_form_not_found",
                    )

                # Gin & Juice uses a hidden username field populated by JS.
                # For generic pages, prefer a visible username/email field.
                visible_user = page.locator(
                    'input[name="username"]:visible, '
                    'input[name="user"]:visible, '
                    'input[name="login"]:visible, '
                    'input[type="email"]:visible'
                ).first

                hidden_user = page.locator(
                    'input[name="username"], '
                    'input[name="user"], '
                    'input[name="login"]'
                ).first

                if visible_user.count() > 0:
                    visible_user.fill(cred.username)
                elif hidden_user.count() > 0:
                    # Hidden fields cannot always be filled normally.
                    # Set the value and dispatch the events the page expects.
                    hidden_user.evaluate(
                        """(el, value) => {
                            el.value = value;
                            el.dispatchEvent(new Event('input', {bubbles:true}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                        }""",
                        cred.username,
                    )
                else:
                    browser.close()
                    return AttemptResult(
                        cred.username,
                        cred.password,
                        False,
                        evidence=f"{pair} browser_username_field_not_found",
                        failure_reason="username_field_not_found",
                    )

                password_locator.fill(cred.password)

                # Submit the page's own login form/button so hidden CSRF
                # fields and JavaScript handlers are preserved.
                submit = page.locator(
                    'button[type="submit"], '
                    'input[type="submit"], '
                    'button:has-text("Log in"), '
                    'button:has-text("Login")'
                ).first

                if submit.count() > 0:
                    submit.click()
                else:
                    password_locator.press("Enter")

                try:
                    remaining = self._remaining_timeout()
                    if remaining > 0:
                        page.wait_for_load_state(
                            "networkidle",
                            timeout=max(250, int(remaining * 1000)),
                        )
                except PlaywrightTimeoutError:
                    pass

                page.wait_for_timeout(500)

                final_url = page.url
                body = page.locator("body").inner_text().lower()

                # Explicit authentication errors always override URL/body
                # success hints.
                alert = ""
                for marker in (
                    "login and/or password are wrong",
                    "invalid username or password",
                    "invalid credentials",
                    "incorrect password",
                    "wrong password",
                    "login failed",
                    "authentication failed",
                    "access denied",
                ):
                    if marker in body:
                        alert = marker
                        break

                rate_limited = any(marker in body for marker in _RATE_LIMIT_MARKERS)
                success = (
                    not alert
                    and not rate_limited
                    and (
                        "/my-account" in final_url.lower()
                        or "log out" in body
                        or "logout" in body
                        or "sign out" in body
                    )
                )

                status = 200
                evidence = (
                    f"{pair} browser_auth "
                    f"final_url={final_url}"
                )

                if alert:
                    evidence += f' alert="{alert}"'

                browser.close()

                return AttemptResult(
                    cred.username,
                    cred.password,
                    success,
                    status,
                    evidence=evidence,
                    failure_reason=None if success else (
                        "rate_limited" if rate_limited
                        else ("invalid_credentials" if alert else "not_confirmed")
                    ),
                    alert=alert or None,
                )

        except Exception as exc:
            return AttemptResult(
                cred.username,
                cred.password,
                False,
                evidence=f"{pair} browser_request_error:{exc}",
                failure_reason="browser_error",
            )

    def _run_browser_form(
        self,
        login_url: str,
        creds: list[CredPair],
        guard: LockoutGuard,
        result: DefaultCredResult,
        stop_on_first_hit: bool = False,
        baseline_attempt: Optional[AttemptResult] = None,
    ) -> DefaultCredResult:
        """Execute authorized credential pairs through the JS/browser fallback."""
        for cred in creds:
            if self._budget_exhausted():
                result.result = ResultStatus.UNRESOLVED
                result.evidence.append(
                    f"overall authentication budget exhausted after "
                    f"{result.attempts_made} credential attempt(s)"
                )
                break

            if not guard.can_proceed():
                result.result = ResultStatus.LOCKOUT_ABORTED
                result.evidence.append(
                    f"lockout/attempt guard stopped testing after "
                    f"{result.attempts_made} credential attempt(s)"
                )
                break

            guard.record_attempt()
            result.attempts_made += 1

            attempt = self._browser_login_attempt(login_url, cred)
            result.evidence.append(attempt.evidence)

            if attempt.failure_reason == "rate_limited":
                result.result = ResultStatus.LOCKOUT_ABORTED
                result.evidence.append(
                    "browser authentication detected rate limiting/lockout; testing stopped"
                )
                break

            if attempt.success:
                result.successful_pairs.append(
                    _safe_pair(cred.username, cred.password)
                )
                result.evidence.append(
                    f"{_safe_pair(cred.username, cred.password)} "
                    "confirmed_success=browser_authenticated_state"
                )
                if stop_on_first_hit:
                    break

        _apply_auth_verdict(result)

        result.client_status = _client_status(result.result)
        result.summary = _default_cred_summary(result)
        result.finished_at = datetime.now(timezone.utc).isoformat()
        return result


    def _submit_fields(
        self,
        url: str,
        fields: dict,
        method: str = "post",
    ) -> Optional[requests.Response]:
        timeout = self._remaining_timeout()
        if timeout <= 0:
            self._last_request_error = "scan_budget_exhausted"
            return None
        method = (method or "post").lower()
        try:
            if method == "get":
                resp = self.session.get(
                    url,
                    params=fields,
                    timeout=timeout,
                    allow_redirects=True,
                )
            else:
                resp = self.session.post(
                    url,
                    data=fields,
                    timeout=timeout,
                    allow_redirects=True,
                )
            self._last_request_error = None
            self._last_response = resp
            return resp
        except requests.Timeout as exc:
            self._last_request_error = f"request_timeout:{exc}"
            return None
        except requests.RequestException as exc:
            self._last_request_error = f"request_error:{exc}"
            return None

    def _post_login_form(
        self,
        url: str,
        username: str,
        password: str,
        user_field: str,
        pass_field: str,
        extra_fields: Optional[dict] = None,
        login_page_url: str = "",
        method: str = "post",
    ) -> Optional[requests.Response]:
        """Submit the discovered form using the already-warmed session.

        The old implementation created a brand-new Session and fetched the
        login page again for every credential. That could turn 12 credentials
        into 24+ HTTP requests before the actual authentication attempts.
        The initial probe already populated cookies/session state, so reuse it.
        """
        payload = dict(extra_fields or {})
        if user_field:
            payload[user_field] = username
        if pass_field:
            payload[pass_field] = password

        return self._submit_fields(url, payload, method=method)

    def _try_basic_auth(self, url: str, cred: CredPair) -> AttemptResult:
        pair = _safe_pair(cred.username, cred.password)
        timeout = self._remaining_timeout()
        if timeout <= 0:
            return AttemptResult(
                cred.username, cred.password, False,
                evidence=f"{pair} auth_budget_exhausted",
                failure_reason="scan_budget_exhausted",
            )
        try:
            resp = self.session.get(
                url, auth=(cred.username, cred.password),
                timeout=timeout, allow_redirects=True,
            )
        except requests.Timeout as exc:
            return AttemptResult(
                cred.username, cred.password, False,
                evidence=f"{pair} request_timeout:{exc}",
                failure_reason="request_timeout",
            )
        except requests.RequestException as exc:
            return AttemptResult(
                cred.username, cred.password, False,
                evidence=f"{pair} request_error:{exc}",
                failure_reason="request_error",
            )

        if _is_rate_limited_response(resp):
            return AttemptResult(
                cred.username, cred.password, False, resp.status_code,
                evidence=f"{pair} http_basic rate_limited status={resp.status_code}",
                failure_reason="rate_limited",
            )

        success = resp.status_code not in (401, 403)
        return AttemptResult(
            cred.username, cred.password, success, resp.status_code,
            evidence=f"{pair} http_basic status={resp.status_code} final_url={resp.url}",
            failure_reason=None if success else "invalid_credentials",
        )


    def _verify_form_success(
        self,
        attempt: AttemptResult,
    ) -> tuple[bool, str]:
        """Verify a candidate success using the resulting authenticated state."""
        if not attempt.success:
            return False, "candidate_not_successful"

        timeout = self._remaining_timeout()
        if timeout <= 0:
            return False, "auth_budget_exhausted"

        # Extract the final URL from the evidence emitted by _try_form_auth.
        match = re.search(r"redirected_to=(\S+)", attempt.evidence)
        verify_url = match.group(1) if match else None
        if not verify_url:
            return False, "missing_final_url"

        try:
            resp = self.session.get(
                verify_url,
                timeout=timeout,
                allow_redirects=True,
            )
        except requests.RequestException:
            return False, "verification_request_failed"

        if _is_rate_limited_response(resp):
            return False, "rate_limited"

        body = (resp.text or "").lower()
        if any(marker in body for marker in _SUCCESS_MARKERS):
            return True, "authenticated_state_marker"

        final_path = urlsplit(resp.url or "").path.lower()
        if any(word in final_path for word in (
            "/dashboard", "/account", "/profile", "/my-account", "/home"
        )):
            return True, "authenticated_destination"

        return False, "authenticated_state_not_confirmed"


    def _try_form_auth(
        self, url: str, cred: CredPair, user_field: str, pass_field: str,
        failure_markers: tuple[str, ...], extra_fields: Optional[dict] = None,
        login_page_url: str = "",
        baseline_body_lower: Optional[str] = None,
    ) -> AttemptResult:
        pair = _safe_pair(cred.username, cred.password)
        resp = self._post_login_form(
            url, cred.username, cred.password, user_field, pass_field,
            extra_fields=extra_fields, login_page_url=login_page_url,
        )
        if resp is None:
            return AttemptResult(
                cred.username, cred.password, False,
                evidence=f"{pair} request_error:{self._last_request_error or 'unknown'}",
                failure_reason=self._last_request_error or "unknown",
            )

        if _is_rate_limited_response(resp):
            return AttemptResult(
                cred.username, cred.password, False, resp.status_code,
                evidence=(
                    f"{pair} rate_limited status={resp.status_code} "
                    f"retry_after={resp.headers.get('Retry-After', '')}"
                ),
                failure_reason="rate_limited",
            )

        body_lower = (resp.text or "").lower()
        alert = _extract_login_alert(resp.text)

        # The previous implementation treated any redirect away from the POST
        # endpoint as success. That incorrectly marked:
        #
        #   POST /signin.html
        #   -> /login.html?login_error=true
        #
        # as a valid credential.
        #
        # Decide success using the same conservative detector used elsewhere.
        success = _form_response_success(
            resp=resp,
            posted_url=url,
            login_page_url=login_page_url,
            failure_markers=failure_markers,
        )
        if success:
            failure_reason: Optional[str] = None
        else:
            # Verdict comes only from the post-login alert/error text.
            failure_reason = _classify_failure_reason((alert or "").lower(), None)
        reason_note = f" failure_reason={failure_reason}" if failure_reason else ""
        alert_note = f' alert="{alert}"' if alert else ""
        return AttemptResult(
            cred.username, cred.password, success, resp.status_code,
            evidence=(
                f"{pair} form fields={user_field}/{pass_field} "
                f"posted_to={url} status={resp.status_code} redirected_to={resp.url}"
                f"{alert_note}{reason_note}"
            ),
            failure_reason=failure_reason,
            alert=alert,
        )

    def _try_stepped_form_auth(
        self,
        first_form: DiscoveredForm,
        cred: CredPair,
        failure_markers: tuple[str, ...],
        login_page_url: str = "",
    ) -> AttemptResult:
        """Username-first then password-page login, using the same session."""
        pair = _safe_pair(cred.username, cred.password)
        start_url = login_page_url or first_form.action_url
        timeout = self._remaining_timeout()
        if timeout > 0:
            try:
                page = self.session.get(
                    start_url, timeout=timeout, allow_redirects=True,
                )
                refreshed = discover_username_step_form(str(page.url), page.text or "")
                if refreshed:
                    first_form = refreshed
            except requests.RequestException as exc:
                self._last_request_error = f"request_error:{exc}"
        step1 = self._post_login_form(
            first_form.action_url,
            cred.username,
            "",
            first_form.user_field,
            "",
            extra_fields=first_form.extra_fields,
            login_page_url=login_page_url,
            method=first_form.method,
        )
        if step1 is None:
            return AttemptResult(
                cred.username, cred.password, False,
                evidence=f"{pair} stepped_request_error:{self._last_request_error or 'unknown'}",
                failure_reason=self._last_request_error or "unknown",
            )
        if _is_rate_limited_response(step1):
            return AttemptResult(
                cred.username, cred.password, False, step1.status_code,
                evidence=f"{pair} rate_limited status={step1.status_code} at username step",
                failure_reason="rate_limited",
            )

        step2_form = discover_login_form(str(step1.url), step1.text or "")
        if step2_form is None and _html_has_password_field(step1.text or ""):
            step2_form = DiscoveredForm(
                str(step1.url),
                first_form.user_field or "username",
                "password",
                {},
            )
        if step2_form is None:
            return AttemptResult(
                cred.username, cred.password, False, step1.status_code,
                evidence=(
                    f"{pair} username_step posted_to={first_form.action_url} "
                    f"status={step1.status_code} redirected_to={step1.url} "
                    "password_step_not_presented"
                ),
                failure_reason="invalid_username",
            )

        return self._try_form_auth(
            step2_form.action_url,
            cred,
            step2_form.user_field or first_form.user_field,
            step2_form.pass_field,
            failure_markers,
            extra_fields=step2_form.extra_fields,
            login_page_url=str(step1.url),
        )

    def run(
        self,
        login_path: str,
        creds: list[CredPair],
        user_field: Optional[str] = None,
        pass_field: Optional[str] = None,
        failure_markers: tuple[str, ...] = ("invalid", "incorrect", "failed", "denied"),
        stop_on_first_hit: bool = False,
        guard: Optional[LockoutGuard] = None,
        classify_failures: bool = True,
    ) -> DefaultCredResult:
        """Run WSTG-ATHN-02 with discovery, baseline, bounded testing and verification."""
        test_case_id = f"DEFCREDS-{uuid.uuid4().hex[:8]}"
        fallback_url = resolve_login_url(self.base_url, login_path)
        started = datetime.now(timezone.utc).isoformat()

        result = DefaultCredResult(
            test_case_id=test_case_id,
            target=fallback_url,
            started_at=started,
        )

        if not creds:
            result.result = ResultStatus.UNRESOLVED
            result.evidence.append(
                "no authorized credential pairs were supplied; "
                "load credential pairs from the configured JSON file"
            )
            result.client_status = _client_status(result.result)
            result.summary = _default_cred_summary(result)
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        skip = federated_login_skip(self.base_url, login_path, probe=True)
        if skip:
            _apply_federated_skip(result, skip, "Default Credentials")
            return result

        guard = guard or LockoutGuard(
            max_attempts=max(1, min(len(creds), 10)),
            min_delay_seconds=0.5,
        )

        self._start_budget(self.auth_budget_seconds)
        try:
            mechanism, page_url, form = self._probe_login_page(login_path)
            result.auth_mechanism = mechanism
            result.target = page_url or fallback_url
            result.evidence.append(
                f"login discovery: mechanism={mechanism} page={page_url}"
            )

            if mechanism == "unresolved":
                result.result = ResultStatus.UNRESOLVED
                result.evidence.append(
                    "authentication mechanism could not be resolved; "
                    f"reason={self._last_request_error or 'unknown'}"
                )
                return result

            if mechanism == "http_basic":
                baseline_cred = CredPair(
                    f"nonexistent_{uuid.uuid4().hex[:12]}",
                    "__wrong_password_auth_baseline__",
                )
                baseline = self._try_basic_auth(page_url, baseline_cred)
                if baseline.failure_reason == "rate_limited":
                    result.result = ResultStatus.LOCKOUT_ABORTED
                    result.evidence.append(
                        "baseline HTTP Basic probe triggered rate limiting/lockout"
                    )
                    return result
                if baseline.http_status != 401:
                    result.result = ResultStatus.UNRESOLVED
                    result.evidence.append(
                        "HTTP Basic challenge was detected, but the baseline invalid "
                        f"credential did not return HTTP 401 (got {baseline.http_status}); "
                        "real credential results were not trusted"
                    )
                    return result
                result.evidence.append(
                    "baseline HTTP Basic failure established with HTTP 401"
                )
                result.result = ResultStatus.NOT_VULNERABLE

            if mechanism == "browser_form":
                fake = CredPair(
                    f"nonexistent_{uuid.uuid4().hex[:12]}",
                    "__wrong_password_auth_baseline__",
                )
                baseline = self._browser_login_attempt(page_url, fake)
                if baseline.failure_reason == "rate_limited":
                    result.result = ResultStatus.LOCKOUT_ABORTED
                    result.evidence.append(
                        "baseline failed-login probe triggered rate limiting/lockout"
                    )
                    return result
                if baseline.success:
                    result.result = ResultStatus.UNRESOLVED
                    result.evidence.append(
                        "baseline invalid credential appeared successful; "
                        "real credential results were not trusted"
                    )
                    return result

                result.evidence.append("baseline failed-login response established")
                result.result = ResultStatus.NOT_VULNERABLE
                return self._run_browser_form(
                    login_url=page_url,
                    creds=creds,
                    guard=guard,
                    result=result,
                    stop_on_first_hit=stop_on_first_hit,
                    baseline_attempt=baseline,
                )

            post_url = form.action_url if form else fallback_url
            user_field = user_field or (form.user_field if form else "username")
            pass_field = pass_field or (form.pass_field if form else "password")
            extra_fields = form.extra_fields if form else {}
            stepped = bool(form and form.stepped)
            form_method = form.method if form else "post"
            result.target = post_url

            result.evidence.append(
                f"discovered form action={post_url} "
                f"user_field={user_field} pass_field={pass_field or '(later-step)'} "
                f"stepped={stepped}"
            )

            # Baseline failed login before any supplied credential is tested.
            baseline_cred = CredPair(
                f"nonexistent_{uuid.uuid4().hex[:12]}",
                "__wrong_password_auth_baseline__",
            )
            if stepped and form is not None:
                baseline = self._try_stepped_form_auth(
                    form,
                    baseline_cred,
                    failure_markers,
                    login_page_url=page_url,
                )
            else:
                baseline = self._try_form_auth(
                    post_url,
                    baseline_cred,
                    user_field,
                    pass_field,
                    failure_markers,
                    extra_fields=extra_fields,
                    login_page_url=page_url,
                )

            if baseline.failure_reason == "rate_limited":
                result.result = ResultStatus.LOCKOUT_ABORTED
                result.evidence.append(
                    "baseline failed-login probe triggered rate limiting/lockout"
                )
                return result
            if baseline.http_status is None:
                result.result = ResultStatus.UNRESOLVED
                result.evidence.append("baseline failed-login probe produced no response")
                return result
            if baseline.success:
                result.result = ResultStatus.UNRESOLVED
                result.evidence.append(
                    "baseline invalid credential was not rejected reliably; "
                    "real credential results were not trusted"
                )
                return result

            result.evidence.append(
                f"baseline failed-login established: status={baseline.http_status} "
                f"reason={baseline.failure_reason or 'rejected'}"
            )
            result.result = ResultStatus.NOT_VULNERABLE

            consecutive_rejects = 0
            for cred in creds:
                if self._budget_exhausted():
                    result.result = ResultStatus.UNRESOLVED
                    result.evidence.append(
                        f"overall authentication budget exhausted after "
                        f"{result.attempts_made} credential attempt(s)"
                    )
                    break

                if not guard.can_proceed():
                    result.result = ResultStatus.LOCKOUT_ABORTED
                    result.evidence.append(
                        f"lockout/attempt guard stopped testing after "
                        f"{result.attempts_made} credential attempt(s)"
                    )
                    break

                guard.record_attempt()
                result.attempts_made += 1

                if mechanism == "http_basic":
                    attempt = self._try_basic_auth(page_url, cred)
                elif stepped and form is not None:
                    attempt = self._try_stepped_form_auth(
                        form,
                        cred,
                        failure_markers,
                        login_page_url=page_url,
                    )
                else:
                    attempt = self._try_form_auth(
                        post_url, cred, user_field, pass_field, failure_markers,
                        extra_fields=extra_fields, login_page_url=page_url,
                    )
                result.evidence.append(attempt.evidence)

                if attempt.failure_reason == "rate_limited":
                    result.result = ResultStatus.LOCKOUT_ABORTED
                    result.evidence.append(
                        "target signaled rate limiting/lockout; testing stopped immediately"
                    )
                    break

                if attempt.http_status in (403, 405, 404, 501):
                    consecutive_rejects += 1
                    if consecutive_rejects >= 2:
                        result.result = ResultStatus.ERROR
                        result.evidence.append(
                            "authentication requests were rejected before a reliable "
                            f"credential verdict could be established (HTTP {attempt.http_status})"
                        )
                        break
                else:
                    consecutive_rejects = 0

                if not attempt.success:
                    continue

                if mechanism == "form":
                    verified, reason = self._verify_form_success(attempt)
                else:
                    verified, reason = True, "http_basic_authenticated_response"

                if verified:
                    result.successful_pairs.append(
                        _safe_pair(cred.username, cred.password)
                    )
                    result.evidence.append(
                        f"{_safe_pair(cred.username, cred.password)} "
                        f"confirmed_success={reason}"
                    )
                    if stop_on_first_hit:
                        break
                else:
                    result.evidence.append(
                        f"{_safe_pair(cred.username, cred.password)} "
                        f"candidate_success_not_confirmed={reason}"
                    )

            _apply_auth_verdict(result)
            return result
        finally:
            result.client_status = _client_status(result.result)
            result.summary = _default_cred_summary(result)
            result.finished_at = datetime.now(timezone.utc).isoformat()
            self._clear_budget()


    def _timed_form_request(
        self,
        url: str,
        username: str,
        password: str,
        user_field: str,
        pass_field: str,
        samples: int,
        extra_fields: Optional[dict] = None,
        login_page_url: str = "",
        guard: Optional[LockoutGuard] = None,
        method: str = "post",
    ) -> tuple[Optional[requests.Response], float]:
        durations: list[float] = []
        last_resp: Optional[requests.Response] = None
        for _ in range(max(1, samples)):
            if self._budget_exhausted():
                self._last_request_error = "scan_budget_exhausted"
                break
            if guard is not None:
                if not guard.can_proceed():
                    break
                guard.record_attempt()
            t0 = time.perf_counter()
            resp = self._post_login_form(
                url, username, password, user_field, pass_field,
                extra_fields=extra_fields, login_page_url=login_page_url,
                method=method,
            )
            elapsed = time.perf_counter() - t0
            if resp is not None:
                last_resp = resp
                durations.append(elapsed)
        if not durations:
            return None, 0.0
        return last_resp, statistics.median(durations)

    def enumerate_usernames(
        self,
        login_path: str,
        candidate_usernames: list[str],
        probe_password: str = "__wrong_password_idnt04__",
        samples_per_probe: int = 1,
        timing_ratio_threshold: float = 1.5,
        length_delta_threshold: int = 15,
        guard: Optional[LockoutGuard] = None,
        known_valid_username: Optional[str] = None,
    ) -> EnumerationResult:
        """
        Conservative WSTG-IDNT-04 username-enumeration check.

        Controls used:
          1. synthetic/nonexistent username + guaranteed-wrong password
          2. optional known-valid username + the same guaranteed-wrong password

        When a known-valid control is available, candidate responses are compared
        with both controls. This is substantially stronger than treating every
        response difference from a single baseline as account enumeration.

        Timing is only used when multiple samples are explicitly requested.
        """
        started = datetime.now(timezone.utc).isoformat()
        test_case_id = f"IDNT04-{uuid.uuid4().hex[:8]}"
        fallback_url = resolve_login_url(self.base_url, login_path)

        samples = max(1, int(samples_per_probe))
        use_timing = samples >= 2
        control_username = (known_valid_username or "").strip() or None

        result = EnumerationResult(
            test_case_id=test_case_id,
            target=fallback_url,
            signal_used=(
                "status,length,message,timing,control_comparison"
                if use_timing
                else "status,length,message,control_comparison"
            ),
            started_at=started,
        )

        skip = federated_login_skip(self.base_url, login_path, probe=True)
        if skip:
            _apply_federated_skip(result, skip, "User Enumeration")
            return result

        if not candidate_usernames:
            result.result = ResultStatus.UNRESOLVED
            result.client_status = _client_status(result.result)
            result.summary = "No authorized candidate usernames were supplied."
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result

        self._start_budget(self.enum_budget_seconds)

        # One baseline + optional known-valid control + candidates.
        control_requests = 1 if control_username else 0
        guard = guard or LockoutGuard(
            max_attempts=(len(candidate_usernames) + 1 + control_requests) * samples,
            min_delay_seconds=0.5,
        )

        mechanism, page_url, form = self._probe_login_page(login_path)
        disclosed = extract_disclosed_usernames(self._last_login_html)
        if disclosed:
            result.evidence.append(
                "login page disclosed account identifier(s): " + ", ".join(disclosed)
            )
            for username in disclosed:
                result.candidates.append(
                    EnumerationCandidate(
                        username=username,
                        classification="likely_valid",
                        signals={"page_disclosure": True, "source": "login_html"},
                        evidence=(
                            f"{username} likely_valid: account identifier was "
                            "published on the login page"
                        ),
                    )
                )
            result.signal_used = "page_disclosure"

        if mechanism != "form":
            if disclosed:
                result.target = page_url or fallback_url
                result.result = ResultStatus.VULNERABLE
                result.client_status = _client_status(result.result)
                result.summary = _enum_summary(result)
                result.finished_at = datetime.now(timezone.utc).isoformat()
                self._clear_budget()
                return result
            result.finished_at = datetime.now(timezone.utc).isoformat()
            result.signal_used = f"login_form_not_found:{mechanism or 'unresolved'}"
            result.result = ResultStatus.UNRESOLVED
            result.client_status = _client_status(result.result)
            result.summary = _enum_summary(result)
            self._clear_budget()
            return result

        post_url = form.action_url if form else fallback_url
        user_field = form.user_field if form else "username"
        stepped = bool(form and form.stepped)
        pass_field = "" if stepped else (form.pass_field if form else "password")
        extra_fields = form.extra_fields if form else {}
        form_method = form.method if form else "post"
        result.target = post_url

        if stepped:
            result.evidence.append("username-first login step detected")
            result.signal_used = (
                (result.signal_used + ",password_step,control_comparison")
                if result.signal_used
                else "password_step,status,length,message,control_comparison"
            )

        baseline_user = f"nonexistent_{uuid.uuid4().hex[:12]}"
        baseline_resp, baseline_median = self._timed_form_request(
            post_url,
            baseline_user,
            probe_password,
            user_field,
            pass_field,
            samples,
            extra_fields=extra_fields,
            login_page_url=page_url,
            guard=guard,
            method=form_method,
        )

        if baseline_resp is None:
            result.result = ResultStatus.UNRESOLVED
            result.client_status = _client_status(result.result)
            result.summary = "The baseline invalid-username probe failed, so enumeration could not be determined."
            result.evidence.append("baseline username probe failed")
            result.finished_at = datetime.now(timezone.utc).isoformat()
            self._clear_budget()
            return result

        if _is_rate_limited_response(baseline_resp):
            result.result = ResultStatus.LOCKOUT_ABORTED
            result.client_status = _client_status(result.result)
            result.summary = _enum_summary(result)
            result.evidence.append("baseline username probe triggered rate limiting/lockout; enumeration stopped")
            result.finished_at = datetime.now(timezone.utc).isoformat()
            self._clear_budget()
            return result

        baseline_body = _normalize_dynamic_content(baseline_resp.text or "")
        baseline_body_lower = baseline_body.lower()
        baseline_len = len(baseline_body)
        baseline_status = baseline_resp.status_code
        baseline_fp = _fingerprint_response(baseline_resp)
        baseline_password_step = _html_has_password_field(baseline_resp.text or "")
        result.evidence.append(
            f"invalid-username control established: status={baseline_status} "
            f"normalized_length={baseline_len} password_step={baseline_password_step}"
        )

        # Optional known-valid control: same wrong password, known existing username.
        valid_fp = None
        valid_median = 0.0
        valid_control_usable = False
        if control_username:
            if control_username.lower() == baseline_user.lower():
                control_username = None
            else:
                valid_resp, valid_median = self._timed_form_request(
                    post_url,
                    control_username,
                    probe_password,
                    user_field,
                    pass_field,
                    samples,
                    extra_fields=extra_fields,
                    login_page_url=page_url,
                    guard=guard,
                    method=form_method,
                )
                if valid_resp is not None and not _is_rate_limited_response(valid_resp):
                    valid_success = _form_response_success(
                        valid_resp,
                        post_url,
                        page_url,
                        ("invalid", "incorrect", "failed", "denied"),
                    )
                    if valid_success:
                        result.evidence.append(
                            f"known-valid control username={control_username} appeared to authenticate; "
                            "the control password was not safely usable as an invalid-password probe, "
                            "so control comparison was disabled"
                        )
                    else:
                        valid_fp = _fingerprint_response(valid_resp)
                        valid_control_usable = valid_fp is not None
                        result.evidence.append(
                            f"known-valid control established: username={control_username} "
                            f"status={(valid_fp or {}).get('status')} "
                            f"path={(valid_fp or {}).get('path')}"
                        )
                else:
                    result.evidence.append(
                        f"known-valid control probe failed for username={control_username}; "
                        "falling back to invalid-username baseline comparison"
                    )

        low_ratio = 1.0 / timing_ratio_threshold
        high_ratio = timing_ratio_threshold

        for username in candidate_usernames:
            username = str(username or "").strip()
            if not username:
                continue
            if any(c.username.lower() == username.lower() for c in result.candidates):
                continue

            # A known-valid control is not itself evidence of a vulnerability.
            if control_username and username.lower() == control_username.lower():
                result.candidates.append(
                    EnumerationCandidate(
                        username=username,
                        classification="known_valid_control",
                        signals={"known_valid_control": True},
                        evidence=f"{username} is the operator-supplied/previously-confirmed valid-account control; not counted as enumeration evidence",
                    )
                )
                continue

            if self._budget_exhausted():
                result.candidates.append(
                    EnumerationCandidate(
                        username=username,
                        classification="inconclusive",
                        signals={"error": "enumeration_budget_exhausted"},
                        evidence=f"{username} inconclusive: enumeration safety budget exhausted",
                    )
                )
                for remaining_username in candidate_usernames[candidate_usernames.index(username) + 1:]:
                    if control_username and str(remaining_username).strip().lower() == control_username.lower():
                        continue
                    result.candidates.append(
                        EnumerationCandidate(
                            username=str(remaining_username),
                            classification="inconclusive",
                            signals={"error": "enumeration_budget_exhausted"},
                            evidence=f"{remaining_username} inconclusive: enumeration safety budget exhausted",
                        )
                    )
                break

            cand_resp, cand_median = self._timed_form_request(
                post_url,
                username,
                probe_password,
                user_field,
                pass_field,
                samples,
                extra_fields=extra_fields,
                login_page_url=page_url,
                guard=guard,
                method=form_method,
            )

            if cand_resp is None:
                result.candidates.append(
                    EnumerationCandidate(
                        username=username,
                        classification="inconclusive",
                        signals={"error": "probe_failed"},
                        evidence=f"{username} inconclusive: probe failed",
                    )
                )
                continue

            if _is_rate_limited_response(cand_resp):
                result.result = ResultStatus.LOCKOUT_ABORTED
                result.candidates.append(
                    EnumerationCandidate(
                        username=username,
                        classification="inconclusive",
                        signals={"error": "rate_limited"},
                        evidence=f"{username} inconclusive: target rate-limited the probe",
                    )
                )
                break

            cand_body = _normalize_dynamic_content(cand_resp.text or "")
            cand_body_lower = cand_body.lower()
            cand_len = len(cand_body)
            length_delta = abs(cand_len - baseline_len)
            status_differs = cand_resp.status_code != baseline_status
            length_differs = length_delta >= length_delta_threshold
            cand_fp = _fingerprint_response(cand_resp)
            digest_differs = bool(baseline_fp and cand_fp and baseline_fp.get("digest") != cand_fp.get("digest"))
            path_differs = bool(baseline_fp and cand_fp and baseline_fp.get("path") != cand_fp.get("path"))
            cand_password_step = _html_has_password_field(cand_resp.text or "")
            password_step_differs = cand_password_step != baseline_password_step
            message_class = _classify_failure_reason(cand_body_lower, baseline_body_lower)
            message_signal = message_class == "invalid_password"

            if use_timing and baseline_median > 0:
                timing_ratio = cand_median / baseline_median
                timing_differs = timing_ratio < low_ratio or timing_ratio > high_ratio
            else:
                timing_ratio = 1.0
                timing_differs = False

            same_as_invalid = _enum_control_match(cand_fp, baseline_fp)
            same_as_valid = _enum_control_match(cand_fp, valid_fp) if valid_control_usable else False

            if valid_control_usable:
                if same_as_valid and not same_as_invalid:
                    classification = "likely_valid"
                    control_relation = "matches_known_valid_control_only"
                elif same_as_invalid and not same_as_valid:
                    classification = "likely_invalid"
                    control_relation = "matches_invalid_control_only"
                elif same_as_valid and same_as_invalid:
                    classification = "inconclusive"
                    control_relation = "both_controls_indistinguishable"
                elif message_signal and not same_as_invalid:
                    classification = "likely_valid"
                    control_relation = "invalid_password_message"
                else:
                    classification = "inconclusive"
                    control_relation = "does_not_match_either_control"
            else:
                # Fallback when a known-valid control is unavailable.
                body_family = digest_differs or length_differs or message_signal
                routing_family = status_differs or path_differs
                timing_family = timing_differs
                step_family = password_step_differs and stepped
                family_count = int(body_family) + int(routing_family) + int(timing_family) + int(step_family)
                if step_family and cand_password_step and not baseline_password_step:
                    classification = "likely_valid"
                elif message_signal:
                    classification = "likely_valid"
                elif family_count >= 2:
                    classification = "inconclusive"
                elif body_family or routing_family or step_family:
                    classification = "inconclusive"
                else:
                    classification = "likely_invalid"
                control_relation = "baseline_only"

            fired = {
                "status": status_differs,
                "normalized_body": digest_differs,
                "path": path_differs,
                "length": length_differs,
                "message": message_signal,
                "timing": timing_differs,
                "password_step": password_step_differs,
                "matches_known_valid_control": same_as_valid,
                "matches_invalid_control": same_as_invalid,
            }
            fired_names = [name for name, on in fired.items() if on]
            signals = {
                "status_differs": status_differs,
                "baseline_status": baseline_status,
                "candidate_status": cand_resp.status_code,
                "length_delta": length_delta,
                "length_differs": length_differs,
                "normalized_digest_differs": digest_differs,
                "path_differs": path_differs,
                "password_step_differs": password_step_differs,
                "candidate_password_step": cand_password_step,
                "message": message_class,
                "message_invalid_password": message_signal,
                "timing_ratio": round(timing_ratio, 4),
                "timing_differs": timing_differs,
                "timing_enabled": use_timing,
                "matches_known_valid_control": same_as_valid,
                "matches_invalid_control": same_as_invalid,
                "control_relation": control_relation,
                "signals_fired": fired_names,
            }
            result.candidates.append(
                EnumerationCandidate(
                    username=username,
                    classification=classification,
                    signals=signals,
                    evidence=(
                        f"{username} {classification} relation={control_relation} "
                        f"fired=[{','.join(fired_names) or 'none'}] "
                        f"status={cand_resp.status_code}vs{baseline_status} "
                        f"len_delta={length_delta} ratio={timing_ratio:.2f} message={message_class}"
                    ),
                )
            )

        if result.result != ResultStatus.LOCKOUT_ABORTED:
            if any(
                c.classification == "likely_valid" and (c.signals or {}).get("page_disclosure")
                for c in result.candidates
            ):
                result.result = ResultStatus.VULNERABLE
            elif any(c.classification == "likely_valid" for c in result.candidates):
                result.result = ResultStatus.VULNERABLE
            elif any(c.classification == "inconclusive" for c in result.candidates):
                result.result = ResultStatus.UNRESOLVED
            else:
                result.result = ResultStatus.NOT_VULNERABLE

        result.client_status = _client_status(result.result)
        result.summary = _enum_summary(result)
        result.finished_at = datetime.now(timezone.utc).isoformat()
        self._clear_budget()
        return result

    def _guarded_form_probe(
        self,
        post_url: str,
        username: str,
        password: str,
        user_field: str,
        pass_field: str,
        extra_fields: Optional[dict],
        login_page_url: str,
        failure_markers: tuple[str, ...],
        guard: Optional[LockoutGuard],
    ) -> tuple[Optional[dict], bool]:
        if guard is not None:
            if not guard.can_proceed():
                return None, False
            guard.record_attempt()
        resp = self._post_login_form(
            post_url, username, password, user_field, pass_field,
            extra_fields=extra_fields, login_page_url=login_page_url,
        )
        if resp is None:
            return None, False
        return (
            _fingerprint_response(resp),
            _form_response_success(resp, post_url, login_page_url, failure_markers),
        )

    def _site_factor_behavior(
        self,
        post_url: str,
        login_page_url: str,
        user_field: str,
        pass_field: str,
        extra_fields: Optional[dict],
        known_username: str,
        known_password: str,
        failure_markers: tuple[str, ...],
        guard: Optional[LockoutGuard],
    ) -> str:
        """2x2 controls: both-invalid vs username-only vs password-only."""
        fake = f"nonexistent_{uuid.uuid4().hex[:12]}"
        wrong = _PROBE_WRONG_PASSWORD
        fp_both, _ = self._guarded_form_probe(
            post_url, fake, wrong, user_field, pass_field, extra_fields,
            login_page_url, failure_markers, guard,
        )
        fp_user_only, _ = self._guarded_form_probe(
            post_url, fake, known_password, user_field, pass_field, extra_fields,
            login_page_url, failure_markers, guard,
        )
        fp_pass_only, _ = self._guarded_form_probe(
            post_url, known_username, wrong, user_field, pass_field, extra_fields,
            login_page_url, failure_markers, guard,
        )
        if fp_both is None or fp_user_only is None or fp_pass_only is None:
            return "unknown"
        same_user = _same_fingerprint(fp_user_only, fp_both)
        same_pass = _same_fingerprint(fp_pass_only, fp_both)
        same_up = _same_fingerprint(fp_user_only, fp_pass_only)
        if same_user and same_pass and same_up:
            return "indistinguishable"
        parts = []
        if not same_user:
            parts.append("invalid_username")
        if not same_pass:
            parts.append("invalid_password")
        if not same_up:
            parts.append("username_vs_password")
        return "distinguishes:" + ",".join(parts)

    def diagnose_login_factors(
        self,
        login_path: str,
        username: str,
        password: str,
        known_valid_username: Optional[str] = None,
        known_valid_password: Optional[str] = None,
        guard: Optional[LockoutGuard] = None,
        failure_markers: tuple[str, ...] = ("invalid", "incorrect", "failed", "denied"),
    ) -> LoginFactorResult:
        """Classify one pair as both_valid, invalid_username, invalid_password, both_invalid, or indistinguishable."""
        report = self.diagnose_login_factor_pairs(
            login_path,
            [(username, password)],
            known_valid_username=known_valid_username,
            known_valid_password=known_valid_password,
            guard=guard,
            failure_markers=failure_markers,
        )
        row = report.verdicts[0] if report.verdicts else {}
        extra = row.get("evidence")
        evidence = list(report.evidence)
        if extra:
            evidence.append(extra)
        return LoginFactorResult(
            test_case_id=report.test_case_id,
            target=report.target,
            username=username,
            verdict=row.get("verdict", "unknown"),
            username_valid=row.get("username_valid"),
            password_valid=row.get("password_valid"),
            site_behavior=report.site_behavior,
            evidence=evidence,
            started_at=report.started_at,
            finished_at=report.finished_at,
        )

    def diagnose_login_factor_pairs(
        self,
        login_path: str,
        pairs: list[tuple[str, str]],
        known_valid_username: Optional[str] = None,
        known_valid_password: Optional[str] = None,
        guard: Optional[LockoutGuard] = None,
        failure_markers: tuple[str, ...] = ("invalid", "incorrect", "failed", "denied"),
    ) -> LoginFactorReport:
        """
        Test whether a login failure is invalid username, invalid password, or both.

        Builds control responses:
          both invalid     = fake user + guaranteed-wrong password
          username only    = fake user + known-valid password (if provided)
          password only    = known-valid user + guaranteed-wrong password (if provided)
        Then matches each submitted pair against those templates.
        """
        started = datetime.now(timezone.utc).isoformat()
        fallback_url = resolve_login_url(self.base_url, login_path)
        report = LoginFactorReport(
            test_case_id=f"IDNT04-{uuid.uuid4().hex[:8]}",
            target=fallback_url,
            started_at=started,
        )
        self._start_budget(self.enum_budget_seconds)
        extra_controls = int(bool(known_valid_username)) + int(bool(known_valid_password))
        guard = guard or LockoutGuard(
            max_attempts=8 + extra_controls + max(len(pairs), 1),
        )

        mechanism, page_url, form = self._probe_login_page(login_path)
        if mechanism != "form":
            report.site_behavior = "not_applicable"
            report.evidence.append("login_factors require a form-based login")
            report.finished_at = datetime.now(timezone.utc).isoformat()
            self._clear_budget()
            return report

        post_url = form.action_url if form else fallback_url
        user_field = form.user_field if form else "username"
        pass_field = form.pass_field if form else "password"
        extra_fields = form.extra_fields if form else {}
        report.target = post_url

        def probe(user: str, passwd: str) -> tuple[Optional[dict], bool]:
            return self._guarded_form_probe(
                post_url, user, passwd, user_field, pass_field, extra_fields,
                page_url, failure_markers, guard,
            )

        fake = f"nonexistent_{uuid.uuid4().hex[:12]}"
        wrong = _PROBE_WRONG_PASSWORD
        fp_both, _ = probe(fake, wrong)
        report.evidence.append(
            f"control_both_invalid user={fake} marker={(fp_both or {}).get('marker')}"
        )

        fp_user_only: Optional[dict] = None
        fp_pass_only: Optional[dict] = None
        if known_valid_password:
            fp_user_only, _ = probe(fake, known_valid_password)
            report.evidence.append(
                f"control_invalid_username_only marker={(fp_user_only or {}).get('marker')}"
            )
        if known_valid_username:
            fp_pass_only, _ = probe(known_valid_username, wrong)
            report.evidence.append(
                f"control_invalid_password_only marker={(fp_pass_only or {}).get('marker')}"
            )

        if fp_both and fp_user_only and fp_pass_only:
            if (
                _same_fingerprint(fp_both, fp_user_only)
                and _same_fingerprint(fp_both, fp_pass_only)
            ):
                report.site_behavior = "indistinguishable"
                report.evidence.append(
                    "site returns the same failure for invalid username, "
                    "invalid password, and both invalid"
                )
            else:
                report.site_behavior = "distinguishes"
                report.evidence.append(
                    "site distinguishes invalid username vs invalid password vs both invalid"
                )
        else:
            report.site_behavior = "unknown"

        user_exists_cache: dict[str, bool] = {}
        saw_user_existence_signal = False

        for username, password in pairs:
            fp_pair, success = probe(username, password)
            if success:
                report.verdicts.append({
                    "username": username,
                    "verdict": "both_valid",
                    "username_valid": True,
                    "password_valid": True,
                    "evidence": f"{username} verdict=both_valid",
                })
                continue

            if username not in user_exists_cache:
                fp_u, _ = probe(username, wrong)
                exists = False
                if fp_u and fp_u.get("marker") == "invalid_password":
                    exists = True
                elif fp_u and fp_u.get("marker") == "invalid_username":
                    exists = False
                elif fp_u and fp_both:
                    exists = not _same_fingerprint(fp_u, fp_both)
                user_exists_cache[username] = exists
                if exists:
                    saw_user_existence_signal = True

            user_exists = user_exists_cache[username]
            password_valid: Optional[bool] = None
            if known_valid_username:
                _, password_valid = probe(known_valid_username, password)

            if report.site_behavior == "indistinguishable":
                verdict, uv, pv = "indistinguishable", None, None
            elif user_exists:
                verdict, uv, pv = "invalid_password", True, False
            elif password_valid is True:
                # Username does not exist; this password works on a known account.
                verdict, uv, pv = "invalid_username", False, True
            elif password_valid is False:
                # Username does not exist AND password is not valid for the known account.
                verdict, uv, pv = "both_invalid", False, False
            elif fp_pass_only and fp_pair and _same_fingerprint(fp_pair, fp_pass_only):
                verdict, uv, pv = "invalid_password", True, False
            else:
                # Username looks unused; password could not be checked independently.
                verdict, uv, pv = "invalid_username", False, None

            report.verdicts.append({
                "username": username,
                "verdict": verdict,
                "username_valid": uv,
                "password_valid": pv,
                "evidence": (
                    f"{username} verdict={verdict} "
                    f"username_valid={uv} password_valid={pv}"
                ),
            })

        if report.site_behavior == "unknown":
            report.site_behavior = (
                "distinguishes" if saw_user_existence_signal else "indistinguishable"
            )
            report.evidence.append(f"site_behavior_inferred={report.site_behavior}")

        report.finished_at = datetime.now(timezone.utc).isoformat()
        self._clear_budget()
        return report


# ---------------------------------------------------------------------------
# Non-HTTP delegation to Hydra (dormant unless opted in)
# ---------------------------------------------------------------------------
# Master switch: Hydra stays dormant until the caller opts in
# (run_default_creds_tests.py --enable-hydra, or HYDRA_ENABLED = True).
HYDRA_ENABLED = False


def _hydra_skipped_result(
    target: str,
    service: str,
    reason: str = "hydra_dormant: skipped until --enable-hydra",
) -> DefaultCredResult:
    started = datetime.now(timezone.utc).isoformat()
    result = DefaultCredResult(
        test_case_id=f"DEFCREDS-{uuid.uuid4().hex[:8]}",
        target=f"{service}://{target}",
        auth_mechanism=service,
        result=ResultStatus.SKIPPED,
        evidence=[reason],
        started_at=started,
        finished_at=datetime.now(timezone.utc).isoformat(),
    )
    result.client_status = _client_status(result.result)
    result.summary = _default_cred_summary(result)
    return result


def _windows_path_to_wsl(path: str) -> str:
    """Convert a Windows path to a WSL path (e.g. C:\\foo -> /mnt/c/foo)."""
    abs_path = os.path.abspath(path)
    try:
        proc = subprocess.run(
            ["wsl.exe", "wslpath", "-u", abs_path],
            capture_output=True, text=True, timeout=15,
        )
        converted = (proc.stdout or "").strip()
        if proc.returncode == 0 and converted:
            return converted
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    drive, rest = os.path.splitdrive(abs_path)
    if drive:
        return "/mnt/" + drive[0].lower() + rest.replace("\\", "/")
    return abs_path.replace("\\", "/")


def _hydra_command(combo_file_path: str, target: str, service: str, extra_args: Optional[list[str]] = None) -> list[str]:
    """Build the Hydra argv. On Windows this is `wsl.exe hydra -C ...`."""
    combo = combo_file_path
    if sys.platform == "win32":
        combo = _windows_path_to_wsl(combo_file_path)
        cmd = ["wsl.exe", "hydra", "-C", combo, target, service]
    else:
        cmd = ["hydra", "-C", combo, target, service]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def run_hydra_default_creds(
    target: str,
    service: str,
    creds: list[CredPair],
    combo_file_path: Optional[str] = None,
    extra_args: Optional[list[str]] = None,
    enable: Optional[bool] = None,
) -> DefaultCredResult:
    """Delegates service-level (ssh, ftp, mysql, rdp, ...) default-cred
    testing to Hydra. Kept as a thin, deterministic subprocess wrapper —
    no parsing intelligence beyond extracting the 'login:' success line,
    consistent with your Nuclei/Nikto subprocess.run() pattern.

    Dormant by default. Pass enable=True or set HYDRA_ENABLED = True to run.
    """
    active = HYDRA_ENABLED if enable is None else enable
    if not active:
        return _hydra_skipped_result(target, service)

    test_case_id = f"DEFCREDS-{uuid.uuid4().hex[:8]}"
    started = datetime.now(timezone.utc).isoformat()

    result = DefaultCredResult(
        test_case_id=test_case_id, target=f"{service}://{target}",
        auth_mechanism=service, started_at=started,
    )

    own_temp = combo_file_path is None
    if own_temp:
        fd, combo_file_path = tempfile.mkstemp(prefix="default_creds_", suffix=".txt")
        os.close(fd)

    try:
        with open(combo_file_path, "w", encoding="utf-8", newline="\n") as f:
            for c in creds:
                f.write(f"{c.username}:{c.password}\n")

        cmd = _hydra_command(combo_file_path, target, service, extra_args)
        result.evidence.append("hydra_cmd:" + " ".join(cmd))

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        except FileNotFoundError as e:
            missing = "wsl.exe" if sys.platform == "win32" else "hydra"
            result.result = ResultStatus.ERROR
            result.evidence.append(f"{missing}_not_found: {e}")
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result
        except subprocess.TimeoutExpired:
            result.result = ResultStatus.ERROR
            result.evidence.append("hydra_timeout")
            result.finished_at = datetime.now(timezone.utc).isoformat()
            return result
    finally:
        if own_temp and combo_file_path:
            try:
                os.unlink(combo_file_path)
            except OSError:
                pass

    combined = ((proc.stdout or "") + "\n" + (proc.stderr or "")).strip()
    result.evidence.append(combined[-2000:] if combined else f"hydra_exit_{proc.returncode}")
    hits = [line for line in (proc.stdout or "").splitlines() if "login:" in line and "password:" in line]
    result.attempts_made = len(creds)
    result.successful_pairs = hits
    result.result = ResultStatus.VULNERABLE if hits else ResultStatus.NOT_VULNERABLE
    result.client_status = _client_status(result.result)
    result.summary = _default_cred_summary(result)
    result.finished_at = datetime.now(timezone.utc).isoformat()
    return result


# ---------------------------------------------------------------------------
# Dispatcher — the one deterministic decision point
# ---------------------------------------------------------------------------

def execute_default_creds_test(
    target: str,
    is_http: bool,
    service_or_path: str,
    creds_path: Optional[str] = None,
) -> DefaultCredResult:
    creds = load_cred_pairs(creds_path)
    if is_http:
        checker = HttpDefaultCredChecker(base_url=target)
        return checker.run(login_path=service_or_path, creds=creds)
    return run_hydra_default_creds(
        target=target, service=service_or_path, creds=creds,
    )


if __name__ == "__main__":
    # Example: form-based target
    res = execute_default_creds_test(
        target="http://demo.testfire.net",
        is_http=True,
        service_or_path="/login.jsp",
    )
    print(res.to_json())
