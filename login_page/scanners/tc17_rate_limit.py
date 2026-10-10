from __future__ import annotations

"""
TC17 - Rate Limit / Login Throttling

Additive scanner. It deliberately requires explicitly authorized credentials and
uses a small, configurable number of wrong-password attempts. It never guesses
credentials, rotates IPs, spoofs proxy headers, or performs distributed attacks.
"""

from dataclasses import dataclass, field, asdict, make_dataclass
from html.parser import HTMLParser
from time import monotonic, sleep
from typing import Any
from urllib.parse import urljoin, urlparse

from authentication.auth_discovery import (
    login_page_candidates,
    normalize_login_url,
    target_looks_like_login_page,
)

import requests


try:
    from core.models import ScanResult
except ImportError:  # pragma: no cover
    ScanResult = make_dataclass(
        "_FallbackScanResult",
        [
            ("key", str),
            ("name", str),
            ("status", str),
            ("summary", str),
            ("raw_output", str, field(default="")),
            ("evidence", list, field(default_factory=list)),
            ("details", dict, field(default_factory=dict)),
        ],
    )


@dataclass
class RateLimitConfig:
    login_path: str = "/login"
    authorized_username: str | None = None
    authorized_password: str | None = None

    # Optional second explicitly authorized account. This is never guessed.
    secondary_username: str | None = None
    secondary_password: str | None = None

    timeout: float = 12.0
    verify_tls: bool = True
    max_wrong_attempts: int = 6
    min_interval_seconds: float = 0.75
    max_wait_after_block_seconds: float = 3.0

    # Optional protected URL used only to establish a valid-session baseline.
    protected_url: str | None = None

    # Browser fallback is intentionally opt-in. The scanner remains HTTP-first.
    allow_browser_fallback: bool = False
    browser_timeout_ms: int = 15000

    # Severity metadata is optional and only used if the project's engine exists.
    attack_vector: str = "NETWORK"
    asset_exposure: str = "INTERNET"
    scope: str = "UNCHANGED"


@dataclass
class AttemptRecord:
    index: int
    username: str
    status_code: int | None
    elapsed_seconds: float
    final_url: str
    rate_limited: bool
    captcha_detected: bool
    lockout_detected: bool
    rejected: bool
    authenticated: bool
    retry_after_seconds: float | None
    headers: dict[str, str]
    signals: list[str] = field(default_factory=list)
    error: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RateLimitResult:
    status: str
    summary: str
    evidence: list[str]
    details: dict[str, Any]
    raw_output: str = ""


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self.current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_d = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            self.current = {
                "action": attrs_d.get("action", ""),
                "method": (attrs_d.get("method") or "post").lower(),
                "inputs": [],
            }
        elif tag == "input" and self.current is not None:
            self.current["inputs"].append(attrs_d)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None


def _result(status: str, summary: str, *, evidence=None, details=None) -> RateLimitResult:
    return RateLimitResult(
        status=status,
        summary=summary,
        evidence=list(evidence or []),
        details=dict(details or {}),
    )


def _assessment_state(status: str) -> str:
    return {
        "UNSAFE": "CONFIRMED",
        "SAFE": "NOT_A_FINDING",
        "REVIEW REQUIRED": "REVIEW_REQUIRED",
        "INCOMPLETE": "INCOMPLETE",
        "NOT ASSESSED": "NOT_ASSESSED",
    }.get(status, "REVIEW_REQUIRED")


def _redact_username(username: str | None) -> str:
    if not username:
        return ""
    if "@" in username:
        local, domain = username.split("@", 1)
        return (local[:1] + "***@" + domain) if local else "***@" + domain
    return username[:1] + "***"


def _redact_password(password: str | None) -> str:
    if password is None:
        return ""
    return f"<redacted:length={len(password)}>"


def _normalize_target(target: str) -> str:
    value = (target or "").strip()
    if not value:
        raise ValueError("target is required")
    if "://" not in value:
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an absolute HTTP(S) URL")
    return value.rstrip("/")


def _login_url(target: str, login_path: str) -> str:
    # If the operator already supplied the login page, use it directly.
    # Otherwise use the shared resolver and preserve the application's base path.
    normalized = _normalize_target(target)
    if target_looks_like_login_page(normalized):
        return normalized
    return normalize_login_url(normalized, login_path)


def _safe_header_value(value: str | None) -> str:
    if value is None:
        return ""
    lowered = value.lower()
    if "token" in lowered or "cookie" in lowered or "authorization" in lowered:
        return "<redacted>"
    return value[:240]


def _relevant_headers(response: requests.Response) -> dict[str, str]:
    names = {
        "retry-after",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "server",
        "location",
    }
    return {
        k.lower(): _safe_header_value(v)
        for k, v in response.headers.items()
        if k.lower() in names
    }


def _retry_after(response: requests.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if not raw:
        return None
    try:
        value = float(raw.strip())
        return value if value >= 0 else None
    except ValueError:
        # HTTP-date form is intentionally recorded as present but not converted,
        # avoiding dependency on wall-clock parsing for the security decision.
        return None


def _response_text(response: requests.Response) -> str:
    return (response.text or "")[:250_000]


_RATE_TERMS = (
    "too many requests",
    "too many attempts",
    "rate limit",
    "rate-limit",
    "rate limited",
    "temporarily blocked",
    "temporarily locked",
    "try again later",
    "slow down",
    "requests are being throttled",
    "throttled",
    "login attempts exceeded",
    "attempt limit",
)
_CAPTCHA_TERMS = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "turnstile",
    "arkose",
)
_LOCKOUT_TERMS = (
    "account locked",
    "account is locked",
    "temporarily locked",
    "locked out",
    "too many failed",
    "login disabled",
    "account disabled",
    "try again later",
)
_SUCCESS_TERMS = (
    "logout",
    "sign out",
    "dashboard",
    "my account",
    "welcome",
)


def _signals(response: requests.Response) -> tuple[list[str], bool, bool, bool, bool]:
    body = _response_text(response).lower()
    signals: list[str] = []

    captcha = any(term in body for term in _CAPTCHA_TERMS)
    lockout = any(term in body for term in _LOCKOUT_TERMS)
    # Specific account-lockout language takes priority over overlapping rate
    # tokens (for example, "temporarily locked" appears in both sets).
    rate_signal = any(term in body for term in _RATE_TERMS)
    rate = response.status_code == 429 or (rate_signal and not lockout)
    success = (
        response.status_code in {301, 302, 303, 307, 308}
        and any(token in (response.headers.get("Location", "").lower()) for token in
                ("dashboard", "account", "home", "profile"))
    ) or any(term in body for term in _SUCCESS_TERMS)

    if response.status_code == 429:
        signals.append("http_429")
    if response.headers.get("Retry-After"):
        signals.append("retry_after_present")
    if any(k.lower().startswith(("x-ratelimit-", "ratelimit-")) for k in response.headers):
        signals.append("rate_limit_headers_present")
    if rate:
        signals.append("rate_limit_signal")
    if captcha:
        signals.append("captcha_signal")
    if lockout:
        signals.append("lockout_signal")
    if success:
        signals.append("possible_success_signal")

    rejected = not success and not rate and not captcha and not lockout
    return signals, rate, captcha, lockout, success and not rejected


def _find_login_form(html: str, page_url: str) -> dict[str, Any] | None:
    parser = _FormParser()
    parser.feed(html or "")
    candidates = []
    for form in parser.forms:
        password_inputs = [
            i for i in form["inputs"] if str(i.get("type", "")).lower() == "password"
        ]
        if not password_inputs:
            continue
        action = urljoin(page_url, form["action"] or page_url)
        method = str(form["method"] or "post").lower()
        candidates.append((form, action, method))

    if not candidates:
        return None

    # Prefer a form whose action contains login/signin/auth.
    candidates.sort(
        key=lambda item: (
            not any(token in item[1].lower() for token in ("login", "signin", "sign-in", "auth")),
            item[2] != "post",
        )
    )
    form, action, method = candidates[0]
    return {"form": form, "action": action, "method": method}


def _field_names(form: dict[str, Any]) -> tuple[str, str, dict[str, str]]:
    inputs = form["inputs"]
    password_name = ""
    username_name = ""
    hidden: dict[str, str] = {}

    for item in inputs:
        name = str(item.get("name") or item.get("id") or "").strip()
        if not name:
            continue
        typ = str(item.get("type") or "text").lower()
        if typ == "password" and not password_name:
            password_name = name
        elif typ in {"hidden"}:
            hidden[name] = str(item.get("value") or "")
        elif not username_name and (
            typ in {"email", "text"} or any(
                token in name.lower() for token in ("user", "email", "login", "identifier")
            )
        ):
            username_name = name

    if not username_name:
        username_name = "username"
    if not password_name:
        password_name = "password"

    return username_name, password_name, hidden


def _candidate_wrong_password(valid_password: str, index: int) -> str:
    """
    Generates deterministic wrong passwords derived from the authorized password.
    No password dictionary or credential guessing is used.
    """
    if not valid_password:
        return ""
    suffix = f"__TC17_{index:02d}_WRONG"
    candidate = valid_password + suffix
    if candidate == valid_password:
        candidate += "x"
    return candidate


def _fresh_session(verify_tls: bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify_tls
    session.headers.update(
        {
            "User-Agent": "TC17-RateLimit-Authorized-Assessment/1.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        }
    )
    return session


def _fetch_login_form(
    session: requests.Session,
    target: str,
    config: RateLimitConfig,
) -> tuple[str, dict[str, Any] | None, str]:
    last_url = _login_url(target, config.login_path)
    last_status = "login_page_unreached"
    for page_url in login_page_candidates(target, config.login_path):
        response = session.get(
            page_url,
            timeout=config.timeout,
            allow_redirects=True,
        )
        last_url = response.url
        last_status = f"login_page_status={response.status_code}"
        form = _find_login_form(_response_text(response), response.url)
        if form:
            return response.url, form, last_status
    return last_url, None, last_status


def _submit(
    session: requests.Session,
    form_info: dict[str, Any],
    username: str,
    password: str,
    timeout: float,
) -> requests.Response:
    username_name, password_name, hidden = _field_names(form_info["form"])
    data = dict(hidden)
    data[username_name] = username
    data[password_name] = password

    method = form_info["method"]
    if method == "get":
        return session.get(
            form_info["action"],
            params=data,
            timeout=timeout,
            allow_redirects=True,
        )
    return session.post(
        form_info["action"],
        data=data,
        timeout=timeout,
        allow_redirects=True,
    )


def _authorized_control(
    session: requests.Session,
    form_info: dict[str, Any],
    username: str,
    password: str,
    config: RateLimitConfig,
) -> tuple[bool, AttemptRecord]:
    started = monotonic()
    try:
        response = _submit(session, form_info, username, password, config.timeout)
        elapsed = monotonic() - started
        signals, rate, captcha, lockout, success = _signals(response)
        record = AttemptRecord(
            index=0,
            username=_redact_username(username),
            status_code=response.status_code,
            elapsed_seconds=round(elapsed, 4),
            final_url=response.url,
            rate_limited=rate,
            captcha_detected=captcha,
            lockout_detected=lockout,
            rejected=not success and not rate and not captcha and not lockout,
            authenticated=success,
            retry_after_seconds=_retry_after(response),
            headers=_relevant_headers(response),
            signals=signals,
        )
        return success, record
    except requests.RequestException as exc:
        return False, AttemptRecord(
            index=0,
            username=_redact_username(username),
            status_code=None,
            elapsed_seconds=round(monotonic() - started, 4),
            final_url=form_info["action"],
            rate_limited=False,
            captcha_detected=False,
            lockout_detected=False,
            rejected=False,
            authenticated=False,
            retry_after_seconds=None,
            headers={},
            error=str(exc),
        )


def _probe_wrong_attempts(
    session: requests.Session,
    form_info: dict[str, Any],
    username: str,
    valid_password: str,
    config: RateLimitConfig,
    progress=None,
) -> tuple[list[AttemptRecord], bool]:
    records: list[AttemptRecord] = []
    blocked = False

    count = max(1, min(int(config.max_wrong_attempts), 10))

    for index in range(1, count + 1):
        if progress:
            progress(f"TC17 rate-limit probe attempt {index}/{count}")

        if records:
            sleep(max(0.0, min(config.min_interval_seconds, 5.0)))

        password = _candidate_wrong_password(valid_password, index)
        started = monotonic()

        try:
            response = _submit(
                session,
                form_info,
                username,
                password,
                config.timeout,
            )
            elapsed = monotonic() - started
            signals, rate, captcha, lockout, success = _signals(response)
            record = AttemptRecord(
                index=index,
                username=_redact_username(username),
                status_code=response.status_code,
                elapsed_seconds=round(elapsed, 4),
                final_url=response.url,
                rate_limited=rate,
                captcha_detected=captcha,
                lockout_detected=lockout,
                rejected=not success and not rate and not captcha and not lockout,
                authenticated=success,
                retry_after_seconds=_retry_after(response),
                headers=_relevant_headers(response),
                signals=signals,
            )
            records.append(record)

            # A rate-limit/CAPTCHA/lockout response is the control under test.
            # Stop immediately to avoid extending an account lockout.
            if rate or captcha or lockout:
                blocked = True
                break

            # Never continue if the supposedly wrong password appears accepted.
            if success:
                break

        except requests.RequestException as exc:
            records.append(
                AttemptRecord(
                    index=index,
                    username=_redact_username(username),
                    status_code=None,
                    elapsed_seconds=round(monotonic() - started, 4),
                    final_url=form_info["action"],
                    rate_limited=False,
                    captcha_detected=False,
                    lockout_detected=False,
                    rejected=False,
                    authenticated=False,
                    retry_after_seconds=None,
                    headers={},
                    error=str(exc),
                )
            )
            break

    return records, blocked


def _attempt_to_dict(record: Any) -> dict[str, Any]:
    """Serialize an attempt record without assuming a dataclass implementation."""
    if hasattr(record, "as_dict") and callable(record.as_dict):
        try:
            return dict(record.as_dict())
        except Exception:
            pass
    if hasattr(record, "__dict__"):
        return {str(k): v for k, v in vars(record).items() if not str(k).startswith("_")}
    fields = ("index", "rate_limited", "captcha_detected", "lockout_detected", "authenticated", "rejected", "status_code", "elapsed_seconds")
    return {name: getattr(record, name) for name in fields if hasattr(record, name)}


def _classify(
    control_ok: bool,
    records: list[AttemptRecord],
    *,
    captcha_on_page: bool,
    target_url: str,
) -> RateLimitResult:
    evidence: list[str] = [
        f"target={target_url}",
        f"wrong_attempts_observed={len(records)}",
        f"authorized_valid_control={control_ok}",
    ]

    if not records:
        return _result(
            "INCOMPLETE",
            "TC17 could not perform any bounded wrong-password rate-limit probe.",
            evidence=evidence,
        )

    rate_index = next((r.index for r in records if r.rate_limited), None)
    captcha_index = next((r.index for r in records if r.captcha_detected), None)
    lockout_index = next((r.index for r in records if r.lockout_detected), None)
    accidental_success = next((r.index for r in records if r.authenticated), None)

    for r in records:
        evidence.append(
            "attempt="
            f"{r.index}:status={r.status_code}:rate_limited={r.rate_limited}:"
            f"captcha={r.captcha_detected}:lockout={r.lockout_detected}:"
            f"elapsed={r.elapsed_seconds:.4f}s"
        )

    if accidental_success is not None:
        return _result(
            "REVIEW REQUIRED",
            "A derived wrong-password probe produced a possible authentication-success signal; "
            "the scanner stopped rather than continuing attempts.",
            evidence=evidence + [f"possible_success_attempt={accidental_success}"],
            details={"attempts": [_attempt_to_dict(r) for r in records]},
        )

    if rate_index is not None or captcha_index is not None or lockout_index is not None:
        block_type = (
            "rate limit" if rate_index is not None
            else "CAPTCHA challenge" if captcha_index is not None
            else "account lockout"
        )
        index = rate_index or captcha_index or lockout_index
        status = "SAFE"
        summary = (
            f"TC17 observed an anti-automation control ({block_type}) after a bounded "
            f"sequence of authorized-account wrong-password attempts."
        )
        details = {
            "attempts": [_attempt_to_dict(r) for r in records],
            "first_block_attempt": index,
            "control_type": block_type,
            "captcha_on_login_page": captcha_on_page,
        }
        return _result(status, summary, evidence=evidence, details=details)

    if len(records) >= 1 and all(r.rejected for r in records):
        return _result(
            "UNSAFE",
            (
                f"No rate-limit, CAPTCHA, or lockout control was observed after {len(records)} "
                "consecutive failed login attempts. A pentester would report missing login throttling."
            ),
            evidence=evidence + ["no_observed_throttle_within_test_window"],
            details={
                "attempts": [_attempt_to_dict(r) for r in records],
                "tested_attempt_limit": len(records),
                "control_type": "none_observed",
                "limitation": (
                    "A longer-window, distributed, or WAF control could still exist outside this "
                    "bounded probe; none was observed in the tested window."
                ),
            },
        )

    return _result(
        "REVIEW REQUIRED",
        "TC17 could not reliably determine the rate-limit behavior from the observed responses.",
        evidence=evidence,
        details={"attempts": [_attempt_to_dict(r) for r in records]},
    )


def scan_rate_limit(
    target: str,
    config: RateLimitConfig | None = None,
    *,
    progress=None,
) -> ScanResult:
    config = config or RateLimitConfig()

    has_authorized = bool(config.authorized_username and config.authorized_password)
    if not has_authorized:
        config.authorized_username = config.authorized_username or "tc17-rate-limit-invalid-user"
        config.authorized_password = config.authorized_password or "Tc17-Wrong-Password-7F3A"

    try:
        target_url = _normalize_target(target)
        login_url = _login_url(target_url, config.login_path)
    except ValueError as exc:
        return _as_scan_result(
            _result(
                "INCOMPLETE",
                f"Invalid TC17 target: {exc}",
                evidence=[f"target_validation_error={exc}"],
            )
        )

    session = _fresh_session(config.verify_tls)

    if progress:
        progress("TC17 discovering the login form")

    try:
        final_login_url, form_info, page_evidence = _fetch_login_form(
            session, target_url, config
        )
    except requests.RequestException as exc:
        return _as_scan_result(
            _result(
                "INCOMPLETE",
                "TC17 could not retrieve the login page.",
                evidence=[f"login_page_request_error={exc}", f"login_url={login_url}"],
            )
        )

    if form_info is None:
        body = ""
        try:
            body_response = session.get(
                final_login_url, timeout=config.timeout, allow_redirects=True
            )
            body = _response_text(body_response).lower()
        except requests.RequestException:
            pass

        if any(term in body for term in _CAPTCHA_TERMS):
            return _as_scan_result(
                _result(
                    "NOT ASSESSED",
                    "TC17 could not safely exercise the local password login because the login page is CAPTCHA-protected.",
                    evidence=[page_evidence, "captcha_detected_on_login_page"],
                )
            )

        return _as_scan_result(
            _result(
                "INCOMPLETE",
                "TC17 could not identify a password-bearing login form.",
                evidence=[page_evidence, "password_login_form_not_found"],
            )
        )

    login_body = ""
    try:
        page_response = session.get(
            final_login_url, timeout=config.timeout, allow_redirects=True
        )
        login_body = _response_text(page_response).lower()
    except requests.RequestException:
        pass

    captcha_on_page = any(term in login_body for term in _CAPTCHA_TERMS)

    if captcha_on_page:
        return _as_scan_result(
            _result(
                "NOT ASSESSED",
                "TC17 did not bypass the login CAPTCHA; automated rate-limit probing was not performed.",
                evidence=[page_evidence, "captcha_detected_on_login_page"],
            )
        )

    control_ok = False
    control_record = None
    if has_authorized:
        if progress:
            progress("TC17 establishing the authorized valid-login control")

        control_ok, control_record = _authorized_control(
            session,
            form_info,
            config.authorized_username,
            config.authorized_password,
            config,
        )

        if control_record.rate_limited or control_record.captcha_detected or control_record.lockout_detected:
            return _as_scan_result(
                _result(
                    "REVIEW REQUIRED",
                    "The authorized valid-login control was itself throttled or challenged before TC17 could establish a clean baseline.",
                    evidence=[
                        page_evidence,
                        "valid_control_interrupted",
                        *control_record.signals,
                    ],
                    details={"valid_control": control_record.as_dict()},
                )
            )

        if not control_ok:
            return _as_scan_result(
                _result(
                    "INCOMPLETE",
                    "The authorized valid-login control did not establish a reliable authenticated baseline; "
                    "TC17 stopped without guessing credentials.",
                    evidence=[
                        page_evidence,
                        "valid_control_failed",
                        *control_record.signals,
                    ],
                    details={"valid_control": control_record.as_dict()},
                )
            )
    elif progress:
        progress("TC17 probing failed-login rate limiting with synthetic invalid credentials")

    # If the project supplies a protected URL, verify that the valid control really
    # established access. This remains read-only.
    protected_check = None
    if has_authorized and config.protected_url:
        protected_url = urljoin(target_url + "/", config.protected_url.lstrip("/"))
        try:
            response = session.get(
                protected_url,
                timeout=config.timeout,
                allow_redirects=True,
            )
            protected_check = {
                "status_code": response.status_code,
                "final_url": response.url,
                "authenticated_cookie_count": len(session.cookies),
                "possible_auth_success": response.status_code < 400,
            }
        except requests.RequestException as exc:
            protected_check = {"error": str(exc)}

    if progress:
        progress("TC17 running the bounded wrong-password rate-limit probe")

    records, blocked = _probe_wrong_attempts(
        session,
        form_info,
        config.authorized_username,
        config.authorized_password,
        config,
        progress=progress,
    )

    result = _classify(
        control_ok=control_ok,
        records=records,
        captcha_on_page=captcha_on_page,
        target_url=final_login_url,
    )

    result.details.update(
        {
            "test_case": "TC17",
            "name": "Rate Limit / Login Throttling",
            "login_url": final_login_url,
            "valid_control": control_record.as_dict() if control_record is not None else {"used": False, "synthetic_invalid_credentials": not has_authorized},
            "protected_access_check": protected_check,
            "configured_max_wrong_attempts": max(1, min(int(config.max_wrong_attempts), 10)),
            "configured_min_interval_seconds": config.min_interval_seconds,
            "bounded_probe_stopped_on_control": blocked,
            "secondary_account_available": bool(
                config.secondary_username and config.secondary_password
            ),
            "scope_boundaries": [
                "An authorized account is used when supplied; otherwise synthetic invalid credentials probe throttling.",
                "No credential dictionary, password guessing, spraying, or brute-force list is used.",
                "No IP rotation, proxy rotation, X-Forwarded-For spoofing, or distributed bypass is performed.",
                "The scanner stops on rate-limit, CAPTCHA, or account-lockout signals.",
                "Long-window, WAF/CDN, distributed, or multi-account enforcement cannot be proven from a single bounded source.",
                "Default credentials belong to the default-credential testcase.",
                "Username enumeration belongs to the username-enumeration testcase.",
                "Wrong-password acceptance belongs to the password-validation testcase.",
            ],
        }
    )

    return _as_scan_result(result)


def _as_scan_result(result: RateLimitResult):
    details = dict(result.details)
    details["assessment_state"] = _assessment_state(result.status)
    try:
        return ScanResult(
            key="TC17",
            name="Rate Limit / Login Throttling",
            status=result.status,
            summary=result.summary,
            raw_output=result.raw_output,
            evidence=result.evidence,
            details=details,
        )
    except TypeError:  # compatibility with richer ScanResult models
        return ScanResult(
            key="TC17",
            name="Rate Limit / Login Throttling",
            status=result.status,
            summary=result.summary,
            raw_output=result.raw_output,
            evidence=result.evidence,
            details=details,
        )


def scan(
    target: str,
    *,
    config: RateLimitConfig | None = None,
    progress=None,
    **kwargs: Any,
):
    if config is None:
        config = RateLimitConfig(
            login_path=str(kwargs.get("login_path") or "/login"),
            authorized_username=kwargs.get("authorized_username"),
            authorized_password=kwargs.get("authorized_password"),
            secondary_username=kwargs.get("secondary_username"),
            secondary_password=kwargs.get("secondary_password"),
            timeout=float(kwargs.get("timeout", 12.0)),
            verify_tls=bool(kwargs.get("verify_tls", True)),
            max_wrong_attempts=int(kwargs.get("max_wrong_attempts", 6)),
            min_interval_seconds=float(kwargs.get("min_interval_seconds", 0.75)),
            protected_url=kwargs.get("protected_url"),
        )
    return scan_rate_limit(target, config, progress=progress)


if __name__ == "__main__":
    import argparse
    import json

    parser = argparse.ArgumentParser(description="TC17 Rate Limit / Login Throttling scanner")
    parser.add_argument("target")
    parser.add_argument("--login-path", default="/login")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--max-attempts", type=int, default=6)
    parser.add_argument("--interval", type=float, default=0.75)
    parser.add_argument("--insecure", action="store_true")
    args = parser.parse_args()

    result = scan_rate_limit(
        args.target,
        RateLimitConfig(
            login_path=args.login_path,
            authorized_username=args.username,
            authorized_password=args.password,
            max_wrong_attempts=args.max_attempts,
            min_interval_seconds=args.interval,
            verify_tls=not args.insecure,
        ),
    )
    print(json.dumps(asdict(result) if hasattr(result, "__dataclass_fields__") else result.__dict__, indent=2, default=str))
