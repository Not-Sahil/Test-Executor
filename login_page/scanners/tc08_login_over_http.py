from __future__ import annotations

"""
TC08 - Login over HTTP

Purpose
-------
Determine whether an application's login page or credential-submission endpoint
uses plaintext HTTP instead of HTTPS.

Design goals
------------
* Do not submit real credentials by default.
* Detect HTTP login pages, HTTP form actions, HTTP redirects, and HTTP-only
  authentication endpoints.
* Distinguish a page being reachable over HTTP from credentials actually being
  submitted over HTTP.
* Never treat the mere existence of an HTTP listener as sufficient evidence
  when it immediately redirects to HTTPS.
* Preserve evidence without recording credentials.
* Return the same result vocabulary used by the login-page suite:
  SAFE, UNSAFE, REVIEW REQUIRED, INCOMPLETE, NOT ASSESSED.
* Avoid modifying or depending on TC01-TC07 behavior.

The scanner is intentionally transport-focused. It does not perform credential
validation, default-credential testing, enumeration, method interchange,
browser-memory inspection, session persistence, or TLS cipher analysis.
"""

from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import requests


MAX_REDIRECTS = 8
MAX_BODY_BYTES = 1_500_000
DEFAULT_TIMEOUT = 10.0
USER_AGENT = "TestExecutor-TC08/1.0"

# Login-like path tokens are only used as weak evidence. They never establish
# a finding by themselves.
LOGIN_PATH_TOKENS = (
    "login",
    "signin",
    "sign-in",
    "authenticate",
    "auth",
    "session",
)

PASSWORD_INPUT_TYPES = {"password"}

SENSITIVE_FORM_FIELD_NAMES = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "current_password",
    "current-password",
    "new_password",
    "new-password",
}

SENSITIVE_FORM_FIELD_TYPES = {
    "password",
}

SECURITY_HEADER_NAMES = (
    "strict-transport-security",
    "content-security-policy",
    "upgrade-insecure-requests",
)


@dataclass
class FormInfo:
    action_raw: str
    action_url: str
    method: str
    has_password_field: bool
    password_field_count: int
    field_names: list[str]
    source_url: str
    action_resolution: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class LoginFormParser(HTMLParser):
    """Small, dependency-free parser for login form transport analysis."""

    def __init__(self, source_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.source_url = source_url
        self.forms: list[FormInfo] = []
        self._current: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        attrs_d = {str(k).lower(): (v or "") for k, v in attrs}

        if tag == "form":
            action_raw = attrs_d.get("action", "").strip()
            method = attrs_d.get("method", "GET").strip().upper() or "GET"

            # HTML form submission with an empty/relative action resolves
            # against the document URL.
            action_url = urljoin(self.source_url, action_raw or self.source_url)

            if not action_raw:
                resolution = "document_url"
            elif urlparse(action_raw).scheme:
                resolution = "explicit_scheme"
            else:
                resolution = "relative_action"

            self._current = {
                "action_raw": action_raw,
                "action_url": action_url,
                "method": method,
                "has_password_field": False,
                "password_field_count": 0,
                "field_names": [],
                "source_url": self.source_url,
                "action_resolution": resolution,
            }
            return

        if tag == "input" and self._current is not None:
            input_type = attrs_d.get("type", "text").strip().lower()
            name = attrs_d.get("name", "").strip().lower()

            if name:
                self._current["field_names"].append(name)

            if input_type in PASSWORD_INPUT_TYPES or name in SENSITIVE_FORM_FIELD_NAMES:
                self._current["has_password_field"] = True
                self._current["password_field_count"] += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current is None:
            return

        self.forms.append(FormInfo(**self._current))
        self._current = None

    def close(self) -> None:
        super().close()
        # Malformed HTML can omit </form>. Preserve the discovered form instead
        # of silently losing it.
        if self._current is not None:
            self.forms.append(FormInfo(**self._current))
            self._current = None


def _normalize_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target URL is empty")

    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("target must use http:// or https://")

    if not parsed.netloc:
        raise ValueError("target URL has no host")

    if not parsed.hostname or any(ch.isspace() for ch in parsed.hostname):
        raise ValueError("target URL has an invalid hostname")

    # Fragments are never sent to the server.
    return parsed._replace(fragment="").geturl()


def _opposite_scheme(url: str) -> str:
    parsed = urlparse(url)
    scheme = "http" if parsed.scheme.lower() == "https" else "https"
    return parsed._replace(scheme=scheme).geturl()


def _default_port(scheme: str) -> int:
    return 443 if scheme.lower() == "https" else 80


def _origin(url: str) -> tuple[str, str, int]:
    p = urlparse(url)
    return (
        (p.scheme or "").lower(),
        (p.hostname or "").lower(),
        p.port or _default_port(p.scheme),
    )


def _same_origin(a: str, b: str) -> bool:
    return _origin(a) == _origin(b)


def _looks_like_login_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(token in path for token in LOGIN_PATH_TOKENS)


def _header_subset(response: requests.Response) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in SECURITY_HEADER_NAMES:
        value = response.headers.get(name)
        if value:
            result[name] = value
    return result


def _response_snapshot(response: requests.Response) -> dict[str, Any]:
    body = response.content or b""
    return {
        "status_code": response.status_code,
        "url": response.url,
        "content_type": response.headers.get("Content-Type", ""),
        "content_length": len(body),
        "location": response.headers.get("Location", ""),
        "security_headers": _header_subset(response),
    }


def _request(
    session: requests.Session,
    url: str,
    *,
    timeout: float,
    verify_tls: bool,
    allow_redirects: bool,
) -> requests.Response:
    return session.get(
        url,
        timeout=timeout,
        verify=verify_tls,
        allow_redirects=allow_redirects,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        },
    )


def _walk_get(
    session: requests.Session,
    start_url: str,
    *,
    timeout: float,
    verify_tls: bool,
    max_redirects: int = MAX_REDIRECTS,
) -> tuple[list[dict[str, Any]], requests.Response | None, list[str]]:
    """
    Follow GET redirects manually so an HTTP -> HTTPS transition is visible.

    This is important because requests' normal redirect handling hides the
    intermediate HTTP response from the testcase.
    """
    chain: list[dict[str, Any]] = []
    evidence: list[str] = []
    visited: set[str] = set()
    current = start_url

    for hop in range(max_redirects + 1):
        if current in visited:
            evidence.append("redirect_loop_detected")
            chain.append({"hop": hop, "url": current, "error": "redirect_loop"})
            return chain, None, evidence

        visited.add(current)

        try:
            response = _request(
                session,
                current,
                timeout=timeout,
                verify_tls=verify_tls if urlparse(current).scheme == "https" else False,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            chain.append({
                "hop": hop,
                "url": current,
                "error_type": "tls_error",
                "error": str(exc),
            })
            return chain, None, evidence
        except requests.RequestException as exc:
            chain.append({
                "hop": hop,
                "url": current,
                "error_type": "request_error",
                "error": str(exc),
            })
            return chain, None, evidence

        item = _response_snapshot(response)
        item["hop"] = hop
        chain.append(item)

        if 300 <= response.status_code < 400:
            location = response.headers.get("Location", "").strip()
            if not location:
                evidence.append(
                    f"redirect_without_location status={response.status_code} url={current}"
                )
                return chain, response, evidence

            next_url = urljoin(current, location)
            evidence.append(f"redirect {current} -> {next_url}")

            if next_url in visited:
                evidence.append("redirect_loop_detected")
                return chain, None, evidence

            current = next_url
            continue

        return chain, response, evidence

    evidence.append(f"redirect_limit_exceeded={max_redirects}")
    return chain, None, evidence


def _fetch_http_and_https(
    target: str,
    *,
    login_path: str,
    timeout: float,
    verify_tls: bool,
) -> dict[str, Any]:
    parsed = urlparse(target)

    https_base = parsed._replace(scheme="https").geturl()
    http_base = parsed._replace(scheme="http").geturl()

    relative_login = (login_path or "/login").strip() or "/login"
    https_login = urljoin(https_base.rstrip("/") + "/", relative_login.lstrip("/"))
    http_login = urljoin(http_base.rstrip("/") + "/", relative_login.lstrip("/"))

    session = requests.Session()

    http_chain, http_final, http_evidence = _walk_get(
        session,
        http_login,
        timeout=timeout,
        verify_tls=verify_tls,
    )

    https_chain, https_final, https_evidence = _walk_get(
        session,
        https_login,
        timeout=timeout,
        verify_tls=verify_tls,
    )

    return {
        "http_login_url": http_login,
        "https_login_url": https_login,
        "http_chain": http_chain,
        "http_final": http_final,
        "http_evidence": http_evidence,
        "https_chain": https_chain,
        "https_final": https_final,
        "https_evidence": https_evidence,
    }


def _parse_forms(response: requests.Response | None) -> list[FormInfo]:
    if response is None:
        return []

    content_type = response.headers.get("Content-Type", "").lower()
    if "html" not in content_type and "<form" not in (response.text or "").lower():
        return []

    parser = LoginFormParser(response.url)
    try:
        parser.feed((response.text or "")[:MAX_BODY_BYTES])
        parser.close()
    except Exception:
        return parser.forms

    return parser.forms


def _is_plaintext_login_form(form: FormInfo) -> bool:
    return (
        form.has_password_field
        and urlparse(form.action_url).scheme.lower() == "http"
        and form.method.upper() in {"POST", "PUT", "PATCH"}
    )


def _collect_login_forms(
    http_final: requests.Response | None,
    https_final: requests.Response | None,
) -> dict[str, Any]:
    http_forms = _parse_forms(http_final)
    https_forms = _parse_forms(https_final)

    return {
        "http_forms": [form.as_dict() for form in http_forms],
        "https_forms": [form.as_dict() for form in https_forms],
        "http_password_forms": [
            form.as_dict()
            for form in http_forms
            if form.has_password_field
        ],
        "https_password_forms": [
            form.as_dict()
            for form in https_forms
            if form.has_password_field
        ],
        "http_plaintext_submission_forms": [
            form.as_dict()
            for form in http_forms
            if _is_plaintext_login_form(form)
        ],
        "https_forms_with_http_action": [
            form.as_dict()
            for form in https_forms
            if form.has_password_field
            and urlparse(form.action_url).scheme.lower() == "http"
        ],
    }


def _analyze(
    *,
    target: str,
    data: dict[str, Any],
    login_path: str,
) -> tuple[str, str, list[str], dict[str, Any]]:
    evidence: list[str] = []
    details: dict[str, Any] = {
        "finding_confirmed": False,
        "scope_boundary": [
            "TC08 evaluates whether login pages or credential-submission endpoints use plaintext HTTP.",
            "TC01 owns autocomplete/autofill behavior.",
            "TC02 owns default credentials.",
            "TC03 owns blank/missing credential acceptance.",
            "TC04 owns username enumeration.",
            "TC05 owns incorrect-password validation.",
            "TC06 owns HTTP-method interchange behavior.",
            "TC07 owns browser-memory retention.",
            "TC09 owns TLS certificate expiry.",
            "TC08 does not evaluate weak TLS protocols/ciphers.",
        ],
    }

    http_final = data["http_final"]
    https_final = data["https_final"]
    http_chain = data["http_chain"]
    https_chain = data["https_chain"]
    forms = data["forms"]

    details["http_redirect_chain"] = http_chain
    details["https_redirect_chain"] = https_chain
    details["http_evidence"] = data["http_evidence"]
    details["https_evidence"] = data["https_evidence"]
    details["forms"] = forms

    # ---------------------------------------------------------
    # Strong finding 1: credentials can be submitted to HTTP.
    # ---------------------------------------------------------
    plaintext_forms = forms["http_plaintext_submission_forms"]
    if plaintext_forms:
        evidence.append(
            f"plaintext_credential_submission_forms={len(plaintext_forms)}"
        )
        details["finding_confirmed"] = True
        details["finding_type"] = "http_credential_submission"
        return (
            "UNSAFE",
            "The login form exposes a password field whose credential-submission endpoint uses plaintext HTTP.",
            evidence,
            details,
        )

    https_http_actions = forms["https_forms_with_http_action"]
    if https_http_actions:
        evidence.append(
            f"https_login_page_with_http_password_action={len(https_http_actions)}"
        )
        details["finding_confirmed"] = True
        details["finding_type"] = "http_credential_submission"
        return (
            "UNSAFE",
            "The HTTPS login page submits password credentials to an HTTP endpoint.",
            evidence,
            details,
        )

    # ---------------------------------------------------------
    # Strong finding 2: HTTP login page actually serves a login
    # form containing a password field instead of redirecting to
    # HTTPS.
    # ---------------------------------------------------------
    http_password_forms = forms["http_password_forms"]
    if http_password_forms and http_final is not None:
        final_scheme = urlparse(http_final.url).scheme.lower()

        if final_scheme == "http":
            evidence.append(
                f"http_login_page_served_password_form={len(http_password_forms)}"
            )
            details["finding_confirmed"] = True
            details["finding_type"] = "http_login_page"
            return (
                "UNSAFE",
                "A login page containing a password field is served over plaintext HTTP.",
                evidence,
                details,
            )

    # ---------------------------------------------------------
    # Strong finding 3: HTTP endpoint is an authentication page
    # and remains HTTP. This handles applications whose login UI
    # is generated dynamically and has no static <form>.
    # ---------------------------------------------------------
    if http_final is not None and urlparse(http_final.url).scheme.lower() == "http":
        status = http_final.status_code
        content = (http_final.text or "")[:MAX_BODY_BYTES].lower()
        login_signal = (
            _looks_like_login_url(http_final.url)
            or "type=\"password\"" in content
            or "type='password'" in content
            or "name=\"password\"" in content
            or "name='password'" in content
        )

        if 200 <= status < 300 and login_signal:
            evidence.append(
                f"http_login_endpoint_served_application status={status}"
            )
            details["finding_confirmed"] = True
            details["finding_type"] = "http_login_endpoint"
            return (
                "UNSAFE",
                "A login endpoint remains accessible over plaintext HTTP and exposes login-related content.",
                evidence,
                details,
            )

    # ---------------------------------------------------------
    # HTTPS baseline.
    # ---------------------------------------------------------
    if https_final is None:
        evidence.append("https_login_endpoint_unreachable_or_not_completed")

        if http_final is not None and urlparse(http_final.url).scheme.lower() == "http":
            return (
                "UNSAFE",
                "The login endpoint is available over HTTP while no usable HTTPS login endpoint could be established.",
                evidence,
                details,
            )

        return (
            "REVIEW REQUIRED",
            "The scanner could not establish a usable HTTPS login endpoint, so login transport security could not be verified reliably.",
            evidence,
            details,
        )

    https_forms = forms["https_password_forms"]

    if https_forms:
        evidence.append(f"https_password_forms={len(https_forms)}")

        # If the HTTPS form has a relative/HTTPS action, credential transport
        # is encrypted at the HTTP layer.
        safe_actions = [
            f for f in https_forms
            if urlparse(f["action_url"]).scheme.lower() == "https"
        ]
        if safe_actions:
            evidence.append(
                f"password_forms_submitting_over_https={len(safe_actions)}"
            )

    # ---------------------------------------------------------
    # If the final HTTPS page appears to be a dynamic login UI
    # but exposes no static password form, do not claim SAFE.
    # Browser-side JavaScript may create the credential endpoint
    # after page load. This remains a manual-review condition.
    # ---------------------------------------------------------
    if https_final is not None:
        content = (https_final.text or "")[:MAX_BODY_BYTES].lower()
        if (
            not https_forms
            and (
                _looks_like_login_url(https_final.url)
                or any(
                    token in content
                    for token in ("login", "sign in", "signin", "authenticate")
                )
            )
        ):
            evidence.append("login_flow_detected_without_static_password_form")
            if http_final is not None and http_final.url.startswith("https://"):
                evidence.append("http_login_request_redirects_to_https_before_final_login_page")
                details["finding_type"] = "dynamic_https_login"
            else:
                details["finding_type"] = "dynamic_login"
            return (
                "REVIEW REQUIRED",
                "The login flow appears to be HTTPS-based, but no static password form was available to verify the credential-submission endpoint.",
                evidence,
                details,
            )

    # ---------------------------------------------------------
    # If the HTTP endpoint redirects to HTTPS and the final
    # login page is HTTPS, no plaintext credential submission was
    # demonstrated by the static transport test.
    # ---------------------------------------------------------
    if http_final is not None and http_final.url.startswith("https://"):
        if https_forms or not forms["http_password_forms"]:
            evidence.append("http_login_request_redirects_to_https_before_final_login_page")
            details["finding_confirmed"] = False
            details["finding_type"] = "https_enforced_by_redirect"
            return (
                "SAFE",
                "The HTTP login URL redirects to HTTPS before the final login page is served, and no plaintext password submission was identified.",
                evidence,
                details,
            )

    # ---------------------------------------------------------
    # HTTPS login page exists and no HTTP credential path was
    # demonstrated.
    # ---------------------------------------------------------
    if https_forms:
        details["finding_confirmed"] = False
        details["finding_type"] = "https_login_transport"
        return (
            "SAFE",
            "The detected login form and credential-submission endpoint use HTTPS; no plaintext HTTP credential path was confirmed.",
            evidence,
            details,
        )

    return (
        "REVIEW REQUIRED",
        "The scanner could not reliably identify a login credential transport path.",
        evidence,
        details,
    )


def _result(
    *,
    target: str,
    status: str,
    summary: str,
    evidence: list[str],
    details: dict[str, Any],
) -> dict[str, Any]:
    assessment_state = {
        "SAFE": "NOT_A_FINDING",
        "UNSAFE": "CONFIRMED",
        "REVIEW REQUIRED": "REVIEW_REQUIRED",
        "INCOMPLETE": "INCOMPLETE",
        "NOT ASSESSED": "NOT_ASSESSED",
    }.get(status, "REVIEW_REQUIRED")

    return {
        "key": "tc08_login_over_http",
        "name": "Login over HTTP",
        "status": status,
        "assessment_state": assessment_state,
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


def scan_login_over_http(
    target: str,
    *,
    login_path: str = "/login",
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
) -> dict[str, Any]:
    """
    Execute TC08.

    No credentials are required and no authentication attempt is performed.
    This keeps TC08 independent from TC02-TC05 and avoids lockout side effects.
    """
    try:
        normalized_target = _normalize_target(target)
    except Exception as exc:
        return _result(
            target=target,
            status="INCOMPLETE",
            summary="TC08 could not normalize the configured target URL.",
            evidence=[f"{type(exc).__name__}: {exc}"],
            details={"finding_confirmed": False},
        )

    try:
        data = _fetch_http_and_https(
            normalized_target,
            login_path=login_path,
            timeout=max(0.1, float(timeout)),
            verify_tls=bool(verify_tls),
        )

        data["forms"] = _collect_login_forms(
            data["http_final"],
            data["https_final"],
        )

        status, summary, evidence, details = _analyze(
            target=normalized_target,
            data=data,
            login_path=login_path,
        )

        details["login_path"] = login_path
        details["credentials_submitted"] = False
        details["authorized_credentials_required"] = False
        details["transport_only"] = True

        return _result(
            target=normalized_target,
            status=status,
            summary=summary,
            evidence=evidence,
            details=details,
        )

    except KeyboardInterrupt:
        raise
    except Exception as exc:
        return _result(
            target=normalized_target,
            status="INCOMPLETE",
            summary="TC08 encountered an unexpected error while analyzing login transport.",
            evidence=[f"{type(exc).__name__}: {exc}"],
            details={
                "finding_confirmed": False,
                "credentials_submitted": False,
                "authorized_credentials_required": False,
            },
        )


# Compatibility entry point matching the existing login-page scanners.
scan = scan_login_over_http


__all__ = [
    "FormInfo",
    "LoginFormParser",
    "scan_login_over_http",
    "scan",
]
