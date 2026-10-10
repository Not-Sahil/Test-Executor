from __future__ import annotations

"""
TC09 - ClearText Traffic

Transport-focused login-page assessment.

TC08 owns direct "login over HTTP" exposure. TC09 focuses on cleartext HTTP/WS
traffic initiated or referenced by an HTTPS login page, including mixed-content
resources and browser-observed requests.

No credentials are submitted and no authentication state is modified.
"""

from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse
import re

import requests

try:
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover
    sync_playwright = None


DEFAULT_TIMEOUT = 10.0
DEFAULT_BROWSER_TIMEOUT_MS = 15000
MAX_BODY_BYTES = 1_500_000
MAX_STATIC_REFERENCES = 300
MAX_BROWSER_REQUESTS = 500
USER_AGENT = "TestExecutor-TC09/1.0"

# These are deliberately categorized rather than treating every HTTP URL in
# HTML as equally severe.
ACTIVE_CONTENT_TYPES = {
    "script",
    "stylesheet",
    "iframe",
    "frame",
    "worker",
    "manifest",
    "websocket",
    "fetch",
    "xhr",
    "eventsource",
}

PASSIVE_CONTENT_TYPES = {
    "image",
    "font",
    "media",
    "texttrack",
    "other",
}

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "pass",
    "pwd",
    "token",
    "access_token",
    "refresh_token",
    "authorization",
    "api_key",
    "apikey",
    "secret",
    "session",
    "sessionid",
    "session_id",
}

HTTP_SCHEMES = {"http", "ws"}


@dataclass
class StaticReference:
    tag: str
    attribute: str
    raw_value: str
    resolved_url: str
    method: str
    has_sensitive_field: bool
    sensitive_fields: list[str]
    source_url: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class ReferenceParser(HTMLParser):
    """Extract network-capable references without executing page code."""

    def __init__(self, source_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.source_url = source_url
        self.references: list[StaticReference] = []
        self._current_form: dict[str, Any] | None = None

    @staticmethod
    def _sensitive_names(attrs: dict[str, str]) -> list[str]:
        found: list[str] = []
        for key in ("name", "id", "autocomplete"):
            value = attrs.get(key, "").strip().lower()
            if value and (
                value in SENSITIVE_FIELD_NAMES
                or any(token in value for token in SENSITIVE_FIELD_NAMES)
            ):
                found.append(value)
        input_type = attrs.get("type", "").strip().lower()
        if input_type == "password":
            found.append("password")
        return sorted(set(found))

    def _add(
        self,
        *,
        tag: str,
        attribute: str,
        raw_value: str,
        method: str = "GET",
        sensitive_fields: list[str] | None = None,
    ) -> None:
        raw = (raw_value or "").strip()
        if not raw or raw.startswith(("#", "data:", "javascript:", "mailto:", "tel:")):
            return

        resolved = urljoin(self.source_url, raw)
        scheme = urlparse(resolved).scheme.lower()
        if scheme not in HTTP_SCHEMES:
            return

        self.references.append(
            StaticReference(
                tag=tag,
                attribute=attribute,
                raw_value=raw,
                resolved_url=resolved,
                method=method.upper(),
                has_sensitive_field=bool(sensitive_fields),
                sensitive_fields=sensitive_fields or [],
                source_url=self.source_url,
            )
        )

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_l = tag.lower()
        d = {str(k).lower(): (v or "") for k, v in attrs}

        if tag_l == "form":
            action = d.get("action", "").strip() or self.source_url
            method = d.get("method", "GET").strip().upper() or "GET"
            self._current_form = {
                "action": action,
                "method": method,
                "sensitive_fields": [],
            }
            return

        if tag_l == "input" and self._current_form is not None:
            self._current_form["sensitive_fields"].extend(self._sensitive_names(d))
            return

        attr_map = {
            "script": ("src", "script"),
            "iframe": ("src", "iframe"),
            "frame": ("src", "frame"),
            "img": ("src", "image"),
            "audio": ("src", "media"),
            "video": ("src", "media"),
            "source": ("src", "media"),
            "track": ("src", "texttrack"),
            "link": ("href", "stylesheet"),
            "object": ("data", "other"),
            "embed": ("src", "other"),
            "form": ("action", "form"),
        }
        item = attr_map.get(tag_l)
        if item:
            attr, kind = item
            self._add(tag=kind, attribute=attr, raw_value=d.get(attr, ""))

        # WebSocket URLs sometimes appear in inline event/data attributes or
        # custom elements. They are only a static candidate here; browser
        # network evidence is authoritative.
        for key, value in d.items():
            if isinstance(value, str) and value.strip().lower().startswith("ws://"):
                self._add(tag=tag_l, attribute=key, raw_value=value)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "form" or self._current_form is None:
            return

        form = self._current_form
        self._add(
            tag="form",
            attribute="action",
            raw_value=form["action"],
            method=form["method"],
            sensitive_fields=sorted(set(form["sensitive_fields"])),
        )
        self._current_form = None

    def close(self) -> None:
        super().close()
        if self._current_form is not None:
            form = self._current_form
            self._add(
                tag="form",
                attribute="action",
                raw_value=form["action"],
                method=form["method"],
                sensitive_fields=sorted(set(form["sensitive_fields"])),
            )
            self._current_form = None


def _normalize_target(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        raise ValueError("target URL is empty")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urlparse(raw)
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
        raise ValueError("target must be an absolute HTTP(S) URL")
    return parsed._replace(fragment="").geturl()


def _login_url(target: str, login_path: str) -> str:
    return urljoin(
        target.rstrip("/") + "/",
        (login_path or "/login").lstrip("/"),
    )


def _origin(url: str) -> tuple[str, str, int]:
    p = urlparse(url)
    default = 443 if p.scheme.lower() == "https" else 80
    return (
        p.scheme.lower(),
        (p.hostname or "").lower(),
        p.port or default,
    )


def _same_host(a: str, b: str) -> bool:
    return (urlparse(a).hostname or "").lower() == (urlparse(b).hostname or "").lower()


def _fetch_login_page(
    url: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> tuple[requests.Response | None, list[str]]:
    evidence: list[str] = []
    try:
        response = requests.get(
            url,
            timeout=timeout,
            verify=verify_tls,
            allow_redirects=True,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
        )
        evidence.append(f"login_page_status={response.status_code}")
        evidence.append(f"login_page_final_url={response.url}")
        evidence.append(
            f"strict_transport_security={'present' if response.headers.get('Strict-Transport-Security') else 'absent'}"
        )
        return response, evidence
    except requests.exceptions.SSLError as exc:
        return None, [f"tls_error={exc}"]
    except requests.RequestException as exc:
        return None, [f"request_error={exc}"]


def _static_analysis(
    response: requests.Response,
    *,
    login_url: str,
    max_references: int,
) -> tuple[list[StaticReference], list[str]]:
    evidence: list[str] = []
    content = (response.text or "")[:MAX_BODY_BYTES]
    parser = ReferenceParser(response.url)
    try:
        parser.feed(content)
        parser.close()
    except Exception as exc:
        evidence.append(f"html_parse_error={type(exc).__name__}:{exc}")

    refs = parser.references[:max_references]
    if len(parser.references) > max_references:
        evidence.append(f"static_reference_limit={max_references}")

    return refs, evidence


def _safe_request_metadata(request) -> dict[str, Any]:
    try:
        url = request.url
        method = request.method
        resource_type = request.resource_type
        post_data = request.post_data
    except Exception as exc:
        return {"error": f"{type(exc).__name__}:{exc}"}

    # Never persist raw POST data. Record only whether data was present and
    # whether its field names look credential/token-like.
    sensitive_names: list[str] = []
    if post_data:
        for part in re.split(r"[&=]", post_data):
            key = part.strip().lower()
            if key in SENSITIVE_FIELD_NAMES or any(x in key for x in SENSITIVE_FIELD_NAMES):
                sensitive_names.append(key)

    return {
        "url": url,
        "method": method,
        "resource_type": resource_type,
        "post_data_present": bool(post_data),
        "sensitive_field_names": sorted(set(sensitive_names)),
        "has_sensitive_data_marker": bool(sensitive_names),
    }


def _browser_analysis(
    login_url: str,
    *,
    timeout_ms: int,
    verify_tls: bool,
    max_requests: int,
) -> dict[str, Any]:
    if sync_playwright is None:
        return {
            "available": False,
            "completed": False,
            "requests": [],
            "errors": ["Playwright is not installed."],
        }

    observed: list[dict[str, Any]] = []
    errors: list[str] = []

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            context = browser.new_context(
                ignore_https_errors=not verify_tls,
                service_workers="block",
            )
            page = context.new_page()

            def on_request(request) -> None:
                if len(observed) >= max_requests:
                    return
                try:
                    scheme = urlparse(request.url).scheme.lower()
                    if scheme in HTTP_SCHEMES:
                        observed.append(_safe_request_metadata(request))
                except Exception as exc:
                    errors.append(f"request_observer_error={type(exc).__name__}:{exc}")

            page.on("request", on_request)

            try:
                page.goto(
                    login_url,
                    wait_until="domcontentloaded",
                    timeout=timeout_ms,
                )
            except Exception as exc:
                errors.append(f"browser_navigation_error={type(exc).__name__}:{exc}")

            # Allow short-lived JS bootstrap requests to be captured without
            # turning TC09 into an unbounded crawler.
            try:
                page.wait_for_timeout(min(3000, max(250, timeout_ms // 4)))
            except Exception:
                pass

            try:
                final_url = page.url
            except Exception:
                final_url = ""

            try:
                title = page.title()
            except Exception:
                title = ""

            browser.close()

        return {
            "available": True,
            "completed": bool(final_url),
            "final_url": final_url,
            "title": title,
            "requests": observed,
            "errors": errors,
        }
    except Exception as exc:
        return {
            "available": True,
            "completed": False,
            "requests": observed,
            "errors": errors + [f"browser_start_error={type(exc).__name__}:{exc}"],
        }


def _classify(
    *,
    target: str,
    login_url: str,
    final_url: str,
    static_refs: list[StaticReference],
    browser: dict[str, Any],
    browser_available: bool,
) -> tuple[str, str, list[str], dict[str, Any]]:
    evidence: list[str] = []
    details: dict[str, Any] = {
        "finding_confirmed": False,
        "credentials_submitted": False,
        "scope_boundary": [
            "TC08 owns direct login-over-HTTP exposure.",
            "TC09 owns cleartext HTTP/WS traffic initiated or referenced by an HTTPS login page.",
            "TC01 owns autocomplete/autofill semantics.",
            "TC06 owns HTTP-method interchange.",
            "TC07 owns browser-memory retention.",
            "TC10 owns remember-me/session persistence.",
            "TC09 does not evaluate TLS certificate expiry or weak cipher configuration.",
        ],
    }

    static_dicts = [r.as_dict() for r in static_refs]
    details["static_cleartext_references"] = static_dicts
    details["browser_cleartext_requests"] = browser.get("requests", [])
    details["browser_errors"] = browser.get("errors", [])
    details["browser_available"] = browser_available
    details["browser_completed"] = browser.get("completed", False)

    # A login page that itself remains HTTP belongs to TC08. Do not duplicate
    # the same finding under TC09.
    if final_url.lower().startswith("http://"):
        details["delegated_to_tc08"] = True
        return (
            "NOT ASSESSED",
            "TC09 did not duplicate a direct HTTP login-page finding; TC08 owns login-page transport over HTTP.",
            ["final_login_page_scheme=http", "scope_delegated_to_tc08"],
            details,
        )

    # Browser evidence is stronger than static HTML because it tells us what
    # was actually requested after JavaScript execution.
    browser_requests = browser.get("requests", [])
    same_origin_browser = [
        r for r in browser_requests
        if _same_host(r.get("url", ""), final_url or login_url)
    ]
    third_party_browser = [
        r for r in browser_requests
        if r not in same_origin_browser
    ]

    active_browser = [
        r for r in same_origin_browser
        if (r.get("resource_type") or "").lower() in ACTIVE_CONTENT_TYPES
        or urlparse(r.get("url", "")).scheme.lower() == "ws"
        or r.get("has_sensitive_data_marker")
    ]
    passive_browser = [
        r for r in same_origin_browser
        if r not in active_browser
    ]

    sensitive_browser = [
        r for r in browser_requests
        if r.get("has_sensitive_data_marker")
    ]

    if sensitive_browser:
        details["finding_confirmed"] = True
        details["finding_type"] = "cleartext_sensitive_traffic"
        details["credentials_submitted"] = True
        evidence.append(f"browser_sensitive_cleartext_requests={len(sensitive_browser)}")
        return (
            "UNSAFE",
            "The HTTPS login flow generated a cleartext HTTP/WS request carrying a sensitive-data marker.",
            evidence,
            details,
        )

    if active_browser:
        details["finding_confirmed"] = True
        details["finding_type"] = "cleartext_active_content"
        evidence.append(f"browser_same_origin_active_cleartext_requests={len(active_browser)}")
        return (
            "UNSAFE",
            "The HTTPS login page generated cleartext HTTP/WS traffic for an active or executable resource.",
            evidence,
            details,
        )

    if passive_browser:
        evidence.append(f"browser_same_origin_passive_cleartext_requests={len(passive_browser)}")
        details["finding_type"] = "cleartext_passive_traffic"
        # Passive same-origin traffic is real cleartext traffic, but without
        # evidence of sensitive data we avoid overstating impact.
        return (
            "REVIEW REQUIRED",
            "The HTTPS login page generated same-origin cleartext traffic for passive resources.",
            evidence,
            details,
        )

    # Static references are candidates only. A browser that successfully ran
    # and produced no HTTP/WS request means blocked/unused mixed content should
    # not be falsely reported as transmitted traffic.
    same_origin_static = [
        r for r in static_refs
        if _same_host(r.resolved_url, final_url or login_url)
    ]
    active_static = [
        r for r in same_origin_static
        if r.tag in ACTIVE_CONTENT_TYPES
        or r.tag == "form"
        or urlparse(r.resolved_url).scheme.lower() == "ws"
    ]
    passive_static = [
        r for r in same_origin_static
        if r not in active_static
    ]

    if browser_available and browser.get("completed"):
        if same_origin_static:
            evidence.append(
                f"static_same_origin_cleartext_candidates={len(same_origin_static)}"
            )
            evidence.append("browser_observation_found_no_cleartext_requests")
            details["finding_type"] = "blocked_or_unused_cleartext_reference"
            return (
                "REVIEW REQUIRED",
                "The HTTPS login page contains same-origin cleartext references, but browser observation did not confirm that they were transmitted.",
                evidence,
                details,
            )

        if third_party_browser:
            evidence.append(
                f"browser_third_party_cleartext_requests={len(third_party_browser)}"
            )
            details["finding_type"] = "third_party_cleartext_traffic"
            return (
                "REVIEW REQUIRED",
                "The HTTPS login page generated third-party cleartext traffic without evidence that sensitive login data was carried.",
                evidence,
                details,
            )

    if active_static:
        evidence.append(f"static_same_origin_active_cleartext_candidates={len(active_static)}")
        details["finding_type"] = "static_active_cleartext_candidate"
        return (
            "REVIEW REQUIRED",
            "The HTTPS login page contains same-origin active-resource references using cleartext HTTP/WS; runtime transmission could not be confirmed.",
            evidence,
            details,
        )

    if passive_static:
        evidence.append(f"static_same_origin_passive_cleartext_candidates={len(passive_static)}")
        details["finding_type"] = "static_passive_cleartext_candidate"
        return (
            "REVIEW REQUIRED",
            "The HTTPS login page contains same-origin passive-resource references using cleartext HTTP; runtime transmission could not be confirmed.",
            evidence,
            details,
        )

    # No cleartext traffic/reference found.
    details["finding_type"] = "no_cleartext_traffic"
    evidence.append("no_cleartext_http_or_ws_traffic_observed")
    return (
        "SAFE",
        "No cleartext HTTP/WS traffic was identified in the HTTPS login-page assessment.",
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
        "key": "tc09_cleartext_traffic",
        "name": "ClearText Traffic",
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


def scan_cleartext_traffic(
    target: str,
    *,
    login_path: str = "/login",
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    browser_timeout_ms: int = DEFAULT_BROWSER_TIMEOUT_MS,
    use_browser: bool = True,
    max_static_references: int = MAX_STATIC_REFERENCES,
    max_browser_requests: int = MAX_BROWSER_REQUESTS,
    progress=None,
) -> dict[str, Any]:
    """
    Execute TC09 without submitting credentials.

    Browser execution is passive: it loads the login page only. No username,
    password, form submission, or CAPTCHA bypass is attempted.
    """
    try:
        normalized_target = _normalize_target(target)
        login_url = _login_url(normalized_target, login_path)
    except Exception as exc:
        return _result(
            target=target,
            status="INCOMPLETE",
            summary="TC09 could not normalize the configured target/login URL.",
            evidence=[f"{type(exc).__name__}: {exc}"],
            details={"finding_confirmed": False},
        )

    # TC09 is a secure-login transport companion. If the configured login URL
    # itself is HTTP, leave that finding to TC08 instead of duplicating it.
    if urlparse(login_url).scheme.lower() == "http":
        return _result(
            target=normalized_target,
            status="NOT ASSESSED",
            summary="TC09 is not independently assessed when the configured login URL is HTTP; TC08 owns direct login-over-HTTP testing.",
            evidence=["configured_login_url_scheme=http", "scope_delegated_to_tc08"],
            details={
                "finding_confirmed": False,
                "delegated_to_tc08": True,
            },
        )

    response, fetch_evidence = _fetch_login_page(
        login_url,
        timeout=max(0.1, float(timeout)),
        verify_tls=bool(verify_tls),
    )

    if response is None:
        return _result(
            target=normalized_target,
            status="INCOMPLETE",
            summary="TC09 could not retrieve the HTTPS login page.",
            evidence=fetch_evidence,
            details={"finding_confirmed": False},
        )

    final_url = response.url
    if not final_url.lower().startswith("https://"):
        return _result(
            target=normalized_target,
            status="NOT ASSESSED",
            summary="TC09 did not duplicate a direct HTTP login-page finding; TC08 owns that transport condition.",
            evidence=fetch_evidence + [
                f"final_login_page_scheme={urlparse(final_url).scheme.lower()}",
                "scope_delegated_to_tc08",
            ],
            details={
                "finding_confirmed": False,
                "delegated_to_tc08": True,
            },
        )

    static_refs, static_evidence = _static_analysis(
        response,
        login_url=login_url,
        max_references=max(1, int(max_static_references)),
    )

    if progress:
        progress("Analyzing cleartext references in the HTTPS login page")

    browser = {
        "available": False,
        "completed": False,
        "requests": [],
        "errors": [],
    }

    if use_browser:
        if progress:
            progress("Observing browser-generated cleartext traffic")
        browser = _browser_analysis(
            final_url,
            timeout_ms=max(1000, int(browser_timeout_ms)),
            verify_tls=bool(verify_tls),
            max_requests=max(1, int(max_browser_requests)),
        )

    status, summary, evidence, details = _classify(
        target=normalized_target,
        login_url=login_url,
        final_url=final_url,
        static_refs=static_refs,
        browser=browser,
        browser_available=bool(browser.get("available")),
    )

    details.update(
        {
            "login_url": login_url,
            "final_url": final_url,
            "credentials_submitted": False
            if not details.get("credentials_submitted")
            else True,
            "authorized_credentials_required": False,
            "static_reference_count": len(static_refs),
            "browser_request_count": len(browser.get("requests", [])),
            "fetch_evidence": fetch_evidence,
            "static_evidence": static_evidence,
            "browser_available": bool(browser.get("available")),
            "browser_used": bool(use_browser),
        }
    )

    # Browser execution errors should not turn an independently confirmed
    # finding into INCOMPLETE. For a clean result, however, preserve the
    # limitation so the operator can see whether static-only analysis was used.
    if browser.get("errors"):
        evidence.extend(
            f"browser_note={item}" for item in browser["errors"][:10]
        )

    return _result(
        target=normalized_target,
        status=status,
        summary=summary,
        evidence=evidence,
        details=details,
    )


scan = scan_cleartext_traffic

__all__ = ["scan_cleartext_traffic", "scan", "ReferenceParser", "StaticReference"]
