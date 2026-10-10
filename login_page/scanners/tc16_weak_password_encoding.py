from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import requests


STATUS_SAFE = "SAFE"
STATUS_UNSAFE = "UNSAFE"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_NOT_ASSESSED = "NOT ASSESSED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_ERROR = "ERROR"

DEFAULT_TIMEOUT = 8.0
MAX_BODY = 300_000

WEAK_PASSWORD_HINTS = (
    "minimum password length",
    "password must be at least",
    "password length",
    "password complexity",
    "uppercase",
    "lowercase",
    "special character",
    "number",
    "password history",
    "password reuse",
    "common password",
    "password policy",
    "strong password",
)

SSO_MARKERS = (
    "saml", "oauth", "openid", "oidc", "microsoftonline.com",
    "sign in with microsoft", "okta", "pingidentity",
)

CAPTCHA_MARKERS = ("captcha", "recaptcha", "hcaptcha", "turnstile")

PASSWORD_FIELD_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]password['\"][^>]*>",
    re.I | re.S,
)

STORAGE_RE = re.compile(
    r"(localStorage|sessionStorage)\s*\.\s*(?:setItem|getItem)\s*\(",
    re.I,
)

PASSWORD_CLIENT_TRANSFORM_RE = re.compile(
    r"(?:password|passwd|pwd)[^;\n]{0,180}"
    r"(?:btoa|atob|encodeURIComponent|decodeURIComponent|"
    r"toString\s*\(\s*16\s*\)|Buffer\.from|CryptoJS)",
    re.I,
)

COMMON_WEAK_MARKERS = (
    "123456",
    "password",
    "qwerty",
    "password1",
    "12345678",
)

CHARSET_RESTRICTION_RE = re.compile(
    r"(password).{0,250}(?:must|only|allow).{0,250}"
    r"(?:[a-z]|[A-Z]|digit|number|special|alphanumeric|ascii)",
    re.I | re.S,
)


@dataclass
class WeakPasswordConfig:
    timeout: float = DEFAULT_TIMEOUT
    verify_tls: bool = True
    login_path: str | None = None
    max_pages: int = 4
    allow_browser_visible_checks: bool = True
    include_public_password_pages: bool = True
    synthetic_marker: str = "TC16_SYNTHETIC_PASSWORD_7F3A"
    user_agent: str = "SecurityAssessment-TC16-WeakPassword/1.0"


def _normalize_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    p = urlparse(value)
    if not p.hostname:
        return ""
    return value.rstrip("/")


def _text(body: str) -> str:
    return (body or "")[:MAX_BODY]


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (
        pa.scheme.lower() == pb.scheme.lower()
        and pa.netloc.lower() == pb.netloc.lower()
    )


def _password_fields(body: str) -> list[dict[str, Any]]:
    fields = []
    for m in PASSWORD_FIELD_RE.finditer(body):
        tag = m.group(0)
        nm = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        aid = re.search(r'\bid\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        minlength = re.search(r'\bminlength\s*=\s*["\']?(\d+)', tag, re.I)
        maxlength = re.search(r'\bmaxlength\s*=\s*["\']?(\d+)', tag, re.I)
        pattern = re.search(r'\bpattern\s*=\s*["\']([^"\']+)["\']', tag, re.I)
        autocomplete = re.search(
            r'\bautocomplete\s*=\s*["\']([^"\']+)["\']', tag, re.I
        )
        fields.append({
            "name": nm.group(1) if nm else "",
            "id": aid.group(1) if aid else "",
            "minlength": int(minlength.group(1)) if minlength else None,
            "maxlength": int(maxlength.group(1)) if maxlength else None,
            "pattern": pattern.group(1) if pattern else "",
            "autocomplete": autocomplete.group(1) if autocomplete else "",
        })
    return fields[:20]


def _forms(body: str, base_url: str) -> list[dict[str, Any]]:
    out = []
    for m in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.I | re.S):
        attrs, inner = m.group(1), m.group(2)
        action_m = re.search(r'\baction\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(r'\bmethod\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        action = urljoin(base_url, action_m.group(1)) if action_m else base_url
        method = (method_m.group(1) if method_m else "GET").upper()
        passwords = _password_fields(inner)
        if passwords:
            out.append({
                "action": action,
                "method": method,
                "password_fields": passwords,
            })
    return out[:10]


def _looks_like_base64(value: str) -> bool:
    value = value.strip()
    if len(value) < 12 or len(value) % 4:
        return False
    try:
        decoded = base64.b64decode(value, validate=True)
        return bool(decoded) and all(9 <= b <= 126 or b in (10, 13) for b in decoded)
    except Exception:
        return False


def _storage_findings(body: str) -> list[str]:
    hits = []
    for m in STORAGE_RE.finditer(body):
        start = max(0, m.start() - 180)
        end = min(len(body), m.end() + 260)
        context = body[start:end]
        if re.search(r"(password|passwd|pwd|credential|secret)", context, re.I):
            hits.append("Password-related data appears near local/session storage access.")
    return hits[:10]


def _client_transform_findings(body: str) -> list[str]:
    hits = []
    for m in PASSWORD_CLIENT_TRANSFORM_RE.finditer(body):
        context = body[max(0, m.start() - 100):min(len(body), m.end() + 180)]
        hits.append(
            "Password-related client-side transformation detected: "
            + re.sub(r"\s+", " ", context)[:280]
        )
    return hits[:10]


def _policy_findings(body: str, fields: list[dict[str, Any]]) -> list[str]:
    low = body.lower()
    findings = []

    if "password" in low:
        if not any(x in low for x in WEAK_PASSWORD_HINTS):
            findings.append("No explicit password-policy guidance was observable.")

    for field in fields:
        if field["maxlength"] is not None and field["maxlength"] < 15:
            findings.append(
                f"Password field exposes a maximum length of {field['maxlength']}."
            )
        if field["maxlength"] is not None and field["maxlength"] < 64:
            findings.append(
                f"Password field maximum length is below 64 characters: {field['maxlength']}."
            )
        if field["pattern"]:
            findings.append("Password field uses a client-visible character/pattern restriction.")

    if CHARSET_RESTRICTION_RE.search(body):
        findings.append("Password character-set restrictions are visible to the client.")

    if any(x in low for x in COMMON_WEAK_MARKERS):
        findings.append("Common weak-password examples are visible in the application.")

    return list(dict.fromkeys(findings))[:20]


def _scan_page(session: requests.Session, url: str, config: WeakPasswordConfig) -> dict:
    response = session.get(
        url,
        timeout=config.timeout,
        verify=config.verify_tls,
        allow_redirects=True,
    )
    body = _text(response.text)
    headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    combined = body + "\n" + headers

    fields = _password_fields(body)
    forms = _forms(body, response.url)

    sso = [x for x in SSO_MARKERS if x.lower() in combined.lower()]
    captcha = [x for x in CAPTCHA_MARKERS if x.lower() in combined.lower()]

    return {
        "requested_url": url,
        "final_url": response.url,
        "status_code": response.status_code,
        "content_type": response.headers.get("Content-Type", ""),
        "password_field_count": len(fields),
        "password_fields": fields,
        "forms": forms,
        "sso_markers": sorted(set(sso)),
        "captcha_markers": sorted(set(captcha)),
        "policy_findings": _policy_findings(body, fields),
        "storage_findings": _storage_findings(body),
        "client_transform_findings": _client_transform_findings(body),
        "response_contains_synthetic_marker": config.synthetic_marker in body,
        "body_length": len(body),
    }


def _public_password_urls(target: str, login_path: str | None) -> list[str]:
    paths = []
    if login_path:
        paths.append(login_path)
    paths.extend((
        "/login",
        "/login.jsp",
        "/signin",
        "/sign-in",
        "/register",
        "/signup",
        "/password",
        "/change-password",
        "/forgot-password",
        "/reset-password",
    ))
    seen = set()
    out = []
    for path in paths:
        u = urljoin(target + "/", path.lstrip("/"))
        if _same_origin(u, target) and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _result(
    status: str,
    summary: str,
    details: dict,
    evidence: list[str] | None = None,
) -> dict:
    return {
        "status": status,
        "summary": summary,
        "details": details,
        "evidence": evidence or [],
        "raw_output": json.dumps(details, ensure_ascii=False, default=str),
    }


def scan_weak_password_encoding(
    target: str,
    *,
    config: WeakPasswordConfig | None = None,
    **kwargs: Any,
) -> dict:
    if config is None:
        allowed = {
            k: v for k, v in kwargs.items()
            if k in WeakPasswordConfig.__dataclass_fields__
        }
        config = WeakPasswordConfig(**allowed)

    target = _normalize_url(target)
    if not target:
        return _result(
            STATUS_INCOMPLETE,
            "The target URL could not be resolved.",
            {"error": "invalid_target"},
        )

    session = requests.Session()
    session.headers.update({"User-Agent": config.user_agent})

    pages = []
    errors = []

    urls = _public_password_urls(target, config.login_path)
    urls = urls[: max(1, config.max_pages)]

    for url in urls:
        try:
            page = _scan_page(session, url, config)
            pages.append(page)
        except requests.RequestException as exc:
            errors.append({"url": url, "error": str(exc)})
        except Exception as exc:
            errors.append({
                "url": url,
                "error": str(exc),
                "exception_type": type(exc).__name__,
            })

    if not pages:
        return _result(
            STATUS_INCOMPLETE,
            "No configured password-handling page could be inspected.",
            {"tested_urls": urls, "errors": errors},
        )

    all_sso = sorted({x for p in pages for x in p["sso_markers"]})
    all_captcha = sorted({x for p in pages for x in p["captcha_markers"]})
    all_policy = []
    all_storage = []
    all_transform = []

    for page in pages:
        all_policy.extend(page["policy_findings"])
        all_storage.extend(page["storage_findings"])
        all_transform.extend(page["client_transform_findings"])

    evidence = []
    unsafe_reasons = []

    # Transport-level check: an HTTP password page is unsafe for credential entry.
    for page in pages:
        if page["password_field_count"] and page["final_url"].lower().startswith("http://"):
            unsafe_reasons.append("A password input is served over unencrypted HTTP.")
            evidence.append(f"Password form exposed over HTTP: {page['final_url']}")

    # Password in URL/query parameters is a strong finding even without submitting it.
    for page in pages:
        parsed = urlparse(page["final_url"])
        qs = parse_qs(parsed.query, keep_blank_values=True)
        password_keys = [
            k for k in qs
            if re.search(r"(password|passwd|pwd|secret|credential)", k, re.I)
        ]
        if password_keys:
            unsafe_reasons.append("Password-like data is present in a URL query parameter.")
            evidence.append(
                "Password-like query parameter observed in URL; value was not recorded."
            )

    # Echoing the synthetic marker proves reflection into a response.
    if any(p["response_contains_synthetic_marker"] for p in pages):
        unsafe_reasons.append("A synthetic password marker was reflected by a password-handling response.")
        evidence.append("Synthetic password marker was reflected; the marker value was not emitted.")

    # Browser-visible storage of password-related values is unsafe.
    if all_storage:
        unsafe_reasons.append("Password-related data appears associated with browser local/session storage.")
        evidence.extend(all_storage[:5])

    # Policy weaknesses are review findings rather than proof of compromise.
    review_reasons = list(dict.fromkeys(all_policy + all_transform))

    if all_sso and not any(p["password_field_count"] for p in pages):
        return _result(
            STATUS_NOT_ASSESSED,
            "The observable authentication flow appears federated/SSO rather than local password authentication.",
            {
                "pages": pages,
                "sso_markers": all_sso,
                "captcha_markers": all_captcha,
                "errors": errors,
            },
            evidence,
        )

    if all_captcha and not any(p["password_field_count"] for p in pages):
        return _result(
            STATUS_NOT_ASSESSED,
            "Password testing could not be completed because the observable flow is CAPTCHA-gated.",
            {"pages": pages, "captcha_markers": all_captcha, "errors": errors},
            evidence,
        )

    if unsafe_reasons:
        status = STATUS_UNSAFE
        summary = "A high-confidence password handling weakness was observed."
        evidence.extend(unsafe_reasons)
    elif review_reasons:
        status = STATUS_REVIEW
        summary = "Password policy or client-side encoding behavior requires manual review."
        evidence.extend(review_reasons[:20])
    elif any(p["password_field_count"] for p in pages):
        status = STATUS_SAFE
        summary = "No high-confidence weak password/encoding issue was observed in the bounded public checks."
    else:
        status = STATUS_NOT_ASSESSED
        summary = "No observable password-handling flow was found on the tested public pages."

    details = {
        "target": target,
        "pages": pages,
        "policy_findings": list(dict.fromkeys(all_policy)),
        "storage_findings": list(dict.fromkeys(all_storage)),
        "client_transform_findings": list(dict.fromkeys(all_transform)),
        "sso_markers": all_sso,
        "captcha_markers": all_captcha,
        "errors": errors,
        "active_password_submission": False,
        "password_spraying": False,
        "brute_force": False,
        "real_credentials_used": False,
    }

    return _result(status, summary, details, evidence[:50])


def scan(target: str, **kwargs: Any) -> dict:
    return scan_weak_password_encoding(target, **kwargs)
