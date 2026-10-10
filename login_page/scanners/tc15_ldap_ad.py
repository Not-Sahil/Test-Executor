"""
TC15 — LDAP / Active Directory authentication security checks.

Additive scanner. No existing testcase is modified.

The implementation is intentionally bounded and non-destructive:
- discovers public LDAP/AD indicators;
- performs controlled login-flow probes only when an input endpoint can be
  identified;
- never performs directory enumeration, password spraying, or directory writes.
"""

from __future__ import annotations

import html
import json
import re
import time
from dataclasses import dataclass, asdict
from typing import Any, Iterable
from urllib.parse import urljoin, urlparse

import requests

from payloads.manager import load_lines


STATUS_SAFE = "SAFE"
STATUS_UNSAFE = "UNSAFE"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_NOT_ASSESSED = "NOT ASSESSED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_ERROR = "ERROR"

DEFAULT_TIMEOUT = 8.0
DEFAULT_MAX_PROBES = 8
MAX_BODY = 300_000

# These are detection strings, not credentials or secrets.
LDAP_INDICATORS = (
    "ldap://",
    "ldaps://",
    "active directory",
    "microsoft active directory",
    "ldap authentication",
    "ldapauth",
    "ldap bind",
    "ldap server",
    "ldap provider",
    "ldap realm",
    "directory services",
    "ad authentication",
    "windows domain",
    "ntlm",
    "kerberos",
    "negotiate",
    "userprincipalname",
    "samaccountname",
    "distinguishedname",
    "objectcategory",
    "objectclass",
)

LDAP_ERROR_PATTERNS = (
    r"\bldap\b.{0,80}\b(error|exception|failure|invalid)\b",
    r"\bjavax\.naming\b",
    r"\bcom\.sun\.jndi\b",
    r"\bldapexception\b",
    r"\bcommunicationexception\b",
    r"\bAuthenticationException\b",
    r"\bInvalidNameException\b",
    r"\bNamingException\b",
    r"\bDirectoryService\b.{0,80}\b(exception|error)\b",
    r"\bADSI\b.{0,80}\b(error|exception)\b",
    r"\bSystem\.DirectoryServices\b",
    r"\bSystem\.DirectoryServices\.Protocols\b",
    r"\bDirectoryServicesCOMException\b",
)

GENERIC_AUTH_FAILURE = (
    "invalid username",
    "invalid password",
    "invalid credentials",
    "incorrect username",
    "incorrect password",
    "authentication failed",
    "login failed",
    "unable to authenticate",
    "unauthorized",
    "access denied",
)

SSO_MARKERS = (
    "saml",
    "oauth",
    "openid",
    "oidc",
    "sign in with microsoft",
    "microsoftonline.com",
    "login.microsoftonline.com",
    "okta",
    "pingidentity",
)

CAPTCHA_MARKERS = (
    "captcha",
    "recaptcha",
    "hcaptcha",
    "turnstile",
)

# Synthetic LDAP metacharacter probes. They are deliberately inert and do not
# contain a valid authentication-bypass predicate.
DEFAULT_PROBES = tuple(load_lines(
    "payloads_all_the_things/ldap_injection/safe_syntax_markers.txt",
    limit=5,
    substitutions={"nonce": "7F3A"},
))


@dataclass(frozen=True)
class LDAPProbe:
    label: str
    username: str
    password: str


@dataclass
class LDAPConfig:
    timeout: float = DEFAULT_TIMEOUT
    verify_tls: bool = True
    max_probes: int = DEFAULT_MAX_PROBES
    login_path: str | None = None
    allow_active_probes: bool = True
    authorized_username: str | None = None
    authorized_password: str | None = None
    protected_urls: tuple[str, ...] = ()
    probes: tuple[str, ...] = DEFAULT_PROBES
    user_agent: str = "SecurityAssessment-TC15-LDAP/1.0"


def _normalize_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = "https://" + value
    parsed = urlparse(value)
    if not parsed.hostname:
        return ""
    return value.rstrip("/")


def _safe_text(value: str) -> str:
    return html.unescape(value or "")[:MAX_BODY]


def _lower(value: str) -> str:
    return _safe_text(value).lower()


def _find_markers(text: str, markers: Iterable[str]) -> list[str]:
    low = _lower(text)
    return [m for m in markers if m.lower() in low]


def _redact(value: str) -> str:
    if not value:
        return ""
    return "[REDACTED]"


def _origin(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _same_origin(url: str, target: str) -> bool:
    return _origin(url).lower() == _origin(target).lower()


def _classify_final_status(results: list[dict], *, discovery: dict) -> str:
    if discovery.get("sso_detected"):
        return STATUS_NOT_ASSESSED
    if discovery.get("captcha_detected") and not results:
        return STATUS_NOT_ASSESSED

    if any(r.get("classification") == "UNSAFE" for r in results):
        return STATUS_UNSAFE
    ldap_indicated = bool(discovery.get("ldap_indicators") or discovery.get("body_ldap_error_patterns"))
    if any(r.get("classification") == "REVIEW REQUIRED" for r in results):
        return STATUS_REVIEW if ldap_indicated else STATUS_SAFE
    if any(r.get("classification") == "INCOMPLETE" for r in results):
        return STATUS_INCOMPLETE
    if results:
        return STATUS_SAFE
    return STATUS_NOT_ASSESSED


def _response_signature(response: requests.Response) -> dict[str, Any]:
    body = _safe_text(response.text)
    low = body.lower()
    return {
        "status_code": response.status_code,
        "final_url": response.url,
        "path": urlparse(response.url).path,
        "body_length": len(body),
        "title": (
            re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S).group(1).strip()
            if re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
            else ""
        )[:200],
        "auth_failure_markers": _find_markers(low, GENERIC_AUTH_FAILURE),
        "ldap_errors": [
            p for p in LDAP_ERROR_PATTERNS if re.search(p, body, re.I | re.S)
        ],
        "location": response.headers.get("Location", ""),
    }


def _extract_forms(target: str, body: str) -> list[dict[str, Any]]:
    forms = []
    for match in re.finditer(r"<form\b([^>]*)>(.*?)</form>", body, re.I | re.S):
        attrs, inner = match.group(1), match.group(2)
        action_m = re.search(r'\baction\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        method_m = re.search(r'\bmethod\s*=\s*["\']([^"\']*)["\']', attrs, re.I)
        action = urljoin(target, action_m.group(1)) if action_m else target
        method = (method_m.group(1) if method_m else "GET").upper()

        fields = []
        for im in re.finditer(r"<input\b([^>]*)>", inner, re.I):
            a = im.group(1)
            nm = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', a, re.I)
            typ = re.search(r'\btype\s*=\s*["\']([^"\']+)["\']', a, re.I)
            if nm:
                val = re.search(r'\bvalue\s*=\s*["\']([^"\']*)["\']', a, re.I)
                fields.append({
                    "name": nm.group(1),
                    "type": (typ.group(1) if typ else "text").lower(),
                    "value": val.group(1) if val else "",
                })

        low_fields = [f["name"].lower() for f in fields]
        password_fields = [
            f["name"] for f in fields
            if f["type"] == "password" or "pass" in f["name"].lower()
        ]
        user_fields = [
            f["name"] for f in fields
            if any(k in f["name"].lower() for k in
                   ("user", "uid", "uname", "email", "login", "account", "samaccountname"))
            or f["type"] in {"text", "email", "username"}
        ]

        if password_fields or user_fields:
            forms.append({
                "action": action,
                "method": method,
                "username_fields": user_fields[:3],
                "password_fields": password_fields[:3],
                "all_fields": fields[:30],
            })
    return forms[:10]


def _discover(session: requests.Session, target: str, config: LDAPConfig) -> dict:
    from authentication.auth_discovery import login_page_candidates
    start_url = target
    try:
        start_url = login_page_candidates(target, config.login_path)[0]
    except Exception:
        start_url = target
    response = session.get(
        start_url,
        timeout=config.timeout,
        verify=config.verify_tls,
        allow_redirects=True,
    )
    body = _safe_text(response.text)
    headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
    combined = body + "\n" + headers

    ldap = _find_markers(combined, LDAP_INDICATORS)
    sso = _find_markers(combined, SSO_MARKERS)
    captcha = _find_markers(combined, CAPTCHA_MARKERS)
    forms = _extract_forms(response.url, body)

    login_form = None
    for form in forms:
        if form["password_fields"] and form["username_fields"]:
            login_form = form
            break

    try:
        from authentication.auth_discovery import login_page_candidates
        extra_urls = login_page_candidates(target, config.login_path)[1:6]
    except Exception:
        extra_urls = []
        if config.login_path:
            extra_urls = [urljoin(response.url + "/", config.login_path.lstrip("/"))]
    for candidate in extra_urls:
        if not _same_origin(candidate, target):
            continue
        try:
            lp = session.get(
                candidate,
                timeout=config.timeout,
                verify=config.verify_tls,
                allow_redirects=True,
            )
            lbody = _safe_text(lp.text)
            combined += "\n" + lbody
            ldap.extend(_find_markers(lbody, LDAP_INDICATORS))
            sso.extend(_find_markers(lbody, SSO_MARKERS))
            captcha.extend(_find_markers(lbody, CAPTCHA_MARKERS))
            forms.extend(_extract_forms(lp.url, lbody))
            for form in forms:
                if form["password_fields"] and form["username_fields"]:
                    login_form = form
                    break
            if login_form:
                break
        except requests.RequestException:
            continue

    return {
        "http_status": response.status_code,
        "final_url": response.url,
        "ldap_indicators": sorted(set(ldap))[:30],
        "sso_markers": sorted(set(sso))[:20],
        "captcha_markers": sorted(set(captcha))[:20],
        "sso_detected": bool(sso),
        "captcha_detected": bool(captcha),
        "forms": forms[:10],
        "login_form": login_form,
        "server": response.headers.get("Server", ""),
        "www_authenticate": response.headers.get("WWW-Authenticate", ""),
        "body_ldap_error_patterns": [
            p for p in LDAP_ERROR_PATTERNS if re.search(p, body, re.I | re.S)
        ],
    }


def _select_login_endpoint(discovery: dict, target: str) -> dict | None:
    form = discovery.get("login_form")
    if not form:
        return None
    if not _same_origin(form["action"], target):
        return None
    return form


def _build_probe_payload(form: dict, username: str, password: str) -> dict:
    payload: dict[str, str] = {}
    for field in form.get("all_fields", []):
        name = field["name"]
        typ = field["type"]
        if typ in {"image", "file"}:
            continue
        if typ in {"submit", "button"}:
            payload[name] = field.get("value") or "Login"
            continue
        if name in form.get("username_fields", []):
            payload[name] = username
        elif name in form.get("password_fields", []):
            payload[name] = password
        else:
            payload[name] = ""
    return payload


def _probe_login(
    session: requests.Session,
    target: str,
    form: dict,
    username: str,
    password: str,
    config: LDAPConfig,
) -> dict:
    if form["method"] not in {"POST", "GET"}:
        return {
            "classification": "INCOMPLETE",
            "reason": f"unsupported_form_method:{form['method']}",
        }

    payload = _build_probe_payload(form, username, password)
    headers = {"User-Agent": config.user_agent, "Accept": "text/html,application/json"}

    started = time.monotonic()
    try:
        if form["method"] == "POST":
            response = session.post(
                form["action"],
                data=payload,
                headers=headers,
                timeout=config.timeout,
                verify=config.verify_tls,
                allow_redirects=False,
            )
        else:
            response = session.get(
                form["action"],
                params=payload,
                headers=headers,
                timeout=config.timeout,
                verify=config.verify_tls,
                allow_redirects=False,
            )
    except requests.RequestException as exc:
        return {
            "classification": "INCOMPLETE",
            "reason": type(exc).__name__,
            "error": str(exc),
        }

    elapsed = time.monotonic() - started
    sig = _response_signature(response)
    ldap_errors = sig["ldap_errors"]

    # Strong signal: application explicitly leaks an LDAP/AD exception/error.
    if ldap_errors:
        classification = "UNSAFE"
        reason = "explicit_ldap_error_disclosure"
    elif sig["status_code"] in {401, 403} or sig.get("auth_failure_markers"):
        classification = "SAFE"
        reason = "authorization_failure_without_ldap_error"
    elif sig["status_code"] in {500, 502, 503}:
        classification = "REVIEW REQUIRED"
        reason = "server_error_on_ldap_probe"
    else:
        classification = "SAFE"
        reason = "no_ldap_error_or_bypass_indicator"

    return {
        "classification": classification,
        "reason": reason,
        "status_code": sig["status_code"],
        "final_path": sig["path"],
        "location": sig["location"][:300],
        "body_length": sig["body_length"],
        "response_time_ms": round(elapsed * 1000, 2),
        "ldap_errors": ldap_errors,
        "auth_failure_markers": sig["auth_failure_markers"][:8],
        "probe_username": "[SYNTHETIC]",
        "probe_password": "[SYNTHETIC]",
    }


def scan_ldap_ad(
    target: str,
    *,
    config: LDAPConfig | None = None,
    **kwargs: Any,
) -> dict:
    """Run bounded TC15 LDAP/AD checks."""
    config = config or LDAPConfig(**{
        k: v for k, v in kwargs.items()
        if k in LDAPConfig.__dataclass_fields__
    })
    target = _normalize_url(target)

    if not target:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "The target URL could not be resolved.",
            "details": {"error": "invalid_target"},
            "evidence": [],
            "raw_output": "",
        }

    session = requests.Session()
    session.headers.update({"User-Agent": config.user_agent})

    try:
        discovery = _discover(session, target, config)
    except requests.RequestException as exc:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "The login page could not be reached or inspected.",
            "details": {"error": str(exc), "exception_type": type(exc).__name__},
            "evidence": [],
            "raw_output": "",
        }
    except Exception as exc:
        return {
            "status": STATUS_ERROR,
            "summary": "TC15 failed during login-flow discovery.",
            "details": {"error": str(exc), "exception_type": type(exc).__name__},
            "evidence": [],
            "raw_output": "",
        }

    if discovery["sso_detected"] and not discovery["login_form"]:
        return {
            "status": STATUS_NOT_ASSESSED,
            "summary": "The authentication flow appears federated/SSO, so local LDAP/AD form testing was not performed.",
            "details": discovery,
            "evidence": discovery["sso_markers"],
            "raw_output": "",
        }

    form = _select_login_endpoint(discovery, target)

    results: list[dict] = []
    evidence: list[str] = []

    # Public LDAP/AD indicators alone are not treated as a vulnerability.
    if discovery["ldap_indicators"]:
        evidence.extend(
            f"Observed LDAP/AD indicator: {x}" for x in discovery["ldap_indicators"][:12]
        )

    if discovery["body_ldap_error_patterns"]:
        evidence.extend(
            f"Observed LDAP/AD error pattern: {x}"
            for x in discovery["body_ldap_error_patterns"][:8]
        )

    if not form:
        status = STATUS_NOT_ASSESSED
        if discovery["captcha_detected"]:
            summary = "A CAPTCHA-gated or non-observable authentication flow prevented bounded LDAP/AD input testing."
        elif discovery["ldap_indicators"]:
            summary = "LDAP/AD indicators were observed, but no same-origin username/password form was safely testable."
        else:
            summary = "No observable local LDAP/AD authentication form was found."
        return {
            "status": status,
            "summary": summary,
            "details": discovery,
            "evidence": evidence[:30],
            "raw_output": "",
        }

    if discovery["captcha_detected"] and config.allow_active_probes:
        # Do not bypass or automate CAPTCHA.
        return {
            "status": STATUS_NOT_ASSESSED,
            "summary": "CAPTCHA was detected on the authentication flow; active LDAP/AD probes were not attempted.",
            "details": discovery,
            "evidence": evidence + ["CAPTCHA detected; active testing stopped."],
            "raw_output": "",
        }

    if not config.allow_active_probes:
        return {
            "status": STATUS_NOT_ASSESSED,
            "summary": "Active LDAP/AD probes are disabled by configuration.",
            "details": discovery,
            "evidence": evidence,
            "raw_output": "",
        }

    # Never require or use real credentials for the synthetic probe lane.
    # If supplied, they are retained only as an operator-controlled signal and
    # are never emitted or submitted by this scanner.
    probes = list(config.probes)[: max(0, config.max_probes)]

    # Synthetic invalid password is intentionally fixed and non-secret.
    for idx, marker in enumerate(probes, start=1):
        probe = LDAPProbe(
            label=f"TC15-P{idx}",
            username=marker,
            password="TC15_INVALID_PASSWORD_7F3A",
        )
        result = _probe_login(
            session,
            target,
            form,
            probe.username,
            probe.password,
            config,
        )
        result["probe"] = probe.label
        result["payload"] = probe.username
        result["payload_kind"] = "synthetic LDAP syntax marker"
        results.append(result)

        if result.get("classification") == "UNSAFE":
            evidence.append(
                f"{probe.label}: payload {probe.username!r} caused explicit LDAP/AD error disclosure."
            )
        elif result.get("classification") == "REVIEW REQUIRED":
            evidence.append(
                f"{probe.label}: payload {probe.username!r} produced a review-required LDAP/AD response "
                f"({result.get('reason')})."
            )

    status = _classify_final_status(results, discovery=discovery)

    if status == STATUS_UNSAFE:
        summary = "The authentication flow disclosed explicit LDAP/AD error information during controlled probes."
    elif status == STATUS_REVIEW:
        summary = "The authentication flow showed behavior requiring manual review for LDAP/AD input handling."
    elif status == STATUS_SAFE:
        summary = "No tested LDAP/AD unsafe signal was observed in the bounded probe set."
    else:
        summary = "The LDAP/AD testcase could not be conclusively assessed."

    triggering = next(
        (
            {
                "name": item.get("probe"),
                "payload": item.get("payload"),
                "reason": item.get("reason"),
                "verdict": item.get("classification"),
            }
            for item in results
            if item.get("classification") in {STATUS_UNSAFE, STATUS_REVIEW}
        ),
        None,
    )
    details = {
        "target": target,
        "discovery": discovery,
        "probe_count": len(results),
        "probe_results": results,
        "payloads_used": [
            {"name": item.get("probe"), "payload": item.get("payload"), "kind": "ldap_syntax"}
            for item in results if item.get("payload")
        ],
        "triggering_payload": triggering,
        "payload_library": {
            "file": "payloads/payloads_all_the_things/ldap_injection/safe_syntax_markers.txt",
            "source_mode": "bounded synthetic syntax markers",
            "payloads_used": [item.get("payload") for item in results if item.get("payload")],
            "destructive_payloads_enabled": False,
        },
        "credentials_used": False,
        "directory_enumeration": False,
        "directory_write_operations": False,
    }

    return {
        "status": status,
        "summary": summary,
        "details": details,
        "evidence": evidence[:50],
        "raw_output": json.dumps(details, ensure_ascii=False, default=str),
    }


def scan(target: str, **kwargs: Any) -> dict:
    return scan_ldap_ad(target, **kwargs)
