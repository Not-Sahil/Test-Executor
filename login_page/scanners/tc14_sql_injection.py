"""TC14 - login-page SQL injection assessment scanner.

Authorized, non-destructive scanner. It locates the login form, injects
library payloads into the username field, and submits a random non-empty
password. Authentication bypass, SQL error disclosure, and TRUE/FALSE
differentials are treated as evidence. It does not extract data, issue
stacked queries, or perform writes/DDL/DML.
"""
from __future__ import annotations

import html
import re
import secrets
from difflib import SequenceMatcher
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

import requests

from authentication.auth_discovery import html_has_password_form, login_page_candidates
from payloads.manager import load_json_records

STATUS_SAFE = "SAFE"
STATUS_UNSAFE = "UNSAFE"
STATUS_REVIEW = "REVIEW REQUIRED"
STATUS_INCOMPLETE = "INCOMPLETE"
STATUS_NOT_ASSESSED = "NOT ASSESSED"
STATUS_ERROR = "ERROR"

SQL_ERROR_PATTERNS = {
    "mysql": re.compile(r"mysql|mysqli|you have an error in your sql syntax|warning.*mysql", re.I),
    "postgresql": re.compile(r"postgresql|postgres|pg_query|unterminated quoted string", re.I),
    "mssql": re.compile(r"microsoft sql server|\bsql server\b|odbc sql server|unclosed quotation mark", re.I),
    "oracle": re.compile(r"ora-\d{4,5}|oracle.*error|quoted string not properly terminated", re.I),
    "sqlite": re.compile(r"sqlite|sqlite3|near \".*\": syntax error", re.I),
    "generic": re.compile(r"sql syntax|sqlstate|database error|db error|query failed|syntax error.*sql", re.I),
}

AUTH_SUCCESS_MARKERS = (
    "sign off", "sign out", "log off", "log out", "logout", "signoff",
    "welcome", "my account", "dashboard", "hello admin",
    "account summary", "view account summary", "recent transactions",
)
AUTH_SUCCESS_PATHS = ("/bank/", "/account", "/dashboard", "/home", "/main", "/profile", "/portal")
AUTH_FAILURE_MARKERS = (
    "login failed", "invalid credentials", "invalid username", "invalid password",
    "authentication failed", "sign in", "log in",
)
USERNAME_HINTS = (
    "username", "user", "userid", "user_id", "uid", "uname", "usr",
    "login", "email", "account", "identifier", "j_username",
)
CSRF_NAMES = {"csrf", "csrf_token", "xsrf", "token", "nonce", "state", "code"}


@dataclass(frozen=True)
class Probe:
    name: str
    value: str
    kind: str
    destructive: bool = False


@dataclass
class SQLiConfig:
    timeout: float = 8.0
    verify_tls: bool = True
    max_targets: int = 12
    max_probes_per_target: int = 12
    allow_post_forms: bool = True
    allow_get_params: bool = True
    user_agent: str = "SecurityAssessmentTestExecutor-TC14/1.0"
    follow_redirects: bool = True
    login_path: str = "/login"
    random_password: str = ""

    def __post_init__(self):
        self.max_targets = max(1, min(int(self.max_targets), 30))
        self.max_probes_per_target = max(1, min(int(self.max_probes_per_target), 16))
        if not str(self.random_password or "").strip():
            self.random_password = f"Tc14Np{secrets.token_hex(4)}"


def _clean_text(value: str) -> str:
    value = html.unescape(value or "")
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def _body_signature(text: str) -> str:
    t = _clean_text(text).lower()
    t = re.sub(r"csrf[^=:\s]*[=:]\s*[^\s]+", "csrf=<redacted>", t)
    t = re.sub(r"token[^=:\s]*[=:]\s*[^\s]+", "token=<redacted>", t)
    return t[:12000]


def _error_families(text: str) -> list[str]:
    return [name for name, rx in SQL_ERROR_PATTERNS.items() if rx.search(text or "")]


def _looks_like_username_field(name: str, field_type: str) -> bool:
    lname = (name or "").lower()
    ltype = (field_type or "text").lower()
    if ltype in {"password", "hidden", "submit", "button", "reset", "file", "image", "checkbox", "radio"}:
        return False
    return any(hint == lname or hint in lname for hint in USERNAME_HINTS) or ltype in {"text", "email", "username"}


def _is_login_form(form: dict[str, Any]) -> bool:
    types = {str(f.get("type") or "text").lower() for f in form.get("fields") or []}
    names = {str(f.get("name") or "").lower() for f in form.get("fields") or []}
    has_password = "password" in types or any("pass" in n for n in names)
    has_user = any(_looks_like_username_field(n, "text") for n in names)
    return has_password and has_user


def _auth_success(response: requests.Response, login_url: str) -> dict[str, Any]:
    text = (response.text or "").lower()
    final = (response.url or "").lower()
    login = (login_url or "").lower()
    location = str(response.headers.get("Location") or "").lower()
    path_left_login = bool(final and login and final.rstrip("/") != login.rstrip("/") and "login" not in urlsplit(final).path.lower())
    path_hit = any(token in final or token in location for token in AUTH_SUCCESS_PATHS)
    marker_hit = any(token in text for token in AUTH_SUCCESS_MARKERS)
    failure_hit = any(token in text for token in AUTH_FAILURE_MARKERS)
    redirect = response.status_code in {301, 302, 303, 307, 308} and path_hit
    confirmed = bool(
        (marker_hit and not failure_hit)
        or path_hit
        or redirect
        or (path_left_login and not failure_hit and marker_hit)
    )
    reasons = []
    if marker_hit:
        reasons.append("authenticated-page marker in response body")
    if path_hit:
        reasons.append(f"authenticated path {urlsplit(response.url).path or location}")
    if redirect:
        reasons.append(f"redirect status {response.status_code}")
    if path_left_login and confirmed:
        reasons.append("response left the login page")
    return {
        "authenticated": confirmed,
        "final_url": response.url,
        "status_code": response.status_code,
        "reasons": reasons,
    }


def _origin_target(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme or "https", p.netloc, p.path or "/", "", ""))


def _replace_query_param(url: str, name: str, value: str) -> str:
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    changed = False
    out = []
    for k, v in pairs:
        if k == name and not changed:
            out.append((k, value)); changed = True
        else:
            out.append((k, v))
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(out), p.fragment))


def _parse_forms(base_url: str, response: requests.Response) -> list[dict[str, Any]]:
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        return []
    soup = BeautifulSoup(response.text or "", "html.parser")
    forms = []
    for form in soup.find_all("form")[:20]:
        action = urljoin(response.url or base_url, form.get("action") or response.url or base_url)
        method = str(form.get("method") or "get").lower()
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            typ = str(inp.get("type") or "text").lower()
            if typ in {"reset", "file", "image"}:
                continue
            value = inp.get("value") or ""
            if typ in {"submit", "button"} and not value:
                value = "Login"
            fields.append({"name": str(name), "value": str(value), "type": typ})
        if fields:
            forms.append({"action": action, "method": method, "fields": fields, "page_url": response.url or base_url})
    return forms


def _resolve_login_response(
    session: requests.Session,
    target: str,
    cfg: SQLiConfig,
) -> tuple[requests.Response | None, str]:
    headers = {"User-Agent": cfg.user_agent, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    last_error = ""
    fallback: requests.Response | None = None
    for url in login_page_candidates(target, cfg.login_path):
        try:
            response = session.get(
                url,
                headers=headers,
                timeout=cfg.timeout,
                verify=cfg.verify_tls,
                allow_redirects=True,
            )
        except requests.RequestException as exc:
            last_error = str(exc)
            continue
        if response.status_code >= 500:
            last_error = f"HTTP {response.status_code} at {url}"
            continue
        if fallback is None:
            fallback = response
        if html_has_password_form(response.text or "") or any(_is_login_form(form) for form in _parse_forms(url, response)):
            return response, ""
        last_error = f"No login form at {response.url}"
    if fallback is not None:
        return fallback, ""
    return None, last_error or "No login form was discovered."


def _candidate_targets(base_url: str, response: requests.Response, cfg: SQLiConfig) -> list[dict[str, Any]]:
    targets = []
    forms = _parse_forms(base_url, response)
    login_forms = [form for form in forms if _is_login_form(form)]
    selected_forms = login_forms or forms
    if cfg.allow_post_forms or cfg.allow_get_params:
        for form in selected_forms:
            username_fields = [
                field for field in form["fields"]
                if _looks_like_username_field(field["name"], field["type"])
                and field["name"].lower() not in CSRF_NAMES
                and field["type"] != "password"
            ]
            if not username_fields:
                continue
            hinted = [
                field for field in username_fields
                if any(hint == field["name"].lower() or hint in field["name"].lower() for hint in USERNAME_HINTS)
            ]
            field = (hinted or username_fields)[0]
            kind = "form" if form["method"] == "post" and cfg.allow_post_forms else None
            if form["method"] == "get" and cfg.allow_get_params:
                kind = "form_get"
            if not kind:
                continue
            targets.append({
                "type": kind,
                "form": form,
                "name": field["name"],
                "value": field["value"],
                "login_form": _is_login_form(form),
            })
    if not targets:
        p = urlsplit(response.url or base_url)
        for name, value in parse_qsl(p.query, keep_blank_values=True):
            if name.lower() in CSRF_NAMES:
                continue
            targets.append({"type": "query", "url": response.url or base_url, "name": name, "value": value, "login_form": False})
    return targets[: cfg.max_targets]


def _probes() -> tuple[Probe, ...]:
    records = load_json_records(
        "payloads_all_the_things/sql_injection/safe_differential_probes.json",
        limit=16,
    )
    return tuple(
        Probe(
            name=str(item["name"]),
            value=str(item["value"]),
            kind=str(item.get("kind", "syntax")),
            destructive=bool(item.get("destructive", False)),
        )
        for item in records
        if not bool(item.get("destructive", False))
    )


def _form_data(form: dict[str, Any], username_field: str, username_value: str, password_value: str) -> dict[str, str]:
    data = {}
    for field in form["fields"]:
        name = field["name"]
        typ = str(field.get("type") or "text").lower()
        if typ in {"submit", "button"}:
            data[name] = field.get("value") or "Login"
            continue
        data[name] = field.get("value") or ""
    data[username_field] = username_value
    for field in form["fields"]:
        if str(field.get("type") or "").lower() == "password" or "pass" in str(field.get("name") or "").lower():
            data[field["name"]] = password_value
    return data


def _request(session: requests.Session, target: dict[str, Any], value: str, cfg: SQLiConfig) -> requests.Response:
    headers = {"User-Agent": cfg.user_agent, "Accept": "text/html,application/json;q=0.9,*/*;q=0.8"}
    if target["type"] == "query":
        url = _replace_query_param(target["url"], target["name"], value)
        return session.get(url, headers=headers, timeout=cfg.timeout, verify=cfg.verify_tls, allow_redirects=cfg.follow_redirects)
    form = target["form"]
    data = _form_data(form, target["name"], value, cfg.random_password)
    if target["type"] == "form_get":
        return session.get(form["action"], params=data, headers=headers, timeout=cfg.timeout, verify=cfg.verify_tls, allow_redirects=cfg.follow_redirects)
    return session.post(form["action"], data=data, headers=headers, timeout=cfg.timeout, verify=cfg.verify_tls, allow_redirects=cfg.follow_redirects)


def _response_difference(true_result: dict[str, Any], false_result: dict[str, Any]) -> dict[str, Any]:
    status_changed = true_result.get("status_code") != false_result.get("status_code")
    true_sig = true_result.get("_body_signature", "")
    false_sig = false_result.get("_body_signature", "")
    body_changed = bool(true_sig and false_sig and true_sig != false_sig)
    true_len = int(true_result.get("response_length") or 0)
    false_len = int(false_result.get("response_length") or 0)
    length_delta = abs(true_len - false_len)
    meaningful_length_delta = length_delta >= 32
    if true_sig and false_sig:
        matcher = SequenceMatcher(None, true_sig, false_sig, autojunk=False)
        changed_chars = sum(
            max(i2 - i1, j2 - j1)
            for tag, i1, i2, j1, j2 in matcher.get_opcodes()
            if tag != "equal"
        )
        similarity = matcher.ratio()
    else:
        changed_chars = 0
        similarity = 1.0
    auth_delta = bool(true_result.get("authenticated") and not false_result.get("authenticated"))
    meaningful_body_difference = body_changed and changed_chars >= 32 and similarity < 0.995
    confirmed = bool(auth_delta or status_changed or meaningful_length_delta or meaningful_body_difference)
    return {
        "status_changed": status_changed,
        "body_changed": body_changed,
        "authentication_delta": auth_delta,
        "response_length_delta": length_delta,
        "meaningful_length_delta": meaningful_length_delta,
        "body_changed_characters": changed_chars,
        "body_similarity_ratio": round(similarity, 5),
        "meaningful_body_difference": meaningful_body_difference,
        "confirmed_differential": confirmed,
    }


def _build_control_probe(probe: Probe) -> Probe | None:
    replacements = (
        ("1=1", "1=2"),
        ("'1'='1", "'1'='2"),
    )
    false_value = probe.value
    for old, new in replacements:
        if old in false_value:
            false_value = false_value.replace(old, new, 1)
            break
    if false_value == probe.value:
        return None
    return Probe(
        name=f"{probe.name}_false_control",
        value=false_value,
        kind="differential_control",
        destructive=False,
    )


def _probe_result(probe: Probe, response: requests.Response, login_url: str, baseline_errors: set[str], baseline_text: str) -> dict[str, Any]:
    text = response.text or ""
    errors = sorted(set(_error_families(text)) - baseline_errors)
    success = _auth_success(response, login_url)
    return {
        "probe": probe.name,
        "kind": probe.kind,
        "payload": probe.value,
        "status_code": response.status_code,
        "final_url": response.url,
        "response_length": len(text),
        "status_changed": False,
        "body_changed": _body_signature(text) != _body_signature(baseline_text),
        "new_sql_error_families": errors,
        "authenticated": success["authenticated"],
        "auth_success_reasons": success["reasons"],
        "_body_signature": _body_signature(text),
    }


def _assess_target(
    session: requests.Session,
    target: dict[str, Any],
    baseline: requests.Response,
    cfg: SQLiConfig,
) -> dict[str, Any]:
    evidence: list[str] = []
    findings: list[str] = []
    probes = list(_probes())[:cfg.max_probes_per_target]
    login_url = str((target.get("form") or {}).get("page_url") or target.get("url") or "")
    baseline_username = f"tc14_baseline_{secrets.token_hex(3)}"
    try:
        failed_login = _request(session, target, baseline_username, cfg)
        baseline_text = failed_login.text or ""
        baseline_errors = set(_error_families(baseline_text))
        baseline_auth = _auth_success(failed_login, login_url)
    except requests.RequestException:
        failed_login = baseline
        baseline_text = baseline.text or ""
        baseline_errors = set(_error_families(baseline_text))
        baseline_auth = {"authenticated": False, "reasons": []}

    if baseline_auth.get("authenticated"):
        evidence.append(
            "The random non-injection control authenticated; SQL injection evidence would be unreliable."
        )

    results: list[dict[str, Any]] = []
    triggering_payload: dict[str, Any] | None = None

    for probe in probes:
        try:
            response = _request(session, target, probe.value, cfg)
            result = _probe_result(probe, response, login_url, baseline_errors, baseline_text)
            result["status_changed"] = result["status_code"] != failed_login.status_code
            results.append(result)

            if result["new_sql_error_families"]:
                findings.append("new_sql_error")
                evidence.append(
                    f"{probe.name}: payload {probe.value!r} produced a SQL error family "
                    f"({', '.join(result['new_sql_error_families'])})."
                )
                if triggering_payload is None:
                    triggering_payload = {
                        "payload": probe.value,
                        "name": probe.name,
                        "reason": f"SQL error family disclosed: {', '.join(result['new_sql_error_families'])}",
                        "verdict": STATUS_REVIEW,
                    }

            if result["authenticated"] and not baseline_auth.get("authenticated"):
                findings.append("auth_bypass")
                why = "; ".join(result["auth_success_reasons"]) or "login succeeded with an injected username"
                evidence.append(
                    f"{probe.name}: payload {probe.value!r} in the username field authenticated "
                    f"while the random-password control did not ({why})."
                )
                triggering_payload = {
                    "payload": probe.value,
                    "name": probe.name,
                    "reason": (
                        "This username payload bypassed authentication with a random non-empty "
                        f"password. {why}."
                    ),
                    "verdict": STATUS_UNSAFE,
                }

            control_probe = _build_control_probe(probe) if probe.kind == "differential" else None
            if control_probe is not None:
                try:
                    control_response = _request(session, target, control_probe.value, cfg)
                    control_result = _probe_result(
                        control_probe, control_response, login_url, baseline_errors, baseline_text
                    )
                    control_result["status_changed"] = control_result["status_code"] != failed_login.status_code
                    results.append(control_result)
                    if control_result["new_sql_error_families"]:
                        findings.append("control_sql_error")
                        evidence.append(
                            f"{control_probe.name}: payload {control_probe.value!r} produced a SQL error family "
                            f"({', '.join(control_result['new_sql_error_families'])})."
                        )
                except requests.RequestException as exc:
                    results.append({"probe": control_probe.name, "kind": control_probe.kind, "payload": control_probe.value, "error": str(exc)})
        except requests.RequestException as exc:
            results.append({"probe": probe.name, "payload": probe.value, "error": str(exc)})

    differential = False
    differential_pair = None
    differential_details = None
    pair_analyses: list[dict[str, Any]] = []
    executed = [item for item in results if item.get("payload") and not item.get("error")]
    seen_pairs: set[tuple[str, str]] = set()
    for true_r in executed:
        if true_r.get("kind") not in {"differential"}:
            continue
        false_r = next(
            (
                item for item in executed
                if item.get("probe") == f"{true_r['probe']}_false_control"
                or (
                    item.get("kind") == "differential_control"
                    and item.get("payload")
                    and item["payload"] != true_r["payload"]
                    and true_r["payload"].replace("1=1", "1=2").replace("'1'='1", "'1'='2") == item["payload"]
                )
            ),
            None,
        )
        if not false_r:
            continue
        pair_key = (true_r["probe"], false_r["probe"])
        if pair_key in seen_pairs:
            continue
        seen_pairs.add(pair_key)
        comparison = _response_difference(true_r, false_r)
        pair_analyses.append({"pair": [true_r["probe"], false_r["probe"]], "payloads": [true_r["payload"], false_r["payload"]], "assessed": True, **comparison})
        if comparison["confirmed_differential"] and not differential:
            differential = True
            differential_pair = [true_r["probe"], false_r["probe"]]
            differential_details = comparison
            evidence.append(
                f"TRUE/FALSE differential confirmed for {true_r['probe']} vs {false_r['probe']} "
                f"using payloads {true_r['payload']!r} and {false_r['payload']!r}."
            )
            if triggering_payload is None or triggering_payload.get("verdict") != STATUS_UNSAFE:
                triggering_payload = {
                    "payload": true_r["payload"],
                    "name": true_r["probe"],
                    "reason": (
                        "The TRUE payload produced a meaningfully different response than its FALSE control "
                        "(status, body, length, or authentication state)."
                    ),
                    "verdict": STATUS_UNSAFE,
                }

    if differential:
        findings.append("boolean_differential")

    suspicious_probe_changes = [
        item for item in results
        if not item.get("error")
        and item.get("body_changed")
        and item.get("kind") in {"syntax", "differential"}
        and not item.get("authenticated")
    ]
    for item in suspicious_probe_changes:
        evidence.append(
            f"{item['probe']}: payload {item.get('payload')!r} changed the response from the failed-login baseline; "
            "suspicious but not independently sufficient to confirm SQL injection."
        )

    payloads_used = [
        {"name": item.get("probe"), "payload": item.get("payload"), "kind": item.get("kind")}
        for item in results
        if item.get("payload")
    ]

    if "auth_bypass" in findings or differential:
        status = STATUS_UNSAFE
        summary = (
            "SQL injection was confirmed on the login username field: "
            + (
                f"payload {triggering_payload['payload']!r} authenticated with a random password."
                if "auth_bypass" in findings and triggering_payload
                else "a controlled TRUE/FALSE differential was observed."
            )
        )
    elif "new_sql_error" in findings or "control_sql_error" in findings:
        status = STATUS_UNSAFE
        summary = (
            "The login form disclosed a database/SQL error when a library payload was submitted as the username."
        )
        if triggering_payload:
            triggering_payload["verdict"] = STATUS_UNSAFE
            triggering_payload["reason"] = (
                triggering_payload.get("reason")
                or "The payload caused the application to return a SQL/database error."
            )
    elif suspicious_probe_changes:
        status = STATUS_REVIEW
        summary = (
            "One or more SQL payloads changed the login response from the failed-login baseline, "
            "but authentication bypass and a TRUE/FALSE differential were not confirmed."
        )
        if triggering_payload is None:
            first = suspicious_probe_changes[0]
            triggering_payload = {
                "payload": first.get("payload"),
                "name": first.get("probe"),
                "reason": "Response body differed from the failed-login baseline without a confirmed bypass.",
                "verdict": STATUS_REVIEW,
            }
    else:
        status = STATUS_SAFE
        summary = (
            "No SQL-injection indicator was observed: library payloads in the username field with a "
            "random non-empty password did not authenticate, disclose SQL errors, or produce a TRUE/FALSE differential."
        )

    public_results = []
    for item in results:
        public = {k: v for k, v in item.items() if k != "_body_signature"}
        public_results.append(public)

    details = {
        "target": {k: v for k, v in target.items() if k not in {"form"}},
        "username_field": target.get("name"),
        "password_strategy": "random_non_empty",
        "payloads_used": payloads_used,
        "triggering_payload": triggering_payload,
        "results": public_results,
        "differential_analysis": {
            "confirmed_differential": differential,
            "triggering_pair": differential_pair,
            "triggering_pair_comparison": differential_details,
            "pairs": pair_analyses,
        },
    }
    return {
        "status": status,
        "summary": summary,
        "evidence": evidence,
        "details": details,
    }


def _payload_metadata() -> dict[str, Any]:
    probes = _probes()
    return {
        "sources": ["PayloadsAllTheThings", "SecLists (safe differential methodology)"],
        "source_mode": "project-curated login-form SQL probes",
        "file": "payloads/payloads_all_the_things/sql_injection/safe_differential_probes.json",
        "probe_count": len(probes),
        "payloads": [{"name": p.name, "payload": p.value, "kind": p.kind} for p in probes],
        "probe_limit_per_target": 16,
        "destructive_payloads_enabled": False,
        "username_field_injected": True,
        "password_field": "random non-empty value, never empty",
    }


def scan_sql_injection(target: str, *, config: SQLiConfig | None = None, verify_tls: bool | None = None) -> dict[str, Any]:
    cfg = config or SQLiConfig()
    if verify_tls is not None:
        cfg.verify_tls = bool(verify_tls)
    if not str(cfg.random_password or "").strip():
        cfg.random_password = f"Tc14Np{secrets.token_hex(4)}"
    target = _origin_target(target)
    session = requests.Session()
    session.headers.update({"User-Agent": cfg.user_agent})
    tls_relaxed = False

    def _tls_failed(message: str) -> bool:
        text = (message or "").upper()
        return any(token in text for token in ("CERTIFICATE", "SSLCERT", "CERTIFICATE_VERIFY_FAILED"))

    try:
        baseline, resolve_error = _resolve_login_response(session, target, cfg)
    except requests.RequestException as exc:
        baseline, resolve_error = None, str(exc)
    if baseline is None and cfg.verify_tls and _tls_failed(resolve_error or ""):
        cfg.verify_tls = False
        tls_relaxed = True
        try:
            baseline, resolve_error = _resolve_login_response(session, target, cfg)
        except requests.RequestException as exc:
            return {
                "status": STATUS_ERROR,
                "summary": "Unable to establish the login-page baseline request.",
                "details": {"error": str(exc), "payload_library": _payload_metadata(), "tls_verification_relaxed": True},
                "evidence": [str(exc)],
            }
    if baseline is None:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "No login form was discovered for SQL injection testing.",
            "details": {"error": resolve_error, "payload_library": _payload_metadata()},
            "evidence": [resolve_error],
        }
    if baseline.status_code >= 500:
        return {
            "status": STATUS_INCOMPLETE,
            "summary": "Baseline returned a server error; SQL injection could not be assessed reliably.",
            "details": {"status_code": baseline.status_code, "payload_library": _payload_metadata()},
            "evidence": [],
        }
    targets = _candidate_targets(target, baseline, cfg)
    if not targets:
        return {
            "status": STATUS_NOT_ASSESSED,
            "summary": "No suitable login username field was discovered for SQL injection testing.",
            "details": {"discovered_targets": 0, "payload_library": _payload_metadata()},
            "evidence": [],
        }
    assessments = [_assess_target(session, item, baseline, cfg) for item in targets]
    statuses = [x["status"] for x in assessments]
    if STATUS_UNSAFE in statuses:
        status = STATUS_UNSAFE
        chosen = next(a for a in assessments if a["status"] == STATUS_UNSAFE)
        summary = chosen["summary"]
    elif STATUS_REVIEW in statuses:
        status = STATUS_REVIEW
        chosen = next(a for a in assessments if a["status"] == STATUS_REVIEW)
        summary = chosen["summary"]
    elif all(s == STATUS_SAFE for s in statuses):
        status = STATUS_SAFE
        summary = (
            f"TC14 tested {len(targets)} login input(s) with {len(_probes())} library payloads "
            "in the username field and a random non-empty password; no SQL injection was observed."
        )
    else:
        status = STATUS_INCOMPLETE
        summary = "SQL injection testing did not complete for every discovered login input."

    triggering = None
    for assessment in assessments:
        payload = (assessment.get("details") or {}).get("triggering_payload")
        if payload and payload.get("verdict") == STATUS_UNSAFE:
            triggering = payload
            break
        if triggering is None and payload:
            triggering = payload

    return {
        "status": status,
        "summary": summary,
        "evidence": [e for a in assessments for e in a.get("evidence", [])][:40],
        "details": {
            "target": target,
            "baseline_url": baseline.url,
            "baseline_status": baseline.status_code,
            "targets_assessed": len(targets),
            "payload_library": _payload_metadata(),
            "payloads_used": _payload_metadata()["payloads"],
            "triggering_payload": triggering,
            "password_strategy": "random_non_empty",
            "tls_verification_relaxed": tls_relaxed,
            "assessments": assessments,
        },
        "raw_output": "",
    }


def scan(target: str, **kwargs: Any) -> dict[str, Any]:
    return scan_sql_injection(target, **kwargs)


__all__ = ["SQLiConfig", "scan_sql_injection", "scan"]
