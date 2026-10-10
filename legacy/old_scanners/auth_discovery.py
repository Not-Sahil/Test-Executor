"""
Adaptive authentication discovery for the six-check security scanner.

This module identifies common authentication mechanisms without attempting
credentials. It supports:
- traditional HTML username/password forms
- JSON API login endpoints
- HTTP Basic authentication challenges

Credential testing is intentionally separate and limited to credentials and
usernames supplied by the operator for an authorized target.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests


@dataclass
class AuthMechanism:
    type: str
    endpoint: str
    method: str = "POST"
    username_field: str | None = None
    password_field: str | None = None
    content_type: str | None = None
    confidence: str = "medium"
    evidence: list[str] | None = None

    def as_dict(self):
        return asdict(self)


class LoginFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms: list[dict] = []
        self._form: dict | None = None
        self._current_input: dict | None = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        tag = tag.lower()

        if tag == "form":
            self._form = {
                "action": attrs.get("action", ""),
                "method": (attrs.get("method") or "POST").upper(),
                "inputs": [],
            }
            self.forms.append(self._form)

        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({
                "name": attrs.get("name", ""),
                "type": (attrs.get("type") or "text").lower(),
                "autocomplete": (attrs.get("autocomplete") or "").lower(),
            })

    def handle_endtag(self, tag):
        if tag.lower() == "form":
            self._form = None


def _same_origin(base: str, candidate: str) -> bool:
    a = urlparse(base)
    b = urlparse(candidate)
    return a.scheme == b.scheme and a.netloc == b.netloc


def _normalize_endpoint(base: str, path: str) -> str:
    return urljoin(base.rstrip("/") + "/", path.lstrip("/"))


def _form_to_mechanism(page_url: str, form: dict) -> AuthMechanism | None:
    username_names = []
    password_names = []

    for field in form["inputs"]:
        name = field["name"]
        autocomplete = field["autocomplete"]
        field_type = field["type"]
        low = name.lower()

        if field_type == "password" or autocomplete == "current-password":
            if name:
                password_names.append(name)

        if (
            autocomplete == "username"
            or any(x in low for x in ("username", "user", "email", "login"))
        ) and field_type != "password":
            if name:
                username_names.append(name)

    if not password_names:
        return None

    password_field = password_names[0]
    username_field = username_names[0] if username_names else None
    if not username_field:
        return None

    endpoint = urljoin(page_url, form["action"] or page_url)
    if not _same_origin(page_url, endpoint):
        return None

    return AuthMechanism(
        type="html_form",
        endpoint=endpoint,
        method=form["method"] if form["method"] in {"POST", "GET"} else "POST",
        username_field=username_field,
        password_field=password_field,
        content_type="application/x-www-form-urlencoded",
        confidence="high",
        evidence=["HTML form contains username-like and password fields"],
    )


def _extract_forms(page_url: str, text: str) -> list[AuthMechanism]:
    parser = LoginFormParser()
    try:
        parser.feed(text)
    except Exception:
        return []

    mechanisms = []
    for form in parser.forms:
        mechanism = _form_to_mechanism(page_url, form)
        if mechanism:
            mechanisms.append(mechanism)
    return mechanisms


def _response_suggests_json_login(response: requests.Response) -> bool:
    content_type = response.headers.get("Content-Type", "").lower()
    text = response.text[:5000].lower()
    return (
        "application/json" in content_type
        or "authentication" in text
        or "invalid email" in text
        or "invalid password" in text
        or "login" in text and "password" in text
    )


def discover_authentication(
    target: str,
    login_hint: str | None = None,
    timeout: int = 12,
) -> tuple[AuthMechanism | None, dict]:
    """Discover a likely authentication mechanism without submitting credentials."""

    session = requests.Session()
    session.headers.update({"User-Agent": "SixScan-AuthDiscovery/1.0"})

    base = target.rstrip("/")
    evidence: list[str] = []
    responses: list[dict] = []

    page_urls = []
    if login_hint:
        hint = login_hint.strip()
        if hint:
            page_urls.append(
                hint if hint.startswith(("http://", "https://"))
                else _normalize_endpoint(base, hint)
            )

    page_urls.append(base)

    # Common API login paths. These are discovery probes only; no credentials
    # are submitted during this phase.
    api_paths = (
        "/rest/user/login",       # common Juice Shop pattern
        "/api/auth/login",
        "/api/login",
        "/auth/login",
        "/login",
        "/signin",
    )
    api_urls = [_normalize_endpoint(base, path) for path in api_paths]

    def unique(items):
        seen = set()
        out = []
        for item in items:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    page_urls = unique(page_urls)
    api_urls = unique(api_urls)

    # First inspect pages for normal HTML forms.
    for url in page_urls:
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
            responses.append({
                "url": response.url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
            })

            if response.status_code < 500:
                mechanisms = _extract_forms(response.url, response.text)
                if mechanisms:
                    mechanism = mechanisms[0]
                    mechanism.evidence = (mechanism.evidence or []) + [
                        f"Login form discovered at {response.url}"
                    ]
                    return mechanism, {
                        "discovery": "html_form",
                        "responses": responses,
                    }

            if "www-authenticate" in {k.lower() for k in response.headers}:
                challenge = response.headers.get("WWW-Authenticate", "")
                if challenge:
                    mechanism = AuthMechanism(
                        type="http_basic",
                        endpoint=response.url,
                        method="GET",
                        confidence="high",
                        evidence=[f"WWW-Authenticate: {challenge}"],
                    )
                    return mechanism, {
                        "discovery": "http_basic",
                        "responses": responses,
                    }

        except requests.RequestException as exc:
            evidence.append(f"Could not inspect {url}: {exc}")

    # Then inspect common API endpoints. A 405 is useful evidence that a route
    # exists but expects another HTTP method. A JSON response also increases
    # confidence that an API route is present.
    for url in api_urls:
        try:
            response = session.get(url, timeout=timeout, allow_redirects=False)
            content_type = response.headers.get("Content-Type", "").lower()
            body = response.text[:5000].lower()

            responses.append({
                "url": response.url,
                "status": response.status_code,
                "content_type": content_type,
            })

            route_name = urlparse(url).path.lower()
            looks_like_login_route = any(
                token in route_name for token in ("login", "signin", "auth")
            )

            if response.status_code == 405 and looks_like_login_route:
                mechanism = AuthMechanism(
                    type="json_api",
                    endpoint=url,
                    method="POST",
                    username_field="email",
                    password_field="password",
                    content_type="application/json",
                    confidence="high",
                    evidence=["Login-like endpoint returned HTTP 405 to GET; POST is likely required"],
                )
                return mechanism, {"discovery": "api_route_405", "responses": responses}

            if response.status_code in (200, 400, 401, 422) and looks_like_login_route:
                if "json" in content_type or _response_suggests_json_login(response):
                    mechanism = AuthMechanism(
                        type="json_api",
                        endpoint=url,
                        method="POST",
                        username_field="email",
                        password_field="password",
                        content_type="application/json",
                        confidence="medium",
                        evidence=["Login-like endpoint returned a JSON/login-related response"],
                    )
                    return mechanism, {"discovery": "json_login_route", "responses": responses}

        except requests.RequestException as exc:
            evidence.append(f"Could not inspect {url}: {exc}")

    return None, {
        "discovery": "unresolved",
        "responses": responses,
        "evidence": evidence,
    }


def result_dict(mechanism: AuthMechanism | None, metadata: dict) -> dict:
    return {
        "mechanism": mechanism.as_dict() if mechanism else None,
        "metadata": metadata,
    }


def _safe_text(response: requests.Response) -> str:
    try:
        return response.text[:20000]
    except Exception:
        return ""


def _json_signature(response: requests.Response) -> tuple:
    text = _safe_text(response)
    try:
        data = response.json()
        if isinstance(data, dict):
            keys = tuple(sorted(str(k).lower() for k in data.keys()))
            auth = "authentication" in data or "token" in data
            return response.status_code, keys, auth, len(text)
    except ValueError:
        pass
    return response.status_code, (), False, len(text)


def _looks_successful(response: requests.Response, mechanism: AuthMechanism) -> bool:
    text = _safe_text(response).lower()
    location = response.headers.get("Location", "").lower()

    if mechanism.type == "http_basic":
        return response.status_code not in (401, 403)

    if mechanism.type == "json_api":
        try:
            data = response.json()
            if isinstance(data, dict):
                if data.get("authentication") or data.get("token"):
                    return True
        except ValueError:
            pass
        return response.status_code in (200, 201) and "error" not in text[:1000]

    # HTML form: a redirect away from login or a post-login marker is useful.
    if response.status_code in (301, 302, 303, 307, 308):
        return "/login" not in location and "/signin" not in location

    return (
        response.status_code == 200
        and any(marker in text for marker in ("logout", "dashboard", "sign out", "my account"))
    )


def _request_auth(
    session: requests.Session,
    mechanism: AuthMechanism,
    username: str,
    password: str,
    timeout: int,
) -> requests.Response:
    if mechanism.type == "http_basic":
        return session.get(
            mechanism.endpoint,
            auth=(username, password),
            timeout=timeout,
            allow_redirects=False,
        )

    if mechanism.type == "json_api":
        field_user = mechanism.username_field or "email"
        field_pass = mechanism.password_field or "password"
        payload = {field_user: username, field_pass: password}
        return session.post(
            mechanism.endpoint,
            json=payload,
            timeout=timeout,
            allow_redirects=False,
        )

    field_user = mechanism.username_field or "username"
    field_pass = mechanism.password_field or "password"
    data = {field_user: username, field_pass: password}
    return session.post(
        mechanism.endpoint,
        data=data,
        timeout=timeout,
        allow_redirects=False,
    )


def test_default_credentials(
    mechanism: AuthMechanism,
    credential_pairs: list[dict],
    max_attempts: int = 5,
    timeout: int = 12,
) -> dict:
    """Test only operator-supplied credential pairs; no guessing/wordlist is performed."""
    session = requests.Session()
    session.headers.update({
        "User-Agent": "SixScan-AuthTest/1.0",
        "Accept": "application/json, text/plain, */*",
    })

    attempted = []
    successful = []

    for pair in credential_pairs[:max_attempts]:
        username = str(pair.get("username", ""))
        password = str(pair.get("password", ""))
        if not username:
            continue

        try:
            response = _request_auth(session, mechanism, username, password, timeout)
            success = _looks_successful(response, mechanism)
            attempted.append({
                "username": username,
                "status": response.status_code,
                "success": success,
                "location": response.headers.get("Location", ""),
            })
            if success:
                successful.append({
                    "username": username,
                    "status": response.status_code,
                })
                # Stop after first confirmed success to avoid unnecessary attempts.
                break
        except requests.RequestException as exc:
            attempted.append({"username": username, "error": str(exc), "success": False})

    if successful:
        return {
            "status": "UNSAFE",
            "summary": "A supplied credential pair successfully authenticated.",
            "attempts": attempted,
            "successful_pairs": successful,
        }

    if attempted and all("error" in x for x in attempted):
        return {
            "status": "ERROR",
            "summary": "Authentication requests could not be completed.",
            "attempts": attempted,
            "successful_pairs": [],
        }

    return {
        "status": "SAFE",
        "summary": "None of the supplied credential pairs authenticated.",
        "attempts": attempted,
        "successful_pairs": [],
    }


def _enumeration_signature(response: requests.Response) -> tuple:
    text = re.sub(r"\s+", " ", _safe_text(response).lower()).strip()
    # Keep the comparison deterministic and avoid treating timing as evidence.
    return (
        response.status_code,
        response.headers.get("location", "").lower(),
        len(text),
        text[:3000],
    )


def test_user_enumeration(
    mechanism: AuthMechanism,
    candidate_usernames: list[str],
    probe_password: str,
    timeout: int = 12,
    max_attempts: int = 10,
) -> dict:
    """Compare candidate responses against a deliberately invalid username baseline."""
    if not candidate_usernames:
        return {
            "status": "SKIPPED",
            "summary": "No authorized candidate usernames were supplied.",
            "candidates": [],
        }

    session = requests.Session()
    session.headers.update({
        "User-Agent": "SixScan-Enumeration/1.0",
        "Accept": "application/json, text/plain, */*",
    })

    invalid_username = "sixscan-nonexistent-user-9f7c2a1e"

    try:
        baseline_response = _request_auth(
            session, mechanism, invalid_username, probe_password, timeout
        )
        baseline = _enumeration_signature(baseline_response)
    except requests.RequestException as exc:
        return {
            "status": "ERROR",
            "summary": f"Could not establish enumeration baseline: {exc}",
            "candidates": [],
        }

    candidates = []
    for username in candidate_usernames[:max_attempts]:
        try:
            response = _request_auth(
                session, mechanism, username, probe_password, timeout
            )
            signature = _enumeration_signature(response)
            differs = signature != baseline

            # Stronger indicator: explicit account-existence language.
            text = _safe_text(response).lower()
            explicit_valid = any(
                phrase in text
                for phrase in (
                    "incorrect password",
                    "invalid password",
                    "wrong password",
                    "password is incorrect",
                )
            )
            explicit_invalid = any(
                phrase in text
                for phrase in (
                    "user not found",
                    "username not found",
                    "email not found",
                    "account does not exist",
                    "user does not exist",
                )
            )

            if explicit_valid and not explicit_invalid:
                classification = "likely_valid"
                reason = "Response explicitly indicates a password problem rather than an unknown account."
            elif differs:
                classification = "inconclusive"
                reason = "The candidate response differs from the invalid-user baseline; manual validation is recommended."
            else:
                classification = "likely_invalid"
                reason = "The candidate response matches the invalid-user baseline."

            candidates.append({
                "username": username,
                "classification": classification,
                "status": response.status_code,
                "evidence": reason,
            })
        except requests.RequestException as exc:
            candidates.append({
                "username": username,
                "classification": "inconclusive",
                "evidence": f"Request error: {exc}",
            })

    likely_valid = [c for c in candidates if c["classification"] == "likely_valid"]
    inconclusive = [c for c in candidates if c["classification"] == "inconclusive"]

    if likely_valid:
        status = "UNSAFE"
        summary = "The login flow exposed response differences consistent with account enumeration."
    elif inconclusive:
        status = "REVIEW REQUIRED"
        summary = "Some username probes differed from the invalid-user baseline and require review."
    else:
        status = "SAFE"
        summary = "No username was classified as likely valid by the configured response signals."

    return {
        "status": status,
        "summary": summary,
        "baseline": {
            "username": invalid_username,
            "status": baseline_response.status_code,
        },
        "candidates": candidates,
    }
