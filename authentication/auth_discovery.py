from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import requests

from .models import AuthMechanism


COMMON_LOGIN_PATHS = (
    "/login",
    "/login.jsp",
    "/login.html",
    "/login.php",
    "/signin",
    "/signin.html",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/user/login",
    "/users/sign_in",
)

_USER_HINTS = (
    "username", "user", "userid", "user_id", "uid", "uname", "usr",
    "login", "email", "j_username", "account", "identifier",
)
_PASSWORD_HINTS = ("password", "pass", "passwd", "passw", "pwd", "j_password")


def normalize_login_url(target: str, login_path: str | None) -> str:
    """Resolve a login URL without duplicating an already-login target path.

    The executor accepts either a site root (``https://host/app``) or the
    login page itself (``https://host/login.jsp``).  The old implementation
    always appended ``login_path`` to the target, which could produce URLs
    such as ``/login.jsp/login.jsp``.
    """
    target_raw = (target or "").strip()
    if not target_raw:
        raise ValueError("target is required")
    if not target_raw.startswith(("http://", "https://")):
        target_raw = "https://" + target_raw

    target_parts = urlparse(target_raw)
    if target_parts.scheme not in {"http", "https"} or not target_parts.netloc:
        raise ValueError("target must be an absolute HTTP(S) URL")

    raw = (login_path or "/login").strip()
    if raw.startswith(("http://", "https://")):
        login_parts = urlparse(raw)
        if login_parts.netloc.lower() != target_parts.netloc.lower():
            raise ValueError("login_path must remain on the target host")
        return raw.rstrip("/") or raw

    # If the supplied target is already the requested login path, keep it.
    # This is the critical guard for inputs such as target=/login.jsp and
    # login_path=/login.jsp.
    target_path = target_parts.path.rstrip("/") or "/"
    requested_path = ("/" + raw.lstrip("/")).rstrip("/") or "/"
    if target_path.lower() == requested_path.lower():
        return target_raw.rstrip("/")

    # Also treat an already-login target as authoritative when its final path
    # component matches the requested login endpoint name.  This handles a
    # target like /app/login.jsp with the default /login.jsp hint without
    # manufacturing /app/login.jsp/login.jsp.
    target_leaf = target_path.rsplit("/", 1)[-1].lower()
    requested_leaf = requested_path.rsplit("/", 1)[-1].lower()
    login_tokens = ("login", "signin", "sign-in", "auth")
    if target_leaf == requested_leaf and any(token in target_leaf for token in login_tokens):
        return target_raw.rstrip("/")

    return urljoin(target_raw.rstrip("/") + "/", raw.lstrip("/"))




def login_page_candidates(target: str, login_hint: str | None = None) -> list[str]:
    """Bounded same-origin login URLs: configured hint, site root, then common paths."""
    base = (target or "").strip()
    if not base:
        return []
    if not base.startswith(("http://", "https://")):
        base = "https://" + base
    parts = urlparse(base)
    origin = f"{parts.scheme}://{parts.netloc}"
    ordered: list[str] = []
    if login_hint:
        ordered.append(normalize_login_url(base, login_hint))
    if target_looks_like_login_page(base):
        ordered.append(base.rstrip("/") or base)
    ordered.append(origin.rstrip("/") + "/")
    ordered.append(base.rstrip("/") or base)
    for path in COMMON_LOGIN_PATHS:
        ordered.append(normalize_login_url(base, path))
    seen: set[str] = set()
    unique: list[str] = []
    for url in ordered:
        key = url.rstrip("/") or url
        if key in seen:
            continue
        seen.add(key)
        unique.append(url)
    return unique


def html_has_password_form(html: str) -> bool:
    return bool(re.search(r"<\s*input\b[^>]*type\s*=\s*['\"]password['\"]", html or "", re.I))


def target_looks_like_login_page(target: str) -> bool:
    """Return True when the supplied target already names a login-like page."""
    path = urlparse(target).path.rstrip("/").lower()
    leaf = path.rsplit("/", 1)[-1]
    return bool(leaf) and any(token in leaf for token in ("login", "signin", "sign-in", "auth"))

def _same_origin(base: str, candidate: str) -> bool:
    a, b = urlparse(base), urlparse(candidate)
    return a.scheme == b.scheme and a.netloc == b.netloc


def _pick_field(fields: list[dict], kind: str) -> str | None:
    hints = _USER_HINTS if kind == "username" else _PASSWORD_HINTS
    if kind == "password":
        candidates = [
            f for f in fields
            if f.get("name") and f.get("type") == "password"
        ]
    else:
        candidates = [
            f for f in fields
            if f.get("name") and f.get("type") in {"text", "email", "username", "hidden"}
        ]

    for hint in hints:
        for item in candidates:
            name = str(item["name"]).lower()
            if name == hint or hint in name:
                return str(item["name"])
    return str(candidates[0]["name"]) if candidates else None


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self._current: dict | None = None

    def handle_starttag(self, tag: str, attrs) -> None:
        attrs_d = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "form":
            if self._current is not None:
                self.forms.append(self._current)
            self._current = {
                "action": str(attrs_d.get("action", "")),
                "method": str(attrs_d.get("method", "post")).upper(),
                "inputs": [],
                "autocomplete": str(attrs_d.get("autocomplete", "")),
            }
        elif tag == "input" and self._current is not None:
            self._current["inputs"].append({
                "name": str(attrs_d.get("name", "")),
                "type": str(attrs_d.get("type", "text")).lower(),
                "value": str(attrs_d.get("value", "")),
                "autocomplete": str(attrs_d.get("autocomplete", "")).lower(),
            })

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def close(self) -> None:
        if self._current is not None:
            self.forms.append(self._current)
            self._current = None
        super().close()


def discover_html_form(page_url: str, html: str) -> AuthMechanism | None:
    parser = _FormParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        return None

    for form in parser.forms:
        password_field = _pick_field(form["inputs"], "password")
        username_field = _pick_field(form["inputs"], "username")
        if not password_field or not username_field:
            continue

        endpoint = urljoin(page_url, form["action"] or page_url)
        if not _same_origin(page_url, endpoint):
            continue

        hidden = {
            item["name"]: item["value"]
            for item in form["inputs"]
            if item.get("name") and item.get("type") == "hidden"
        }
        return AuthMechanism(
            type="html_form",
            endpoint=endpoint,
            method=form["method"] if form["method"] in {"POST", "GET"} else "POST",
            username_field=username_field,
            password_field=password_field,
            content_type="application/x-www-form-urlencoded",
            extra_fields=hidden,
            confidence="high",
            evidence=("HTML login form contains username-like and password fields",),
            source_url=page_url,
        )
    return None


def _looks_like_json_login(url: str, response: requests.Response) -> bool:
    path = urlparse(url).path.lower()
    route_hint = any(token in path for token in ("login", "signin", "auth"))
    content_type = response.headers.get("Content-Type", "").lower()
    body = response.text[:5000].lower()
    return route_hint and (
        "application/json" in content_type
        or any(marker in body for marker in ("invalid credentials", "invalid password", "authentication", '"token"'))
    )


def discover_authentication(
    target: str,
    login_hint: str | None = None,
    timeout: float = 8.0,
    verify_tls: bool = True,
) -> tuple[AuthMechanism | None, dict]:
    """Discover authentication without submitting credentials."""
    base = target.rstrip("/")
    candidate_pages: list[str] = []
    if login_hint:
        candidate_pages.append(normalize_login_url(base, login_hint))
    candidate_pages.append(base)

    # Keep discovery deterministic and bounded.
    candidate_pages.extend(normalize_login_url(base, path) for path in COMMON_LOGIN_PATHS)
    seen: set[str] = set()
    candidate_pages = [url for url in candidate_pages if not (url in seen or seen.add(url))]

    session = requests.Session()
    session.headers.update({
        "User-Agent": "CareerSecurityScanner/AuthDiscovery/2.0",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.7",
    })
    responses: list[dict] = []

    for url in candidate_pages:
        try:
            response = session.get(url, timeout=timeout, allow_redirects=True, verify=verify_tls)
            responses.append({
                "requested_url": url,
                "final_url": response.url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
            })

            if response.status_code < 500:
                mechanism = discover_html_form(response.url, response.text)
                if mechanism:
                    return mechanism, {"discovery": "html_form", "responses": responses}

            challenge = response.headers.get("WWW-Authenticate", "")
            if challenge:
                return AuthMechanism(
                    type="http_basic",
                    endpoint=response.url,
                    method="GET",
                    confidence="high",
                    evidence=(f"WWW-Authenticate challenge: {challenge}",),
                    source_url=response.url,
                ), {"discovery": "http_basic", "responses": responses}
        except requests.RequestException as exc:
            responses.append({"requested_url": url, "error": str(exc)})

    api_paths = ("/api/login", "/api/auth/login", "/auth/login", "/rest/user/login")
    for path in api_paths:
        url = normalize_login_url(base, path)
        try:
            response = session.get(url, timeout=timeout, allow_redirects=False, verify=verify_tls)
            responses.append({
                "requested_url": url,
                "final_url": response.url,
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
            })
            route = urlparse(url).path.lower()
            if any(token in route for token in ("login", "signin", "auth")) and response.status_code == 405:
                return AuthMechanism(
                    type="json_api",
                    endpoint=url,
                    method="POST",
                    username_field="email",
                    password_field="password",
                    content_type="application/json",
                    confidence="medium",
                    evidence=("Login-like API endpoint returned HTTP 405 to GET",),
                    source_url=response.url,
                ), {"discovery": "json_route_405", "responses": responses}
            if _looks_like_json_login(url, response):
                return AuthMechanism(
                    type="json_api",
                    endpoint=url,
                    method="POST",
                    username_field="email",
                    password_field="password",
                    content_type="application/json",
                    confidence="medium",
                    evidence=("Login-like endpoint returned a JSON/authentication-related response",),
                    source_url=response.url,
                ), {"discovery": "json_login_route", "responses": responses}
        except requests.RequestException as exc:
            responses.append({"requested_url": url, "error": str(exc)})

    return None, {"discovery": "unresolved", "responses": responses}
