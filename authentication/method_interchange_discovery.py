from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import requests

from authentication.auth_discovery import (
    login_page_candidates,
    normalize_login_url,
    target_looks_like_login_page,
)
from .method_interchange_client import DiscoveredLogin

class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict] = []
        self.current: dict | None = None

    def handle_starttag(self, tag: str, attrs):
        attrs_d = {str(k).lower(): str(v or "") for k, v in attrs}
        tag_l = tag.lower()

        if tag_l == "form":
            self.current = {
                "action": attrs_d.get("action", ""),
                "method": attrs_d.get("method", "GET").upper(),
                "inputs": [],
            }
            self.forms.append(self.current)
        elif tag_l == "input" and self.current is not None:
            self.current["inputs"].append({
                "name": attrs_d.get("name", ""),
                "id": attrs_d.get("id", ""),
                "type": attrs_d.get("type", "text").lower(),
                "value": attrs_d.get("value", ""),
                "autocomplete": attrs_d.get("autocomplete", "").lower(),
            })

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self.current = None

_USERNAME_HINTS = ("username", "user", "userid", "uid", "uname", "email", "login", "account", "identifier")
_PASSWORD_HINTS = ("password", "passwd", "passw", "pass", "pwd")

def _pick(inputs: list[dict], hints: tuple[str, ...], types: tuple[str, ...]) -> str:
    """Pick a login field using semantic hints, then a safe type fallback.

    Some real applications use short field names such as ``uid``/``passw``
    that do not contain the usual words ``user``/``password``.  The previous
    implementation returned no username field in that situation even though
    a normal text input was present.
    """
    candidates: list[str] = []
    for item in inputs:
        name = str(item.get("name") or "").strip()
        identifier = name or str(item.get("id") or "").strip()
        low = identifier.lower()
        if not identifier:
            continue

        if item.get("type") in types:
            candidates.append(identifier)
            if any(h == low or h in low for h in hints):
                return identifier

        if item.get("type") == "password" and "password" in hints:
            return identifier
        if item.get("autocomplete") == "username" and "username" in hints:
            return identifier
        if item.get("autocomplete") == "current-password" and "password" in hints:
            return identifier

    # A type-based fallback is preferable to declaring a usable form missing.
    return candidates[0] if candidates else ""

def discover_login_form(
    target: str,
    login_path: str,
    *,
    timeout: float,
    verify_tls: bool,
) -> tuple[DiscoveredLogin | None, list[str], str]:
    # Prefer the supplied target itself when it already looks like a login page.
    # Otherwise resolve the configured login path normally.  This makes the
    # discovery layer resilient when the UI supplies /login.jsp directly.
    target_url = target.strip()
    candidates_to_try = login_page_candidates(target_url, login_path)
    if not candidates_to_try:
        resolved_login = normalize_login_url(target_url, login_path)
        candidates_to_try = [resolved_login]
    if target_url and target_looks_like_login_page(target_url):
        if target_url.rstrip("/") not in {u.rstrip("/") for u in candidates_to_try}:
            candidates_to_try.insert(0, target_url.rstrip("/"))

    last_url = candidates_to_try[-1] if candidates_to_try else target_url
    all_evidence: list[str] = []

    for page_url in candidates_to_try:
        try:
            response = requests.get(
                page_url,
                timeout=timeout,
                verify=verify_tls,
                allow_redirects=True,
                headers={"User-Agent": "Authorized-Security-Assessment/1.0"},
            )
        except requests.RequestException as exc:
            all_evidence.append(f"Login page request failed for {page_url}: {exc}")
            continue

        final_url = response.url
        last_url = final_url
        parser = _FormParser()
        try:
            parser.feed(response.text)
            parser.close()
        except Exception as exc:
            all_evidence.append(f"Login HTML parsing failed for {final_url}: {exc}")
            continue

        candidates: list[DiscoveredLogin] = []

        for form in parser.forms:
            inputs = form["inputs"]
            username_field = _pick(
                inputs,
                _USERNAME_HINTS,
                ("text", "email", "search", "username"),
            )
            password_field = _pick(
                inputs,
                _PASSWORD_HINTS,
                ("password",),
            )

            if not username_field or not password_field:
                continue

            method = form["method"].upper()
            if method not in {"GET", "POST"}:
                # TC06 only performs safe GET/POST interchange.
                continue

            action = urljoin(final_url, form["action"] or final_url)
            base_parts = urlparse(final_url)
            action_parts = urlparse(action)
            if (base_parts.scheme, base_parts.netloc.lower()) != (
                action_parts.scheme,
                action_parts.netloc.lower(),
            ):
                continue

            hidden = {
                item["name"]: item["value"]
                for item in inputs
                if item["name"]
                and item["type"] in {"hidden", "submit"}
                and item["name"] not in {username_field, password_field}
            }

            candidates.append(
                DiscoveredLogin(
                    page_url=final_url,
                    action_url=action,
                    method=method,
                    username_field=username_field,
                    password_field=password_field,
                    hidden_fields=hidden,
                    mechanism="html_form",
                )
            )

        if candidates:
            # Prefer a POST login form because it is the common authentication pattern,
            # otherwise use the first discovered login form.
            candidates.sort(key=lambda item: 0 if item.method == "POST" else 1)
            selected = candidates[0]
            return selected, [
                *all_evidence,
                f"Discovered local login form: method={selected.method}, action={selected.action_url}",
                f"username_field={selected.username_field}",
                f"password_field={selected.password_field}",
            ], final_url

        all_evidence.append(f"No usable login form found at {final_url}")

    return None, [*all_evidence, "No local HTML username/password form using GET or POST was discovered."], last_url
