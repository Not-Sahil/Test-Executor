from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from .auth_discovery import discover_authentication, discover_html_form
from .enumeration_models import EnumerationConfig, ResponseFingerprint
from .enumeration_signals import (
    classify_message,
    has_password_step,
    is_rate_limited,
    normalize_path,
    normalized_digest,
)
from .lockout_guard import LockoutGuard
from .models import AuthMechanism


@dataclass
class ProbeResponse:
    username: str
    password_used: str
    response: requests.Response | None
    elapsed: float
    fingerprint: ResponseFingerprint | None
    rate_limited: bool = False
    error: str = ""
    source: str = "http"
    csrf_refreshed: bool = False


class UserEnumerationClient:
    """Bounded HTTP client dedicated to TC04.

    It never attempts a real password. Every username is paired with a synthetic
    high-entropy wrong password unless the caller explicitly supplies another
    operator-approved probe value.
    """

    def __init__(self, target: str, config: EnumerationConfig) -> None:
        self.target = target.rstrip("/")
        self.config = config
        self._probe_password = config.probe_password or (
            "__TC04_INVALID_" + secrets.token_urlsafe(18) + "__"
        )

    @property
    def probe_password_marker(self) -> str:
        return "<probe-password-redacted>"

    @property
    def actual_probe_password(self) -> str:
        """Internal wire value; never place this in evidence or UI output."""
        return self._probe_password

    def discover(self) -> tuple[AuthMechanism | None, dict]:
        return discover_authentication(
            self.target,
            login_hint=self.config.login_path,
            timeout=self.config.timeout,
            verify_tls=self.config.verify_tls,
        )

    def fetch_page(self, url: str) -> tuple[requests.Response | None, str]:
        session = requests.Session()
        session.verify = self.config.verify_tls
        session.headers.update(self._headers())
        try:
            response = session.get(
                url,
                timeout=self.config.page_fetch_timeout,
                allow_redirects=True,
            )
            return response, ""
        except requests.RequestException as exc:
            return None, str(exc)

    def probe(
        self,
        mechanism: AuthMechanism,
        username: str,
        guard: LockoutGuard,
    ) -> ProbeResponse:
        if not guard.before_attempt():
            return ProbeResponse(
                username=username,
                password_used=self._probe_password,
                response=None,
                elapsed=0.0,
                fingerprint=None,
                error="attempt_guard_exhausted",
            )

        if mechanism.type == "html_form":
            return self._probe_html(mechanism, username)
        if mechanism.type == "json_api":
            return self._probe_json(mechanism, username)
        if mechanism.type == "http_basic":
            return self._probe_basic(mechanism, username)
        return ProbeResponse(
            username=username,
            password_used=self._probe_password,
            response=None,
            elapsed=0.0,
            fingerprint=None,
            error=f"unsupported_mechanism:{mechanism.type}",
        )

    def _headers(self) -> dict[str, str]:
        return {
            "User-Agent": "SecurityAssessmentScanner/TC04-1.0",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.7",
        }

    def _new_session(self) -> requests.Session:
        session = requests.Session()
        session.verify = self.config.verify_tls
        session.headers.update(self._headers())
        return session

    def _refresh_form(self, mechanism: AuthMechanism) -> AuthMechanism:
        if not self.config.refresh_form_each_attempt or not mechanism.source_url:
            return mechanism
        try:
            response = self._new_session().get(
                mechanism.source_url,
                timeout=self.config.timeout,
                allow_redirects=True,
            )
            refreshed = discover_html_form(response.url, response.text or "")
            return refreshed or mechanism
        except requests.RequestException:
            return mechanism

    def _fingerprint(self, response: requests.Response, body: str) -> ResponseFingerprint:
        location = response.headers.get("Location", "")
        return ResponseFingerprint(
            status=response.status_code,
            final_path=normalize_path(response.url),
            location_path=normalize_path(urljoin(response.url, location)) if location else "",
            content_type=response.headers.get("Content-Type", "").split(";", 1)[0].lower(),
            body_length=len(body),
            normalized_digest=normalized_digest(body),
            message_class=classify_message(body),
            password_step=has_password_step(body),
        )

    def _probe_html(self, mechanism: AuthMechanism, username: str) -> ProbeResponse:
        effective = self._refresh_form(mechanism)
        session = self._new_session()
        payload = dict(effective.extra_fields)
        user_field = effective.username_field or "username"
        pass_field = effective.password_field or "password"
        payload[user_field] = username
        payload[pass_field] = self._probe_password

        started = time.perf_counter()
        try:
            response = session.request(
                effective.method,
                effective.endpoint,
                data=payload,
                timeout=self.config.timeout,
                allow_redirects=False,
            )
            elapsed = time.perf_counter() - started
            body = response.text[:20000]
            return ProbeResponse(
                username=username,
                password_used=self._probe_password,
                response=response,
                elapsed=elapsed,
                fingerprint=self._fingerprint(response, body),
                rate_limited=is_rate_limited(response.status_code, body),
                csrf_refreshed=effective is not mechanism,
            )
        except requests.RequestException as exc:
            return ProbeResponse(
                username=username,
                password_used=self._probe_password,
                response=None,
                elapsed=time.perf_counter() - started,
                fingerprint=None,
                error=str(exc),
            )

    def _probe_json(self, mechanism: AuthMechanism, username: str) -> ProbeResponse:
        session = self._new_session()
        payload: dict[str, Any] = dict(mechanism.extra_fields)
        payload[mechanism.username_field or "email"] = username
        payload[mechanism.password_field or "password"] = self._probe_password

        started = time.perf_counter()
        try:
            response = session.request(
                mechanism.method,
                mechanism.endpoint,
                json=payload,
                timeout=self.config.timeout,
                allow_redirects=False,
                headers={"Content-Type": "application/json"},
            )
            elapsed = time.perf_counter() - started
            body = response.text[:20000]
            return ProbeResponse(
                username=username,
                password_used=self._probe_password,
                response=response,
                elapsed=elapsed,
                fingerprint=self._fingerprint(response, body),
                rate_limited=is_rate_limited(response.status_code, body),
            )
        except requests.RequestException as exc:
            return ProbeResponse(
                username=username,
                password_used=self._probe_password,
                response=None,
                elapsed=time.perf_counter() - started,
                fingerprint=None,
                error=str(exc),
            )

    def _probe_basic(self, mechanism: AuthMechanism, username: str) -> ProbeResponse:
        session = self._new_session()
        started = time.perf_counter()
        try:
            response = session.get(
                mechanism.endpoint,
                auth=(username, self._probe_password),
                timeout=self.config.timeout,
                allow_redirects=False,
            )
            elapsed = time.perf_counter() - started
            body = response.text[:20000]
            return ProbeResponse(
                username=username,
                password_used=self._probe_password,
                response=response,
                elapsed=elapsed,
                fingerprint=self._fingerprint(response, body),
                rate_limited=is_rate_limited(response.status_code, body),
            )
        except requests.RequestException as exc:
            return ProbeResponse(
                username=username,
                password_used=self._probe_password,
                response=None,
                elapsed=time.perf_counter() - started,
                fingerprint=None,
                error=str(exc),
            )
