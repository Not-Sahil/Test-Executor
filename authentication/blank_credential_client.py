from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import requests

from .auth_discovery import discover_html_form
from .credential_variants import CredentialState, CredentialVariant, state_value
from .evidence import safe_url
from .models import AuthMechanism


@dataclass(frozen=True)
class VariantRequestResult:
    response: requests.Response | None
    final_url: str = ""
    error: str = ""
    prepared_fields: dict[str, Any] = field(default_factory=dict)
    captcha_detected: bool = False
    session: requests.Session | None = None


def _new_session(verify_tls: bool) -> requests.Session:
    session = requests.Session()
    session.verify = verify_tls
    session.headers.update({
        "User-Agent": "CareerSecurityScanner/TC03-BlankCredentials/1.0",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.7",
    })
    return session


def _materialize_state(
    state: CredentialState,
    supplied_value: str,
    *,
    json_mode: bool,
) -> tuple[bool, Any]:
    if state == CredentialState.MISSING:
        return False, None
    if state == CredentialState.NULL:
        if not json_mode:
            raise ValueError("NULL credential state is JSON-only")
        return True, None
    return True, state_value(state, supplied_value)


def submit_variant(
    mechanism: AuthMechanism,
    variant: CredentialVariant,
    *,
    authorized_username: str = "",
    authorized_password: str = "",
    probe_password: str = "__tc03_blank_probe_password__",
    timeout: float = 8.0,
    verify_tls: bool = True,
    extra_headers: dict[str, str] | None = None,
) -> VariantRequestResult:
    """Execute one TC03 variant in an isolated HTTP session.

    HTML form submissions refresh the login page first so dynamic hidden fields
    (such as CSRF tokens) can be carried into the exact request under test.
    """
    session = _new_session(verify_tls)
    if extra_headers:
        session.headers.update(extra_headers)

    try:
        if mechanism.type == "html_form":
            if variant.json_only:
                return VariantRequestResult(None, error="variant_is_json_only")

            active_mechanism = mechanism
            # Refresh the source page and re-discover the form to obtain fresh
            # hidden inputs and the current action/method.
            if mechanism.source_url:
                page = session.get(
                    mechanism.source_url,
                    timeout=timeout,
                    allow_redirects=True,
                )
                refreshed = discover_html_form(page.url, page.text)
                if refreshed:
                    active_mechanism = refreshed

            user_supplied = authorized_username if variant.username_state == CredentialState.VALUE else ""
            pass_supplied = (
                authorized_password
                if variant.password_state == CredentialState.VALUE
                else probe_password
            )

            include_user, user_value = _materialize_state(
                variant.username_state, user_supplied, json_mode=False
            )
            include_pass, pass_value = _materialize_state(
                variant.password_state, pass_supplied, json_mode=False
            )

            payload: dict[str, Any] = dict(active_mechanism.extra_fields)
            if include_user:
                payload[active_mechanism.username_field or "username"] = user_value
            if include_pass:
                payload[active_mechanism.password_field or "password"] = pass_value

            response = session.request(
                active_mechanism.method,
                active_mechanism.endpoint,
                data=payload,
                timeout=timeout,
                allow_redirects=True,
            )
            return VariantRequestResult(
                response=response,
                final_url=safe_url(response.url),
                prepared_fields={
                    "username_present": include_user,
                    "password_present": include_pass,
                    "username_state": variant.username_state.value,
                    "password_state": variant.password_state.value,
                },
                session=session,
            )

        if mechanism.type == "json_api":
            if variant.html_only:
                return VariantRequestResult(None, error="variant_is_html_only")

            user_supplied = authorized_username if variant.username_state == CredentialState.VALUE else ""
            pass_supplied = (
                authorized_password
                if variant.password_state == CredentialState.VALUE
                else probe_password
            )

            include_user, user_value = _materialize_state(
                variant.username_state, user_supplied, json_mode=True
            )
            include_pass, pass_value = _materialize_state(
                variant.password_state, pass_supplied, json_mode=True
            )

            payload: dict[str, Any] = dict(mechanism.extra_fields)
            if include_user:
                payload[mechanism.username_field or "email"] = user_value
            if include_pass:
                payload[mechanism.password_field or "password"] = pass_value

            response = session.request(
                mechanism.method,
                mechanism.endpoint,
                json=payload,
                timeout=timeout,
                allow_redirects=True,
                headers={"Content-Type": "application/json"},
            )
            return VariantRequestResult(
                response=response,
                final_url=safe_url(response.url),
                prepared_fields={
                    "username_present": include_user,
                    "password_present": include_pass,
                    "username_state": variant.username_state.value,
                    "password_state": variant.password_state.value,
                },
                session=session,
            )

        if mechanism.type == "http_basic":
            user_supplied = authorized_username if variant.username_state == CredentialState.VALUE else ""
            pass_supplied = (
                authorized_password
                if variant.password_state == CredentialState.VALUE
                else probe_password
            )
            include_user, user_value = _materialize_state(
                variant.username_state, user_supplied, json_mode=False
            )
            include_pass, pass_value = _materialize_state(
                variant.password_state, pass_supplied, json_mode=False
            )

            if not include_user:
                user_value = ""
            if not include_pass:
                pass_value = ""

            response = session.get(
                mechanism.endpoint,
                auth=(str(user_value or ""), str(pass_value or "")),
                timeout=timeout,
                allow_redirects=True,
            )
            return VariantRequestResult(
                response=response,
                final_url=safe_url(response.url),
                prepared_fields={
                    "username_present": include_user,
                    "password_present": include_pass,
                    "username_state": variant.username_state.value,
                    "password_state": variant.password_state.value,
                },
                session=session,
            )

        return VariantRequestResult(None, error=f"unsupported_auth_mechanism:{mechanism.type}")

    except requests.RequestException as exc:
        return VariantRequestResult(None, error=str(exc))
