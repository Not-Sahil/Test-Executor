from __future__ import annotations

import json
from pathlib import Path

from authentication.auth_discovery import discover_html_form
from authentication.credential_registry import filter_credentials_by_product, load_authorized_credentials
from authentication.models import CredentialCandidate
from authentication.success_verifier import verify_authentication


class FakeResponse:
    def __init__(self, status_code: int, url: str, text: str = "", headers=None):
        self.status_code = status_code
        self.url = url
        self.text = text
        self.headers = headers or {}


def test_form_discovery() -> None:
    mechanism = discover_html_form(
        "https://example.test/login",
        '''<form action="/session" method="post"><input name="email" type="email"><input name="password" type="password"><input type="hidden" name="csrf" value="x"></form>''',
    )
    assert mechanism is not None
    assert mechanism.endpoint == "https://example.test/session"
    assert mechanism.username_field == "email"
    assert mechanism.password_field == "password"
    assert mechanism.extra_fields == {"csrf": "x"}


def test_success_verifier_rejects_explicit_failure() -> None:
    from authentication.models import AuthMechanism
    result = verify_authentication(
        FakeResponse(200, "https://example.test/login", "Invalid username or password"),
        AuthMechanism(type="html_form", endpoint="https://example.test/login"),
    )
    assert result.state == "REJECTED"
    assert result.confirmed is False


def test_success_verifier_accepts_post_login_marker() -> None:
    from authentication.models import AuthMechanism
    result = verify_authentication(
        FakeResponse(200, "https://example.test/dashboard", "Welcome, admin <a>Logout</a>"),
        AuthMechanism(type="html_form", endpoint="https://example.test/login"),
    )
    assert result.state == "AUTHENTICATED"
    assert result.confirmed is True


def test_credential_registry_preserves_source(tmp_path: Path) -> None:
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps([
        {"username": "admin", "password": "admin", "credential_source": "product_default", "product_hint": "demo"},
        {"username": "blank", "password": "", "credential_source": "operator_supplied"},
    ]), encoding="utf-8")
    creds = load_authorized_credentials(path)
    assert creds[0].credential_source == "product_default"
    assert creds[1].credential_source == "blank_password"


def test_product_filter() -> None:
    candidates = [
        CredentialCandidate("a", "b", "product_default", "demo"),
        CredentialCandidate("c", "d", "generic", None),
    ]
    assert len(filter_credentials_by_product(candidates, "demo")) == 2
    assert len(filter_credentials_by_product(candidates, "other")) == 1
