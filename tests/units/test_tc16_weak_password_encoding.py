import requests

from login_page.scanners.tc16_weak_password_encoding import (
    WeakPasswordConfig,
    STATUS_INCOMPLETE,
    STATUS_NOT_ASSESSED,
    STATUS_REVIEW,
    STATUS_SAFE,
    STATUS_UNSAFE,
    _password_fields,
    _policy_findings,
    scan_weak_password_encoding,
)


def test_password_field_parsing():
    html = '<input type="password" name="password" minlength="8" maxlength="32">'
    fields = _password_fields(html)
    assert fields[0]["name"] == "password"
    assert fields[0]["minlength"] == 8
    assert fields[0]["maxlength"] == 32


def test_policy_detects_short_maximum():
    html = '<input type="password" maxlength="10">'
    findings = _policy_findings(html, _password_fields(html))
    assert findings


def test_invalid_target():
    result = scan_weak_password_encoding("")
    assert result["status"] == STATUS_INCOMPLETE


def test_sso_without_password_form(monkeypatch):
    class Resp:
        status_code = 200
        url = "https://example.com/"
        text = "Sign in with Microsoft OAuth OpenID"
        headers = {}

    monkeypatch.setattr(requests.Session, "get", lambda *a, **k: Resp())
    result = scan_weak_password_encoding("https://example.com", config=WeakPasswordConfig(max_pages=1))
    assert result["status"] == STATUS_NOT_ASSESSED


def test_http_password_page_is_unsafe(monkeypatch):
    class Resp:
        status_code = 200
        url = "http://example.com/login"
        text = '<form><input type="password" name="password"></form>'
        headers = {}

    monkeypatch.setattr(requests.Session, "get", lambda *a, **k: Resp())
    result = scan_weak_password_encoding("http://example.com", config=WeakPasswordConfig(max_pages=1))
    assert result["status"] == STATUS_UNSAFE


def test_policy_review(monkeypatch):
    class Resp:
        status_code = 200
        url = "https://example.com/login"
        text = '<form><input type="password" name="password" maxlength="8"></form>'
        headers = {}

    monkeypatch.setattr(requests.Session, "get", lambda *a, **k: Resp())
    result = scan_weak_password_encoding("https://example.com", config=WeakPasswordConfig(max_pages=1))
    assert result["status"] == STATUS_REVIEW


def test_safe_password_page(monkeypatch):
    class Resp:
        status_code = 200
        url = "https://example.com/login"
        text = '<form><input type="password" name="password" maxlength="64"></form>'
        headers = {}

    monkeypatch.setattr(requests.Session, "get", lambda *a, **k: Resp())
    result = scan_weak_password_encoding("https://example.com", config=WeakPasswordConfig(max_pages=1))
    assert result["status"] in {STATUS_SAFE, STATUS_REVIEW}
