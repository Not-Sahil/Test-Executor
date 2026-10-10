import requests

from login_page.scanners.tc15_ldap_ad import (
    LDAPConfig,
    STATUS_INCOMPLETE,
    STATUS_NOT_ASSESSED,
    STATUS_SAFE,
    STATUS_UNSAFE,
    _extract_forms,
    _normalize_url,
    _response_signature,
    scan_ldap_ad,
)


def test_normalize_url():
    assert _normalize_url("example.com") == "https://example.com"
    assert _normalize_url("https://example.com/") == "https://example.com"


def test_extract_login_form():
    html = """
    <form action="/login" method="post">
      <input name="username" type="text">
      <input name="password" type="password">
      <input name="csrf" type="hidden">
      <button type="submit">Login</button>
    </form>
    """
    forms = _extract_forms("https://example.com/login", html)
    assert forms
    assert "username" in forms[0]["username_fields"]
    assert "password" in forms[0]["password_fields"]


def test_response_signature_detects_ldap_error():
    class R:
        text = "javax.naming.AuthenticationException: LDAP error"
        status_code = 500
        url = "https://example.com/login"
        headers = {"Location": ""}

    sig = _response_signature(R())
    assert sig["ldap_errors"]


def test_scan_invalid_target():
    result = scan_ldap_ad("")
    assert result["status"] == STATUS_INCOMPLETE


def test_scan_sso_without_form(monkeypatch):
    class Resp:
        status_code = 200
        url = "https://example.com/"
        text = "Sign in with Microsoft OAuth OpenID"
        headers = {}

    monkeypatch.setattr(requests.Session, "get", lambda *a, **k: Resp())
    result = scan_ldap_ad("https://example.com")
    assert result["status"] == STATUS_NOT_ASSESSED


def test_scan_no_login_form(monkeypatch):
    class Resp:
        status_code = 200
        url = "https://example.com/"
        text = "<html>public page</html>"
        headers = {}

    monkeypatch.setattr(requests.Session, "get", lambda *a, **k: Resp())
    result = scan_ldap_ad("https://example.com")
    assert result["status"] == STATUS_NOT_ASSESSED


def test_scan_explicit_ldap_error(monkeypatch):
    class Resp:
        status_code = 200
        url = "https://example.com/login"
        text = """
        <form action="/login" method="post">
          <input name="username" type="text">
          <input name="password" type="password">
        </form>
        """
        headers = {}

    class ErrorResp:
        status_code = 500
        url = "https://example.com/login"
        text = "System.DirectoryServices.Protocols.LdapException: invalid bind"
        headers = {}

    calls = {"n": 0}

    def fake_get(self, *args, **kwargs):
        calls["n"] += 1
        return Resp()

    def fake_post(self, *args, **kwargs):
        return ErrorResp()

    monkeypatch.setattr(requests.Session, "get", fake_get)
    monkeypatch.setattr(requests.Session, "post", fake_post)

    result = scan_ldap_ad(
        "https://example.com",
        config=LDAPConfig(max_probes=1),
    )
    assert result["status"] == STATUS_UNSAFE
    assert result["details"]["probe_count"] == 1


def test_scan_safe_401(monkeypatch):
    class Resp:
        status_code = 200
        url = "https://example.com/login"
        text = """
        <form action="/login" method="post">
          <input name="username" type="text">
          <input name="password" type="password">
        </form>
        """
        headers = {}

    class LoginResp:
        status_code = 401
        url = "https://example.com/login"
        text = "Invalid credentials"
        headers = {}

    monkeypatch.setattr(requests.Session, "get", lambda *a, **k: Resp())
    monkeypatch.setattr(requests.Session, "post", lambda *a, **k: LoginResp())

    result = scan_ldap_ad(
        "https://example.com",
        config=LDAPConfig(max_probes=2),
    )
    assert result["status"] == STATUS_SAFE
