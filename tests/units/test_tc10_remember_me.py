from __future__ import annotations

from unittest.mock import Mock, patch

from login_page.scanners.tc10_remember_me import (
    LoginPageParser,
    _classify_cookie_persistence,
    _looks_like_remember_me,
    scan_remember_me,
)


def response(url: str, body: str, status: int = 200) -> Mock:
    r = Mock()
    r.url = url
    r.status_code = status
    r.text = body
    r.content = body.encode()
    r.headers = {"Content-Type": "text/html"}
    return r


def test_remember_me_phrase_detection():
    assert _looks_like_remember_me("Remember me")
    assert _looks_like_remember_me("Keep me signed in")
    assert _looks_like_remember_me("stay logged in")
    assert not _looks_like_remember_me("Forgot password")


def test_parser_finds_remember_me_checkbox():
    html = """
    <form action="/login" method="post">
      <input id="user" name="username">
      <input id="pass" name="password" type="password">
      <label for="remember">Remember me</label>
      <input id="remember" name="remember" type="checkbox" value="1">
    </form>
    """

    parser = LoginPageParser("https://example.test/login")
    parser.feed(html)
    parser.close()

    assert len(parser.controls) == 1
    assert parser.controls[0].name == "remember"
    assert parser.controls[0].value == "1"


def test_persistent_cookie_classification():
    cookies = [
        {
            "name": "session",
            "persistent": False,
        },
        {
            "name": "remember_token",
            "persistent": True,
        },
        {
            "name": "csrf",
            "persistent": True,
        },
    ]

    result = _classify_cookie_persistence(cookies)

    assert result["auth_cookie_names"] == ["remember_token", "session"]
    assert result["persistent_auth_cookie_names"] == ["remember_token"]


def test_missing_credentials_is_incomplete():
    result = scan_remember_me(
        "https://example.test",
        authorized_username=None,
        authorized_password=None,
    )
    assert result["status"] == "INCOMPLETE"


def test_no_remember_me_control_is_not_assessed():
    login = response(
        "https://example.test/login",
        """
        <form method="post">
          <input name="username">
          <input name="password" type="password">
          <button type="submit">Login</button>
        </form>
        """,
    )

    with patch(
        "login_page.scanners.tc10_remember_me._fetch_login_page",
        return_value=(login, ["login_page_status=200"], login.url),
    ):
        result = scan_remember_me(
            "https://example.test",
            authorized_username="authorized-user",
            authorized_password="authorized-password",
            allow_browser=False,
        )

    assert result["status"] == "NOT ASSESSED"


def test_captcha_requires_review_without_browser_bypass():
    login = response(
        "https://example.test/login",
        """
        <form method="post">
          <input name="username">
          <input name="password" type="password">
          <input type="checkbox" name="remember" value="1">
          <div class="g-recaptcha"></div>
        </form>
        """,
    )

    with patch(
        "login_page.scanners.tc10_remember_me._fetch_login_page",
        return_value=(login, ["login_page_status=200"], login.url),
    ):
        result = scan_remember_me(
            "https://example.test",
            authorized_username="authorized-user",
            authorized_password="authorized-password",
            allow_browser=False,
        )

    assert result["status"] == "REVIEW REQUIRED"


def test_sso_is_not_assessed():
    login = response(
        "https://example.test/login",
        """
        <a href="https://accounts.google.com/o/oauth2/auth">
            Sign in with Google
        </a>
        """,
    )

    with patch(
        "login_page.scanners.tc10_remember_me._fetch_login_page",
        return_value=(login, ["login_page_status=200"], login.url),
    ):
        result = scan_remember_me(
            "https://example.test",
            authorized_username="authorized-user",
            authorized_password="authorized-password",
            allow_browser=False,
        )

    assert result["status"] == "NOT ASSESSED"


def test_browser_unavailable_falls_back_to_review():
    login = response(
        "https://example.test/login",
        """
        <form method="post">
          <input name="username">
          <input name="password" type="password">
          <label for="remember">Remember me</label>
          <input id="remember" name="remember" type="checkbox">
        </form>
        """,
    )

    with patch(
        "login_page.scanners.tc10_remember_me._fetch_login_page",
        return_value=(login, ["login_page_status=200"], login.url),
    ), patch(
        "login_page.scanners.tc10_remember_me.sync_playwright",
        None,
    ):
        result = scan_remember_me(
            "https://example.test",
            authorized_username="authorized-user",
            authorized_password="authorized-password",
            allow_browser=True,
        )

    assert result["status"] == "REVIEW REQUIRED"
