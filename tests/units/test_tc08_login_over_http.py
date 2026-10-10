from __future__ import annotations

from unittest.mock import Mock, patch

from login_page.scanners.tc08_login_over_http import (
    LoginFormParser,
    scan_login_over_http,
)


def make_response(
    *,
    url: str,
    status: int = 200,
    body: str = "",
    headers: dict[str, str] | None = None,
) -> Mock:
    response = Mock()
    response.url = url
    response.status_code = status
    response.headers = headers or {"Content-Type": "text/html"}
    response.text = body
    response.content = body.encode()
    return response


def test_parser_resolves_relative_action_against_http_document():
    html = """
    <form method="POST" action="/authenticate">
      <input name="username">
      <input type="password" name="password">
    </form>
    """

    parser = LoginFormParser("http://example.test/login")
    parser.feed(html)
    parser.close()

    assert len(parser.forms) == 1
    form = parser.forms[0]
    assert form.has_password_field is True
    assert form.action_url == "http://example.test/authenticate"


def test_http_login_form_is_unsafe():
    http_login = make_response(
        url="http://example.test/login",
        body="""
        <form method="POST" action="/authenticate">
            <input name="username">
            <input type="password" name="password">
        </form>
        """,
    )

    https_login = make_response(
        url="https://example.test/login",
        body="""
        <form method="POST" action="/authenticate">
            <input name="username">
            <input type="password" name="password">
        </form>
        """,
    )

    def fake_request(session, url, **kwargs):
        return http_login if url.startswith("http://") else https_login

    with patch(
        "login_page.scanners.tc08_login_over_http._request",
        side_effect=fake_request,
    ):
        result = scan_login_over_http("https://example.test")

    assert result["status"] == "UNSAFE"
    assert result["assessment_state"] == "CONFIRMED"
    assert result["details"]["finding_type"] == "http_credential_submission"
    assert result["details"]["credentials_submitted"] is False


def test_http_redirect_to_https_is_safe():
    http_redirect = make_response(
        url="http://example.test/login",
        status=302,
        headers={
            "Content-Type": "text/html",
            "Location": "https://example.test/login",
        },
    )

    https_login = make_response(
        url="https://example.test/login",
        body="""
        <form method="POST" action="/authenticate">
            <input name="username">
            <input type="password" name="password">
        </form>
        """,
    )

    def fake_request(session, url, **kwargs):
        if url == "http://example.test/login":
            return http_redirect
        return https_login

    with patch(
        "login_page.scanners.tc08_login_over_http._request",
        side_effect=fake_request,
    ):
        result = scan_login_over_http("https://example.test")

    assert result["status"] == "SAFE"
    assert result["assessment_state"] == "NOT_A_FINDING"


def test_https_login_form_with_http_action_is_unsafe():
    http_response = make_response(
        url="http://example.test/login",
        status=301,
        headers={
            "Content-Type": "text/html",
            "Location": "https://example.test/login",
        },
    )

    https_response = make_response(
        url="https://example.test/login",
        body="""
        <form method="POST" action="http://example.test/authenticate">
            <input name="username">
            <input type="password" name="password">
        </form>
        """,
    )

    def fake_request(session, url, **kwargs):
        if url == "http://example.test/login":
            return http_response
        return https_response

    with patch(
        "login_page.scanners.tc08_login_over_http._request",
        side_effect=fake_request,
    ):
        result = scan_login_over_http("https://example.test")

    assert result["status"] == "UNSAFE"
    assert result["details"]["finding_type"] == "http_credential_submission"


def test_https_only_login_is_safe():
    http_redirect = make_response(
        url="http://example.test/login",
        status=301,
        headers={
            "Content-Type": "text/html",
            "Location": "https://example.test/login",
        },
    )

    https_login = make_response(
        url="https://example.test/login",
        body="""
        <form method="POST" action="/authenticate">
            <input name="username">
            <input type="password" name="password">
        </form>
        """,
    )

    def fake_request(session, url, **kwargs):
        return http_redirect if url.startswith("http://") else https_login

    with patch(
        "login_page.scanners.tc08_login_over_http._request",
        side_effect=fake_request,
    ):
        result = scan_login_over_http("https://example.test")

    assert result["status"] == "SAFE"
    assert result["details"]["credentials_submitted"] is False


def test_dynamic_https_login_without_static_form_requires_review():
    http_redirect = make_response(
        url="http://example.test/login",
        status=302,
        headers={
            "Content-Type": "text/html",
            "Location": "https://example.test/login",
        },
    )

    https_login = make_response(
        url="https://example.test/login",
        body="<html><body><div id='login-root'>Sign in</div></body></html>",
    )

    def fake_request(session, url, **kwargs):
        return http_redirect if url.startswith("http://") else https_login

    with patch(
        "login_page.scanners.tc08_login_over_http._request",
        side_effect=fake_request,
    ):
        result = scan_login_over_http("https://example.test")

    assert result["status"] == "REVIEW REQUIRED"
    assert result["assessment_state"] == "REVIEW_REQUIRED"


def test_invalid_target_is_incomplete():
    result = scan_login_over_http("not a valid url")
    assert result["status"] == "INCOMPLETE"
    assert result["assessment_state"] == "INCOMPLETE"
