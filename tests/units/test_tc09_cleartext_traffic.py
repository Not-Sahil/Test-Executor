from __future__ import annotations

from unittest.mock import Mock, patch

from login_page.scanners.tc09_cleartext_traffic import (
    ReferenceParser,
    scan_cleartext_traffic,
)


def response(url: str, body: str, status: int = 200):
    r = Mock()
    r.url = url
    r.status_code = status
    r.text = body
    r.content = body.encode()
    r.headers = {"Content-Type": "text/html"}
    return r


def test_parser_finds_http_script_and_form():
    html = """
    <html>
      <script src="http://example.test/app.js"></script>
      <form method="POST" action="http://example.test/auth">
        <input name="username">
        <input type="password" name="password">
      </form>
    </html>
    """
    p = ReferenceParser("https://example.test/login")
    p.feed(html)
    p.close()

    urls = {x.resolved_url for x in p.references}
    assert "http://example.test/app.js" in urls
    assert "http://example.test/auth" in urls
    form = next(x for x in p.references if x.tag == "form")
    assert form.method == "POST"
    assert form.has_sensitive_field is True


def test_https_login_with_http_active_resource_requires_runtime_evidence():
    page = response(
        "https://example.test/login",
        '<script src="http://example.test/app.js"></script>',
    )

    with patch(
        "login_page.scanners.tc09_cleartext_traffic._fetch_login_page",
        return_value=(page, ["login_page_status=200"]),
    ), patch(
        "login_page.scanners.tc09_cleartext_traffic._browser_analysis",
        return_value={
            "available": True,
            "completed": True,
            "final_url": "https://example.test/login",
            "title": "Login",
            "requests": [],
            "errors": [],
        },
    ):
        result = scan_cleartext_traffic("https://example.test")

    assert result["status"] == "REVIEW REQUIRED"
    assert result["details"]["finding_type"] == "blocked_or_unused_cleartext_reference"


def test_browser_observed_same_origin_active_cleartext_is_unsafe():
    page = response(
        "https://example.test/login",
        "<html><body>Login</body></html>",
    )

    browser = {
        "available": True,
        "completed": True,
        "final_url": "https://example.test/login",
        "title": "Login",
        "requests": [
            {
                "url": "http://example.test/app.js",
                "method": "GET",
                "resource_type": "script",
                "post_data_present": False,
                "sensitive_field_names": [],
                "has_sensitive_data_marker": False,
            }
        ],
        "errors": [],
    }

    with patch(
        "login_page.scanners.tc09_cleartext_traffic._fetch_login_page",
        return_value=(page, ["login_page_status=200"]),
    ), patch(
        "login_page.scanners.tc09_cleartext_traffic._browser_analysis",
        return_value=browser,
    ):
        result = scan_cleartext_traffic("https://example.test")

    assert result["status"] == "UNSAFE"
    assert result["assessment_state"] == "CONFIRMED"
    assert result["details"]["finding_type"] == "cleartext_active_content"


def test_browser_observed_passive_same_origin_cleartext_requires_review():
    page = response(
        "https://example.test/login",
        "<html><body>Login</body></html>",
    )

    browser = {
        "available": True,
        "completed": True,
        "final_url": "https://example.test/login",
        "title": "Login",
        "requests": [
            {
                "url": "http://example.test/logo.png",
                "method": "GET",
                "resource_type": "image",
                "post_data_present": False,
                "sensitive_field_names": [],
                "has_sensitive_data_marker": False,
            }
        ],
        "errors": [],
    }

    with patch(
        "login_page.scanners.tc09_cleartext_traffic._fetch_login_page",
        return_value=(page, ["login_page_status=200"]),
    ), patch(
        "login_page.scanners.tc09_cleartext_traffic._browser_analysis",
        return_value=browser,
    ):
        result = scan_cleartext_traffic("https://example.test")

    assert result["status"] == "REVIEW REQUIRED"
    assert result["details"]["finding_type"] == "cleartext_passive_traffic"


def test_no_cleartext_is_safe():
    page = response(
        "https://example.test/login",
        """
        <html>
          <script src="/app.js"></script>
          <form method="POST" action="/authenticate">
            <input name="username">
            <input type="password" name="password">
          </form>
        </html>
        """,
    )

    with patch(
        "login_page.scanners.tc09_cleartext_traffic._fetch_login_page",
        return_value=(page, ["login_page_status=200"]),
    ), patch(
        "login_page.scanners.tc09_cleartext_traffic._browser_analysis",
        return_value={
            "available": True,
            "completed": True,
            "final_url": "https://example.test/login",
            "title": "Login",
            "requests": [],
            "errors": [],
        },
    ):
        result = scan_cleartext_traffic("https://example.test")

    assert result["status"] == "SAFE"
    assert result["assessment_state"] == "NOT_A_FINDING"


def test_http_login_is_delegated_to_tc08():
    result = scan_cleartext_traffic(
        "http://example.test",
        login_path="/login",
    )

    assert result["status"] == "NOT ASSESSED"
    assert result["details"]["delegated_to_tc08"] is True


def test_invalid_target_is_incomplete():
    result = scan_cleartext_traffic("not a valid url")
    assert result["status"] == "INCOMPLETE"


def test_sensitive_post_data_is_not_retained():
    # Verify the metadata helper indirectly through a browser request record
    # is safe: the implementation only records names/presence, never values.
    page = response(
        "https://example.test/login",
        "<html><body>Login</body></html>",
    )
    browser = {
        "available": True,
        "completed": True,
        "final_url": "https://example.test/login",
        "title": "Login",
        "requests": [
            {
                "url": "http://example.test/auth",
                "method": "POST",
                "resource_type": "fetch",
                "post_data_present": True,
                "sensitive_field_names": ["password"],
                "has_sensitive_data_marker": True,
            }
        ],
        "errors": [],
    }

    with patch(
        "login_page.scanners.tc09_cleartext_traffic._fetch_login_page",
        return_value=(page, ["login_page_status=200"]),
    ), patch(
        "login_page.scanners.tc09_cleartext_traffic._browser_analysis",
        return_value=browser,
    ):
        result = scan_cleartext_traffic("https://example.test")

    assert result["status"] == "UNSAFE"
    assert "password" in result["details"]["browser_cleartext_requests"][0]["sensitive_field_names"]
    assert "post_data" not in result["details"]["browser_cleartext_requests"][0]
