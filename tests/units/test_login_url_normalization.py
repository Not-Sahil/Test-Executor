from authentication.auth_discovery import normalize_login_url


def test_login_target_is_not_appended_to_itself():
    assert normalize_login_url(
        "https://demo.testfire.net/login.jsp",
        "/login.jsp",
    ) == "https://demo.testfire.net/login.jsp"


def test_login_target_with_trailing_slash_is_normalized():
    assert normalize_login_url(
        "https://demo.testfire.net/login.jsp/",
        "/login.jsp",
    ) == "https://demo.testfire.net/login.jsp"


def test_site_root_gets_login_path():
    assert normalize_login_url(
        "https://demo.testfire.net",
        "/login.jsp",
    ) == "https://demo.testfire.net/login.jsp"


def test_application_base_path_is_preserved():
    assert normalize_login_url(
        "https://demo.testfire.net/app",
        "/login.jsp",
    ) == "https://demo.testfire.net/app/login.jsp"


def test_same_path_is_case_insensitive():
    assert normalize_login_url(
        "https://example.test/Login.jsp",
        "/login.jsp",
    ) == "https://example.test/Login.jsp"


def test_absolute_login_url_must_stay_on_target_host():
    try:
        normalize_login_url(
            "https://example.test",
            "https://evil.example/login",
        )
    except ValueError as exc:
        assert "target host" in str(exc)
    else:
        raise AssertionError("cross-origin login URL should be rejected")
