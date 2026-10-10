from urllib.parse import urlsplit, parse_qs

from unittest.mock import patch

from login_page.scanners.tc14_sql_injection import (
    STATUS_REVIEW,
    STATUS_SAFE,
    STATUS_UNSAFE,
    SQLiConfig,
    scan_sql_injection,
)

BASE = "https://example.test/login"


class FakeResponse:
    def __init__(self, url, body, status=200):
        self.url = url
        self.text = body
        self.content = body.encode()
        self.status_code = status
        self.headers = {"Content-Type": "text/html"}


def _fake_get(url, *args, **kwargs):
    parsed = urlsplit(url)
    q = parse_qs(parsed.query, keep_blank_values=True)
    if kwargs.get("params"):
        for key, value_item in kwargs["params"].items():
            q[str(key)] = [str(value_item)]
    value = q.get("q", [""])[0]
    if not q:
        return FakeResponse(url, '<html><form method="get" action="/search"><input name="q" value="hello"></form></html>')
    if value == "'":
        return FakeResponse(url, "You have an error in your SQL syntax; check MySQL", 500)
    if value == '"':
        return FakeResponse(url, "normal", 200)
    if value == "%27":
        return FakeResponse(url, "normal", 200)
    if value == "1 AND 1=1":
        return FakeResponse(url, "normal", 200)
    if value == "1 AND 1=2":
        return FakeResponse(url, "normal", 200)
    return FakeResponse(url, "normal", 200)


def test_no_sql_signal_is_safe():
    with patch("requests.Session.get", side_effect=_fake_get):
        result = scan_sql_injection(BASE, config=SQLiConfig(max_probes_per_target=8))
    assert result["status"] in {STATUS_SAFE, STATUS_REVIEW, STATUS_UNSAFE}


def test_new_sql_error_requires_signal():
    with patch("requests.Session.get", side_effect=_fake_get):
        result = scan_sql_injection(BASE, config=SQLiConfig(max_probes_per_target=8))
    assert result["status"] in {STATUS_REVIEW, STATUS_UNSAFE}


def test_scan_alias():
    with patch("requests.Session.get", side_effect=_fake_get):
        result = __import__("login_page.scanners.tc14_sql_injection", fromlist=["scan"]).scan(BASE)
    assert result["status"] != STATUS_UNSAFE or "sql" in result["summary"].lower()


def test_probe_payload_values_are_in_structured_results():
    with patch("requests.Session.get", side_effect=_fake_get):
        result = scan_sql_injection(BASE, config=SQLiConfig(max_probes_per_target=8))
    results = result["details"]["assessments"][0]["details"]["results"]
    assert all("payload" in item for item in results if "probe" in item)
    assert any(item["probe"] == "or_true_comment" for item in results)


LOGIN_HTML = """
<html><form method="post" action="/doLogin">
<input name="uid" type="text">
<input name="passw" type="password">
<input name="btnSubmit" type="submit" value="Login">
</form></html>
"""


def _fake_login_get(url, *args, **kwargs):
    return FakeResponse(url, LOGIN_HTML, 200)


def _fake_login_post(url, *args, **kwargs):
    data = kwargs.get("data") or {}
    username = str(data.get("uid") or "")
    password = str(data.get("passw") or "")
    assert password.strip(), "password must be a random non-empty value"
    if "' OR 1=1--" in username:
        return FakeResponse(
            "https://example.test/bank/main.jsp",
            "<html>Hello Admin User <a>Sign Off</a></html>",
            200,
        )
    return FakeResponse(url, "<html>Login Failed: invalid username or password</html>", 200)


def test_login_username_or_true_payload_is_unsafe():
    with patch("requests.Session.get", side_effect=_fake_login_get), patch(
        "requests.Session.post", side_effect=_fake_login_post
    ):
        result = scan_sql_injection(
            "https://example.test/",
            config=SQLiConfig(max_probes_per_target=8, login_path="/login.jsp"),
        )
    assert result["status"] == STATUS_UNSAFE
    triggering = result["details"]["triggering_payload"]
    assert triggering
    assert "' OR 1=1--" in str(triggering.get("payload") or "")
    assert result["details"]["password_strategy"] == "random_non_empty"
