from __future__ import annotations

from unittest.mock import MagicMock, patch
import pytest

from pre_login.scanners.tc30_prototype_pollution_dom_xss import scan_prototype_pollution_dom_xss


def _mock_response(status_code: int = 200, text: str = "<html><body><h1>App</h1></body></html>"):
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    resp.url = "https://example.com/"
    return resp


def test_pp_confirmed_and_dom_sink_flow_returns_unsafe():
    # Both PP and canary in DOM confirmed in browser
    html_text = "<html><body><script>target[key]=source[key]; document.write(data);</script></body></html>"
    resp = _mock_response(200, html_text)

    mock_playwright = MagicMock()
    mock_browser = MagicMock()
    mock_page = MagicMock()
    mock_playwright.chromium.launch.return_value = mock_browser
    mock_browser.new_page.return_value = mock_page
    # Prototype pollution succeeded
    mock_page.evaluate.return_value = "canary_val_active_probe"
    # Rendered DOM contains the canary value (XSS confirmed)
    mock_page.content.return_value = "<html><body><div>canary_val_active_probe</div></body></html>"

    with patch("requests.Session.get", return_value=resp):
        with patch.dict("sys.modules", {"playwright.sync_api": MagicMock()}):
            with patch("playwright.sync_api.sync_playwright") as mock_sp:
                mock_sp.return_value.__enter__.return_value = mock_playwright
                res = scan_prototype_pollution_dom_xss("https://example.com/", check_browser=True)
                assert res["status"] == "UNSAFE"
                assert "Prototype Pollution Leading to DOM-Based XSS Confirmed" in res["summary"]
                assert res["details"]["dom_xss_confirmed"] is True


def test_pp_confirmed_without_dom_xss_returns_review_required():
    html_text = "<html><body><script>target[key]=source[key];</script></body></html>"
    resp = _mock_response(200, html_text)

    mock_playwright = MagicMock()
    mock_browser = MagicMock()
    mock_page = MagicMock()
    mock_playwright.chromium.launch.return_value = mock_browser
    mock_browser.new_page.return_value = mock_page
    mock_page.evaluate.return_value = "canary_val_active_probe"
    # Rendered DOM does NOT contain canary (pollution exists, but no XSS sink reached)
    mock_page.content.return_value = "<html><body><div>Static Safe Output</div></body></html>"

    with patch("requests.Session.get", return_value=resp):
        with patch.dict("sys.modules", {"playwright.sync_api": MagicMock()}):
            with patch("playwright.sync_api.sync_playwright") as mock_sp:
                mock_sp.return_value.__enter__.return_value = mock_playwright
                res = scan_prototype_pollution_dom_xss("https://example.com/", check_browser=True)
                # MUST be REVIEW REQUIRED, NOT UNSAFE!
                assert res["status"] == "REVIEW REQUIRED"
                assert "Prototype Pollution Detected" in res["summary"]
                assert res["details"]["prototype_pollution_confirmed"] is True
                assert res["details"]["dom_xss_confirmed"] is False


def test_static_merge_and_sink_without_browser_returns_review_required():
    html_text = (
        "<html><body>"
        "<script>"
        "function deepMerge(dest, src) { target[prop] = source[prop]; }\n"
        "document.getElementById('out').innerHTML = userInput;\n"
        "</script>"
        "</body></html>"
    )
    resp = _mock_response(200, html_text)

    with patch("requests.Session.get", return_value=resp):
        res = scan_prototype_pollution_dom_xss("https://example.com/", check_browser=False)
        assert res["status"] == "REVIEW REQUIRED"
        assert "Potential Prototype Pollution and DOM Sink Exploit Chain" in res["summary"]


def test_clean_client_scripts_returns_safe():
    html_text = "<html><body><p>Hello world</p><script>console.log('App loaded');</script></body></html>"
    resp = _mock_response(200, html_text)

    with patch("requests.Session.get", return_value=resp):
        res = scan_prototype_pollution_dom_xss("https://example.com/", check_browser=False)
        assert res["status"] == "SAFE"
        assert "No prototype pollution patterns" in res["summary"]


def test_connection_failure_returns_incomplete():
    with patch("requests.Session.get", side_effect=ConnectionResetError("Reset")):
        res = scan_prototype_pollution_dom_xss("https://broken.invalid/", check_browser=False)
        assert res["status"] == "INCOMPLETE"
