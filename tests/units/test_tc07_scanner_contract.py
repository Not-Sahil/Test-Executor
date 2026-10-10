from __future__ import annotations

from unittest.mock import patch

from login_page.scanners.tc07_browser_memory_dump import scan_browser_memory_dump
from authentication.browser_memory_models import BrowserMemoryConfig


def test_invalid_target_is_incomplete():
    result = scan_browser_memory_dump("not a url", config=BrowserMemoryConfig(perform_authenticated_lane=False))
    assert result["status"] == "INCOMPLETE"
    assert result["assessment_state"] == "INCOMPLETE"


def test_scanner_has_stable_identity():
    # Avoid launching a browser in the unit test environment.
    with patch("login_page.scanners.tc07_browser_memory_dump.sync_playwright", None):
        result = scan_browser_memory_dump(
            "https://example.test",
            config=BrowserMemoryConfig(perform_authenticated_lane=False),
        )
    assert result["key"] == "tc07_browser_memory_dump"
    assert result["name"] == "Browser Memory Dump"
    assert "scope_boundary" not in result.get("details", {}) or isinstance(result["details"], dict)
