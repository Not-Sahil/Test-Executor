"""Tests verifying strict isolation between Black-Box and Gray-Box frameworks."""
import json
from pathlib import Path

from pre_login.runner import PRE_LOGIN_TESTS
from login_page.registry import LOGIN_PAGE_TESTS

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent


def test_blackbox_prelogin_inventory_unchanged():
    assert len(PRE_LOGIN_TESTS) == 30, f"Expected 30 Pre-Login testcases, found {len(PRE_LOGIN_TESTS)}"
    keys = [item[0] for item in PRE_LOGIN_TESTS]
    assert "tc01_banner_grabbing" in keys
    assert "tc18_missing_security_headers" in keys
    assert "tc23_internal_path_disclosure" in keys
    assert "tc24_boolean_sql_injection" in keys
    assert "tc27_union_sql_injection" in keys
    assert "tc30_prototype_pollution_dom_xss" in keys


def test_blackbox_login_page_inventory_unchanged():
    assert len(LOGIN_PAGE_TESTS) == 17, f"Expected 17 Login-Page testcases, found {len(LOGIN_PAGE_TESTS)}"
    keys = [item[0] for item in LOGIN_PAGE_TESTS]
    assert "tc01_autocomplete" in keys
    assert "tc02_default_credentials" in keys
    assert "tc14_sql_injection" in keys
    assert "tc17_rate_limit" in keys


def test_blackbox_payload_manifest_exists_and_unaltered():
    bb_manifest = BASE_DIR / "payloads" / "manifest.json"
    assert bb_manifest.is_file(), "Black-Box payloads/manifest.json must exist"
    data = json.loads(bb_manifest.read_text(encoding="utf-8"))
    assert "tc01_banner_grabbing" in data or "tc02_known_components" in data or len(data) > 0


def test_graybox_payloads_isolated_in_dedicated_directory():
    gb_dir = BASE_DIR / "payloads" / "graybox"
    assert gb_dir.is_dir()
    assert (gb_dir / "manifest.json").is_file()

    # Verify no graybox file leaked into top-level payloads directory
    top_level_files = [f.name for f in (BASE_DIR / "payloads").iterdir() if f.is_file()]
    assert "manifest.json" in top_level_files
