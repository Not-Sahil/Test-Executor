"""Tests verifying Gray-Box testcase registry completeness and taxonomy integrity."""
import pytest

from graybox.models import AutomationLevel, TestCategory
from graybox.registry import (
    GRAYBOX_REGISTRY,
    SCANNER_MAP,
    get_graybox_registry,
    get_scanner_class,
    get_testcase,
    get_testcases_by_category,
)


def test_registry_contains_all_85_testcases():
    reg = get_graybox_registry()
    assert len(reg) == 85, f"Expected exactly 85 registered testcases, found {len(reg)}"


def test_category_counts():
    basic_tests = get_testcases_by_category(TestCategory.BASIC)
    enc_tests = get_testcases_by_category(TestCategory.ENCRYPTION)
    form_tests = get_testcases_by_category(TestCategory.FORM_AUTHENTICATION)
    session_tests = get_testcases_by_category(TestCategory.SESSION_MANAGEMENT)
    inj_tests = get_testcases_by_category(TestCategory.INJECTION)
    ssrf_tests = get_testcases_by_category(TestCategory.SSRF)

    assert len(basic_tests) == 21, f"Expected 21 Basic tests, got {len(basic_tests)}"
    assert len(enc_tests) == 8, f"Expected 8 Encryption tests, got {len(enc_tests)}"
    assert len(form_tests) == 16, f"Expected 16 Form Authentication tests, got {len(form_tests)}"
    assert len(session_tests) == 19, f"Expected 19 Session Management tests, got {len(session_tests)}"
    assert len(inj_tests) == 20, f"Expected 20 Injection tests, got {len(inj_tests)}"
    assert len(ssrf_tests) == 1, f"Expected 1 SSRF test, got {len(ssrf_tests)}"


def test_every_testcase_has_valid_scanner_class():
    for tc_id, tc in GRAYBOX_REGISTRY.items():
        scanner_cls = get_scanner_class(tc_id)
        assert scanner_cls is not None, f"Testcase {tc_id} has no scanner class in SCANNER_MAP"
        assert tc.id.startswith(("GB-BASIC-", "GB-ENC-", "GB-FORM-", "GB-SESSION-", "GB-INJ-", "GB-SSRF-"))
        assert tc.name.strip(), f"Testcase {tc_id} missing name"
        assert tc.objective.strip(), f"Testcase {tc_id} missing objective"
        assert tc.payload_file.strip(), f"Testcase {tc_id} missing payload_file"
        assert tc.automation_level in (AutomationLevel.AUTOMATED, AutomationLevel.ASSISTED, AutomationLevel.MANUAL)


def test_scanner_map_keys_match_registry():
    assert set(SCANNER_MAP.keys()) == set(GRAYBOX_REGISTRY.keys())
