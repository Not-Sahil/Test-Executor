"""Unit tests for TC18 Missing Security Headers Scanner - HSTS max-age evaluation."""
from __future__ import annotations

import pytest

from pre_login.scanners.tc18_missing_security_headers import (
    IDEAL_HEADERS,
    check_hsts,
)


def test_tc18_ideal_headers_max_age():
    """Verify IDEAL_HEADERS Strict-Transport-Security uses max-age=31536000 (1 year)."""
    hsts_ideal = IDEAL_HEADERS["Strict-Transport-Security"]
    assert "max-age=31536000" in hsts_ideal
    assert "63072000" not in hsts_ideal


def test_tc18_hsts_one_year_compliant():
    """Verify that a 1-year max-age with includeSubDomains and preload is evaluated as SAFE."""
    res = check_hsts("max-age=31536000; includeSubDomains; preload")
    assert res["status"] == "SAFE"
    assert res["max_age"] == 31536000
    assert len(res["hardening"]) == 0


def test_tc18_hsts_greater_than_one_year():
    """Verify that max-age greater than 1 year is also compliant."""
    res = check_hsts("max-age=63072000; includeSubDomains; preload")
    assert res["status"] == "SAFE"
    assert res["max_age"] == 63072000
    assert len(res["hardening"]) == 0


def test_tc18_hsts_less_than_one_year():
    """Verify that max-age below 31536000 (1 year) flags REVIEW REQUIRED."""
    res = check_hsts("max-age=2592000; includeSubDomains; preload")
    assert res["status"] == "REVIEW REQUIRED"
    assert "less than 31536000" in res["reason"]


def test_tc18_hsts_missing_max_age():
    """Verify that missing max-age flags UNSAFE."""
    res = check_hsts("includeSubDomains; preload")
    assert res["status"] == "UNSAFE"
    assert "max-age missing" in res["reason"]
