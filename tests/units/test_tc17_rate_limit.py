from __future__ import annotations

from types import SimpleNamespace

import pytest

from login_page.scanners.tc17_rate_limit import (
    RateLimitConfig,
    _candidate_wrong_password,
    _classify,
    _find_login_form,
    _retry_after,
    _signals,
    scan_rate_limit,
)


def response(status=401, body="", headers=None, url="https://example.test/login"):
    return SimpleNamespace(
        status_code=status,
        text=body,
        headers=headers or {},
        url=url,
    )


def test_wrong_password_is_derived_and_deterministic():
    value = _candidate_wrong_password("CorrectHorseBatteryStaple!", 1)
    assert value != "CorrectHorseBatteryStaple!"
    assert "TC17_01_WRONG" in value


def test_login_form_discovery():
    html = """
    <form action="/session" method="post">
      <input type="hidden" name="csrf" value="abc">
      <input type="email" name="email">
      <input type="password" name="password">
      <button>Login</button>
    </form>
    """
    form = _find_login_form(html, "https://example.test/login")
    assert form is not None
    assert form["action"] == "https://example.test/session"
    assert form["method"] == "post"


def test_429_and_retry_after_are_rate_limit_signals():
    r = response(429, "Too many requests", {"Retry-After": "5"})
    signals, rate, captcha, lockout, success = _signals(r)
    assert rate is True
    assert captcha is False
    assert lockout is False
    assert success is False
    assert "http_429" in signals
    assert _retry_after(r) == 5.0


def test_captcha_is_detected():
    r = response(403, "<html><div>hCaptcha challenge</div></html>")
    _, rate, captcha, lockout, success = _signals(r)
    assert captcha is True
    assert rate is False
    assert lockout is False
    assert success is False


def test_lockout_is_detected():
    r = response(200, "Your account has been temporarily locked.")
    _, rate, captcha, lockout, success = _signals(r)
    assert lockout is True
    assert rate is False
    assert captcha is False
    assert success is False


def test_safe_when_rate_limit_observed():
    records = [
        SimpleNamespace(
            index=1, rate_limited=False, captcha_detected=False,
            lockout_detected=False, authenticated=False, rejected=True,
            status_code=401, elapsed_seconds=0.1
        ),
        SimpleNamespace(
            index=2, rate_limited=False, captcha_detected=False,
            lockout_detected=False, authenticated=False, rejected=True,
            status_code=401, elapsed_seconds=0.1
        ),
        SimpleNamespace(
            index=3, rate_limited=True, captcha_detected=False,
            lockout_detected=False, authenticated=False, rejected=False,
            status_code=429, elapsed_seconds=0.1
        ),
    ]
    result = _classify(True, records, captcha_on_page=False, target_url="https://example.test/login")
    assert result.status == "SAFE"
    assert result.details["first_block_attempt"] == 3


def test_unsafe_when_all_wrong_attempts_are_rejected_without_throttle():
    records = [
        SimpleNamespace(
            index=1, rate_limited=False, captcha_detected=False,
            lockout_detected=False, authenticated=False, rejected=True,
            status_code=401, elapsed_seconds=0.1
        ),
        SimpleNamespace(
            index=2, rate_limited=False, captcha_detected=False,
            lockout_detected=False, authenticated=False, rejected=True,
            status_code=401, elapsed_seconds=0.1
        ),
    ]
    result = _classify(True, records, captcha_on_page=False, target_url="https://example.test/login")
    assert result.status == "UNSAFE"
    assert "no_observed_throttle_within_test_window" in result.evidence


def test_incomplete_without_authorized_credentials(monkeypatch):
    result = scan_rate_limit(
        "https://example.test",
        RateLimitConfig(authorized_username=None, authorized_password=None),
    )
    assert result.status == "INCOMPLETE"


def test_invalid_target_is_incomplete():
    result = scan_rate_limit(
        "not a url",
        RateLimitConfig(
            authorized_username="authorized",
            authorized_password="CorrectPassword!",
        ),
    )
    assert result.status == "INCOMPLETE"


def test_derived_password_never_equals_valid():
    for i in range(1, 11):
        assert _candidate_wrong_password("abc", i) != "abc"
