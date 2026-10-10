from authentication.enumeration_signals import (
    classify_message,
    explicit_username_disclosure,
    is_rate_limited,
    normalize_dynamic_content,
)


def test_message_classification():
    assert classify_message("Invalid username or user not found") == "invalid_username"
    assert classify_message("Incorrect password") == "invalid_password"
    assert classify_message("Invalid credentials") == "generic_failure"


def test_dynamic_normalization_removes_common_tokens():
    a = 'csrf=abc123 timestamp=2026-09-23T10:00:00Z sessionid=deadbeefcafebabe'
    b = 'csrf=def456 timestamp=2026-09-23T10:01:00Z sessionid=0011223344556677'
    assert normalize_dynamic_content(a) == normalize_dynamic_content(b)


def test_explicit_disclosure_requires_username_and_strong_marker():
    assert explicit_username_disclosure("account alice exists", "alice") is True
    assert explicit_username_disclosure("welcome alice", "alice") is False


def test_rate_limit_detection():
    assert is_rate_limited(429, "") is True
    assert is_rate_limited(200, "Too many requests, try again later") is True
    assert is_rate_limited(200, "Invalid username") is False
