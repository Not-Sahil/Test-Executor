import pytest

from core.target_policy import TargetPolicy, validate_target_url


def test_target_policy_rejects_embedded_credentials():
    with pytest.raises(ValueError):
        validate_target_url("https://user:pass@example.com", TargetPolicy())


def test_target_policy_rejects_loopback_by_default():
    with pytest.raises(ValueError):
        validate_target_url("http://127.0.0.1:8000", TargetPolicy())


def test_target_policy_allows_private_when_explicitly_enabled():
    result = validate_target_url(
        "http://127.0.0.1:8000",
        TargetPolicy(allow_private_targets=True),
    )
    assert result == "http://127.0.0.1:8000"


def test_origin_root_url_handles_deep_targets():
    from pre_login.scanners.common import origin_root_url
    assert origin_root_url("https://example.com/login?next=/x") == "https://example.com"
