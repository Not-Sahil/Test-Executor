from authentication.method_interchange_models import MethodInterchangeConfig
from login_page.scanners.tc06_method_interchange import scan_method_interchange

def test_missing_credentials_is_incomplete():
    result = scan_method_interchange(
        "https://example.com",
        config=MethodInterchangeConfig(
            login_path="/login",
            authorized_username=None,
            authorized_password=None,
        ),
    )
    assert result["key"] == "tc06_method_interchange"
    assert result["status"] in {"INCOMPLETE", "SAFE", "REVIEW REQUIRED", "UNSAFE", "NOT ASSESSED"}

def test_config_disables_non_get_post():
    cfg = MethodInterchangeConfig()
    normalized = cfg.normalized()
    assert normalized.allow_non_get_post is False

def test_scan_alias_exists():
    from login_page.scanners.tc06_method_interchange import scan
    assert scan is scan_method_interchange
