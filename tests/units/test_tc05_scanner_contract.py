from __future__ import annotations

from login_page.scanners.tc05_password_validation import scan_password_validation
from authentication.password_validation_models import PasswordValidationConfig


def test_missing_authorized_control_is_incomplete():
    result = scan_password_validation(
        "https://example.invalid",
        PasswordValidationConfig(login_path="/login"),
    )
    assert result.status == "INCOMPLETE"
    assert result.details.get("assessment_state") == "INCOMPLETE"
