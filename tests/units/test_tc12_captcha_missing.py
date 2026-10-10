from login_page.scanners.tc12_captcha_missing import (
    TC12Config,
    _classify,
    detect_captcha,
    detect_local_login_form,
)


def test_detect_recaptcha():
    html = '<form><input type="password"><div class="g-recaptcha"></div></form>'
    result = detect_captcha(html)
    assert result["present"] is True
    assert result["provider"] == "reCAPTCHA"


def test_detect_hcaptcha_response_field():
    html = '<input type="hidden" name="h-captcha-response" value="">'
    result = detect_captcha(html)
    assert result["present"] is True
    assert "h-captcha-response" in result["response_fields"]


def test_no_captcha_marker():
    result = detect_captcha('<form><input type="text"><input type="password"></form>')
    assert result["present"] is False


def test_local_password_form():
    result = detect_local_login_form(
        '<form action="/login" method="post"><input name="email" type="email"><input type="password"></form>'
    )
    assert result["local_password_login"] is True
    assert result["likely_federated"] is False


def test_federated_without_local_password_is_not_local_login():
    result = detect_local_login_form('<a href="https://accounts.google.com/o/oauth2/auth">Google</a>')
    assert result["local_password_login"] is False
    assert result["likely_federated"] is True


def test_initial_captcha_means_safe_for_this_testcase():
    status, _ = _classify(
        local_login={"local_password_login": True, "likely_federated": False},
        initial_captcha={"present": True},
        post_probe_captchas=[],
        attempted_probes=0,
        rate_limited=False,
        browser_available=False,
        probe_error=None,
    )
    assert status == "SAFE"


def test_missing_after_bounded_probes_is_unsafe():
    status, _ = _classify(
        local_login={"local_password_login": True, "likely_federated": False},
        initial_captcha={"present": False},
        post_probe_captchas=[{"present": False}, {"present": False}],
        attempted_probes=2,
        rate_limited=False,
        browser_available=False,
        probe_error=None,
    )
    assert status == "UNSAFE"


def test_captcha_appears_after_failure_is_safe():
    status, _ = _classify(
        local_login={"local_password_login": True, "likely_federated": False},
        initial_captcha={"present": False},
        post_probe_captchas=[{"present": False}, {"present": True}],
        attempted_probes=2,
        rate_limited=False,
        browser_available=False,
        probe_error=None,
    )
    assert status == "SAFE"


def test_rate_limit_before_captcha_is_review_required():
    status, _ = _classify(
        local_login={"local_password_login": True, "likely_federated": False},
        initial_captcha={"present": False},
        post_probe_captchas=[{"present": False}],
        attempted_probes=1,
        rate_limited=True,
        browser_available=False,
        probe_error=None,
    )
    assert status == "REVIEW REQUIRED"


def test_config_defaults_are_bounded():
    cfg = TC12Config()
    assert cfg.max_failed_probes <= 3
    assert cfg.synthetic_password.startswith("TC12-")
