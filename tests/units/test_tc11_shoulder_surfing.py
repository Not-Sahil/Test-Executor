from unittest.mock import Mock, patch
from login_page.scanners.tc11_shoulder_surfing import PasswordFieldParser, classify_secret_field, scan_shoulder_surfing

def resp(url, html, status=200):
    r=Mock(); r.url=url; r.text=html; r.status_code=status; r.content=html.encode(); r.headers={"Content-Type":"text/html"}; return r

def test_parser():
    p=PasswordFieldParser("https://example.test/login"); p.feed('<form><input name="password" type="password" autocomplete="current-password"></form>'); p.close()
    assert len(p.fields)==1 and p.fields[0].likely_role=="password" and p.fields[0].input_type=="password"

def test_classification():
    assert classify_secret_field(name="otp",autocomplete="one-time-code")=="otp"
    assert classify_secret_field(name="confirmPassword",autocomplete="new-password")=="password_confirmation"

def test_no_password():
    r=resp("https://example.test/login",'<form><input name="username"><button>Login</button></form>')
    with patch("login_page.scanners.tc11_shoulder_surfing._fetch",return_value=(r,["status=200"])):
        assert scan_shoulder_surfing("https://example.test",allow_browser=False)["status"]=="NOT ASSESSED"

def test_static_unmasked_is_unsafe():
    r=resp("https://example.test/login",'<form><input name="password" type="text"></form>')
    with patch("login_page.scanners.tc11_shoulder_surfing._fetch",return_value=(r,["status=200"])):
        assert scan_shoulder_surfing("https://example.test",allow_browser=False)["status"]=="UNSAFE"

def test_masked_requires_browser_for_full_assessment():
    r=resp("https://example.test/login",'<form><input name="password" type="password"></form>')
    with patch("login_page.scanners.tc11_shoulder_surfing._fetch",return_value=(r,["status=200"])):
        assert scan_shoulder_surfing("https://example.test",allow_browser=False)["status"]=="REVIEW REQUIRED"

def test_captcha_not_bypassed():
    r=resp("https://example.test/login",'<input name="password" type="password"><div class="g-recaptcha"></div>')
    with patch("login_page.scanners.tc11_shoulder_surfing._fetch",return_value=(r,["status=200"])):
        assert scan_shoulder_surfing("https://example.test",allow_browser=True)["status"]=="REVIEW REQUIRED"

def test_external_auth_not_assessed():
    r=resp("https://example.test/login",'<a href="https://accounts.google.com/o/oauth2/auth">Sign in</a>')
    with patch("login_page.scanners.tc11_shoulder_surfing._fetch",return_value=(r,["status=200"])):
        assert scan_shoulder_surfing("https://example.test",allow_browser=False)["status"]=="NOT ASSESSED"
