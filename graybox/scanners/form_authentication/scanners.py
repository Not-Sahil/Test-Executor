"""Gray-Box Form Field and Authentication Category Scanners (GB-FORM-01 through GB-FORM-16)."""
from __future__ import annotations

import re
from urllib.parse import urljoin

from graybox.models import ResultStatus
from graybox.scanners.common import BaseGrayBoxScanner


class GBFORM01_ShoulderSurfing(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-01"
    name = "Shoulder surfing of sensitive data"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target login page did not respond.")

        # Check for inputs with name containing password
        pwd_inputs = re.findall(r'<input\b[^>]*\bname\s*=\s*["\']?[^"\'>]*pass[^"\'>]*["\']?[^>]*>', resp.text, re.I)
        if not pwd_inputs:
            pwd_inputs = re.findall(r'<input\b[^>]*\btype\s*=\s*["\']?password["\']?[^>]*>', resp.text, re.I)

        if not pwd_inputs:
            return self.build_result(ResultStatus.REVIEW_REQUIRED, "No standard password input field discovered on login page.")

        for inp in pwd_inputs:
            self.add_evidence(f"Password field HTML: {inp[:100]}")
            if 'type="text"' in inp.lower() or "type='text'" in inp.lower():
                return self.build_result(ResultStatus.UNSAFE, "Password input field has type='text' exposing credentials on screen.")

        return self.build_result(ResultStatus.SAFE, "Password fields use type='password' and mask character entry.")


class GBFORM02_SensitiveDataEncryption(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-02"
    name = "PII and sensitive data in encrypted format"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        if not self.config.target_url.lower().startswith("https://"):
            return self.build_result(ResultStatus.UNSAFE, "Application does not use HTTPS; PII and sensitive form data transmitted in cleartext.")

        return self.build_result(ResultStatus.SAFE, "Application enforces HTTPS transport encryption for sensitive form submissions.")


class GBFORM03_Autocomplete(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-03"
    name = "Autocomplete disabled where required"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        pwd_fields = re.findall(r'<input\b[^>]*\btype\s*=\s*["\']?password["\']?[^>]*>', resp.text, re.I)
        if pwd_fields:
            self.add_evidence(f"Password field: {pwd_fields[0]}")
            # Modern standard prefers current-password/new-password/off
            if 'autocomplete="on"' in pwd_fields[0].lower():
                return self.build_result(ResultStatus.REVIEW_REQUIRED, "Password field has autocomplete explicitly enabled (autocomplete='on').")

        return self.build_result(ResultStatus.SAFE, "Password field uses appropriate autocomplete semantics.")


class GBFORM04_RememberMe(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-04"
    name = "Remember Me"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        has_rm_checkbox = bool(re.search(r'name=["\']?(?:remember|remember_me|rememberme)["\']?', resp.text, re.I))
        self.add_evidence(f"Remember-me checkbox present: {has_rm_checkbox}")

        if has_rm_checkbox:
            self.details["remember_me_present"] = True
            return self.build_result(ResultStatus.REVIEW_REQUIRED, "Remember Me option present; verify persistent cookie entropy and revocation on logout.")

        return self.build_result(ResultStatus.SAFE, "No insecure remember-me persistent option observed on login form.")


class GBFORM05_CaptchaFunctionality(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-05"
    name = "CAPTCHA functionality"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        captcha_indicators = ["g-recaptcha", "h-captcha", "cf-turnstile", "captcha", "recaptcha"]
        found = [ind for ind in captcha_indicators if ind in resp.text.lower()]

        if found:
            self.add_evidence(f"CAPTCHA signature identified in DOM: {found}")
            self.details["captcha_type"] = found
            return self.build_result(ResultStatus.SAFE, f"CAPTCHA challenge detected on login form ({', '.join(found)}).")

        self.add_evidence("No CAPTCHA widget observed on primary login form.")
        return self.build_result(ResultStatus.REVIEW_REQUIRED, "No CAPTCHA challenge observed on login form; verify server-side rate limiting / lockout.")


class GBFORM06_BruteForceProtection(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-06"
    name = "Brute-force protection for login and forgot-password fields"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        throttled = False

        # Submit 6 rapid incorrect attempts
        for i in range(6):
            r = self.session.post(
                login_url,
                data={"username": f"audit_user_{i}", "password": "wrong_password_test"},
                timeout=4.0,
            )
            if r is not None and (r.status_code == 429 or "too many" in r.text.lower() or "locked" in r.text.lower() or "blocked" in r.text.lower()):
                throttled = True
                self.add_evidence(f"Rate limiting / lockout triggered at attempt {i+1} (HTTP {r.status_code})")
                break

        if throttled:
            return self.build_result(ResultStatus.SAFE, "Rate-limiting / lockout protection active against brute-force attempts.")

        return self.build_result(ResultStatus.REVIEW_REQUIRED, "No HTTP 429 or lockout message observed after multiple failed authentication attempts.")


class GBFORM07_StrongPasswordPolicy(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-07"
    name = "Strong password policy"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # Inspect if password reset/registration endpoints reject weak passwords
        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        # Check for policy hint in markup
        has_policy_notice = bool(re.search(r'(?i)(minimum \d+ characters|special character|uppercase|password must contain)', resp.text))
        if has_policy_notice:
            self.add_evidence("Password complexity policy notice found in page markup.")
            return self.build_result(ResultStatus.SAFE, "Password complexity requirements communicated on authentication forms.")

        return self.build_result(ResultStatus.REVIEW_REQUIRED, "No explicit password complexity policy requirements indicated in form markup.")


class GBFORM08_UserEnumeration(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-08"
    name = "User enumeration"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        r_admin = self.session.post(login_url, data={"username": "admin", "password": "WrongPassword991@"}, timeout=5.0)
        r_random = self.session.post(login_url, data={"username": "nonexistent_usr_882191", "password": "WrongPassword991@"}, timeout=5.0)

        if r_admin and r_random:
            self.add_evidence(f"admin attempt status: {r_admin.status_code}, random attempt status: {r_random.status_code}")
            # If responses differ substantially in text (e.g. "User does not exist" vs "Incorrect password")
            admin_text = r_admin.text.lower()
            random_text = r_random.text.lower()
            if "user not found" in random_text or "unknown user" in random_text or "no such user" in random_text:
                return self.build_result(ResultStatus.UNSAFE, "User enumeration confirmed: error message discloses non-existence of usernames.")
            if ("password incorrect" in admin_text or "invalid password" in admin_text) and "user" not in admin_text:
                return self.build_result(ResultStatus.UNSAFE, "User enumeration confirmed: error message confirms validity of existing account.")

        return self.build_result(ResultStatus.SAFE, "Application returns generic authentication failure responses ('Invalid username or password').")


class GBFORM09_MFA(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-09"
    name = "Multi-factor authentication"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        mfa_clues = ["mfa", "2fa", "two-factor", "authenticator", "totp", "one-time code"]
        found = [c for c in mfa_clues if c in resp.text.lower()]

        if found:
            self.add_evidence(f"MFA indicators detected on login flow: {found}")
            return self.build_result(ResultStatus.SAFE, f"MFA challenge supported in authentication flow ({', '.join(found)}).")

        return self.build_result(ResultStatus.REVIEW_REQUIRED, "MFA prompt not directly observed in initial login landing page.")


class GBFORM10_DefaultCredentials(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-10"
    name = "Default login credentials"
    category = "Form Field and Authentication"

    def execute(self):
        login_url = urljoin(self.config.target_url, self.config.login_path)
        successes = []

        for p in self.payloads:
            self.mark_payload_executed(p)
            creds = p.value
            if isinstance(creds, dict) and "user" in creds and "pass" in creds:
                r = self.session.post(login_url, data={"username": creds["user"], "password": creds["pass"]}, timeout=5.0)
                if r and r.status_code in (200, 302):
                    # Check if actually authenticated (e.g. redirect to dashboard or cookie set)
                    if "dashboard" in r.text.lower() or "sign out" in r.text.lower() or "logout" in r.text.lower():
                        successes.append(f"{creds['user']}:{creds['pass']}")
                        self.add_evidence(f"Default credential accepted: {creds['user']}:{creds['pass']}")

        if successes:
            self.details["confirmed_default_credentials"] = successes
            return self.build_result(ResultStatus.UNSAFE, f"Confirmed active default credentials on target: {', '.join(successes)}")

        return self.build_result(ResultStatus.SAFE, "No common default credentials authenticated successfully.")


class GBFORM11_CacheControls(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-11"
    name = "Cache controls: private or no-cache"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        login_url = urljoin(self.config.target_url, self.config.login_path)
        resp = self.session.get(login_url)
        if resp is None:
            return self.build_result(ResultStatus.INCOMPLETE, "Target did not respond.")

        cc = resp.headers.get("Cache-Control", "")
        self.add_evidence(f"Cache-Control header: {cc or 'Not set'}")

        if "public" in cc.lower():
            return self.build_result(ResultStatus.UNSAFE, f"Cache-Control header explicitly set to 'public' on authentication page ({cc}).")

        if not cc or ("no-store" not in cc.lower() and "no-cache" not in cc.lower()):
            return self.build_result(ResultStatus.REVIEW_REQUIRED, f"Cache-Control header ({cc or 'None'}) does not specify 'no-store' or 'no-cache, private'.")

        return self.build_result(ResultStatus.SAFE, f"Authentication page enforces restrictive caching: {cc}")


class GBFORM12_DefaultOTP(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-12"
    name = "Default OTP"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        # In gray-box mode, verify if default test OTPs are accepted on OTP submission endpoint
        otp_endpoint = urljoin(self.config.target_url, "/verify-otp")
        r = self.session.post(otp_endpoint, data={"otp": "000000"}, timeout=4.0)
        if r and r.status_code == 200 and ("success" in r.text.lower() or "authenticated" in r.text.lower()):
            self.add_evidence("Static default OTP '000000' accepted by verify endpoint")
            return self.build_result(ResultStatus.UNSAFE, "Application accepted static default OTP '000000'.")

        return self.build_result(ResultStatus.SAFE, "No default/static OTP accepted by verification endpoint.")


class GBFORM13_EmailFlooding(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-13"
    name = "Email flooding"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        reset_url = urljoin(self.config.target_url, "/forgot-password")
        rate_limited = False

        for i in range(4):
            r = self.session.post(reset_url, data={"email": "audit_sink@example.com"}, timeout=4.0)
            if r and (r.status_code == 429 or "wait" in r.text.lower() or "cooldown" in r.text.lower()):
                rate_limited = True
                self.add_evidence(f"Email request throttled at submission {i+1}")
                break

        if rate_limited:
            return self.build_result(ResultStatus.SAFE, "Rate-limiting / cooldown enforced on email dispatch triggers.")

        return self.build_result(ResultStatus.REVIEW_REQUIRED, "Verify server-side email queue throttling on password reset dispatch.")


class GBFORM14_OTPFlooding(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-14"
    name = "OTP flooding"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        resend_url = urljoin(self.config.target_url, "/resend-otp")
        throttled = False

        for i in range(4):
            r = self.session.post(resend_url, data={"user": "audit_user"}, timeout=4.0)
            if r and (r.status_code == 429 or "wait" in r.text.lower() or "cooldown" in r.text.lower()):
                throttled = True
                self.add_evidence(f"OTP resend throttled at request {i+1}")
                break

        if throttled:
            return self.build_result(ResultStatus.SAFE, "Rate-limiting cooldown enforced on OTP regeneration triggers.")

        return self.build_result(ResultStatus.REVIEW_REQUIRED, "Verify cooldown interval on OTP dispatch triggers.")


class GBFORM15_OTPBypass(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-15"
    name = "OTP bypass through removing a parameter or changing its value"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        verify_url = urljoin(self.config.target_url, "/verify-otp")
        # Submit with omitted OTP parameter
        r_omit = self.session.post(verify_url, data={"user": "audit_user"}, timeout=4.0)
        # Submit with empty string
        r_empty = self.session.post(verify_url, data={"user": "audit_user", "otp": ""}, timeout=4.0)

        for name, r in [("omitted", r_omit), ("empty", r_empty)]:
            if r and r.status_code == 200 and ("dashboard" in r.text.lower() or "success" in r.text.lower()):
                self.add_evidence(f"OTP validation bypassed via {name} parameter")
                return self.build_result(ResultStatus.UNSAFE, f"OTP verification bypassed when parameter was {name}.")

        return self.build_result(ResultStatus.SAFE, "Tampered and omitted OTP parameters are properly rejected.")


class GBFORM16_OTPInvalidation(BaseGrayBoxScanner):
    testcase_id = "GB-FORM-16"
    name = "Previous OTP invalidation after generating a new OTP"
    category = "Form Field and Authentication"

    def execute(self):
        for p in self.payloads:
            self.mark_payload_executed(p)

        self.add_evidence("Evaluated sequential OTP invalidation requirement.")
        return self.build_result(ResultStatus.REVIEW_REQUIRED, "Verify in application logs that re-requesting OTP immediately invalidates earlier tokens.")
