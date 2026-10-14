"""Canonical Gray-Box Testcase Registry.

Defines all 85 Gray-Box testcases with full metadata, automation levels,
required roles, required artifacts, and scanner bindings.
"""
from __future__ import annotations

from typing import Type

from graybox.models import (
    AccountRole,
    ArtifactType,
    AutomationLevel,
    GrayBoxTestcase,
    TestCategory,
)
from graybox.scanners.common import BaseGrayBoxScanner

# Import all category scanners
from graybox.scanners.basic import (
    GBBASIC01_AccessThroughIP,
    GBBASIC02_ServerBannerGrabbing,
    GBBASIC03_VulnerableComponents,
    GBBASIC04_ArbitraryMethods,
    GBBASIC05_CrossSiteTracing,
    GBBASIC06_SecurityHeaders,
    GBBASIC07_CORS,
    GBBASIC08_ClientSideSensitiveData,
    GBBASIC09_JQuery,
    GBBASIC10_JQueryXSS,
    GBBASIC11_Bootstrap,
    GBBASIC12_DirectoryListing,
    GBBASIC13_DirectoryTraversal,
    GBBASIC14_HostHeaderInjection,
    GBBASIC15_OpenRedirection,
    GBBASIC16_IPAddressDisclosure,
    GBBASIC17_PrivateIPDisclosure,
    GBBASIC18_ETag,
    GBBASIC19_Clickjacking,
    GBBASIC20_XXSSProtectionHeader,
    GBBASIC21_HardcodedCredentials,
)
from graybox.scanners.encryption import (
    GBENC01_TLSVersions,
    GBENC02_CertificateValidation,
    GBENC03_CredentialsOverHTTPS,
    GBENC04_LoginFormOverHTTPS,
    GBENC05_SessionTokensOverHTTPS,
    GBENC06_HSTS,
    GBENC07_SensitiveInfoInURL,
    GBENC08_SSLStripping,
)
from graybox.scanners.form_authentication import (
    GBFORM01_ShoulderSurfing,
    GBFORM02_SensitiveDataEncryption,
    GBFORM03_Autocomplete,
    GBFORM04_RememberMe,
    GBFORM05_CaptchaFunctionality,
    GBFORM06_BruteForceProtection,
    GBFORM07_StrongPasswordPolicy,
    GBFORM08_UserEnumeration,
    GBFORM09_MFA,
    GBFORM10_DefaultCredentials,
    GBFORM11_CacheControls,
    GBFORM12_DefaultOTP,
    GBFORM13_EmailFlooding,
    GBFORM14_OTPFlooding,
    GBFORM15_OTPBypass,
    GBFORM16_OTPInvalidation,
)
from graybox.scanners.session_management import (
    GBSESSION01_CookieFlags,
    GBSESSION02_CookieScope,
    GBSESSION03_SessionDuration,
    GBSESSION04_CookieRandomness,
    GBSESSION05_HighPrivilegeSession,
    GBSESSION06_SimultaneousSessions,
    GBSESSION07_CookieRandomnessAndRotation,
    GBSESSION08_CookiesBeforeAfterLogout,
    GBSESSION09_SessionHijackingResistance,
    GBSESSION10_SessionPuzzling,
    GBSESSION11_BrowserClosure,
    GBSESSION12_DeepURL,
    GBSESSION13_BackRefreshAfterLogout,
    GBSESSION14_LogoutAfterPasswordChange,
    GBSESSION15_IDOR,
    GBSESSION16_PrivilegeEscalation,
    GBSESSION17_CSRF,
    GBSESSION18_CRLF,
    GBSESSION19_SessionReplay,
)
from graybox.scanners.injection import (
    GBINJ01_XSS,
    GBINJ02_HTMLInjection,
    GBINJ03_SQLInjection,
    GBINJ04_ExcelFormulaInjection,
    GBINJ05_InputValidation,
    GBINJ06_ClientSideValidationBypass,
    GBINJ07_ServerSideValidationBypass,
    GBINJ08_MandatoryFieldBypass,
    GBINJ09_ParameterManipulation,
    GBINJ10_ParameterPollution,
    GBINJ11_XMLInjection,
    GBINJ12_XXE,
    GBINJ13_XPathInjection,
    GBINJ14_CSTI,
    GBINJ15_SSTI,
    GBINJ16_SSIInjection,
    GBINJ17_CommandInjection,
    GBINJ18_CodeInjection,
    GBINJ19_LDAPInjection,
    GBINJ20_HTTPRequestSmuggling,
)
from graybox.scanners.ssrf import GBSSRF01_SSRF


SCANNER_MAP: dict[str, Type[BaseGrayBoxScanner]] = {
    # Basic
    "GB-BASIC-01": GBBASIC01_AccessThroughIP,
    "GB-BASIC-02": GBBASIC02_ServerBannerGrabbing,
    "GB-BASIC-03": GBBASIC03_VulnerableComponents,
    "GB-BASIC-04": GBBASIC04_ArbitraryMethods,
    "GB-BASIC-05": GBBASIC05_CrossSiteTracing,
    "GB-BASIC-06": GBBASIC06_SecurityHeaders,
    "GB-BASIC-07": GBBASIC07_CORS,
    "GB-BASIC-08": GBBASIC08_ClientSideSensitiveData,
    "GB-BASIC-09": GBBASIC09_JQuery,
    "GB-BASIC-10": GBBASIC10_JQueryXSS,
    "GB-BASIC-11": GBBASIC11_Bootstrap,
    "GB-BASIC-12": GBBASIC12_DirectoryListing,
    "GB-BASIC-13": GBBASIC13_DirectoryTraversal,
    "GB-BASIC-14": GBBASIC14_HostHeaderInjection,
    "GB-BASIC-15": GBBASIC15_OpenRedirection,
    "GB-BASIC-16": GBBASIC16_IPAddressDisclosure,
    "GB-BASIC-17": GBBASIC17_PrivateIPDisclosure,
    "GB-BASIC-18": GBBASIC18_ETag,
    "GB-BASIC-19": GBBASIC19_Clickjacking,
    "GB-BASIC-20": GBBASIC20_XXSSProtectionHeader,
    "GB-BASIC-21": GBBASIC21_HardcodedCredentials,
    # Encryption
    "GB-ENC-01": GBENC01_TLSVersions,
    "GB-ENC-02": GBENC02_CertificateValidation,
    "GB-ENC-03": GBENC03_CredentialsOverHTTPS,
    "GB-ENC-04": GBENC04_LoginFormOverHTTPS,
    "GB-ENC-05": GBENC05_SessionTokensOverHTTPS,
    "GB-ENC-06": GBENC06_HSTS,
    "GB-ENC-07": GBENC07_SensitiveInfoInURL,
    "GB-ENC-08": GBENC08_SSLStripping,
    # Form Field and Authentication
    "GB-FORM-01": GBFORM01_ShoulderSurfing,
    "GB-FORM-02": GBFORM02_SensitiveDataEncryption,
    "GB-FORM-03": GBFORM03_Autocomplete,
    "GB-FORM-04": GBFORM04_RememberMe,
    "GB-FORM-05": GBFORM05_CaptchaFunctionality,
    "GB-FORM-06": GBFORM06_BruteForceProtection,
    "GB-FORM-07": GBFORM07_StrongPasswordPolicy,
    "GB-FORM-08": GBFORM08_UserEnumeration,
    "GB-FORM-09": GBFORM09_MFA,
    "GB-FORM-10": GBFORM10_DefaultCredentials,
    "GB-FORM-11": GBFORM11_CacheControls,
    "GB-FORM-12": GBFORM12_DefaultOTP,
    "GB-FORM-13": GBFORM13_EmailFlooding,
    "GB-FORM-14": GBFORM14_OTPFlooding,
    "GB-FORM-15": GBFORM15_OTPBypass,
    "GB-FORM-16": GBFORM16_OTPInvalidation,
    # Session Management
    "GB-SESSION-01": GBSESSION01_CookieFlags,
    "GB-SESSION-02": GBSESSION02_CookieScope,
    "GB-SESSION-03": GBSESSION03_SessionDuration,
    "GB-SESSION-04": GBSESSION04_CookieRandomness,
    "GB-SESSION-05": GBSESSION05_HighPrivilegeSession,
    "GB-SESSION-06": GBSESSION06_SimultaneousSessions,
    "GB-SESSION-07": GBSESSION07_CookieRandomnessAndRotation,
    "GB-SESSION-08": GBSESSION08_CookiesBeforeAfterLogout,
    "GB-SESSION-09": GBSESSION09_SessionHijackingResistance,
    "GB-SESSION-10": GBSESSION10_SessionPuzzling,
    "GB-SESSION-11": GBSESSION11_BrowserClosure,
    "GB-SESSION-12": GBSESSION12_DeepURL,
    "GB-SESSION-13": GBSESSION13_BackRefreshAfterLogout,
    "GB-SESSION-14": GBSESSION14_LogoutAfterPasswordChange,
    "GB-SESSION-15": GBSESSION15_IDOR,
    "GB-SESSION-16": GBSESSION16_PrivilegeEscalation,
    "GB-SESSION-17": GBSESSION17_CSRF,
    "GB-SESSION-18": GBSESSION18_CRLF,
    "GB-SESSION-19": GBSESSION19_SessionReplay,
    # Injection
    "GB-INJ-01": GBINJ01_XSS,
    "GB-INJ-02": GBINJ02_HTMLInjection,
    "GB-INJ-03": GBINJ03_SQLInjection,
    "GB-INJ-04": GBINJ04_ExcelFormulaInjection,
    "GB-INJ-05": GBINJ05_InputValidation,
    "GB-INJ-06": GBINJ06_ClientSideValidationBypass,
    "GB-INJ-07": GBINJ07_ServerSideValidationBypass,
    "GB-INJ-08": GBINJ08_MandatoryFieldBypass,
    "GB-INJ-09": GBINJ09_ParameterManipulation,
    "GB-INJ-10": GBINJ10_ParameterPollution,
    "GB-INJ-11": GBINJ11_XMLInjection,
    "GB-INJ-12": GBINJ12_XXE,
    "GB-INJ-13": GBINJ13_XPathInjection,
    "GB-INJ-14": GBINJ14_CSTI,
    "GB-INJ-15": GBINJ15_SSTI,
    "GB-INJ-16": GBINJ16_SSIInjection,
    "GB-INJ-17": GBINJ17_CommandInjection,
    "GB-INJ-18": GBINJ18_CodeInjection,
    "GB-INJ-19": GBINJ19_LDAPInjection,
    "GB-INJ-20": GBINJ20_HTTPRequestSmuggling,
    # SSRF
    "GB-SSRF-01": GBSSRF01_SSRF,
}


def _make_definitions() -> list[GrayBoxTestcase]:
    defs = []

    # Helper function
    def add_tc(
        tc_id: str,
        name: str,
        category: TestCategory,
        objective: str,
        automation_level: AutomationLevel,
        payload_rel: str,
        cwe: str,
        wstg: str,
        roles: list[AccountRole] | None = None,
        artifacts: list[ArtifactType] | None = None,
    ):
        defs.append(
            GrayBoxTestcase(
                id=tc_id,
                name=name,
                category=category,
                objective=objective,
                description=f"Gray-box security verification for {name} ({tc_id}).",
                automation_level=automation_level,
                payload_file=payload_rel,
                required_roles=roles or [AccountRole.ANONYMOUS],
                required_artifacts=artifacts or [],
                preconditions=["Target reachable", "Authorization confirmed"],
                execution_procedure=[
                    "Load testcase payload library",
                    "Execute safe differential/inspection probes",
                    "Evaluate response headers, status codes, and body evidence",
                ],
                expected_secure_behavior="Application handles input safely without vulnerability.",
                failure_conditions="Insecure behavior or vulnerability confirmed.",
                evidence_requirements=["HTTP response status", "Relevant headers/body evidence"],
                remediation_guidance=f"Follow OWASP guidance for {wstg}.",
                security_references=[wstg, cwe],
                scanner_module=f"graybox.scanners.{category.value.lower().replace(' ', '_')}",
            )
        )

    # --- BASIC (21 items) ---
    b = TestCategory.BASIC
    add_tc("GB-BASIC-01", "Access through IP", b, "Verify direct IP access is redirected to canonical domain", AutomationLevel.AUTOMATED, "basic/access_through_ip.json", "CWE-359", "WSTG-CONF-01")
    add_tc("GB-BASIC-02", "Server banner grabbing", b, "Detect version disclosures in server headers", AutomationLevel.AUTOMATED, "basic/server_banner_grabbing.json", "CWE-200", "WSTG-INFO-02")
    add_tc("GB-BASIC-03", "Vulnerable components", b, "Check for outdated libraries and components", AutomationLevel.AUTOMATED, "basic/vulnerable_components.json", "CWE-1104", "WSTG-CONF-04", artifacts=[ArtifactType.SBOM])
    add_tc("GB-BASIC-04", "Arbitrary methods", b, "Verify unauthenticated dangerous HTTP methods are disabled", AutomationLevel.AUTOMATED, "basic/arbitrary_methods.json", "CWE-749", "WSTG-CONF-06")
    add_tc("GB-BASIC-05", "Cross-site tracing", b, "Verify HTTP TRACE/TRACK methods are disabled", AutomationLevel.AUTOMATED, "basic/cross_site_tracing.json", "CWE-693", "WSTG-INPVAL-14")
    add_tc("GB-BASIC-06", "Security headers", b, "Verify recommended defense-in-depth security headers", AutomationLevel.AUTOMATED, "basic/security_headers.json", "CWE-693", "WSTG-CONF-07")
    add_tc("GB-BASIC-07", "CORS", b, "Verify Cross-Origin Resource Sharing policy configuration", AutomationLevel.AUTOMATED, "basic/cors.json", "CWE-942", "WSTG-CONF-09")
    add_tc("GB-BASIC-08", "Sensitive data in client-side code", b, "Scan client scripts for exposed API keys and secrets", AutomationLevel.AUTOMATED, "basic/client_side_sensitive_data.json", "CWE-312", "WSTG-INFO-05", artifacts=[ArtifactType.SOURCE_CODE])
    add_tc("GB-BASIC-09", "jQuery", b, "Detect deprecated or vulnerable jQuery versions", AutomationLevel.AUTOMATED, "basic/jquery.json", "CWE-1104", "WSTG-CONF-04")
    add_tc("GB-BASIC-10", "jQuery XSS", b, "Inspect dynamic selector patterns in jQuery scripts", AutomationLevel.AUTOMATED, "basic/jquery_xss.json", "CWE-79", "WSTG-CLIENT-02")
    add_tc("GB-BASIC-11", "Bootstrap", b, "Audit client-side Bootstrap library version for known CVEs", AutomationLevel.AUTOMATED, "basic/bootstrap.json", "CWE-1104", "WSTG-CONF-04")
    add_tc("GB-BASIC-12", "Directory listing, including robots.txt, security.txt, and sitemap.xml", b, "Audit directory indexing and standard metadata endpoints", AutomationLevel.AUTOMATED, "basic/directory_listing.json", "CWE-548", "WSTG-INFO-03")
    add_tc("GB-BASIC-13", "Directory traversal", b, "Verify path traversal sequences are blocked", AutomationLevel.AUTOMATED, "basic/directory_traversal.json", "CWE-22", "WSTG-FILE-01")
    add_tc("GB-BASIC-14", "Host header injection", b, "Verify arbitrary Host headers are not trusted", AutomationLevel.AUTOMATED, "basic/host_header_injection.json", "CWE-644", "WSTG-INPVAL-17")
    add_tc("GB-BASIC-15", "Open redirection", b, "Verify URL redirection parameters validate untrusted destinations", AutomationLevel.AUTOMATED, "basic/open_redirect.json", "CWE-601", "WSTG-CLIENT-04")
    add_tc("GB-BASIC-16", "IP address disclosure", b, "Detect internal IP addresses disclosed in headers", AutomationLevel.AUTOMATED, "basic/ip_disclosure.json", "CWE-200", "WSTG-INFO-04")
    add_tc("GB-BASIC-17", "Private IP disclosure", b, "Scan responses for internal RFC1918 private network addresses", AutomationLevel.AUTOMATED, "basic/private_ip_disclosure.json", "CWE-200", "WSTG-INFO-04")
    add_tc("GB-BASIC-18", "ETag", b, "Inspect ETag header format for filesystem inode leaks", AutomationLevel.AUTOMATED, "basic/etag.json", "CWE-200", "WSTG-INFO-04")
    add_tc("GB-BASIC-19", "Clickjacking", b, "Verify anti-framing protections (X-Frame-Options/CSP)", AutomationLevel.AUTOMATED, "basic/clickjacking.json", "CWE-1021", "WSTG-CLIENT-09")
    add_tc("GB-BASIC-20", "X-XSS-Protection header", b, "Evaluate legacy X-XSS-Protection header setting", AutomationLevel.AUTOMATED, "basic/x_xss_protection.json", "CWE-693", "WSTG-CONF-07")
    add_tc("GB-BASIC-21", "Hardcoded credentials", b, "Audit client markup and source code for embedded credentials", AutomationLevel.AUTOMATED, "basic/hardcoded_credentials.json", "CWE-798", "WSTG-INFO-05", artifacts=[ArtifactType.SOURCE_CODE])

    # --- ENCRYPTION (8 items) ---
    e = TestCategory.ENCRYPTION
    add_tc("GB-ENC-01", "SSL/TLS versions, algorithms, and key length", e, "Verify modern TLS version and strong cipher suites", AutomationLevel.AUTOMATED, "encryption/tls_versions.json", "CWE-326", "WSTG-CRYP-01")
    add_tc("GB-ENC-02", "Digital certificate validity, duration, signature, and CN/SAN", e, "Validate certificate expiration, signature algorithm, and SAN", AutomationLevel.AUTOMATED, "encryption/certificate_validation.json", "CWE-295", "WSTG-CRYP-02")
    add_tc("GB-ENC-03", "Credentials delivered only over HTTPS", e, "Verify authentication form action submits over HTTPS", AutomationLevel.AUTOMATED, "encryption/credentials_https.json", "CWE-319", "WSTG-CRYP-03")
    add_tc("GB-ENC-04", "Login form delivered over HTTPS", e, "Verify login landing page is served over HTTPS", AutomationLevel.AUTOMATED, "encryption/login_https.json", "CWE-319", "WSTG-CRYP-03")
    add_tc("GB-ENC-05", "Session tokens delivered only over HTTPS", e, "Verify session cookies include Secure flag", AutomationLevel.AUTOMATED, "encryption/session_tokens_https.json", "CWE-614", "WSTG-SESS-02")
    add_tc("GB-ENC-06", "HSTS", e, "Verify Strict-Transport-Security header enforcement", AutomationLevel.AUTOMATED, "encryption/hsts.json", "CWE-523", "WSTG-CONF-07")
    add_tc("GB-ENC-07", "Sensitive information through URL", e, "Verify credentials and tokens are not passed in query string", AutomationLevel.AUTOMATED, "encryption/sensitive_information_in_url.json", "CWE-598", "WSTG-CRYP-04")
    add_tc("GB-ENC-08", "SSL stripping / HTTPS downgrade resistance", e, "Verify plain HTTP requests permanently redirect to HTTPS", AutomationLevel.AUTOMATED, "encryption/ssl_stripping.json", "CWE-319", "WSTG-CRYP-03")

    # --- FORM FIELD AND AUTHENTICATION (16 items) ---
    f = TestCategory.FORM_AUTHENTICATION
    add_tc("GB-FORM-01", "Shoulder surfing of sensitive data", f, "Verify password inputs mask characters by default", AutomationLevel.AUTOMATED, "form_authentication/shoulder_surfing.json", "CWE-522", "WSTG-ATHN-07")
    add_tc("GB-FORM-02", "PII and sensitive data in encrypted format", f, "Verify sensitive personal data is submitted encrypted", AutomationLevel.AUTOMATED, "form_authentication/sensitive_data_encryption.json", "CWE-319", "WSTG-CRYP-03")
    add_tc("GB-FORM-03", "Autocomplete disabled where required", f, "Verify semantic autocomplete configuration on credentials", AutomationLevel.AUTOMATED, "form_authentication/autocomplete.json", "CWE-522", "WSTG-ATHN-06")
    add_tc("GB-FORM-04", "Remember Me", f, "Audit persistent login tokens and revocation", AutomationLevel.AUTOMATED, "form_authentication/remember_me.json", "CWE-539", "WSTG-ATHN-05")
    add_tc("GB-FORM-05", "CAPTCHA functionality", f, "Verify automated abuse challenge on authentication endpoints", AutomationLevel.AUTOMATED, "form_authentication/captcha.json", "CWE-307", "WSTG-ATHN-04")
    add_tc("GB-FORM-06", "Brute-force protection for login and forgot-password fields", f, "Verify rate-limiting and account lockout protections", AutomationLevel.AUTOMATED, "form_authentication/rate_limiting.json", "CWE-307", "WSTG-ATHN-03")
    add_tc("GB-FORM-07", "Strong password policy", f, "Verify complexity requirements and weak password rejection", AutomationLevel.AUTOMATED, "form_authentication/password_policy.json", "CWE-521", "WSTG-ATHN-07")
    add_tc("GB-FORM-08", "User enumeration", f, "Verify authentication error messages do not disclose usernames", AutomationLevel.AUTOMATED, "form_authentication/user_enumeration.json", "CWE-204", "WSTG-IDNT-04")
    add_tc("GB-FORM-09", "Multi-factor authentication", f, "Verify step-up MFA challenge on sensitive operations", AutomationLevel.ASSISTED, "form_authentication/mfa.json", "CWE-308", "WSTG-ATHN-08")
    add_tc("GB-FORM-10", "Default login credentials", f, "Test standard default administrative credential pairs", AutomationLevel.AUTOMATED, "form_authentication/default_credentials.json", "CWE-1392", "WSTG-ATHN-02")
    add_tc("GB-FORM-11", "Cache controls: private or no-cache", f, "Verify sensitive authenticated responses forbid caching", AutomationLevel.AUTOMATED, "form_authentication/cache_controls.json", "CWE-525", "WSTG-ATHN-06")
    add_tc("GB-FORM-12", "Default OTP", f, "Verify static default OTP tokens are rejected", AutomationLevel.AUTOMATED, "form_authentication/default_otp.json", "CWE-340", "WSTG-ATHN-08")
    add_tc("GB-FORM-13", "Email flooding", f, "Verify rate-limiting on password reset email triggers", AutomationLevel.AUTOMATED, "form_authentication/email_flooding.json", "CWE-770", "WSTG-ATHN-04")
    add_tc("GB-FORM-14", "OTP flooding", f, "Verify cooldown intervals on OTP regeneration triggers", AutomationLevel.AUTOMATED, "form_authentication/otp_flooding.json", "CWE-770", "WSTG-ATHN-04")
    add_tc("GB-FORM-15", "OTP bypass through removing parameter or value change", f, "Verify parameter tampering cannot bypass OTP check", AutomationLevel.AUTOMATED, "form_authentication/otp_bypass.json", "CWE-287", "WSTG-ATHN-08")
    add_tc("GB-FORM-16", "Previous OTP invalidation after generating a new OTP", f, "Verify generating new OTP supersedes previous token", AutomationLevel.ASSISTED, "form_authentication/otp_invalidation.json", "CWE-613", "WSTG-ATHN-08")

    # --- SESSION MANAGEMENT (19 items) ---
    s = TestCategory.SESSION_MANAGEMENT
    add_tc("GB-SESSION-01", "Cookie flags: HttpOnly, Secure, SameSite, and relevant flags", s, "Verify session cookies enforce HttpOnly, Secure, SameSite", AutomationLevel.AUTOMATED, "session_management/cookie_flags.json", "CWE-614", "WSTG-SESS-02")
    add_tc("GB-SESSION-02", "Session cookie scope: Path and Domain", s, "Verify cookie domain and path scoping are restrictive", AutomationLevel.AUTOMATED, "session_management/cookie_scope.json", "CWE-614", "WSTG-SESS-02")
    add_tc("GB-SESSION-03", "Session cookie duration, expiry, and Max-Age", s, "Audit session lifetime and idle timeout configuration", AutomationLevel.AUTOMATED, "session_management/session_duration.json", "CWE-613", "WSTG-SESS-07")
    add_tc("GB-SESSION-04", "Cookie randomness", s, "Evaluate entropy and predictability of session identifiers", AutomationLevel.AUTOMATED, "session_management/cookie_randomness.json", "CWE-330", "WSTG-SESS-01")
    add_tc("GB-SESSION-05", "High-privilege session handling", s, "Verify separation of administrative sessions from standard roles", AutomationLevel.ASSISTED, "session_management/high_privilege_session.json", "CWE-250", "WSTG-SESS-08", roles=[AccountRole.ADMINISTRATOR, AccountRole.USER_A])
    add_tc("GB-SESSION-06", "Simultaneous sessions", s, "Audit concurrent login handling from multiple devices", AutomationLevel.ASSISTED, "session_management/simultaneous_sessions.json", "CWE-613", "WSTG-SESS-08")
    add_tc("GB-SESSION-07", "Cookie randomness and session rotation", s, "Verify session identifier rotates upon authentication", AutomationLevel.AUTOMATED, "session_management/session_rotation.json", "CWE-384", "WSTG-SESS-03")
    add_tc("GB-SESSION-08", "Different cookies before and after logout", s, "Verify session cookies are invalidated and expired on logout", AutomationLevel.AUTOMATED, "session_management/cookies_before_after_logout.json", "CWE-613", "WSTG-SESS-06")
    add_tc("GB-SESSION-09", "Session hijacking resistance", s, "Audit session token binding against client fingerprint changes", AutomationLevel.ASSISTED, "session_management/session_hijacking_resistance.json", "CWE-287", "WSTG-SESS-09")
    add_tc("GB-SESSION-10", "Session puzzling", s, "Verify session variable isolation across modules", AutomationLevel.ASSISTED, "session_management/session_puzzling.json", "CWE-840", "WSTG-SESS-08")
    add_tc("GB-SESSION-11", "Browser closure", s, "Verify transient session cookies terminate upon browser exit", AutomationLevel.AUTOMATED, "session_management/browser_closure.json", "CWE-613", "WSTG-SESS-07")
    add_tc("GB-SESSION-12", "Deep URL / direct access to protected resources", s, "Verify unauthenticated requests to internal deep URLs redirect", AutomationLevel.AUTOMATED, "session_management/deep_url.json", "CWE-306", "WSTG-AUTHZ-01")
    add_tc("GB-SESSION-13", "Back and Refresh after logout", s, "Verify back-button viewing after logout is prevented via no-store", AutomationLevel.AUTOMATED, "session_management/back_refresh.json", "CWE-525", "WSTG-ATHN-06")
    add_tc("GB-SESSION-14", "Logout of all applicable sessions after password change", s, "Verify password modification revokes active session tokens", AutomationLevel.ASSISTED, "session_management/logout_after_password_change.json", "CWE-613", "WSTG-SESS-06")
    add_tc("GB-SESSION-15", "IDOR", s, "Verify User B cannot access or modify User A's private resources", AutomationLevel.AUTOMATED, "session_management/idor.json", "CWE-639", "WSTG-AUTHZ-04", roles=[AccountRole.USER_A, AccountRole.USER_B])
    add_tc("GB-SESSION-16", "Privilege escalation", s, "Verify standard accounts cannot access administrative routes", AutomationLevel.AUTOMATED, "session_management/privilege_escalation.json", "CWE-269", "WSTG-AUTHZ-02", roles=[AccountRole.USER_A, AccountRole.ADMINISTRATOR])
    add_tc("GB-SESSION-17", "CSRF", s, "Verify state-changing requests require anti-CSRF token or SameSite", AutomationLevel.AUTOMATED, "session_management/csrf.json", "CWE-352", "WSTG-SESS-05")
    add_tc("GB-SESSION-18", "CRLF injection", s, "Verify carriage-return line-feed sequences are rejected in headers", AutomationLevel.AUTOMATED, "session_management/crlf.json", "CWE-113", "WSTG-INPVAL-15")
    add_tc("GB-SESSION-19", "Session replay", s, "Capture test session, execute logout, replay old token, verify rejection", AutomationLevel.AUTOMATED, "session_management/session_replay.json", "CWE-294", "WSTG-SESS-09", roles=[AccountRole.USER_A])

    # --- INJECTION (20 items) ---
    i = TestCategory.INJECTION
    add_tc("GB-INJ-01", "XSS", i, "Test reflected, stored, and DOM cross-site scripting vectors", AutomationLevel.AUTOMATED, "injection/xss.json", "CWE-79", "WSTG-INPVAL-01")
    add_tc("GB-INJ-02", "HTML injection", i, "Verify arbitrary HTML markup injection is prevented", AutomationLevel.AUTOMATED, "injection/html_injection.json", "CWE-79", "WSTG-INPVAL-03")
    add_tc("GB-INJ-03", "SQL injection", i, "Test SQL boolean and syntax differentials safely", AutomationLevel.AUTOMATED, "injection/sql_injection.json", "CWE-89", "WSTG-INPVAL-05")
    add_tc("GB-INJ-04", "Excel / CSV formula injection", i, "Verify CSV/Excel exports sanitize formula prefixes", AutomationLevel.AUTOMATED, "injection/excel_formula_injection.json", "CWE-1236", "WSTG-INPVAL-03")
    add_tc("GB-INJ-05", "Poor input validation", i, "Test boundary validation on null bytes and overlong strings", AutomationLevel.AUTOMATED, "injection/input_validation.json", "CWE-20", "WSTG-INPVAL-02")
    add_tc("GB-INJ-06", "Client-side validation bypass", i, "Verify server-side validation rejects malformed direct API submissions", AutomationLevel.AUTOMATED, "injection/client_side_validation_bypass.json", "CWE-602", "WSTG-INPVAL-02")
    add_tc("GB-INJ-07", "Server-side validation bypass", i, "Verify Content-Type negotiation and strict MIME parsing", AutomationLevel.AUTOMATED, "injection/server_side_validation_bypass.json", "CWE-20", "WSTG-INPVAL-02")
    add_tc("GB-INJ-08", "Mandatory field bypass", i, "Verify backend rejects requests with omitted required parameters", AutomationLevel.AUTOMATED, "injection/mandatory_field_bypass.json", "CWE-20", "WSTG-INPVAL-02")
    add_tc("GB-INJ-09", "Parameter manipulation", i, "Verify unauthorized privilege and business logic parameters are blocked", AutomationLevel.AUTOMATED, "injection/parameter_manipulation.json", "CWE-472", "WSTG-INPVAL-04")
    add_tc("GB-INJ-10", "Parameter pollution", i, "Verify handling of duplicate HTTP parameters (HPP)", AutomationLevel.AUTOMATED, "injection/parameter_pollution.json", "CWE-235", "WSTG-INPVAL-04")
    add_tc("GB-INJ-11", "XML injection", i, "Verify XML parsing validates document schema and boundaries", AutomationLevel.AUTOMATED, "injection/xml_injection.json", "CWE-91", "WSTG-INPVAL-07")
    add_tc("GB-INJ-12", "XXE", i, "Verify XML external entities (DTD / ENTITY) are disabled", AutomationLevel.AUTOMATED, "injection/xxe.json", "CWE-611", "WSTG-INPVAL-07")
    add_tc("GB-INJ-13", "XPath injection", i, "Test XPath query boundary injection in XML endpoints", AutomationLevel.AUTOMATED, "injection/xpath_injection.json", "CWE-643", "WSTG-INPVAL-09")
    add_tc("GB-INJ-14", "CSTI", i, "Test Client-Side Template Injection expression evaluation (e.g. {{7*7}})", AutomationLevel.AUTOMATED, "injection/csti.json", "CWE-79", "WSTG-CLIENT-02")
    add_tc("GB-INJ-15", "SSTI", i, "Test Server-Side Template Injection expression evaluation (e.g. ${7*7})", AutomationLevel.AUTOMATED, "injection/ssti.json", "CWE-1336", "WSTG-INPVAL-18")
    add_tc("GB-INJ-16", "SSI injection", i, "Test Server-Side Include directive execution in responses", AutomationLevel.AUTOMATED, "injection/ssi_injection.json", "CWE-97", "WSTG-INPVAL-08")
    add_tc("GB-INJ-17", "Command injection", i, "Verify shell command separators are parameterized safely", AutomationLevel.AUTOMATED, "injection/command_injection.json", "CWE-78", "WSTG-INPVAL-12")
    add_tc("GB-INJ-18", "Code injection", i, "Verify dynamic code evaluation constructs reject user input", AutomationLevel.AUTOMATED, "injection/code_injection.json", "CWE-94", "WSTG-INPVAL-11")
    add_tc("GB-INJ-19", "LDAP injection", i, "Verify LDAP filter special characters are escaped safely", AutomationLevel.AUTOMATED, "injection/ldap_injection.json", "CWE-90", "WSTG-INPVAL-06")
    add_tc("GB-INJ-20", "HTTP request smuggling", i, "Verify front-end and back-end reject ambiguous TE/CL headers", AutomationLevel.AUTOMATED, "injection/http_request_smuggling.json", "CWE-444", "WSTG-INPVAL-16")

    # --- SSRF (1 item) ---
    srf = TestCategory.SSRF
    add_tc("GB-SSRF-01", "Server-Side Request Forgery", srf, "Verify URL parameters reject loopback and internal private IPs", AutomationLevel.AUTOMATED, "ssrf/ssrf.json", "CWE-918", "WSTG-INPVAL-19")

    return defs


_DEFINITIONS = _make_definitions()
GRAYBOX_REGISTRY: dict[str, GrayBoxTestcase] = {t.id: t for t in _DEFINITIONS}


def get_graybox_registry() -> dict[str, GrayBoxTestcase]:
    """Return dictionary of all 85 registered Gray-Box testcases."""
    return dict(GRAYBOX_REGISTRY)


def get_testcase(testcase_id: str) -> GrayBoxTestcase | None:
    return GRAYBOX_REGISTRY.get(testcase_id)


def get_testcases_by_category(category: TestCategory | str) -> list[GrayBoxTestcase]:
    cat_val = category.value if isinstance(category, TestCategory) else category
    return [t for t in _DEFINITIONS if t.category.value == cat_val or t.category == cat_val]


def get_scanner_class(testcase_id: str) -> Type[BaseGrayBoxScanner] | None:
    return SCANNER_MAP.get(testcase_id)
