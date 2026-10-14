"""Generator for all 85 Gray-Box payload libraries and manifest.json."""
from __future__ import annotations

import json
from pathlib import Path

PAYLOAD_DIR = Path(__file__).resolve().parents[1] / "payloads" / "graybox"


def build_payload(
    p_id: str,
    testcase_id: str,
    name: str,
    category: str,
    value: any,
    purpose: str,
    expected: str,
    required: bool = True,
    risk: str = "low",
    evidence_type: str = "response_inspection",
    tags: list[str] | None = None,
) -> dict:
    return {
        "id": p_id,
        "testcase_id": testcase_id,
        "name": name,
        "category": category,
        "value": value,
        "encoding": "plain",
        "purpose": purpose,
        "expected_secure_behavior": expected,
        "required": required,
        "risk_level": risk,
        "destructive": False,
        "requires_authorization": True,
        "requires_test_environment": False,
        "requires_account_role": [],
        "evidence_type": evidence_type,
        "source": {
            "repository": "Project-Curated OWASP WSTG v4.2 / ASVS v4.0",
            "file": f"payloads/graybox/{testcase_id.lower()}.json",
            "version": "1.0.0",
        },
        "tags": tags or [category, testcase_id.split("-")[1].lower()],
    }


def main():
    PAYLOAD_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "description": "Comprehensive Gray-Box Testing Payload and Scenario Manifest",
        "testcases": {},
    }

    # -------------------------------------------------------------
    # 1. BASIC (21 items)
    # -------------------------------------------------------------
    basic_dir = PAYLOAD_DIR / "basic"
    basic_dir.mkdir(parents=True, exist_ok=True)

    basic_specs = {
        "GB-BASIC-01": ("access_through_ip.json", "Access through IP", [
            build_payload("GB-BASIC-01-P01", "GB-BASIC-01", "ip_in_host_header", "host_header", {"header": "Host", "mode": "ip_address"}, "Verify application does not accept direct IP Host header without canonical domain redirect", "Redirects to canonical domain or rejects IP Host", True),
            build_payload("GB-BASIC-01-P02", "GB-BASIC-01", "direct_ip_url", "url_probe", {"mode": "direct_ip_target"}, "Verify virtual host isolation when accessed via raw IP address", "Rejection or default safe page", True),
        ]),
        "GB-BASIC-02": ("server_banner_grabbing.json", "Server banner grabbing", [
            build_payload("GB-BASIC-02-P01", "GB-BASIC-02", "head_banner_probe", "headers", {"method": "HEAD"}, "Inspect response headers for detailed server version information", "Server header stripped or generic", True),
            build_payload("GB-BASIC-02-P02", "GB-BASIC-02", "get_banner_probe", "headers", {"method": "GET"}, "Inspect Server and X-Powered-By response headers", "No version numbers disclosed", True),
        ]),
        "GB-BASIC-03": ("vulnerable_components.json", "Vulnerable components", [
            build_payload("GB-BASIC-03-P01", "GB-BASIC-03", "known_library_headers", "signatures", {"libraries": ["jquery", "bootstrap", "angular", "react", "express", "spring"]}, "Detect outdated client/server framework versions in headers/scripts", "Up to date third-party libraries", True),
            build_payload("GB-BASIC-03-P02", "GB-BASIC-03", "sbom_component_scan", "sbom", {"audit_cve": True}, "Cross-reference disclosed components against CVE database", "No high/critical known CVEs in active components", True),
        ]),
        "GB-BASIC-04": ("arbitrary_methods.json", "Arbitrary methods", [
            build_payload("GB-BASIC-04-P01", "GB-BASIC-04", "put_method", "http_method", {"method": "PUT"}, "Verify unauthenticated PUT method is not permitted", "HTTP 405 Method Not Allowed or 403 Forbidden", True),
            build_payload("GB-BASIC-04-P02", "GB-BASIC-04", "delete_method", "http_method", {"method": "DELETE"}, "Verify unauthenticated DELETE method is not permitted", "HTTP 405 Method Not Allowed or 403 Forbidden", True),
            build_payload("GB-BASIC-04-P03", "GB-BASIC-04", "options_method", "http_method", {"method": "OPTIONS"}, "Check allowed methods via OPTIONS probe", "Only safe public methods enabled (GET, POST, HEAD)", True),
        ]),
        "GB-BASIC-05": ("cross_site_tracing.json", "Cross-site tracing", [
            build_payload("GB-BASIC-05-P01", "GB-BASIC-05", "trace_method", "http_method", {"method": "TRACE", "headers": {"X-Custom-Echo": "AuditTraceValue"}}, "Check if TRACE reflects sensitive headers or cookies", "TRACE is disabled (HTTP 405 or 501)", True),
            build_payload("GB-BASIC-05-P02", "GB-BASIC-05", "track_method", "http_method", {"method": "TRACK", "headers": {"X-Custom-Echo": "AuditTrackValue"}}, "Check if proprietary TRACK method is enabled", "TRACK is disabled (HTTP 405 or 501)", True),
        ]),
        "GB-BASIC-06": ("security_headers.json", "Security headers", [
            build_payload("GB-BASIC-06-P01", "GB-BASIC-06", "core_security_headers", "header_presence", {"required_headers": ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy"]}, "Verify presence of essential defense-in-depth security headers", "All recommended security headers configured", True),
        ]),
        "GB-BASIC-07": ("cors.json", "CORS", [
            build_payload("GB-BASIC-07-P01", "GB-BASIC-07", "null_origin", "cors_header", {"origin": "null"}, "Verify application rejects null Origin reflection with credentials", "Origin not reflected or credentials disabled", True),
            build_payload("GB-BASIC-07-P02", "GB-BASIC-07", "arbitrary_origin", "cors_header", {"origin": "https://attacker.example.com"}, "Verify application rejects untrusted Origin reflection with credentials", "Origin not reflected or credentials disabled", True),
        ]),
        "GB-BASIC-08": ("client_side_sensitive_data.json", "Sensitive data in client-side code", [
            build_payload("GB-BASIC-08-P01", "GB-BASIC-08", "sensitive_regex_patterns", "regex_scan", {"patterns": ["api[_-]?key", "bearer\\s+[A-Za-z0-9_-]+", "aws_access_key_id", "secret_key", "password\\s*="]}, "Search client-side HTML and scripts for hardcoded secrets/tokens", "No secret keys or passwords exposed in frontend", True),
        ]),
        "GB-BASIC-09": ("jquery.json", "jQuery", [
            build_payload("GB-BASIC-09-P01", "GB-BASIC-09", "jquery_version_detection", "version_audit", {"min_secure_version": "3.5.0"}, "Detect deployed jQuery version and flag deprecated or end-of-life releases", "jQuery >= 3.5.0 or modern framework without jQuery", True),
        ]),
        "GB-BASIC-10": ("jquery_xss.json", "jQuery XSS", [
            build_payload("GB-BASIC-10-P01", "GB-BASIC-10", "jquery_html_xss_cve", "cve_probe", {"cves": ["CVE-2015-9251", "CVE-2020-11022", "CVE-2020-11023"]}, "Inspect jQuery selectors for known XSS vulnerabilities in $(location.hash)", "Patched against jQuery DOM XSS CVEs", True),
        ]),
        "GB-BASIC-11": ("bootstrap.json", "Bootstrap", [
            build_payload("GB-BASIC-11-P01", "GB-BASIC-11", "bootstrap_version_detection", "version_audit", {"min_secure_version": "4.3.1"}, "Inspect client-side Bootstrap bundle for vulnerable tooltip/popover components", "Bootstrap >= 4.3.1 or 5.x", True),
        ]),
        "GB-BASIC-12": ("directory_listing.json", "Directory listing", [
            build_payload("GB-BASIC-12-P01", "GB-BASIC-12", "robots_txt", "metadata_file", {"path": "/robots.txt"}, "Inspect robots.txt for sensitive administrative paths", "robots.txt does not leak secret administrative portals", True),
            build_payload("GB-BASIC-12-P02", "GB-BASIC-12", "security_txt", "metadata_file", {"path": "/.well-known/security.txt"}, "Check security contact file availability", "Standard security disclosure contact published", True),
            build_payload("GB-BASIC-12-P03", "GB-BASIC-12", "sitemap_xml", "metadata_file", {"path": "/sitemap.xml"}, "Inspect sitemap for unauthenticated internal endpoints", "No restricted portals exposed in public sitemap", True),
            build_payload("GB-BASIC-12-P04", "GB-BASIC-12", "directory_index", "indexing_probe", {"paths": ["/static/", "/images/", "/uploads/", "/assets/"]}, "Verify web server directory index listing is disabled", "HTTP 403 or 404, directory listing disabled", True),
        ]),
        "GB-BASIC-13": ("directory_traversal.json", "Directory traversal", [
            build_payload("GB-BASIC-13-P01", "GB-BASIC-13", "dot_dot_slash", "traversal_string", "../../../../etc/passwd", "Verify path traversal sequences are blocked", "HTTP 400/404 or path normalized safely", True),
            build_payload("GB-BASIC-13-P02", "GB-BASIC-13", "encoded_dot_dot_slash", "traversal_string", "..%2f..%2f..%2fetc%2fpasswd", "Verify URL-encoded path traversal sequences are blocked", "HTTP 400/404 or safe rejection", True),
            build_payload("GB-BASIC-13-P03", "GB-BASIC-13", "windows_traversal", "traversal_string", "..\\..\\..\\windows\\win.ini", "Verify Windows-style backslash traversal is blocked", "HTTP 400/404 or safe rejection", True),
        ]),
        "GB-BASIC-14": ("host_header_injection.json", "Host header injection", [
            build_payload("GB-BASIC-14-P01", "GB-BASIC-14", "untrusted_host_header", "header_tamper", {"Host": "evil-audit-target.com"}, "Verify application does not reflect arbitrary Host header in password reset or link generation", "Host header validated against server allowlist", True),
            build_payload("GB-BASIC-14-P02", "GB-BASIC-14", "forwarded_host_header", "header_tamper", {"X-Forwarded-Host": "evil-audit-target.com"}, "Verify reverse proxy headers are not blindly trusted for canonical URLs", "X-Forwarded-Host ignored or validated", True),
        ]),
        "GB-BASIC-15": ("open_redirect.json", "Open redirection", [
            build_payload("GB-BASIC-15-P01", "GB-BASIC-15", "absolute_url_redirect", "redirect_url", "https://example.org", "Verify redirect parameters reject absolute external URLs", "Redirect rejected or restricted to relative path", True),
            build_payload("GB-BASIC-15-P02", "GB-BASIC-15", "protocol_relative_redirect", "redirect_url", "//example.org", "Verify redirect parameters reject protocol-relative URLs", "Redirect rejected or restricted to relative path", True),
            build_payload("GB-BASIC-15-P03", "GB-BASIC-15", "backslash_redirect", "redirect_url", "/\\example.org", "Verify bypasses using backslashes are rejected", "Redirect rejected or restricted to relative path", True),
        ]),
        "GB-BASIC-16": ("ip_disclosure.json", "IP address disclosure", [
            build_payload("GB-BASIC-16-P01", "GB-BASIC-16", "public_ip_in_headers", "header_inspection", {"headers": ["X-Forwarded-For", "X-Client-IP", "X-Real-IP", "Via"]}, "Inspect response headers for internal routing infrastructure IP disclosure", "Headers stripped or sanitized", True),
        ]),
        "GB-BASIC-17": ("private_ip_disclosure.json", "Private IP disclosure", [
            build_payload("GB-BASIC-17-P01", "GB-BASIC-17", "rfc1918_scan", "body_and_headers", {"patterns": [r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", r"\b172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", r"\b192\.168\.\d{1,3}\.\d{1,3}\b"]}, "Verify private internal RFC1918 IP addresses are not leaked in error traces or headers", "No internal private IP addresses disclosed", True),
        ]),
        "GB-BASIC-18": ("etag.json", "ETag", [
            build_payload("GB-BASIC-18-P01", "GB-BASIC-18", "etag_inode_check", "header_inspection", {"header": "ETag"}, "Verify ETag format does not disclose underlying server filesystem inode information", "ETag is cryptographic hash or inode stripped", True),
        ]),
        "GB-BASIC-19": ("clickjacking.json", "Clickjacking", [
            build_payload("GB-BASIC-19-P01", "GB-BASIC-19", "x_frame_options_check", "header_presence", {"header": "X-Frame-Options", "valid_values": ["DENY", "SAMEORIGIN"]}, "Verify application enforces framing restrictions via X-Frame-Options", "X-Frame-Options set to DENY or SAMEORIGIN", True),
            build_payload("GB-BASIC-19-P02", "GB-BASIC-19", "csp_frame_ancestors", "header_directive", {"header": "Content-Security-Policy", "directive": "frame-ancestors"}, "Verify Content-Security-Policy enforces frame-ancestors directive", "frame-ancestors 'self' or 'none'", True),
        ]),
        "GB-BASIC-20": ("x_xss_protection.json", "X-XSS-Protection header", [
            build_payload("GB-BASIC-20-P01", "GB-BASIC-20", "xss_protection_header", "header_evaluation", {"header": "X-XSS-Protection"}, "Evaluate X-XSS-Protection setting (0 recommended in modern browsers to prevent side-channel leaks)", "Header is 0 or modern CSP enforced instead", True),
        ]),
        "GB-BASIC-21": ("hardcoded_credentials.json", "Hardcoded credentials", [
            build_payload("GB-BASIC-21-P01", "GB-BASIC-21", "client_script_credential_patterns", "regex_scan", {"patterns": [r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]", r"(?i)mongodb(\+srv)?://[^\s'\"]+", r"(?i)postgres(ql)?://[^\s'\"]+"]}, "Scan client JavaScript bundles for leaked hardcoded database credentials or test passwords", "No credentials or database URLs in client scripts", True),
        ]),
    }

    for t_id, (fname, label, payloads) in basic_specs.items():
        rel_path = f"basic/{fname}"
        (basic_dir / fname).write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        manifest["testcases"][t_id] = {
            "label": label,
            "category": "Basic",
            "file": rel_path,
            "count": len(payloads),
        }

    # -------------------------------------------------------------
    # 2. ENCRYPTION (8 items)
    # -------------------------------------------------------------
    enc_dir = PAYLOAD_DIR / "encryption"
    enc_dir.mkdir(parents=True, exist_ok=True)

    enc_specs = {
        "GB-ENC-01": ("tls_versions.json", "SSL/TLS versions, algorithms, and key length", [
            build_payload("GB-ENC-01-P01", "GB-ENC-01", "deprecated_ssl_tls", "protocol_version", {"disallowed": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"]}, "Verify legacy insecure SSL/TLS protocols are rejected", "Only TLS 1.2 and TLS 1.3 negotiated", True),
            build_payload("GB-ENC-01-P02", "GB-ENC-01", "cipher_key_length", "cipher_audit", {"min_key_length": 128}, "Verify cipher suite key length meets modern cryptographic standards", "Key length >= 128 bits, strong ciphers only", True),
        ]),
        "GB-ENC-02": ("certificate_validation.json", "Digital certificate validity, duration, signature, and CN/SAN", [
            build_payload("GB-ENC-02-P01", "GB-ENC-02", "cert_validity_window", "certificate_audit", {"check_expiry": True, "check_not_before": True}, "Verify certificate is within valid time window", "Certificate is active and not expired", True),
            build_payload("GB-ENC-02-P02", "GB-ENC-02", "cert_san_hostname", "certificate_audit", {"check_hostname": True}, "Verify Certificate Subject Alternative Name matches target hostname", "Hostname matches SAN/CN", True),
            build_payload("GB-ENC-02-P03", "GB-ENC-02", "cert_signature_algorithm", "certificate_audit", {"disallowed_hash": ["md5", "sha1"]}, "Verify certificate signature does not use weak digest algorithms", "Signed with SHA-256 or better", True),
        ]),
        "GB-ENC-03": ("credentials_https.json", "Credentials delivered only over HTTPS", [
            build_payload("GB-ENC-03-P01", "GB-ENC-03", "login_form_action_https", "dom_inspection", {"selector": "form", "action_scheme": "https"}, "Verify login form action URL explicitly uses https:// scheme", "Form action uses HTTPS exclusively", True),
        ]),
        "GB-ENC-04": ("login_https.json", "Login form delivered over HTTPS", [
            build_payload("GB-ENC-04-P01", "GB-ENC-04", "login_page_transport", "transport_scheme", {"required_scheme": "https"}, "Verify the login landing page itself is loaded over HTTPS", "HTTPS transport required for login page", True),
        ]),
        "GB-ENC-05": ("session_tokens_https.json", "Session tokens delivered only over HTTPS", [
            build_payload("GB-ENC-05-P01", "GB-ENC-05", "cookie_secure_flag", "cookie_inspection", {"required_flag": "Secure"}, "Verify all session and authentication cookies include Secure flag", "Secure flag present on every auth cookie", True),
        ]),
        "GB-ENC-06": ("hsts.json", "HSTS", [
            build_payload("GB-ENC-06-P01", "GB-ENC-06", "hsts_header_presence", "header_inspection", {"header": "Strict-Transport-Security", "min_max_age": 31536000}, "Verify HTTP Strict Transport Security header with max-age >= 1 year", "Strict-Transport-Security present with max-age >= 31536000", True),
        ]),
        "GB-ENC-07": ("sensitive_information_in_url.json", "Sensitive information through URL", [
            build_payload("GB-ENC-07-P01", "GB-ENC-07", "query_param_credentials", "url_inspection", {"sensitive_keys": ["password", "token", "secret", "auth", "sessionid", "api_key", "ssn"]}, "Verify query string parameters do not expose sensitive credentials in URLs", "Sensitive data passed in request body, not URL parameters", True),
        ]),
        "GB-ENC-08": ("ssl_stripping.json", "SSL stripping / HTTPS downgrade resistance", [
            build_payload("GB-ENC-08-P01", "GB-ENC-08", "http_to_https_redirect", "redirect_check", {"probe_scheme": "http", "expected_redirect": "https"}, "Verify plain HTTP requests are immediately redirected to HTTPS", "HTTP 301/308 redirect to HTTPS target", True),
        ]),
    }

    for t_id, (fname, label, payloads) in enc_specs.items():
        rel_path = f"encryption/{fname}"
        (enc_dir / fname).write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        manifest["testcases"][t_id] = {
            "label": label,
            "category": "Encryption",
            "file": rel_path,
            "count": len(payloads),
        }

    # -------------------------------------------------------------
    # 3. FORM FIELD AND AUTHENTICATION (16 items)
    # -------------------------------------------------------------
    form_dir = PAYLOAD_DIR / "form_authentication"
    form_dir.mkdir(parents=True, exist_ok=True)

    form_specs = {
        "GB-FORM-01": ("shoulder_surfing.json", "Shoulder surfing of sensitive data", [
            build_payload("GB-FORM-01-P01", "GB-FORM-01", "password_input_type", "input_inspection", {"type": "password"}, "Verify password fields mask character input by default", "Input type='password'", True),
        ]),
        "GB-FORM-02": ("sensitive_data_encryption.json", "PII and sensitive data in encrypted format", [
            build_payload("GB-FORM-02-P01", "GB-FORM-02", "pii_storage_in_transit", "transit_encryption", {"fields": ["ssn", "credit_card", "pan", "dob"]}, "Verify PII is submitted only via encrypted POST endpoints", "Sensitive fields encrypted and submitted via HTTPS", True),
        ]),
        "GB-FORM-03": ("autocomplete.json", "Autocomplete disabled where required", [
            build_payload("GB-FORM-03-P01", "GB-FORM-03", "autocomplete_semantic_tokens", "dom_attribute", {"allowed_tokens": ["off", "new-password", "current-password", "username"]}, "Verify autocomplete semantics on sensitive inputs prevent inappropriate caching", "Semantic autocomplete tokens configured", True),
        ]),
        "GB-FORM-04": ("remember_me.json", "Remember Me", [
            build_payload("GB-FORM-04-P01", "GB-FORM-04", "remember_me_cookie_token", "cookie_entropy", {"cookie_names": ["remember_me", "remember", "rm_token", "persist"]}, "Evaluate entropy and secure flags of persistent remember-me tokens", "High-entropy, HttpOnly, Secure remember-me cookie", True),
        ]),
        "GB-FORM-05": ("captcha.json", "CAPTCHA functionality", [
            build_payload("GB-FORM-05-P01", "GB-FORM-05", "captcha_presence_and_token", "form_inspection", {"captcha_signatures": ["g-recaptcha", "h-captcha", "cf-turnstile", "captcha"]}, "Verify CAPTCHA challenge is enforced on public authentication endpoints", "CAPTCHA challenge present or rate-limiting enforced", True),
        ]),
        "GB-FORM-06": ("rate_limiting.json", "Brute-force protection for login and forgot-password fields", [
            build_payload("GB-FORM-06-P01", "GB-FORM-06", "auth_rate_limiting_burst", "throttling_probe", {"burst_count": 8, "endpoint": "login"}, "Submit multiple incorrect authentication requests to verify rate-limiting or lockout", "HTTP 429 Too Many Requests or account lockout triggered", True),
        ]),
        "GB-FORM-07": ("password_policy.json", "Strong password policy", [
            build_payload("GB-FORM-07-P01", "GB-FORM-07", "weak_short_password", "credential_test", "123", "Verify application rejects short trivial passwords", "Password rejected with policy error", True),
            build_payload("GB-FORM-07-P02", "GB-FORM-07", "common_password_blacklist", "credential_test", "password", "Verify application rejects common dictionary passwords", "Password rejected with policy error", True),
        ]),
        "GB-FORM-08": ("user_enumeration.json", "User enumeration", [
            build_payload("GB-FORM-08-P01", "GB-FORM-08", "username_differential_error", "response_comparison", {"valid_user_hint": "admin", "invalid_user_hint": "nonexistent_user_99212"}, "Compare error responses for valid vs invalid usernames", "Generic error message returned ('Invalid username or password')", True),
            build_payload("GB-FORM-08-P02", "GB-FORM-08", "forgot_password_differential", "response_comparison", {"endpoint": "forgot_password"}, "Compare forgot-password response for registered vs unregistered email", "Identical confirmation message returned", True),
        ]),
        "GB-FORM-09": ("mfa.json", "Multi-factor authentication", [
            build_payload("GB-FORM-09-P01", "GB-FORM-09", "mfa_challenge_enforcement", "step_up_check", {"check_step_up": True}, "Verify access to sensitive functionality requires valid secondary authentication factor", "MFA step enforced before session elevation", True),
        ]),
        "GB-FORM-10": ("default_credentials.json", "Default login credentials", [
            build_payload("GB-FORM-10-P01", "GB-FORM-10", "admin_admin", "credential_pair", {"user": "admin", "pass": "admin"}, "Test standard default administrative credentials", "Authentication fails", True),
            build_payload("GB-FORM-10-P02", "GB-FORM-10", "root_root", "credential_pair", {"user": "root", "pass": "root"}, "Test default root credentials", "Authentication fails", True),
            build_payload("GB-FORM-10-P03", "GB-FORM-10", "test_test", "credential_pair", {"user": "test", "pass": "test"}, "Test default test account credentials", "Authentication fails", True),
            build_payload("GB-FORM-10-P04", "GB-FORM-10", "guest_guest", "credential_pair", {"user": "guest", "pass": "guest"}, "Test default guest account credentials", "Authentication fails", True),
        ]),
        "GB-FORM-11": ("cache_controls.json", "Cache controls: private or no-cache", [
            build_payload("GB-FORM-11-P01", "GB-FORM-11", "authenticated_cache_headers", "header_inspection", {"header": "Cache-Control", "disallowed": ["public"]}, "Verify sensitive authenticated responses prohibit caching", "Cache-Control contains no-store or no-cache, private", True),
        ]),
        "GB-FORM-12": ("default_otp.json", "Default OTP", [
            build_payload("GB-FORM-12-P01", "GB-FORM-12", "static_zeroes_otp", "otp_probe", "000000", "Verify application does not accept static default zeroes OTP", "OTP rejected", True),
            build_payload("GB-FORM-12-P02", "GB-FORM-12", "static_sequential_otp", "otp_probe", "123456", "Verify application does not accept default sequential test OTP", "OTP rejected", True),
            build_payload("GB-FORM-12-P03", "GB-FORM-12", "static_ones_otp", "otp_probe", "111111", "Verify application does not accept default repeated digit OTP", "OTP rejected", True),
        ]),
        "GB-FORM-13": ("email_flooding.json", "Email flooding", [
            build_payload("GB-FORM-13-P01", "GB-FORM-13", "reset_email_rate_limit", "rate_limit_probe", {"requests": 6, "interval": 1.0}, "Verify repeated email trigger requests enforce cooldowns", "Rate-limiting applied, cooldown message returned", True),
        ]),
        "GB-FORM-14": ("otp_flooding.json", "OTP flooding", [
            build_payload("GB-FORM-14-P01", "GB-FORM-14", "otp_request_burst", "rate_limit_probe", {"burst": 5, "interval": 0.5}, "Verify rapid repeated requests for new OTP tokens are throttled", "Cooldown enforced on new OTP generation", True),
        ]),
        "GB-FORM-15": ("otp_bypass.json", "OTP bypass through removing a parameter or changing its value", [
            build_payload("GB-FORM-15-P01", "GB-FORM-15", "omit_otp_param", "tamper_scenario", {"action": "delete_parameter", "param": "otp"}, "Verify removing the OTP parameter completely fails validation", "HTTP 400 or validation rejection", True),
            build_payload("GB-FORM-15-P02", "GB-FORM-15", "empty_otp_param", "tamper_scenario", {"action": "set_value", "param": "otp", "value": ""}, "Verify empty string OTP parameter fails validation", "Validation error returned", True),
            build_payload("GB-FORM-15-P03", "GB-FORM-15", "boolean_otp_param", "tamper_scenario", {"action": "set_value", "param": "otp", "value": "true"}, "Verify type-juggling boolean OTP does not bypass check", "Validation error returned", True),
        ]),
        "GB-FORM-16": ("otp_invalidation.json", "Previous OTP invalidation after generating a new OTP", [
            build_payload("GB-FORM-16-P01", "GB-FORM-16", "superseded_otp_invalidation", "transition_scenario", {"steps": ["generate_otp_1", "generate_otp_2", "submit_otp_1"]}, "Verify requesting a new OTP immediately invalidates previously issued OTP token", "Previous OTP is rejected as invalid/expired", True),
        ]),
    }

    for t_id, (fname, label, payloads) in form_specs.items():
        rel_path = f"form_authentication/{fname}"
        (form_dir / fname).write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        manifest["testcases"][t_id] = {
            "label": label,
            "category": "Form Field and Authentication",
            "file": rel_path,
            "count": len(payloads),
        }

    # -------------------------------------------------------------
    # 4. SESSION MANAGEMENT (19 items)
    # -------------------------------------------------------------
    sess_dir = PAYLOAD_DIR / "session_management"
    sess_dir.mkdir(parents=True, exist_ok=True)

    sess_specs = {
        "GB-SESSION-01": ("cookie_flags.json", "Cookie flags: HttpOnly, Secure, SameSite, and relevant flags", [
            build_payload("GB-SESSION-01-P01", "GB-SESSION-01", "httponly_flag_check", "cookie_attribute", {"attribute": "HttpOnly"}, "Verify session cookies have HttpOnly flag set", "HttpOnly flag present", True),
            build_payload("GB-SESSION-01-P02", "GB-SESSION-01", "secure_flag_check", "cookie_attribute", {"attribute": "Secure"}, "Verify session cookies have Secure flag set", "Secure flag present", True),
            build_payload("GB-SESSION-01-P03", "GB-SESSION-01", "samesite_flag_check", "cookie_attribute", {"attribute": "SameSite", "allowed": ["Lax", "Strict"]}, "Verify SameSite attribute is configured", "SameSite set to Lax or Strict", True),
        ]),
        "GB-SESSION-02": ("cookie_scope.json", "Session cookie scope: Path and Domain", [
            build_payload("GB-SESSION-02-P01", "GB-SESSION-02", "cookie_domain_scope", "cookie_attribute", {"attribute": "Domain"}, "Verify session cookie domain is not over-scoped to public super-domains", "Exact domain or restrictive sub-domain scope", True),
            build_payload("GB-SESSION-02-P02", "GB-SESSION-02", "cookie_path_scope", "cookie_attribute", {"attribute": "Path"}, "Verify session cookie path scope is appropriate", "Restricted path or standard root path", True),
        ]),
        "GB-SESSION-03": ("session_duration.json", "Session cookie duration, expiry, and Max-Age", [
            build_payload("GB-SESSION-03-P01", "GB-SESSION-03", "session_idle_timeout", "timeout_audit", {"max_recommended_idle_seconds": 1800}, "Verify session cookies do not remain valid indefinitely without timeout", "Reasonable session lifespan and idle timeout", True),
        ]),
        "GB-SESSION-04": ("cookie_randomness.json", "Cookie randomness", [
            build_payload("GB-SESSION-04-P01", "GB-SESSION-04", "session_token_entropy", "entropy_analysis", {"min_shannon_entropy": 3.5}, "Evaluate randomness and entropy of generated session identifiers", "High entropy, cryptographically random tokens", True),
        ]),
        "GB-SESSION-05": ("high_privilege_session.json", "High-privilege session handling", [
            build_payload("GB-SESSION-05-P01", "GB-SESSION-05", "admin_session_isolation", "privilege_audit", {"roles": ["admin", "user"]}, "Verify administrative sessions use distinct, segregated session tokens", "Isolated token namespaces and strict re-auth on sensitive actions", True),
        ]),
        "GB-SESSION-06": ("simultaneous_sessions.json", "Simultaneous sessions", [
            build_payload("GB-SESSION-06-P01", "GB-SESSION-06", "concurrent_login_handling", "session_concurrency", {"simultaneous_logins": 2}, "Verify application session management policy for concurrent logins from different locations", "Monitored or terminated older sessions", True),
        ]),
        "GB-SESSION-07": ("session_rotation.json", "Cookie randomness and session rotation", [
            build_payload("GB-SESSION-07-P01", "GB-SESSION-07", "pre_post_auth_rotation", "transition_scenario", {"action": "login"}, "Verify pre-authentication session identifier is regenerated upon successful login", "New session token assigned after authentication", True),
        ]),
        "GB-SESSION-08": ("cookies_before_after_logout.json", "Different cookies before and after logout", [
            build_payload("GB-SESSION-08-P01", "GB-SESSION-08", "post_logout_cookie_invalidation", "transition_scenario", {"action": "logout"}, "Verify session cookies are cleared and invalidated upon logout", "Set-Cookie expires token or sets empty value", True),
        ]),
        "GB-SESSION-09": ("session_hijacking_resistance.json", "Session hijacking resistance", [
            build_payload("GB-SESSION-09-P01", "GB-SESSION-09", "user_agent_binding", "security_control", {"tamper_header": "User-Agent"}, "Verify session token cannot be reused from mismatched client fingerprint without validation", "Anomalous client characteristics flagged", True),
        ]),
        "GB-SESSION-10": ("session_puzzling.json", "Session puzzling", [
            build_payload("GB-SESSION-10-P01", "GB-SESSION-10", "session_variable_overloading", "variable_tampering", {"step_order": ["unauth_workflow", "protected_workflow"]}, "Verify session state variables cannot be populated by alternate unauthenticated pathways", "Strict state separation across distinct modules", True),
        ]),
        "GB-SESSION-11": ("browser_closure.json", "Browser closure", [
            build_payload("GB-SESSION-11-P01", "GB-SESSION-11", "non_persistent_session_cookie", "cookie_attribute", {"check_transient": True}, "Verify session cookie is transient (omits persistent Expires/Max-Age for non-remember-me)", "Transient session cookie terminated on browser closure", True),
        ]),
        "GB-SESSION-12": ("deep_url.json", "Deep URL / direct access to protected resources", [
            build_payload("GB-SESSION-12-P01", "GB-SESSION-12", "direct_access_unauthenticated", "authorization_probe", {"paths": ["/admin", "/dashboard", "/account", "/api/profile"]}, "Verify direct access to protected deep URLs without credentials redirects to login", "HTTP 401/403 or redirect to /login", True),
        ]),
        "GB-SESSION-13": ("back_refresh.json", "Back and Refresh after logout", [
            build_payload("GB-SESSION-13-P01", "GB-SESSION-13", "back_button_cache_inspection", "cache_header", {"headers": ["Cache-Control", "Pragma"]}, "Verify sensitive authenticated data cannot be viewed from browser cache after logout", "Cache-Control: no-store prevents back-button viewing", True),
        ]),
        "GB-SESSION-14": ("logout_after_password_change.json", "Logout of all applicable sessions after password change", [
            build_payload("GB-SESSION-14-P01", "GB-SESSION-14", "password_change_session_revocation", "lifecycle_check", {"action": "password_change"}, "Verify changing user password revokes all existing active session tokens", "All prior active sessions invalidated", True),
        ]),
        "GB-SESSION-15": ("idor.json", "IDOR", [
            build_payload("GB-SESSION-15-P01", "GB-SESSION-15", "cross_account_resource_access", "role_comparison", {"owner_role": "USER_A", "requester_role": "USER_B", "resource_id": "test_resource_101"}, "Verify User B cannot access or modify resources owned by User A", "HTTP 403 Forbidden or 404 Not Found", True),
            build_payload("GB-SESSION-15-P02", "GB-SESSION-15", "numeric_id_increment", "parameter_tamper", {"param": "id", "test_values": [1, 2, 999]}, "Test sequential ID manipulation on object endpoints", "Enforced server-side ownership validation", True),
        ]),
        "GB-SESSION-16": ("privilege_escalation.json", "Privilege escalation", [
            build_payload("GB-SESSION-16-P01", "GB-SESSION-16", "user_to_admin_route", "role_comparison", {"requester_role": "USER_A", "target_endpoint": "/admin/users"}, "Verify standard user cannot access administrative endpoints", "HTTP 403 Forbidden", True),
            build_payload("GB-SESSION-16-P02", "GB-SESSION-16", "role_param_injection", "body_tamper", {"param": "role", "value": "administrator"}, "Verify self-assignment of administrative roles in profile update is rejected", "Role parameter ignored or rejected", True),
        ]),
        "GB-SESSION-17": ("csrf.json", "CSRF", [
            build_payload("GB-SESSION-17-P01", "GB-SESSION-17", "csrf_token_presence", "anti_csrf_check", {"methods": ["POST", "PUT", "DELETE"]}, "Verify state-changing POST/PUT requests require valid anti-CSRF token or SameSite=Strict", "CSRF token validated or SameSite policy enforced", True),
            build_payload("GB-SESSION-17-P02", "GB-SESSION-17", "csrf_token_tampering", "tamper_scenario", {"token": "invalid_test_token_8123"}, "Verify state-changing request with invalid anti-CSRF token is rejected", "HTTP 403 or CSRF validation error", True),
        ]),
        "GB-SESSION-18": ("crlf.json", "CRLF injection", [
            build_payload("GB-SESSION-18-P01", "GB-SESSION-18", "header_injection_crlf", "crlf_probe", "%0d%0aSet-Cookie:+auditcrlf=test", "Verify CRLF sequence injection in parameters cannot inject arbitrary response headers", "CRLF stripped or rejected with HTTP 400", True),
            build_payload("GB-SESSION-18-P02", "GB-SESSION-18", "crlf_raw_break", "crlf_probe", "\r\nSet-Cookie: auditcrlf=test", "Verify raw carriage-return line-feed sequences are rejected", "Headers rejected or sanitized", True),
        ]),
        "GB-SESSION-19": ("session_replay.json", "Session replay", [
            build_payload("GB-SESSION-19-P01", "GB-SESSION-19", "replayed_invalid_session", "replay_scenario", {"workflow": ["login_user_a", "capture_token", "logout_user_a", "replay_captured_token"]}, "Capture valid test session, perform logout, replay old token against protected resource", "Old session rejected with HTTP 401/403", True),
        ]),
    }

    for t_id, (fname, label, payloads) in sess_specs.items():
        rel_path = f"session_management/{fname}"
        (sess_dir / fname).write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        manifest["testcases"][t_id] = {
            "label": label,
            "category": "Session Management",
            "file": rel_path,
            "count": len(payloads),
        }

    # -------------------------------------------------------------
    # 5. INJECTION (20 items)
    # -------------------------------------------------------------
    inj_dir = PAYLOAD_DIR / "injection"
    inj_dir.mkdir(parents=True, exist_ok=True)

    inj_specs = {
        "GB-INJ-01": ("xss.json", "XSS", [
            build_payload("GB-INJ-01-P01", "GB-INJ-01", "script_tag", "xss_vector", "<script>/*audit*/</script>", "Test script tag reflection and context filtering", "Payload HTML-entity encoded or stripped", True),
            build_payload("GB-INJ-01-P02", "GB-INJ-01", "img_onerror", "xss_vector", "<img src=x onerror=console.log(1)>", "Test attribute event-handler injection", "Payload HTML-entity encoded", True),
            build_payload("GB-INJ-01-P03", "GB-INJ-01", "svg_onload", "xss_vector", "<svg onload=console.log(1)>", "Test SVG event handler reflection", "Payload HTML-entity encoded", True),
            build_payload("GB-INJ-01-P04", "GB-INJ-01", "javascript_pseudo_proto", "xss_vector", "javascript:console.log(1)", "Test javascript: URI scheme in href/src attributes", "URI scheme sanitized or blocked", True),
        ]),
        "GB-INJ-02": ("html_injection.json", "HTML injection", [
            build_payload("GB-INJ-02-P01", "GB-INJ-02", "heading_tag", "html_vector", "<h1>AuditMarkupTest</h1>", "Verify arbitrary HTML markup injection is prevented", "Tags encoded into &lt;h1&gt;", True),
            build_payload("GB-INJ-02-P02", "GB-INJ-02", "link_injection", "html_vector", "<a href='https://example.org'>AuditLink</a>", "Verify arbitrary anchor link injection is prevented", "Tags encoded or sanitized", True),
        ]),
        "GB-INJ-03": ("sql_injection.json", "SQL injection", [
            build_payload("GB-INJ-03-P01", "GB-INJ-03", "single_quote_syntax", "sqli_probe", "'", "Test SQL string literal boundary parsing and error disclosure", "Handled via parameterized queries without SQL error", True),
            build_payload("GB-INJ-03-P02", "GB-INJ-03", "or_true_comment", "sqli_probe", "' OR 1=1--", "Test SQL boolean tautology bypass", "Parameterized query executes cleanly without auth bypass", True),
            build_payload("GB-INJ-03-P03", "GB-INJ-03", "and_true_differential", "sqli_probe", "' AND '1'='1", "Test boolean TRUE comparison", "No differential data exposure", True),
            build_payload("GB-INJ-03-P04", "GB-INJ-03", "and_false_differential", "sqli_probe", "' AND '1'='2", "Test boolean FALSE comparison", "Handled safely via parameterization", True),
        ]),
        "GB-INJ-04": ("excel_formula_injection.json", "Excel / CSV formula injection", [
            build_payload("GB-INJ-04-P01", "GB-INJ-04", "equals_formula", "formula_vector", "=1+1", "Verify input fields exported to spreadsheet sanitize leading '='", "Prepends single quote or sanitizes formula token", True),
            build_payload("GB-INJ-04-P02", "GB-INJ-04", "at_formula", "formula_vector", "@SUM(1,1)", "Verify input fields sanitize leading '@' spreadsheet directive", "Sanitizes leading '@'", True),
            build_payload("GB-INJ-04-P03", "GB-INJ-04", "plus_minus_formula", "formula_vector", "-2+3+cmd", "Verify input fields sanitize leading '-' or '+' formula operators", "Sanitizes leading operator tokens", True),
        ]),
        "GB-INJ-05": ("input_validation.json", "Poor input validation", [
            build_payload("GB-INJ-05-P01", "GB-INJ-05", "null_byte", "boundary_probe", "test%00value", "Verify null byte injection does not terminate strings prematurely", "Null bytes rejected or sanitized safely", True),
            build_payload("GB-INJ-05-P02", "GB-INJ-05", "overlong_string", "boundary_probe", "A" * 2048, "Verify overlong string inputs are validated against reasonable maximum bounds", "HTTP 400 Bad Request or graceful validation error", True),
            build_payload("GB-INJ-05-P03", "GB-INJ-05", "unicode_homoglyphs", "boundary_probe", "аdmin", "Verify unicode homoglyph spoofing is normalized or detected", "Normalized properly", True),
        ]),
        "GB-INJ-06": ("client_side_validation_bypass.json", "Client-side validation bypass", [
            build_payload("GB-INJ-06-P01", "GB-INJ-06", "direct_backend_payload", "api_submission", {"field": "email", "value": "invalid_email_format"}, "Submit invalid values directly to API endpoint bypassing HTML5 pattern constraints", "Server-side validation rejects invalid format with HTTP 400", True),
        ]),
        "GB-INJ-07": ("server_side_validation_bypass.json", "Server-side validation bypass", [
            build_payload("GB-INJ-07-P01", "GB-INJ-07", "content_type_mutation", "content_type_probe", {"header": "Content-Type", "value": "text/xml"}, "Submit unexpected MIME type to test server-side parser robustness", "Strict Content-Type enforcement (HTTP 415)", True),
        ]),
        "GB-INJ-08": ("mandatory_field_bypass.json", "Mandatory field bypass", [
            build_payload("GB-INJ-08-P01", "GB-INJ-08", "omitted_required_field", "field_omission", {"omit": "required_key"}, "Verify omitting mandatory field is caught by server-side validation", "HTTP 400 Bad Request with missing field notice", True),
            build_payload("GB-INJ-08-P02", "GB-INJ-08", "null_required_field", "field_omission", {"set_null": "required_key"}, "Verify setting mandatory field to JSON null is rejected", "Validation error returned", True),
        ]),
        "GB-INJ-09": ("parameter_manipulation.json", "Parameter manipulation", [
            build_payload("GB-INJ-09-P01", "GB-INJ-09", "admin_flag_manipulation", "parameter_tamper", {"param": "is_admin", "value": "true"}, "Verify client cannot inject unauthorized privilege parameters", "Unauthorized fields ignored or rejected", True),
            build_payload("GB-INJ-09-P02", "GB-INJ-09", "price_tampering", "parameter_tamper", {"param": "amount", "value": "-10.00"}, "Verify numeric business logic inputs validate positive values", "Negative amounts rejected", True),
        ]),
        "GB-INJ-10": ("parameter_pollution.json", "Parameter pollution", [
            build_payload("GB-INJ-10-P01", "GB-INJ-10", "duplicate_query_params", "hpp_probe", {"query": "id=1&id=2"}, "Test HTTP parameter pollution handling across gateway and backend", "Deterministic, safe parameter handling", True),
        ]),
        "GB-INJ-11": ("xml_injection.json", "XML injection", [
            build_payload("GB-INJ-11-P01", "GB-INJ-11", "xml_element_injection", "xml_probe", "<audit>safe_test</audit>", "Verify unescaped XML markup cannot alter XML document schema", "XML parsed securely with schema validation", True),
        ]),
        "GB-INJ-12": ("xxe.json", "XXE", [
            build_payload("GB-INJ-12-P01", "GB-INJ-12", "external_entity_declaration", "xxe_probe", "<!DOCTYPE test [ <!ENTITY xxe 'audit_xxe_test'> ]><test>&xxe;</test>", "Verify XML external entities (DTD / ENTITY) are disabled in XML parsers", "External entity parsing disabled", True),
        ]),
        "GB-INJ-13": ("xpath_injection.json", "XPath injection", [
            build_payload("GB-INJ-13-P01", "GB-INJ-13", "xpath_tautology", "xpath_probe", "' or '1'='1", "Test XPath query injection in search or login fields", "Queries parameterized, no XPath injection", True),
            build_payload("GB-INJ-13-P02", "GB-INJ-13", "xpath_parenthesis", "xpath_probe", "')] | //* | //*[('", "Test XPath structural element escape", "Handled safely without error disclosure", True),
        ]),
        "GB-INJ-14": ("csti.json", "CSTI", [
            build_payload("GB-INJ-14-P01", "GB-INJ-14", "angular_expression", "csti_probe", "{{7*7}}", "Test Client-Side Template Injection expression evaluation in AngularJS / Vue contexts", "Expression rendered as raw string '{{7*7}}', not computed '49'", True),
            build_payload("GB-INJ-14-P02", "GB-INJ-14", "curly_bracket_dollar", "csti_probe", "${7*7}", "Test ES6 / template literal reflection", "Raw string rendered", True),
        ]),
        "GB-INJ-15": ("ssti.json", "SSTI", [
            build_payload("GB-INJ-15-P01", "GB-INJ-15", "jinja_twig_polyglot", "ssti_probe", "{{7*7}}", "Test Server-Side Template Injection in Jinja2, Twig, or Freemarker", "Rendered as raw string, not evaluated into '49'", True),
            build_payload("GB-INJ-15-P02", "GB-INJ-15", "mako_ruby_polyglot", "ssti_probe", "${7*7}", "Test template evaluation in Mako / Ruby ERB engines", "Rendered as raw string, not evaluated into '49'", True),
        ]),
        "GB-INJ-16": ("ssi_injection.json", "SSI injection", [
            build_payload("GB-INJ-16-P01", "GB-INJ-16", "echo_var_ssi", "ssi_probe", "<!--#echo var=\"DATE_LOCAL\" -->", "Test Server-Side Include directive execution", "Server does not execute SSI directive", True),
        ]),
        "GB-INJ-17": ("command_injection.json", "Command injection", [
            build_payload("GB-INJ-17-P01", "GB-INJ-17", "semicolon_echo", "cmd_probe", "; echo audit_cmd_test", "Verify shell command separator ';' is rejected or parameterized", "Commands executed via safe process APIs without shell", True),
            build_payload("GB-INJ-17-P02", "GB-INJ-17", "pipe_echo", "cmd_probe", "| echo audit_cmd_test", "Verify pipe operator '|' is not passed to system shell", "Safe parameterization", True),
            build_payload("GB-INJ-17-P03", "GB-INJ-17", "subshell_echo", "cmd_probe", "$(echo audit_cmd_test)", "Verify subshell execution '$(...)' is blocked", "Safe parameterization", True),
        ]),
        "GB-INJ-18": ("code_injection.json", "Code injection", [
            build_payload("GB-INJ-18-P01", "GB-INJ-18", "eval_phpinfo", "code_probe", "phpinfo();", "Verify dynamic code evaluation constructs (eval, exec) are not fed user input", "Input treated as literal data string", True),
            build_payload("GB-INJ-18-P02", "GB-INJ-18", "python_eval", "code_probe", "__import__('os').name", "Verify Python eval / exec constructs reject user code input", "Literal data handling only", True),
        ]),
        "GB-INJ-19": ("ldap_injection.json", "LDAP injection", [
            build_payload("GB-INJ-19-P01", "GB-INJ-19", "ldap_wildcard", "ldap_probe", "*", "Test LDAP filter wildcard character handling", "Wildcards escaped or rejected", True),
            build_payload("GB-INJ-19-P02", "GB-INJ-19", "ldap_filter_bypass", "ldap_probe", ")(cn=*)", "Test LDAP filter parenthesis closure", "Escaped properly in LDAP queries", True),
        ]),
        "GB-INJ-20": ("http_request_smuggling.json", "HTTP request smuggling", [
            build_payload("GB-INJ-20-P01", "GB-INJ-20", "te_cl_ambiguity", "smuggling_probe", {"headers": {"Transfer-Encoding": "chunked", "Content-Length": "4"}}, "Check front-end vs back-end HTTP header precedence handling", "Rejection of ambiguous Content-Length + Transfer-Encoding (HTTP 400)", True),
        ]),
    }

    for t_id, (fname, label, payloads) in inj_specs.items():
        rel_path = f"injection/{fname}"
        (inj_dir / fname).write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        manifest["testcases"][t_id] = {
            "label": label,
            "category": "Injection",
            "file": rel_path,
            "count": len(payloads),
        }

    # -------------------------------------------------------------
    # 6. SSRF (1 item)
    # -------------------------------------------------------------
    ssrf_dir = PAYLOAD_DIR / "ssrf"
    ssrf_dir.mkdir(parents=True, exist_ok=True)

    ssrf_specs = {
        "GB-SSRF-01": ("ssrf.json", "Server-Side Request Forgery", [
            build_payload("GB-SSRF-01-P01", "GB-SSRF-01", "loopback_ipv4", "ssrf_probe", "http://127.0.0.1:80", "Verify URL parameters reject loopback 127.0.0.1 target addresses", "URL parameter validated against strict domain allowlist; local IPs blocked", True),
            build_payload("GB-SSRF-01-P02", "GB-SSRF-01", "localhost_hostname", "ssrf_probe", "http://localhost:80", "Verify URL parameters reject localhost hostname", "Blocked by outbound request policy", True),
            build_payload("GB-SSRF-01-P03", "GB-SSRF-01", "private_rfc1918", "ssrf_probe", "http://10.0.0.1:80", "Verify URL parameters reject RFC1918 private subnet IP addresses", "Blocked by outbound request policy", True),
            build_payload("GB-SSRF-01-P04", "GB-SSRF-01", "cloud_metadata_service", "ssrf_probe", "http://169.254.169.254/latest/meta-data/", "Verify URL parameters reject cloud provider metadata endpoint", "Blocked by outbound request policy", True),
        ]),
    }

    for t_id, (fname, label, payloads) in ssrf_specs.items():
        rel_path = f"ssrf/{fname}"
        (ssrf_dir / fname).write_text(json.dumps(payloads, indent=2), encoding="utf-8")
        manifest["testcases"][t_id] = {
            "label": label,
            "category": "SSRF",
            "file": rel_path,
            "count": len(payloads),
        }

    manifest_file = PAYLOAD_DIR / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Generated {len(manifest['testcases'])} Gray-Box payload libraries in {PAYLOAD_DIR}")


if __name__ == "__main__":
    main()
