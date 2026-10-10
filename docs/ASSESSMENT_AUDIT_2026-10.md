# Test Executor audit and changes (2026-10-09)

## Validation performed
- `python -m compileall -q .`: passed.
- `python -m pytest -q`: 144 passed.

## Fixes included in this build
1. **TC13 CORS runtime failure**: fixed the `origins` scope error in the payload-library metadata. The output now derives `items_used` from the built probe list.
2. **TC01 Autocomplete discovery**: uses the configured login URL first, then bounded same-origin fallback discovery (homepage, links labelled login/sign-in, and common login paths). Reports `candidate_urls_checked` so the report explains where it looked.
3. **TC07/TC08/TC09 pre-login TLS checks**: when the submitted target is HTTP, the scanner now attempts the same host/path over HTTPS rather than immediately returning NOT APPLICABLE. The output records `https_inferred_from_http_target`. If HTTPS is unavailable, the TLS scanner should report the actual connection/assessment limitation.
4. **TC14 SQL injection**: each executed probe now includes its payload value in structured results. A body change versus baseline without a meaningful TRUE/FALSE differential becomes REVIEW REQUIRED rather than a misleading SAFE. A TRUE/FALSE pair is compared directly, and the report identifies the triggering pair and measurements. This deliberately does not force UNSAFE just because a payload was submitted.
5. **TC15 LDAP/AD injection**: reports the actual bounded synthetic input markers used and their source file.
6. **UI**: removed the visible Authentication Database section while retaining silent loading from `authentication/credentials.json`.
7. **Credentials safety**: `authentication/credentials.example.json` now documents the expected operator-supplied credential shape. Added `authentication/CREDENTIALS_SETUP.md`.

## Credential-dependent testcases and why code alone cannot complete them
The uploaded screenshot showed:
- TC05 Password Validation
- TC06 Method Interchange
- TC10 Remember Me
- TC17 Rate Limit

These tests need a verified, explicitly authorized username/password control. A code change cannot establish that a credential is valid. The executor must not guess passwords or silently use a default credential list. Once an owner-provided valid test account is marked `known_valid_username: true`, these tests can use it.

TC02 Default Credentials needs an operator-approved list of product/application defaults to test. TC04 User Enumeration needs approved candidate usernames (and may use usernames from the same authorized credential file). These are input prerequisites, not proof that the application is secure. Do not replace missing inputs with a hardcoded list of common passwords.

## Review-required results
- **Helpful Error Messages**: keep REVIEW REQUIRED when diagnostic details appear; human review must establish whether the details expose exploitable implementation information.
- **HTTP Arbitrary Methods**: acceptance of TRACE/TRACK or a changed response is not alone proof of impact; confirm whether sensitive data is exposed or a security boundary is bypassed.
- **Google Dorking**: generated queries are not findings until an operator reviews actual indexed results. This testcase intentionally does not query third-party search engines automatically.
- **Website Accessible over IP**: direct reachability is not itself a security bypass. Review whether the IP endpoint bypasses CDN/WAF/virtual-host controls.
- **Weak Password Encoding**: requires application-specific password-policy and client/server behavior review; do not classify encoding or hashing claims without evidence.

## Limits that remain
- TC11 Shoulder Surfing requires a human/physical observation and should remain NOT ASSESSED/manual.
- CAPTCHA interaction, actual account privilege, protected-resource validation, session persistence, and some browser heap behaviors depend on the application and available Playwright/browser setup.
- TC05/TC06/TC10/TC17 remain incomplete until a valid authorized credential control is configured.
- TC02/TC04 remain unassessed/incomplete when no approved credential pairs or candidate usernames are provided.
- No scanner can guarantee pentester-level accuracy on every application from one URL alone. Reports should preserve evidence, coverage, assumptions, and uncertainty rather than force every case to SAFE or UNSAFE.
