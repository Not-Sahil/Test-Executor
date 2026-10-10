# TC03 — Blank Credentials integration

## Add these files

```text
authentication/credential_variants.py
authentication/blank_credential_client.py
authentication/blank_response_verifier.py
authentication/browser_blank_client.py
login_page/scanners/tc03_blank_credentials.py
tests/units/test_tc03_blank_credentials.py
```

These files are designed to sit on top of the shared authentication layer already created for TC02:

```text
authentication/models.py
authentication/auth_discovery.py
authentication/baseline.py
authentication/lockout_guard.py
authentication/login_applicability.py
authentication/captcha_human.py
authentication/privilege.py
```

## Do not replace the TC02 scanner

TC03 is a separate scanner:

```text
login_page/scanners/tc02_default_credentials.py
login_page/scanners/tc03_blank_credentials.py
```

## Runner call

```python
from login_page.scanners.tc03_blank_credentials import TC03Config, scan_blank_credentials

result = scan_blank_credentials(
    target=target_url,
    config=TC03Config(
        login_path=login_path or "/login",
        timeout=8.0,
        verify_tls=True,
        max_attempts=10,
        include_optional_variants=True,
        stop_on_confirmed=True,
        authorized_username=None,       # Explicitly configure when available.
        authorized_password=None,       # Explicitly configure when available.
        protected_urls=("/account", "/dashboard"),
        allow_browser_fallback=True,
    ),
)
```

## Authorized values

`authorized_username` and `authorized_password` are optional and should be supplied only for accounts and credentials that the operator is authorized to use. They are used only to test variants that require a real credential component.

Never put secrets into evidence or UI output.

## Test matrix

Mandatory:

- TC03-A: username empty + password empty
- TC03-B: username missing + password missing
- TC03-C: username empty + bounded probe password
- TC03-D: authorized username + password empty

Optional:

- TC03-E: whitespace + whitespace
- TC03-F: whitespace username + empty password
- TC03-G: empty username + whitespace password
- TC03-H: missing username + empty password
- TC03-I: empty username + missing password
- TC03-J: JSON null + JSON null

The scanner treats EMPTY, MISSING, WHITESPACE and NULL as distinct input states.

## Important result rule

A successful HTTP 200/302 response is not itself a vulnerability. HTTP candidates remain unconfirmed until a protected-resource or equivalent authentication proof is available. Rendered browser flows can produce a candidate success when the final URL and account markers leave the login flow, but the report should still distinguish candidate success from fully confirmed authorization.

## Run unit tests

```bash
python -m pytest tests/units/test_tc03_blank_credentials.py -v
```

## Current scope boundary

TC03 does not perform password brute force, SQL injection, LDAP injection, account enumeration, session fixation, remember-me analysis, or CAPTCHA bypass. Those belong to their respective login testcases.
