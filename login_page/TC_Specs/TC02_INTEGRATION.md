# TC02 Clean Authentication Architecture

## Add these files

Copy the files under `authentication/` into your existing project's `authentication/` directory.
Copy `login_page/scanners/tc02_default_credentials.py` into `login_page/scanners/`.

`authentication/login_applicability.py` is a clean standalone replacement for the current helper.
`authentication/captcha_human.py` is also updated so it no longer imports implementation details from `default_creds_lane.py`.

## Do not copy back

Do not keep using `default_creds_lane.py` as the TC02 engine after migration.
It currently mixes default credentials, username enumeration, login-factor diagnosis and shared authentication mechanics.

Do not use `run_default_creds_tests.py` as the long-term testcase implementation. The main project's orchestrator should dispatch TC02 to `scan_default_credentials()`.

## Required imports

TC02 expects your application-owned severity engine at:

`core/severity_engine.py`

with `SeverityInput` and `calculate_severity()`.

## Credentials file example

```json
[
  {
    "username": "admin",
    "password": "admin",
    "credential_source": "product_default",
    "product_hint": "myproduct",
    "account_hint": "administrator"
  },
  {
    "username": "admin",
    "password": "",
    "credential_source": "blank_password"
  }
]
```

No global default credential dictionary is silently loaded. Lab profiles are opt-in.

## Orchestrator call

```python
from login_page.scanners.tc02_default_credentials import TC02Config, scan_default_credentials_from_file

result = scan_default_credentials_from_file(
    target=target_url,
    credential_file="authentication/credentials.json",
    config=TC02Config(
        login_path=login_path,
        max_attempts=10,
        protected_urls=("/account", "/admin"),
        verify_tls=True,
    ),
)

scan_result = result.as_dict()

# Or adapt directly to the existing shared model:
from login_page.scanners.tc02_default_credentials import to_scan_result
scan_result = to_scan_result(result)
```

Map `scan_result` into the project's existing `ScanResult` if required by the orchestrator.

## Next extraction targets

Reuse these modules for TC03/04/05/06/10/12/14/15/16/17:

- `models.py`
- `auth_discovery.py`
- `auth_client.py`
- `baseline.py`
- `success_verifier.py`
- `lockout_guard.py`
- `credential_registry.py`
- `login_applicability.py`
- `captcha_human.py`
- `evidence.py`
