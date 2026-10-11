# Test Executor — Black-box Website Assessment

A Streamlit application for authorized, bounded web security assessments. The supplied project contains the 23 pre-login checks and 17 login-page checks from the testcase matrix. Use it only against systems you own or have explicit written permission to assess.

## Highlights

- Site-agnostic target input, structured testcase results, and JSON/HTML run output.
- A separate `payloads/` subsystem with a manifest, safe loader, testcase mappings, provenance and per-test probe caps.
- Production-safe payload source catalog covering testcase-relevant SecLists, FuzzDB and PayloadsAllTheThings sources. Large upstream lists are deterministically sampled rather than always taking their first entries.
- Upstream payloads are fetched once into a local cache; scans never download payloads at runtime. Each cached source is recorded with a SHA-256 manifest for reproducibility.
- High-risk material (password dumps, shells, destructive SQL, time-delay probes, credential spraying, authentication bypass and data-exfiltration payloads) is excluded from the automatic client-scan lane.
- Upstream refresh: `python scripts/fetch_payload_sources.py`; use `--force` intentionally to refresh the cache.
- Provisional CVSS v4.0 Base score/vector for confirmed `UNSAFE` findings, including a link to the NIST NVD CVSS calculator. Unconfirmed and safe findings are not scored.
- Authentication tests use only the operator's own authorized credential file, `authentication/credentials.json`. If it is absent, URL-only tests remain available.

## Setup (Windows PowerShell)

```powershell
cd path\to\test_executor
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
streamlit run app.py
```

Open the URL Streamlit prints (normally `http://localhost:8501`). If PowerShell blocks venv activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` and activate again.

Before a live assessment, run the payload-source fetcher once so `payloads/upstream/` is populated. The UI also requires an explicit written-authorization confirmation before a scan starts.

## Setup (Linux / Kali)

```bash
cd /path/to/test_executor
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
streamlit run app.py
```

Payload source updater (required for a fresh production installation; requires internet):

```bash
python scripts/fetch_payload_sources.py
```

It downloads only the testcase-relevant allowlist defined in `payloads/source_catalog.json`; it does not clone or execute the full repositories. The generated manifest records hashes and the runtime remains bounded and safety-filtered. Restart Streamlit after updating sources.

## Payload architecture

```text
scanner logic -> payload manifest/manager -> testcase-specific file-backed inputs
              -> bounded HTTP/browser probe -> response analysis -> finding + evidence
```

The scanners remain responsible for how a test is conducted. Payload files contain input data, not scanner logic. Not every testcase needs a payload list: TLS, certificates, security headers, ETag, browser state and HTTP-method checks use protocol/browser observations. See [`docs/PAYLOADS_AND_CVSS.md`](docs/PAYLOADS_AND_CVSS.md) and [`payloads/SOURCES_AND_LICENSES.md`](payloads/SOURCES_AND_LICENSES.md) for details, testcase mapping and attribution.

## CVSS v4.0

Install requirements to enable local numeric CVSS v4.0 calculation. Only confirmed `UNSAFE` outcomes receive a provisional score and vector; the score does not change the testcase verdict. CVSS is separate from the product's existing 0–100 severity score. Analysts should verify the vector and business impact in the [NIST NVD CVSS v4.0 calculator](https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator) before external reporting.

## Production network policy

The application validates the target before scanning and rejects embedded URL credentials and malformed destinations. For local development and authorized assessments, internal and loopback targets are permitted by default (`ALLOW_PRIVATE_TARGETS=1` in `.env` and via the "Allow private / local network targets" UI toggle). For a public multi-tenant deployment, internal scanning can be disabled by setting `ALLOW_PRIVATE_TARGETS=0` or unchecking the UI option.

The UI requires the operator to explicitly confirm written authorization. Login paths are restricted to same-origin paths, and protected URLs are checked against the target origin.

## Security / secrets

Do not commit `authentication/credentials.json`, `.env`, exported reports, session material or client data. A template is available at `authentication/credentials.example.json`; copy it to `credentials.json` only when you have explicitly authorized test credentials. The application never auto-fills this file from a public password list.

## Test / validation

```bash
python -m pytest -q
```

A `SAFE` result means the configured check found no signal within its bounded scope, not that the target is entirely secure. A finding may still require analyst confirmation. Use `REVIEW REQUIRED` when the scanner detects suspicious but insufficient evidence.

## Authorized test account in the UI (TC05, TC06, TC10, TC17)

When **Login Page Tests (17)** is selected, expand **Authorized test account — TC05, TC06, TC10 & TC17** and enter a dedicated test-account username and password. Check the authorization confirmation to allow the credentials to be passed to the authenticated testcase checks. The credentials are held in Streamlit session state for the current UI session and are not written to `authentication/credentials.json` or included intentionally in reports. Avoid shared/production accounts; use a client-approved test account.

This UI account is separate from the credential candidates used by TC02 (Default Credentials) and TC04 (User Enumeration). If no UI account is supplied and confirmed, the suite continues with available checks and should report authentication-dependent checks as incomplete/not assessed where applicable. Providing credentials does not by itself prove they are valid; the scanner must establish a successful authentication control before making claims that depend on one.


Testing for gihub update.....