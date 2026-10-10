# Production run checklist

## 1. Install

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
```

### Linux/Kali

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
python -m playwright install chromium
```

## 2. Fetch and lock the payload sources

Run once before an assessment environment is used:

```bash
python scripts/fetch_payload_sources.py
```

The command stages the testcase-relevant sources into `payloads/upstream/` and writes `payloads/upstream_sources_manifest.json` with SHA-256 hashes. A client scan never downloads payloads from the internet.

Refresh intentionally with:

```bash
python scripts/fetch_payload_sources.py --force
```

After a refresh, review the generated manifest and run the test suite before using the new source cache in a client engagement.

## 3. Network safety policy

Private and local lab targets (such as loopback, `127.0.0.1`, and private network IP ranges) are allowed by default for local development and authorized assessments. This is configured via `.env` (`ALLOW_PRIVATE_TARGETS=1`) and can also be toggled directly in the Streamlit UI ("Allow private / local network targets").

Embedded URL credentials and malformed destinations remain rejected.

To enforce public-only targets in an internet-facing multi-tenant deployment, set:

```powershell
$env:ALLOW_PRIVATE_TARGETS="0"
```

or:

```bash
export ALLOW_PRIVATE_TARGETS=0
```

or uncheck the "Allow private / local network targets" checkbox in the UI.

## 4. Authorization

The UI requires the operator to confirm written authorization before starting an assessment. This is an operational control, not a legal authorization system; retain the actual client authorization in your engagement records.

## 5. Run

```bash
streamlit run app.py
```

Choose the 23-test pre-login suite or the 17-test login-page suite. Use a same-origin login path and, when needed, a same-origin protected URL.

## 6. Authentication tests

Only credentials explicitly supplied through the operator's credential file are used. Public password lists are not imported into the authentication lane.

Do not commit:

- `authentication/credentials.json`
- `.env` files
- client reports
- cookies/session data
- browser profiles

## 7. Validate before client use

```bash
python -m compileall -q .
python -m pytest -q
```

## 8. Result interpretation

- `UNSAFE` = confirmed by the testcase's evidence rules.
- `REVIEW REQUIRED` = suspicious signal requiring analyst confirmation.
- `SAFE` = no signal within the configured scope; never interpret it as a full security guarantee.
- `INCOMPLETE` / `ERROR` = the testcase did not reach a reliable conclusion.
- `NOT ASSESSED` / `SKIPPED` = the testcase could not or should not run for the discovered application state.

Client reports include a payload-manifest hash so the assessment can be tied to the exact payload configuration used.
