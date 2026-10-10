# Test Executor

Authorized web-assessment tool that runs **six security checks** against a caller-supplied target URL and presents **one combined report**. Use it only on systems you own or are explicitly authorized to test.

The tool is **site-agnostic**. Host, scheme, login path, and output folder names are taken from the URL you enter. It does not hardcode customer hostnames, demo sites, login paths, or expected findings.

---

## What it does

You enter a target website and (optionally) a login page. The app then:

1. Runs four HTTP/header checks against that target.
2. Decides whether Default Credentials and User Enumeration apply.
3. Either runs those two checks automatically, skips them as not applicable (federated SSO), or **pauses** so a person can complete a CAPTCHA.
4. Shows one combined status plus per-test evidence.
5. Writes JSON and HTML under `output/<hostname>_<timestamp>/`.

A **SAFE** result means that scanner’s configured checks did not find an issue. It does **not** mean the whole website is secure.

---

## The six checks

### 1. Banner Disclosure (`banner_grabbing.py`)

Sends `curl -I -L` and looks at response headers such as `Server`, `X-Powered-By`, `X-AspNet-Version`, and `X-AspNetMvc-Version`. **UNSAFE** if a header discloses a product **and a version number** (for example `nginx/1.18.0`). A product name without a version is not treated as banner disclosure by this scanner.

### 2. Security Headers (`security_header_scanner.py`)

Fetches headers with curl and compares them to a baseline:

| Header | Baseline expectation |
|---|---|
| `Content-Security-Policy` | Present, with core directives such as `default-src`, `object-src`, `base-uri`, `frame-ancestors` |
| `Strict-Transport-Security` | Present with a strong `max-age` (and related flags) |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` (or equivalent framing protection) |
| `Referrer-Policy` | A restrictive policy such as `strict-origin-when-cross-origin` |

Missing or weak values are **UNSAFE** for that header; the test’s overall status rolls those results up.

### 3. Website IP Access (`ip_access_scanner.py`)

Resolves the target hostname to an IP, requests both `https://hostname/...` and `https://<ip>/...` (with Host handling via curl), then compares HTTP status and body similarity (hash / length). **UNSAFE** when the site is reachable by raw IP with a 2xx response and content very similar to the hostname response (about 90%+ similarity). That is treated as the application being exposed without needing the intended hostname.

### 4. Host Header Injection (`host_header_inj.py`)

Sends a normal request, then a second request with a **synthetic** `Host` value. **UNSAFE** if that fake host appears in a `Location` redirect. **REVIEW REQUIRED** if it is reflected in the body but not clearly used for redirects. **SAFE** if it is not trusted/reflected in those ways.

### 5. Default Credentials (`default_creds_lane.py` via `run_default_creds_tests.py`)

Uses the username/password pairs in `credentials.json` (capped in the UI, currently 100 attempts). Discovers a login form (or HTTP Basic) at the path you provide, posts each pair, and looks for an authenticated session (redirect off the login page, logout/welcome markers, and similar signals). **UNSAFE** if a supplied pair authenticates. **SAFE** only if a usable login mechanism was found and none of the attempted pairs authenticated. Failed discovery, timeouts, or CAPTCHA-limited runs are **INCOMPLETE**, **ERROR**, or **SKIPPED** — never silently SAFE.

### 6. User Enumeration (`default_creds_lane.py` enumeration mode)

Uses **usernames only** from the same `credentials.json`, with a fixed invalid probe password. Compares responses (status, length, messages, redirects, page disclosure). **UNSAFE** when usernames are distinguishable or the page discloses account identifiers. Inconclusive differences are **REVIEW REQUIRED**. Same rule as above: a failed or blocked check is not SAFE.

---

## How a run is orchestrated

`app.py` (Streamlit UI) calls `integrated_scanner.py`.

```
Start
  → Banner, Security Headers, IP Access, Host Header
  → Probe the login URL
       ├─ Federated SSO / identity provider  → skip checks 5–6 as SKIPPED (not applicable)
       ├─ No CAPTCHA                         → run checks 5–6 automatically
       └─ CAPTCHA on a local login form      → pause; human Solve / Skip pair / Skip the rest / Skip test
  → Combined report + files under output/
```

- **Federated SSO** (`login_applicability.py`): public IdP hosts (Microsoft Entra / Microsoft Online, Okta, Auth0, Google accounts, Ping, Cognito, and similar), OAuth/OIDC URL shapes (`/oauth2/`, `client_id`, `redirect_uri`, …), or a redirect/HTML probe that lands on an IdP **without** a local password form. Application hosts that merely *link* to SSO from a normal HTML login are not skipped just because the path is `/login`.
- **CAPTCHA** (`captcha_human.py`): markers such as reCAPTCHA, hCaptcha, or Cloudflare Turnstile in HTML, or `captcha=fail` in the URL. The app **does not** click “I’m not a robot” and **does not** call solving services. **Solve** opens a visible Playwright Chromium window, fills the current username (and password for Default Credentials), waits up to three minutes for a CAPTCHA token, then submits. You then get the same choices for the next pair or username. After at least one item has been tested, **Skip the rest pairs** (or usernames) keeps those results, marks **UNSAFE** or **SAFE** from the tested items only, and does not try the remainder.

CAPTCHA verdicts:

- A successful login after a human solve → **UNSAFE**
- Skip the whole test with zero attempts → **SKIPPED** (not applicable)
- **Skip the rest pairs** after at least one solve → **UNSAFE** or **SAFE** from the tested items only
- Some human solves plus skipped items → **INCOMPLETE** (not SAFE)
- Every human-solved attempt, none authenticated → **SAFE** for that check

Overall status is the worst of the checks that actually ran: **UNSAFE** > **REVIEW REQUIRED** > **INCOMPLETE** / **ERROR** / **UNKNOWN** > **SAFE**. **SKIPPED** is ignored for the overall roll-up.

---

## Tools and libraries

| Tool | Role |
|---|---|
| **Python 3.11+** | Runtime |
| **Streamlit** | Local web UI (`app.py`) |
| **curl** | First four scanners (headers, redirects, bodies) |
| **requests** | Login discovery, federated/CAPTCHA probes, form posts |
| **Playwright + Chromium** | Headed browser for human CAPTCHA solves; also an optional fallback in the auth lane when a form needs a real browser |
| **credentials.json** | Shared wordlist: pairs for Default Credentials, usernames for User Enumeration |
| **numpy / pandas** | Declared because Streamlit’s table/UI stack expects them |

Python packages are listed in `requirements.txt`. curl is a **system** binary (`curl.exe` on Windows). Chromium is installed separately with `playwright install chromium`.

---

## Project layout

| File | Purpose |
|---|---|
| `app.py` | Streamlit UI, Start flow, CAPTCHA pause |
| `integrated_scanner.py` | Runs the six checks and maps statuses |
| `banner_grabbing.py` | Banner disclosure |
| `security_header_scanner.py` | Security headers |
| `ip_access_scanner.py` | Direct IP access |
| `host_header_inj.py` | Host header injection |
| `default_creds_lane.py` | Form/Basic auth attempts and enumeration |
| `run_default_creds_tests.py` | JSON in/out wrapper for the auth lane |
| `login_applicability.py` | Federated SSO and CAPTCHA detection |
| `captcha_human.py` | Login probe + human CAPTCHA browser |
| `run_output.py` | `output/<domain>_<timestamp>/` JSON + HTML |
| `credentials.json` | Authorized credential database (not shown in the UI) |
| `requirements.txt` | Python dependencies |
| `run_instructions.txt` | Step-by-step how to run and what to type |

---

## Reports

Each finished run creates:

```
output/<target-hostname>_<YYYYMMDD_HHMMSS>/
  compiled.json
  compiled.html
  01_banner_disclosure.json
  02_security_headers.json
  03_website_ip_access.json
  04_host_header_injection.json
  05_default_credentials.json
  06_user_enumeration.json
```

The hostname in the folder name is parsed from the URL you entered.

---

## Status meanings

| Status | Meaning |
|---|---|
| **SAFE** | This scanner’s checks did not identify the issue they look for |
| **UNSAFE** | The issue this scanner looks for was identified |
| **REVIEW REQUIRED** | Signals are mixed; a person should inspect evidence |
| **SKIPPED** | Not applicable (federated SSO, or CAPTCHA test skipped with no attempts) |
| **INCOMPLETE / ERROR / UNKNOWN** | The check did not finish reliably — **not** a pass |

---

## Limits and safety notes

- Live testing is capped (`MAX_CREDENTIAL_ATTEMPTS` in `app.py`, currently 100).
- User Enumeration always uses the same invalid probe password; it is not shown in the UI.
- Passwords from `credentials.json` are not displayed in the UI.
- TLS certificate verification is on for `requests`. If a site’s HTTPS certificate is invalid, use the scheme you are authorized to test (often `http://` on a lab box) rather than disabling verification in code.
- Refreshing the browser does **not** reload Python modules. After code changes, stop Streamlit and start it again.

For how to install and what to type in the UI, see `run_instructions.txt`.
