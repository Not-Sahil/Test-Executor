# Gray-Box Security Testing Framework Architecture & Operations Guide

## 1. Overview and Architecture
The Gray-Box Security Testing Framework extends the existing Test Executor into an enterprise-grade web application penetration testing system while preserving **100% black-box isolation**. The framework is designed for authorized client assessments adhering to OWASP WSTG v4.2, OWASP ASVS v4.0.3, and RFC standards.

### Architectural Separation
```
test_executor/
├── payloads/
│   ├── manifest.json              <-- Black-Box payload manifest (unmodified)
│   ├── fuzzdb/, seclists/, ...    <-- Black-Box payload sources (unmodified)
│   └── graybox/                   <-- Dedicated Gray-Box payload libraries
│       ├── manifest.json          <-- Validated Gray-Box manifest (85 libraries, 143 test inputs)
│       ├── basic/
│       ├── encryption/
│       ├── form_authentication/
│       ├── session_management/
│       ├── injection/
│       └── ssrf/
├── graybox/                       <-- Isolated Gray-Box subsystem
│   ├── models.py                  <-- Typed models, Enums, schemas
│   ├── artifacts.py               <-- Knowledge & Artifact Manager (OpenAPI, SBOM, schemas)
│   ├── accounts.py                <-- Multi-identity Account & Role Manager
│   ├── payload_manager.py         <-- Payload library loader & schema validator
│   ├── registry.py                <-- Canonical registry of all 85 Gray-Box testcases
│   ├── runner.py                  <-- Orchestration engine & prerequisite validator
│   ├── reporting.py               <-- JSON, HTML, and Markdown report generator
│   ├── ui.py                      <-- Dedicated Streamlit interface
│   └── scanners/                  <-- Scanner implementations for all 85 testcases
│       ├── basic/                 <-- 21 scanners (GB-BASIC-01 to GB-BASIC-21)
│       ├── encryption/            <-- 8 scanners (GB-ENC-01 to GB-ENC-08)
│       ├── form_authentication/   <-- 16 scanners (GB-FORM-01 to GB-FORM-16)
│       ├── session_management/    <-- 19 scanners (GB-SESSION-01 to GB-SESSION-19)
│       ├── injection/             <-- 20 scanners (GB-INJ-01 to GB-INJ-20)
│       └── ssrf/                  <-- 1 scanner (GB-SSRF-01)
└── app.py                         <-- Streamlit app with top-level mode toggle
```

---

## 2. Testcase Inventory (85 Testcases Across 6 Categories)

| Category | Count | Range | Description |
|---|:---:|---|---|
| **A. Basic** | 21 | `GB-BASIC-01` to `GB-BASIC-21` | Infrastructure, headers, directory exposure, client libraries, banners, CORS, XST, traversal |
| **B. Encryption** | 8 | `GB-ENC-01` to `GB-ENC-08` | TLS protocols/ciphers, certificates, HTTPS transport for forms/credentials/tokens, HSTS, SSL stripping |
| **C. Form Field & Auth** | 16 | `GB-FORM-01` to `GB-FORM-16` | Shoulder surfing, autocomplete, brute force, CAPTCHA, password policy, user enumeration, MFA, OTP bypass |
| **D. Session Management** | 19 | `GB-SESSION-01` to `GB-SESSION-19` | Cookie flags, expiration, rotation, puzzling, IDOR, privilege escalation, CSRF, CRLF, session replay |
| **E. Injection** | 20 | `GB-INJ-01` to `GB-INJ-20` | XSS, HTMLi, SQLi, CSV formula injection, validation bypass, XML/XXE, XPath, CSTI, SSTI, SSI, Command, Code, LDAP, Smuggling |
| **F. SSRF** | 1 | `GB-SSRF-01` | Loopback, RFC1918 private IP, and link-local request forgery verification |
| **Total** | **85** | | |

---

## 3. Automation Classifications
1. **AUTOMATED (78 Testcases):** Executed autonomously using deterministic probes, payload differentials, or artifact analyses without human intervention.
2. **ASSISTED (7 Testcases):** Supported by automated workflow orchestration with operator-in-the-loop validation (e.g. `GB-FORM-09` MFA, `GB-SESSION-14` Password change logout, `GB-SESSION-19` Session replay).
3. **MANUAL (0 Testcases):** Every testcase in the inventory has a functioning automated or assisted scanner implementation.

---

## 4. Dedicated Payload Library Architecture
All payload files are located under `payloads/graybox/` and validated through `manifest.json`.

### Payload Schema
```json
{
  "id": "GB-INJ-03-P001",
  "testcase_id": "GB-INJ-03",
  "name": "sql_boolean_and_differential",
  "category": "boolean_differential",
  "value": "' AND 1=1 --",
  "encoding": "plain",
  "purpose": "Verify database query boundary isolation",
  "expected_secure_behavior": "Input is treated as literal parameter without altering result set",
  "required": true,
  "risk_level": "low",
  "destructive": false,
  "requires_authorization": true,
  "requires_test_environment": false,
  "requires_account_role": [],
  "evidence_type": "response_comparison",
  "source": {
    "repository": "curated_safe_graybox_library",
    "version": "1.0.0"
  },
  "tags": ["owasp", "wstg-inpval-05"]
}
```

---

## 5. Gray-Box Knowledge & Artifact Manager
The platform ingests gray-box artifacts to deepen test fidelity without executing arbitrary files:
- **OpenAPI / Swagger:** Extracts declared routes, methods, parameter definitions, and auth schemes (`am.get_openapi_endpoints()`).
- **SBOM & Dependency Manifests:** Parses `package.json`, `requirements.txt`, or CycloneDX JSON to detect known vulnerable or deprecated components (`GB-BASIC-03`).
- **Source Code Snippets & Database Schemas:** Ingests endpoints and DDL for offline verification.
- **Role & Permission Matrix:** Maps access control policies against test outcomes for IDOR (`GB-SESSION-15`) and Privilege Escalation (`GB-SESSION-16`).

---

## 6. Multi-Identity Account and Role Manager
Supports isolated testing of authorization boundaries using dedicated test identities:
- `ANONYMOUS`: Public visitor state
- `USER_A`: Standard authenticated user
- `USER_B`: Secondary standard user for horizontal authorization/IDOR checks
- `PRIVILEGED_USER`: Enhanced privilege account
- `ADMINISTRATOR`: Administrative role for vertical privilege escalation checks

All passwords, bearer tokens, and session cookies are automatically redacted from evidence, logs, and reports via `redact_text_secrets()`.

---

## 7. Evidence-Driven Classifications
Findings are strictly evidence-driven:
- **UNSAFE:** Confirmed vulnerability supported by repeatable HTTP response evidence (e.g. reflected payload, unauthenticated write method, IDOR access).
- **SAFE:** Check completed and verified secure behavior within configured scope.
- **REVIEW REQUIRED:** Suspicious or hardening recommendation (e.g. missing CSP/HSTS headers, outdated framework).
- **NOT ASSESSED:** Required prerequisite (account role or artifact) was not provided by the operator.
- **INCOMPLETE:** Target failed to respond or probe budget was reached before completion.
- **SKIPPED:** Testcase intentionally excluded by scope configuration.
- **ERROR:** Unhandled execution exception.

---

## 8. Frontend UI Operation
The Streamlit frontend (`app.py`) provides an interactive toggle:
```
[ BLACK BOX TESTING ] [ GRAY BOX TESTING ]
```
- **Black Box Mode:** Renders original 23 pre-login and 17 login-page tests, credential candidates, and black-box reports intact.
- **Gray Box Mode:** Renders full Gray-Box assessment console with:
  1. Target & Environment controls (with verify TLS and allow private targets).
  2. Safety Budget (request limits and delay per testcase).
  3. Knowledge & Artifact Manager tabs.
  4. Account & Role Manager tabs.
  5. Category & Inventory selector.
  6. Real-time execution progress bar and status feed.
  7. Results dashboard with payload execution metrics, evidence inspector, interactive NIST CVSS v4.0 adjuster, and report downloads (HTML, JSON, Markdown).

---

## 9. Verification & Commands

### Running the Application
```bash
streamlit run app.py
```

### Running Test Suites
```bash
# Run all tests (171 unit + 3 integration tests)
pytest tests/ -v

# Run only Gray-Box unit tests
pytest tests/units/graybox/ -v

# Run existing Black-Box unit tests
pytest tests/units/test_*.py -v
```
