# Black-box testcase ↔ payload/probe matrix (23 + 17)

A testcase uses an external payload list only when that list makes sense for the security property being tested. Protocol/configuration/browser tests should inspect headers, TLS negotiation, certificate state or the rendered page; sending unrelated fuzz payloads would reduce accuracy, not improve it.

## Pre-login suite — 23 tests

| ID | Testcase | Payload strategy | Active files / evidence source |
|---|---|---|---|
| TC01 | Banner Grabbing | No wordlist; inspect response headers/service banner | HTTP response / optional Nmap evidence |
| TC02 | Known Components | No exploit payload; inspect disclosed asset names/versions | HTML/assets/fingerprints |
| TC03 | Helpful Error Message | Controlled missing/malformed-resource sentinels | `payloads/fuzzdb/response_patterns/helpful_error_probe_tokens.txt` |
| TC04 | Robots.txt | Well-known standard path | `/robots.txt` protocol check |
| TC05 | Default Server Page | No payload; root page signature analysis | HTML/title/server response |
| TC06 | E-Tag Header | No payload; inspect `ETag` | HTTP response headers |
| TC07 | Weak Cipher | No payload; negotiate supported TLS protocols/ciphers | TLS handshake / OpenSSL or testssl evidence |
| TC08 | Wildcard Certificate | No payload; inspect SAN/CN identities | TLS certificate |
| TC09 | Certificate Expiry | No payload; inspect `notBefore`/`notAfter` and trust | TLS certificate |
| TC10 | Directory Listing | Bounded directory candidates | `payloads/seclists/discovery/directory_candidates.txt`, `payloads/fuzzdb/discovery/predictable_filepaths_curated.txt`; optional upstream SecLists/FuzzDB caches |
| TC11 | HTTP Arbitrary Methods | Fixed safe method probes; avoid state-changing methods | Protocol method observations |
| TC12 | Host Header Injection | Controlled synthetic host/header sentinels | Host/forwarded-host response comparisons |
| TC13 | Sensitive File Exposure | Bounded config/backup/metadata file candidates | `payloads/seclists/discovery/sensitive_file_candidates.txt`, `source_config_bases.txt`, `backup_suffixes.txt`, plus curated FuzzDB candidates and optional upstream caches |
| TC14 | Google Dorking | Query templates, not an HTTP attack payload list | Passive query templates; no automated search-engine scraping unless separately approved |
| TC15 | Internal IP Disclosure | No payload list; detect private IP / internal host patterns | Response-body regex/signatures |
| TC16 | Clickjacking | No payload list; inspect frame-protection headers and optional browser frame behavior | CSP `frame-ancestors`, X-Frame-Options |
| TC17 | Website Accessible over IP | No payload list; compare hostname and direct-IP responses safely | DNS resolution / controlled IP request |
| TC18 | Missing Security Headers | No payload list; inspect expected headers | HTTP response headers |
| TC19 | Hardcoded Credentials | No active payload list; scan exposed HTML/JS for secret patterns | Client-accessible source/asset scanning; secrets redacted in reports |
| TC20 | Sitemap.xml | Standard well-known path | `/sitemap.xml` |
| TC21 | Crossdomain.xml | Standard well-known path | `/crossdomain.xml` |
| TC22 | Application running on HTTP | No payload list; compare HTTP/HTTPS behavior | Transport check |
| TC23 | Internal Path Disclosure | Controlled malformed/nonexistent paths | `payloads/fuzzdb/response_patterns/error_path_probes.txt` |

## Login-page suite — 17 tests

| ID | Testcase | Payload strategy | Active files / evidence source |
|---|---|---|---|
| TC01 | Autocomplete | No payload; inspect login DOM fields | HTML/browser form attributes |
| TC02 | Default Credential | Operator-supplied, explicitly authorized credential records only | `authentication/credentials.json`; never automatically use a public password dump |
| TC03 | Blank Credential | Submit bounded empty-field control | Form discovery / controlled blank submission |
| TC04 | User Enumeration | One fixed invalid probe password and authorized known/unknown username comparison | Authorized user list; no public username spraying |
| TC05 | Password not Validating on Login | Valid control plus controlled invalid password | Login form/authentication evidence; requires an authorized valid test account for a high-confidence verdict |
| TC06 | Method Interchange | Compare supported GET/POST form behavior | Discovered form action/method/fields |
| TC07 | Browser Memory Dump | Browser-side observation and redacted memory/storage checks | Playwright/browser evidence; not a generic fuzz list |
| TC08 | Login over HTTP method | Transport check at actual credential endpoint | HTTP/HTTPS + login form action |
| TC09 | ClearText Traffic | Controlled request/transport inspection; shares scope with TC08 where appropriate | HTTP evidence/proxy capture when configured |
| TC10 | Remember Me | Inspect controls and session behavior | HTML/browser/session observations |
| TC11 | Shoulder Surfing | Human/device observation | Manual evidence; a wordlist cannot automate it |
| TC12 | Captcha Missing | Inspect login form and CAPTCHA integration markers | DOM/JS/browser evidence |
| TC13 | CORS | Controlled origin and `null`-origin header probes | `payloads/payloads_all_the_things/cors/origin_probe_templates.txt` |
| TC14 | SQL Injection | Five non-destructive syntax/differential probes | `payloads/payloads_all_the_things/sql_injection/safe_differential_probes.json` |
| TC15 | LDAP / Active Directory Injection | Synthetic LDAP metacharacter markers only; no bypass predicates | `payloads/payloads_all_the_things/ldap_injection/safe_syntax_markers.txt` |
| TC16 | Weak Password / Encoding | Inspect password policy/client transformations; no arbitrary credential dictionary | Form/browser source; authorized controlled input as needed |
| TC17 | Rate Limit | Small bounded incorrect-login sequence; no bulk brute-force list | `authentication/lockout_guard.py` and operator-approved attempt budget |

## Why not every testcase has a payload file

Payload files are inputs to particular classes of checks. A certificate expiry check needs certificate metadata; a missing-security-header check needs the response headers; autocomplete needs the form DOM; shoulder surfing requires human observation. Those tests are correctly driven by specialized evidence rather than unrelated exploit strings.

## Current explicit caps

- Directory discovery: 40 candidate requests per scan.
- Sensitive resource checks: 60 candidates per scan with per-response/body limits.
- Helpful-error and internal-path probes: small fixed maximum lists of controlled requests.
- SQLi: maximum 5 reviewed probes per target parameter in the configured default, capped again by scanner config.
- LDAP: synthetic syntax markers; no spraying, directory enumeration, writes or authentication-bypass predicates.
- CORS: a small origin-template set using reserved `.invalid` hosts and `null`.

The cap is a maximum, not a promise that each candidate will be requested; duplicate/invalid inputs can reduce the actual count. Every verdict still depends on response interpretation and the testcase's evidence threshold.
