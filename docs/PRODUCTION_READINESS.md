# Production-readiness changes

This release hardens the existing Test Executor for authorized client assessments. It is **production-hardened software, not a guarantee that every web vulnerability is detectable**. Live client use still requires engagement-specific authorization, monitoring, rate limits, staging validation and analyst review.

## Changes made

### Payloads

- Added `payloads/source_catalog.json` as the canonical upstream-source map.
- Expanded the upstream allowlist to testcase-relevant SecLists, FuzzDB and PayloadsAllTheThings material.
- Reworked `scripts/fetch_payload_sources.py` to stage only catalogued files and write SHA-256 provenance.
- Corrected the FuzzDB response dictionary source from the obsolete `regex/errors.xml` path to the current `regex/errors.txt` source and vendored the supplied upstream copy for reproducible TC03/TC23 response analysis.
- Added deterministic hash-based sampling for large wordlists so scans do not always use the first lines.
- Increased directory/file discovery coverage while retaining hard request budgets.
- Expanded the reviewed SQLi probe set from 5 to 8 non-destructive probes.
- Kept destructive SQL, time delays, auth bypass, credential spraying, shells and exfiltration out of the automatic lane.
- Removed the unused built-in default credential seed so credentials come from explicit operator input only.

### Target/network safety

- Added `core/target_policy.py`.
- Rejects embedded credentials in target URLs.
- Rejects loopback/private/link-local/multicast/reserved/unspecified destinations by default.
- Supports explicitly authorized internal/lab targets through `ALLOW_PRIVATE_TARGETS=1`.
- Requires an explicit written-authorization acknowledgement in the UI.
- Restricts login paths and protected URLs to the target origin.

### Result/reporting integrity

- Reports now include a payload-manifest SHA-256 hash.
- Added report-level secret redaction for common credential/token/header fields.
- Target query parameters containing likely secrets are redacted in reports.
- Existing `SAFE`, `UNSAFE`, `REVIEW REQUIRED` and `INCOMPLETE` semantics are preserved.

### Maintainability

- Added a canonical 17-test login registry.
- Fixed the missing `urlunparse` import in the shared scanner URL helper.
- Added target-policy and payload-source tests.
- Reworked SQLi unit tests to use the standard library instead of a third-party HTTP mocking dependency.

## Validation performed

- `python -m compileall -q .` — passed.
- `python -m pytest -q` — **136 tests passed** in the build environment.
- Local SQLi integration smoke test against a disposable local HTTP server produced the expected `UNSAFE` signal for a simulated SQL-error response.
- Payload source catalog validation passed.

## Required deployment step

A fresh deployment must run:

```bash
python scripts/fetch_payload_sources.py
```

before client scans so the upstream cache is populated. Review the generated `payloads/upstream_sources_manifest.json` and keep it with the assessment configuration.

## What production-ready does not mean

The executor is not a substitute for a full manual penetration test or a mature DAST platform. `SAFE` is bounded negative evidence, not proof of absence. Coverage depends on the testcase matrix, discovered endpoints/parameters, authentication state, request budgets and application behavior.

Before external client delivery, validate the exact build in an isolated vulnerable-application test suite and retain engagement authorization, scan configuration, payload manifest hash and final analyst review with the report.
