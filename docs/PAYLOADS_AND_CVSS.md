# Payload library, source provenance and CVSS v4.0

## Production payload architecture

The executor does **not** blindly execute every entry in SecLists, FuzzDB or PayloadsAllTheThings. Those repositories contain material for many different activities, including credentials, shells, bypasses and destructive or high-impact techniques. A production scanner needs a reviewed execution policy, not an unfiltered wordlist.

The project now uses three layers:

```text
Upstream repositories
        |
        v
payloads/source_catalog.json
        |
        v
payloads/upstream/                 <- fetched cache, never fetched during a scan
        |
        +--> testcase-specific safety policy
        |
        +--> deterministic bounded sampling
        |
        v
payloads/manifest.json             <- runtime allowlist
        |
        v
scanner -> evidence -> SAFE / UNSAFE / REVIEW REQUIRED / INCOMPLETE
```

The official upstream projects are:

- SecLists: <https://github.com/danielmiessler/SecLists>
- PayloadsAllTheThings: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- FuzzDB: <https://github.com/fuzzdb-project/fuzzdb>

SecLists is a broad collection of assessment wordlists; PayloadsAllTheThings is organized by vulnerability/technique and includes README, Intruder and related material; FuzzDB provides attack patterns and discovery primitives. The executor therefore maps only sources relevant to its configured testcases rather than treating a repository as one undifferentiated payload set.

## Refreshing upstream sources

From the project root, on a machine with internet access:

```powershell
python scripts/fetch_payload_sources.py
```

To refresh an existing cache:

```powershell
python scripts/fetch_payload_sources.py --force
```

The resulting `payloads/upstream_sources_manifest.json` records the source URL, local path, byte count and SHA-256 hash. Runtime scans never download payloads from the internet; this makes an assessment reproducible and prevents a source change during a scan from changing the payload set.

The catalog currently covers:

| Repository | Runtime-relevant sources |
|---|---|
| SecLists | web directories, web files, common web content, API endpoints, safe SQLi source material, parameter names |
| FuzzDB | predictable paths/files and response-pattern material |
| PayloadsAllTheThings | SQLi, LDAP and CORS methodology/reference material plus reviewed project-safe active probes |

### Why the whole repositories are not executed

A full repository contains material that should never be silently fired at a client system. Examples include password dumps, credential lists, web shells, destructive SQL, time-delay probes, authentication-bypass predicates and data-exfiltration payloads. The production executor intentionally keeps these outside the automatic scan lane.

### Sampling

Large discovery lists are not sampled by simply taking their first N entries. The loader performs deterministic hash-based sampling using the target/testcase seed. This gives broader coverage while remaining reproducible for the same assessment configuration.

## Current active payload-backed tests

- **TC03 Helpful Error Message** — harmless malformed/nonexistent paths and error sentinels.
- **TC10 Directory Listing** — curated candidates plus bounded deterministic samples from SecLists/FuzzDB web-content sources.
- **TC13 Sensitive File Exposure** — curated sensitive paths plus bounded deterministic samples from SecLists/FuzzDB file sources and safe backup/source variants.
- **TC23 Internal Path Disclosure** — controlled malformed/nonexistent paths.
- **TC13 CORS** — reserved `.invalid` and `null` origins; no cross-origin data exfiltration.
- **TC14 SQL Injection** — eight reviewed non-destructive syntax/differential probes. No writes, stacked queries, time delays, data extraction or authentication-bypass payloads.
- **TC15 LDAP/AD Injection** — synthetic metacharacter markers. No credential spraying, directory enumeration or authentication bypass.

Other testcases are protocol/browser/response-analysis checks and therefore do not need payload wordlists.

## Production scan semantics

`SAFE` means **no signal was observed within the configured test scope**. It does not mean the application is globally secure.

`REVIEW REQUIRED` means the scanner saw suspicious behavior but did not have enough evidence to claim a confirmed vulnerability.

`INCOMPLETE` means the check did not execute to a reliable conclusion. It must not be converted to `SAFE` in client reporting.

## CVSS v4.0

Confirmed `UNSAFE` findings receive a provisional CVSS v4.0 Base vector. The vector and score are evidence-linked estimates. Analysts must validate the actual impact, privileges, attack conditions and business context before external reporting.

Official calculator: <https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator>

## Licensing / attribution

- SecLists: MIT; preserve upstream notices for redistributed extracts.
- PayloadsAllTheThings: MIT according to its repository.
- FuzzDB: review the upstream notices because its repository contains content with different attribution/license terms.

See `payloads/SOURCES_AND_LICENSES.md` before redistributing cached upstream material.
