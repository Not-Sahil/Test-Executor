# Payload sources, provenance and licensing

The executor uses a **reviewed, testcase-specific subset** of three upstream projects. It does not claim or require a complete mirror of any repository.

## SecLists

- Repository: <https://github.com/danielmiessler/SecLists>
- License: MIT
- Relevant paths configured in `payloads/source_catalog.json`:
  - `Discovery/Web-Content/raft-small-directories.txt`
  - `Discovery/Web-Content/raft-small-files.txt`
  - `Discovery/Web-Content/common.txt`
  - `Discovery/Web-Content/api/api-endpoints.txt`
  - `Discovery/Web-Content/burp-parameter-names.txt`
  - `Fuzzing/Databases/SQLi/quick-SQLi.txt` (source material only; active execution is filtered)

SecLists contains many other categories, including credentials and web shells. Those are not automatically loaded into client scans.

## PayloadsAllTheThings

- Repository: <https://github.com/swisskyrepo/PayloadsAllTheThings>
- License: MIT according to upstream
- Relevant paths:
  - `SQL Injection/README.md`
  - `LDAP Injection/README.md`
  - `CORS Misconfiguration/README.md`

These upstream pages are treated as methodology/reference material. The runtime active probes are project-reviewed, non-destructive files whose provenance is recorded in the payload manifest. This prevents a documentation update from silently changing a live client's scan behavior.

## FuzzDB

- Repository: <https://github.com/fuzzdb-project/fuzzdb>
- Relevant areas:
  - `discovery/predictable-filepaths/`
  - `regex/errors.txt` (vendored in `payloads/upstream/FuzzDB/regex/errors.txt` for reproducible response matching)
- Licensing/attribution: review the upstream repository's notices for the specific redistributed content. FuzzDB includes content with different attribution/license terms.

## Cache and reproducibility

`payloads/upstream/` is a local cache/vendor area. The FuzzDB `regex/errors.txt` source is vendored so the response-analysis dictionary remains available even when an upstream path or network is unavailable. `scripts/fetch_payload_sources.py` creates `payloads/upstream_sources_manifest.json` containing the fetched URL, local path, byte count and SHA-256 hash for every source.

The runtime scanner never fetches a payload from GitHub during a client assessment.

## Safety policy

The automatic client-scan lane excludes public password dumps, credential spraying lists, web shells, destructive SQL, time-delay SQL, authentication-bypass payloads, command execution, internal-address SSRF probes and data-exfiltration payloads.

If a future testcase requires a higher-risk technique, it must be introduced as a separate explicitly enabled assessment mode with its own authorization, request budget, evidence model and tests. It should not be added by simply pointing the manifest at an upstream wordlist.
