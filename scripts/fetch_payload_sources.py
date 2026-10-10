#!/usr/bin/env python3
"""Fetch the allowlisted upstream payload sources used by the scanners.

The project intentionally does not execute an entire security repository.
Instead, this script stages only the source files mapped in
payloads/source_catalog.json. Runtime scanners use bounded deterministic
sampling and testcase-specific safety policies. Every fetched file is recorded
with its URL, byte count and SHA-256 so an assessment can be reproduced.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
PAYLOAD_ROOT = ROOT / "payloads"
CATALOG_PATH = PAYLOAD_ROOT / "source_catalog.json"
MAX_FILE_BYTES = 20 * 1024 * 1024
USER_AGENT = "TestExecutor-PayloadSourceFetcher/2.0"


def _catalog() -> list[dict]:
    data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
    sources = data.get("sources")
    if not isinstance(sources, list) or not sources:
        raise ValueError("source_catalog.json contains no sources")
    return sources


def _raw_url(entry: dict) -> str:
    repo = str(entry["repository"]).lower()
    path = quote(str(entry["path"]), safe="/-_.~")
    if repo == "seclists":
        owner_repo = "danielmiessler/SecLists"
    elif repo == "fuzzdb":
        owner_repo = "fuzzdb-project/fuzzdb"
    elif repo == "payloadsallthethings":
        owner_repo = "swisskyrepo/PayloadsAllTheThings"
    else:
        raise ValueError(f"Unsupported repository in catalog: {entry.get('repository')!r}")
    return f"https://raw.githubusercontent.com/{owner_repo}/master/{path}"


def fetch(entry: dict, *, force: bool = False) -> dict:
    relative = str(entry["local"])
    destination = (PAYLOAD_ROOT / relative).resolve()
    if not destination.is_relative_to(PAYLOAD_ROOT.resolve()):
        raise ValueError(f"Catalog path escapes payloads/: {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.exists() and not force:
        data = destination.read_bytes()
        return {
            **entry,
            "url": _raw_url(entry),
            "status": "kept_existing",
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }

    url = _raw_url(entry)
    request = Request(
        url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain,text/markdown,application/xml,*/*"},
    )
    with urlopen(request, timeout=30) as response:
        data = response.read(MAX_FILE_BYTES + 1)
        if len(data) > MAX_FILE_BYTES:
            raise ValueError(f"Refusing source larger than {MAX_FILE_BYTES} bytes: {url}")
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status}: {url}")
    if not data.strip():
        raise ValueError(f"Downloaded empty source: {url}")

    destination.write_bytes(data)
    return {
        **entry,
        "url": url,
        "status": "downloaded",
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="refresh existing cached sources")
    parser.add_argument("--manifest-only", action="store_true", help="write the source manifest without downloading")
    args = parser.parse_args()

    results = []
    failures = 0
    for entry in _catalog():
        try:
            if args.manifest_only:
                result = {**entry, "url": _raw_url(entry), "status": "not_downloaded"}
            else:
                result = fetch(entry, force=args.force)
            print(f"[{result['status']}] {entry['repository']}: {entry['path']}")
            results.append(result)
        except Exception as exc:
            failures += 1
            result = {**entry, "url": _raw_url(entry), "status": "failed", "error": f"{type(exc).__name__}: {exc}"}
            results.append(result)
            print(f"[failed] {entry['repository']}: {entry['path']}: {exc}", file=sys.stderr)

    manifest = {
        "schema_version": 2,
        "generated_at_unix": int(time.time()),
        "catalog": "payloads/source_catalog.json",
        "notice": "Upstream cache only. Runtime execution is controlled by testcase safety policy and bounded deterministic sampling.",
        "sources": results,
    }
    out = PAYLOAD_ROOT / "upstream_sources_manifest.json"
    out.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"Source manifest: {out.relative_to(ROOT)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
