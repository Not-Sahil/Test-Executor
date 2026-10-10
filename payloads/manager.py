"""Safe, file-backed payload access for testcase scanners.

Only files explicitly named in payloads/manifest.json are part of the active
curated library. This module deliberately rejects paths outside payloads/ and
supports bounded loading and de-duplication.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
MANIFEST_PATH = ROOT / "manifest.json"

SOURCE_CATALOG_PATH = ROOT / "source_catalog.json"


def _read_source_catalog() -> dict[str, Any]:
    try:
        value = json.loads(SOURCE_CATALOG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not load payload source catalog: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("sources"), list):
        raise ValueError("payloads/source_catalog.json must contain a sources list")
    return value


def bounded_sample(items: list[str], limit: int, *, seed: str = "") -> list[str]:
    """Select a deterministic, coverage-oriented subset instead of always taking the head.

    Hash ordering avoids bias toward the first lines of a wordlist while keeping
    results reproducible for the same target/testcase seed.
    """
    if limit <= 0:
        return []
    unique = list(dict.fromkeys(str(item).strip() for item in items if str(item).strip()))
    if len(unique) <= limit:
        return unique
    ranked = sorted(unique, key=lambda item: hashlib.sha256((seed + "\0" + item).encode("utf-8", "ignore")).hexdigest())
    return ranked[:limit]


def load_optional_sample(relative_path: str, limit: int, *, seed: str = "") -> list[str]:
    """Load a complete optional upstream list and deterministically sample it."""
    if limit <= 0:
        return []
    path = _safe_path(relative_path)
    if not path.is_file():
        return []
    return bounded_sample(load_lines(relative_path), limit, seed=seed or relative_path)


def source_catalog_summary() -> dict[str, Any]:
    catalog = _read_source_catalog()
    sources = []
    for item in catalog["sources"]:
        local = str(item.get("local", ""))
        path = _safe_path(local) if local else None
        sources.append({
            **item,
            "cached": bool(path and path.is_file()),
            "bytes": path.stat().st_size if path and path.is_file() else 0,
        })
    return {
        "schema_version": catalog.get("schema_version", 1),
        "policy": catalog.get("policy", {}),
        "sources": sources,
    }



def _safe_path(relative_path: str) -> Path:
    raw = Path(str(relative_path).replace("\\", "/"))
    if raw.is_absolute() or any(part in {"..", ""} for part in raw.parts):
        raise ValueError(f"Payload path must be relative and remain inside payloads/: {relative_path!r}")
    path = (ROOT / raw).resolve()
    if not path.is_relative_to(ROOT.resolve()):
        raise ValueError(f"Payload path escapes payload library: {relative_path!r}")
    return path


def _read_manifest() -> dict[str, Any]:
    try:
        value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Could not load payload manifest: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("testcases"), dict):
        raise ValueError("payloads/manifest.json must contain a testcase mapping")
    return value


def get_testcase_spec(testcase_key: str) -> dict[str, Any]:
    return dict(_read_manifest().get("testcases", {}).get(testcase_key, {}))


def load_lines(
    relative_path: str,
    limit: int | None = None,
    substitutions: dict[str, str] | None = None,
) -> list[str]:
    """Load non-empty, non-comment text lines with safe optional token substitution."""
    if limit is not None and int(limit) <= 0:
        return []
    path = _safe_path(relative_path)
    if not path.is_file():
        raise FileNotFoundError(f"Payload source not found: {relative_path}")
    subs = substitutions or {}
    lines: list[str] = []
    seen: set[str] = set()
    for raw in path.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        item = raw.strip()
        if not item or item.startswith(("#", ";")):
            continue
        for key, value in subs.items():
            item = item.replace("{{" + key + "}}", str(value))
        if item not in seen:
            lines.append(item)
            seen.add(item)
        if limit is not None and len(lines) >= max(0, int(limit)):
            break
    return lines



def load_optional_lines(relative_path: str, limit: int | None = None) -> list[str]:
    """Load an optional upstream-cache file when fetched; otherwise return []."""
    path = _safe_path(relative_path)
    if not path.is_file():
        return []
    return load_lines(relative_path, limit=limit)


def load_json_records(relative_path: str, limit: int | None = None) -> list[dict[str, Any]]:
    path = _safe_path(relative_path)
    if not path.is_file():
        raise FileNotFoundError(f"Payload source not found: {relative_path}")
    parsed = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(parsed, list):
        raise ValueError(f"JSON payload file must contain a list: {relative_path}")
    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for item in parsed:
        if not isinstance(item, dict) or not item.get("value"):
            continue
        key = (str(item.get("name", "")), str(item["value"]))
        if key in seen:
            continue
        seen.add(key)
        records.append(dict(item))
        if limit is not None and len(records) >= max(0, int(limit)):
            break
    return records


def testcase_payloads(testcase_key: str) -> list[str]:
    """Return payload file paths configured for a testcase (metadata only)."""
    spec = get_testcase_spec(testcase_key)
    return [str(p) for p in spec.get("files", [])]


def payload_library_summary() -> dict[str, Any]:
    manifest = _read_manifest()
    testcases: list[dict[str, Any]] = []
    source_names = {
        "seclists/": "SecLists (curated/project-managed subset)",
        "payloads_all_the_things/": "PayloadsAllTheThings (curated/project-managed subset)",
        "fuzzdb/": "FuzzDB (curated/project-managed subset)",
        "upstream/SecLists/": "SecLists (optional upstream cache)",
        "upstream/PayloadsAllTheThings/": "PayloadsAllTheThings (optional upstream references)",
        "upstream/FuzzDB/": "FuzzDB (optional upstream cache)",
    }
    active_files: set[str] = set()
    for key, spec in manifest["testcases"].items():
        files = [str(p) for p in spec.get("files", [])]
        optional_files = [str(p) for p in spec.get("optional_upstream_files", [])]
        active_files.update(files)
        active_files.update(p for p in optional_files if _safe_path(p).is_file())
        total = 0
        for relative in files + [p for p in optional_files if _safe_path(p).is_file()]:
            try:
                p = _safe_path(relative)
                if p.suffix.lower() == ".json":
                    total += len(load_json_records(relative))
                elif p.is_file():
                    total += len(load_lines(relative))
            except (OSError, ValueError, json.JSONDecodeError):
                pass
        testcases.append({
            "testcase": key,
            "label": str(spec.get("label", key)),
            "files": files,
            "item_count": total,
            "max_items": int(spec.get("max_items", total or 0)),
            "execution": str(spec.get("execution", "bounded")),
            "purpose": str(spec.get("purpose", "")),
        })
    sources = sorted({name for path in active_files for prefix, name in source_names.items() if path.startswith(prefix)})
    return {
        "schema_version": manifest.get("schema_version", 1),
        "active_testcase_count": len(testcases),
        "active_file_count": len(active_files),
        "total_curated_items": sum(item["item_count"] for item in testcases),
        "sources": sources,
        "testcases": testcases,
    }
