from __future__ import annotations

import importlib
import inspect
from typing import Callable, Any

from core.http_client import effective_verify_tls

from .registry import PRE_LOGIN_TESTS


def _find_scanner(module: Any, key: str) -> Callable[..., Any] | None:
    """Resolve the scanner entry point while supporting legacy function names."""
    suffix = key[5:] if key.startswith("tc") and "_" in key else key

    preferred = f"scan_{suffix}"
    if hasattr(module, preferred):
        return getattr(module, preferred)

    # Compatibility with existing scanners whose public function names
    # don't exactly match the testcase key.
    candidates = (
        f"scan_{key[5:]}",
        "scan",
        "scan_banner",
        "scan_known_components",
        "scan_helpful_error_messages",
        "scan_host_header",
        "scan_ip_access",
        "scan_security_headers",
    )

    for candidate in candidates:
        fn = getattr(module, candidate, None)
        if callable(fn):
            return fn
    return None


def _call_scanner(
    scanner: Callable[..., Any],
    target: str,
    *,
    verify_tls: bool,
) -> Any:
    """Call a scanner without relying on a TypeError retry when avoidable."""
    try:
        sig = inspect.signature(scanner)
        parameters = sig.parameters

        if "verify_tls" in parameters:
            return scanner(target, verify_tls=verify_tls)

        return scanner(target)
    except (TypeError, ValueError):
        # Some built-in/callable objects may not expose inspectable signatures.
        try:
            return scanner(target, verify_tls=verify_tls)
        except TypeError:
            return scanner(target)


def run_pre_login_suite(
    target: str,
    *,
    verify_tls: bool = True,
    enabled_keys: set[str] | None = None,
    progress: Callable[[str], None] | None = None,
) -> list[dict]:
    """Run the registered 23-test pre-login suite in deterministic order."""
    verify_tls, tls_note = effective_verify_tls(target, verify_tls)
    if tls_note and progress:
        progress(tls_note)

    results: list[dict] = []

    for key, name, module_name in PRE_LOGIN_TESTS:
        if enabled_keys is not None and key not in enabled_keys:
            continue

        if progress:
            progress(f"Running {name}")

        try:
            module = importlib.import_module(module_name)
            scanner = _find_scanner(module, key)

            if scanner is None:
                results.append({
                    "key": key,
                    "name": name,
                    "status": "INCOMPLETE",
                    "summary": (
                        f"{name} is registered, but its scanner module does not "
                        "expose a supported scan function."
                    ),
                    "details": {"module": module_name},
                    "evidence": [],
                })
                continue

            payload = _call_scanner(
                scanner,
                target,
                verify_tls=verify_tls,
            )

            if hasattr(payload, "as_dict"):
                payload = payload.as_dict()

            payload = dict(payload or {})
            payload.setdefault("key", key)
            payload.setdefault("name", name)
            payload.setdefault("status", "INCOMPLETE")
            payload.setdefault(
                "summary",
                f"{name} did not produce a structured result.",
            )
            payload.setdefault("details", {})
            payload.setdefault("evidence", [])
            payload.setdefault("raw_output", "")

            results.append(payload)

        except Exception as exc:
            results.append({
                "key": key,
                "name": name,
                "status": "ERROR",
                "summary": f"{name} failed to execute: {exc}",
                "details": {
                    "error": str(exc),
                    "exception_type": type(exc).__name__,
                    "module": module_name,
                },
                "evidence": [str(exc)],
                "raw_output": "",
            })

    return results
