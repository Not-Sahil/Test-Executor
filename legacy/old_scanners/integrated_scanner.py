
"""
Integrated six-check security scanner.

This module reuses the uploaded scanner implementations:
1. Banner disclosure
2. Security headers
3. Website accessible by IP
4. Host header injection
5. Default credentials
6. User enumeration

The first four scanners are imported and called in-process.
They still use curl for HTTP requests; this orchestrator reads their
returned status instead of scraping printed CLI output.
Default credentials and user enumeration use the existing WSTG authentication lane.

Use only against systems you own or are explicitly authorized to test.
"""

from __future__ import annotations

import io
import json
import subprocess
import sys
import tempfile
from contextlib import redirect_stdout
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Optional

import banner_grabbing
import host_header_inj
import ip_access_scanner
import security_header_scanner
from login_applicability import (
    federated_login_skip,
    format_not_applicable_summary,
    skip_evidence,
)

BASE_DIR = Path(__file__).resolve().parent

SCANNERS = {
    "default_runner": BASE_DIR / "run_default_creds_tests.py",
}


@dataclass
class ScanResult:
    key: str
    name: str
    status: str
    summary: str
    raw_output: str = ""
    evidence: list[str] | None = None
    details: dict | None = None

    def as_dict(self):
        return asdict(self)


_INCOMPLETE_STATUSES = {"ERROR", "UNKNOWN", "INCOMPLETE"}
_LOGIN_MISSING_STATUSES = {"unresolved"}
_RESOLVED_AUTH_MECHANISMS = {"form", "browser_form", "http_basic"}


def _incomplete_summary(output: str) -> str:
    if "CONNECTION ERROR" in output:
        return (
            "The scanner did not complete because the target request failed. "
            "This is not a SAFE or UNSAFE security finding."
        )
    if "ERROR:" in output or "CURL ERROR:" in output:
        return (
            "The scanner did not complete due to an error. "
            "See scanner output for details. This is not a SAFE finding."
        )
    return (
        "The scanner finished without a structured SAFE/UNSAFE result. "
        "See scanner output for details."
    )


def _run_inprocess_scanner(
    key: str,
    name: str,
    scan_fn: Callable[[str], dict | None],
    target: str,
    progress: Optional[Callable[[str], None]] = None,
) -> ScanResult:
    """Call a scanner function directly instead of scraping CLI stdout."""
    if progress:
        progress(f"Starting {name}")
        progress(f"Running {name}")

    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            payload = scan_fn(target) or {}
    except Exception as exc:
        return ScanResult(
            key=key,
            name=name,
            status="ERROR",
            summary=f"Scanner error: {exc}",
            details={"error": str(exc)},
        )

    raw = buf.getvalue()
    if not isinstance(payload, dict) or not payload:
        return ScanResult(
            key=key,
            name=name,
            status="INCOMPLETE",
            summary=_incomplete_summary(raw),
            raw_output=raw,
        )

    status = str(payload.get("status") or "INCOMPLETE")
    summary = str(payload.get("summary") or "").strip() or (
        _incomplete_summary(raw) if status in _INCOMPLETE_STATUSES else "Scanner completed."
    )
    return ScanResult(
        key=key,
        name=name,
        status=status,
        summary=summary,
        raw_output=raw,
        evidence=payload.get("evidence") or None,
        details=payload.get("details") or None,
    )


def _login_discovery_summary(test_name: str, login_path: str, evidence: list | None) -> str:
    path = login_path or "/login"
    extra = ""
    joined = " ".join(str(item) for item in (evidence or []) if item)
    if joined:
        extra = f" Discovery detail: {joined}"
    return (
        f"{test_name} did not find a usable login form at '{path}'. "
        "This is not a SAFE or UNSAFE finding. "
        "Enter the real login page path and rerun."
        f"{extra}"
    )


def _lane_is_not_applicable(payload: dict) -> bool:
    mechanism = str(payload.get("auth_mechanism") or "").lower()
    summary = str(payload.get("summary") or "")
    joined = " ".join(str(item) for item in (payload.get("evidence") or []) if item)
    if summary.startswith("Not applicable"):
        return True
    if mechanism in {"federated_idp", "hosted_identity_provider", "oauth_oidc_authorize"}:
        return True
    return "not_applicable" in joined


def _auth_mechanism_resolved(payload: dict) -> bool:
    mechanism = str(payload.get("auth_mechanism") or "").lower()
    if mechanism in _RESOLVED_AUTH_MECHANISMS:
        return True
    joined = " ".join(str(item) for item in (payload.get("evidence") or []) if item)
    return any(
        marker in joined
        for marker in (
            "discovered form",
            "mechanism=form",
            "mechanism=http_basic",
            "mechanism=browser_form",
        )
    )


def _not_applicable_auth_result(key: str, name: str, skip: dict) -> ScanResult:
    reason = skip.get("reason") or "federated authentication is in use"
    final_url = skip.get("final_url") or skip.get("matched_url") or skip.get("login_url")
    hops = skip.get("redirect_hops") or []
    return ScanResult(
        key=key,
        name=name,
        status="SKIPPED",
        summary=format_not_applicable_summary(name, skip),
        evidence=skip_evidence(skip),
        details={
            "not_applicable": True,
            "classification": skip.get("classification"),
            "login_url": skip.get("login_url"),
            "identity_provider_url": final_url,
            "target_host": skip.get("target_host"),
            "login_host": skip.get("login_host"),
            "redirect_hops": hops,
            "reason": reason,
        },
    )


def _load_json_result(path: Path) -> list[dict]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return []


def _write_json(path: Path, data) -> None:
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def run_default_credentials(
    target: str,
    login_path: str,
    credential_pairs: list[dict],
    max_attempts: int = 5,
    verify_tls: bool = True,
    progress: Optional[Callable[[str], None]] = None,
) -> ScanResult:
    """
    Run the existing WSTG-ATHN-02 lane with a caller-supplied credential list.
    This avoids silently using a large wordlist against a live target.
    """
    if not credential_pairs:
        return ScanResult(
            key="default_credentials",
            name="Default Credentials",
            status="SKIPPED",
            summary="No authorized credential pairs were supplied.",
        )

    if progress:
        progress("Running default-credential check")

    with tempfile.TemporaryDirectory(prefix="sixscan_") as td:
        td = Path(td)
        cases = [{
            "test_case_id": "TC-INTEGRATED-DEFCRED",
            "target": target,
            "is_http": True,
            "service_or_path": login_path or "/login",
            "max_attempts": min(max_attempts, len(credential_pairs)),
            "verify_tls": bool(verify_tls),
            "enabled": True,
        }]
        cases_path = td / "cases.json"
        creds_path = td / "creds.json"
        out_path = td / "results.json"
        _write_json(cases_path, cases)
        _write_json(creds_path, credential_pairs)

        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCANNERS["default_runner"]),
                    "--input", str(cases_path),
                    "--creds", str(creds_path),
                    "--output", str(out_path),
                    "--max-attempts", str(min(max_attempts, len(credential_pairs))),
                ],
                text=True,
                capture_output=True,
                cwd=str(BASE_DIR),
                timeout=300,
            )
            raw = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
            results = _load_json_result(out_path)

            if not results:
                return ScanResult(
                    key="default_credentials",
                    name="Default Credentials",
                    status="ERROR",
                    summary="No structured result was produced.",
                    raw_output=raw,
                )

            r = results[0]
            lane_status = str(r.get("result", "unresolved")).lower()
            successful_pairs = r.get("successful_pairs") or []

            if successful_pairs or lane_status == "vulnerable":
                status = "UNSAFE"
                summary = "A supplied credential pair successfully authenticated."
            elif lane_status == "not_vulnerable":
                status = "SAFE"
                summary = "None of the supplied credential pairs authenticated."
            elif lane_status == "lockout_aborted":
                status = "REVIEW REQUIRED"
                summary = "The lockout/attempt guard stopped the credential test."
            elif lane_status == "skipped" or _lane_is_not_applicable(r):
                status = "SKIPPED"
                summary = str(r.get("summary") or "").strip()
                if not summary.startswith("Not applicable"):
                    summary = (
                        "Not applicable: this login is federated SSO / identity-provider "
                        "sign-in, not a local username/password form. Default Credentials "
                        "was skipped."
                    )
            elif lane_status in _LOGIN_MISSING_STATUSES and not _auth_mechanism_resolved(r):
                status = "INCOMPLETE"
                summary = _login_discovery_summary(
                    "Default Credentials",
                    login_path,
                    r.get("evidence"),
                )
            else:
                status = "ERROR" if lane_status == "error" else "INCOMPLETE"
                summary = (
                    "The authentication check could not be completed. "
                    f"Lane result: {lane_status}. This is not a SAFE finding."
                )

            return ScanResult(
                key="default_credentials",
                name="Default Credentials",
                status=status,
                summary=summary,
                raw_output=raw,
                evidence=r.get("evidence", []),
                details={
                    "auth_mechanism": r.get("auth_mechanism"),
                    "attempts_made": r.get("attempts_made"),
                    "successful_pairs": r.get("successful_pairs", []),
                    "target": r.get("target"),
                },
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                key="default_credentials",
                name="Default Credentials",
                status="ERROR",
                summary="The default-credential check timed out.",
            )


def run_user_enumeration(
    target: str,
    login_path: str,
    candidate_usernames: list[str],
    probe_password: str = "__wrong_password_idnt04__",
    max_attempts: int | None = None,
    known_valid_username: str | None = None,
    verify_tls: bool = True,
    progress: Optional[Callable[[str], None]] = None,
) -> ScanResult:
    """Run the existing WSTG-IDNT-04 implementation."""
    if not candidate_usernames:
        return ScanResult(
            key="user_enumeration",
            name="User Enumeration",
            status="SKIPPED",
            summary="No authorized candidate usernames were supplied.",
        )

    if progress:
        progress("Running user-enumeration check")

    with tempfile.TemporaryDirectory(prefix="sixscan_enum_") as td:
        td = Path(td)
        cases = [{
            "test_case_id": "TC-INTEGRATED-IDNT04",
            "target": target,
            "is_http": True,
            "service_or_path": login_path or "/login",
            "test_type": "enumeration",
            "candidate_usernames": candidate_usernames,
            "probe_password": probe_password,
            "known_valid_username": known_valid_username,
            "verify_tls": bool(verify_tls),
            "enabled": True,
        }]
        cases_path = td / "cases.json"
        creds_path = td / "creds.json"
        out_path = td / "results.json"

        # Runner requires --creds even for enumeration; provide an empty list.
        _write_json(cases_path, cases)
        _write_json(creds_path, [])
        _write_json(out_path, [])

        try:
            proc = subprocess.run(
                [
                    sys.executable,
                    str(SCANNERS["default_runner"]),
                    "--input", str(cases_path),
                    "--creds", str(creds_path),
                    "--output", str(out_path),
                ],
                text=True,
                capture_output=True,
                cwd=str(BASE_DIR),
                timeout=240,
            )
            raw = (proc.stdout or "") + (("\n" + proc.stderr) if proc.stderr else "")
            results = _load_json_result(out_path)

            if not results:
                return ScanResult(
                    key="user_enumeration",
                    name="User Enumeration",
                    status="ERROR",
                    summary="No structured enumeration result was produced.",
                    raw_output=raw,
                )

            r = results[0]
            lane_status = str(r.get("result", "")).lower()
            candidates = r.get("candidates", [])
            site_behavior = r.get("signal_used") or r.get("site_behavior", "")

            likely_valid = [
                c.get("username")
                for c in candidates
                if c.get("classification") == "likely_valid"
            ]
            inconclusive = [
                c.get("username")
                for c in candidates
                if c.get("classification") == "inconclusive"
            ]

            if likely_valid:
                status = "UNSAFE"
                disclosed = [
                    c.get("username")
                    for c in candidates
                    if (c.get("signals") or {}).get("page_disclosure")
                ]
                if disclosed:
                    summary = (
                        "The login page disclosed account identifier(s), which is "
                        "username enumeration / information disclosure."
                    )
                else:
                    summary = "The login flow exposed response differences consistent with account enumeration."
            elif lane_status == "skipped" or _lane_is_not_applicable(r):
                status = "SKIPPED"
                summary = str(r.get("summary") or "").strip()
                if not summary.startswith("Not applicable"):
                    summary = (
                        "Not applicable: this login is federated SSO / identity-provider "
                        "sign-in, not a local username/password form. User Enumeration "
                        "was skipped."
                    )
            elif (
                "login_form_not_found" in str(site_behavior)
                or (
                    lane_status in _LOGIN_MISSING_STATUSES
                    and not candidates
                    and not _auth_mechanism_resolved(r)
                )
            ):
                status = "INCOMPLETE"
                summary = _login_discovery_summary(
                    "User Enumeration",
                    login_path,
                    [site_behavior] if site_behavior else None,
                )
            elif inconclusive:
                status = "REVIEW REQUIRED"
                summary = "Some username probes produced inconclusive response differences."
            elif lane_status == "not_vulnerable":
                status = "SAFE"
                summary = "No username was classified as likely valid by the configured signals."
            elif lane_status == "lockout_aborted":
                status = "REVIEW REQUIRED"
                summary = "The lockout/attempt guard stopped the enumeration test."
            elif lane_status == "error":
                status = "ERROR"
                summary = "The user-enumeration check could not be completed. This is not a SAFE finding."
            else:
                status = "SAFE"
                summary = "No username was classified as likely valid by the configured signals."

            return ScanResult(
                key="user_enumeration",
                name="User Enumeration",
                status=status,
                summary=summary,
                raw_output=raw,
                evidence=[c.get("evidence", "") for c in candidates],
                details={
                    "site_behavior": site_behavior,
                    "candidates": candidates,
                    "likely_valid_usernames": likely_valid,
                    "inconclusive_usernames": inconclusive,
                },
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                key="user_enumeration",
                name="User Enumeration",
                status="ERROR",
                summary="The user-enumeration check timed out.",
            )


def run_first_four_tests(
    target: str,
    progress: Optional[Callable[[str], None]] = None,
) -> list[ScanResult]:
    """Banner, security headers, IP access, and host-header checks."""
    results: list[ScanResult] = []
    ordered = [
        ("banner_grabbing", "Banner Disclosure", banner_grabbing.scan_banner),
        ("security_header_scanner", "Security Headers", security_header_scanner.scan_security_headers),
        ("ip_access_scanner", "Website IP Access", ip_access_scanner.scan_ip_access),
        ("host_header_inj", "Host Header Injection", host_header_inj.scan_host_header),
    ]
    for key, name, scan_fn in ordered:
        results.append(
            _run_inprocess_scanner(key, name, scan_fn, target, progress=progress)
        )
    return results


def captcha_auth_result(
    key: str,
    name: str,
    status: str,
    summary: str,
    evidence: list[str] | None = None,
    details: dict | None = None,
) -> ScanResult:
    return ScanResult(
        key=key,
        name=name,
        status=status,
        summary=summary,
        evidence=evidence or [],
        details=details or {},
    )


def run_all(
    target: str,
    login_path: str = "/login",
    credential_pairs: Optional[list[dict]] = None,
    candidate_usernames: Optional[list[str]] = None,
    max_credential_attempts: int = 5,
    probe_password: str = "__wrong_password_idnt04__",
    verify_tls: bool = True,
    progress: Optional[Callable[[str], None]] = None,
) -> list[ScanResult]:
    """
    Execute all six checks sequentially.
    The first four scanners are called in-process; the last two use the
    existing WSTG authentication lane.
    """
    results: list[ScanResult] = run_first_four_tests(target, progress=progress)

    auth_skip = federated_login_skip(target, login_path)
    if auth_skip:
        if progress:
            progress(
                "Skipping Default Credentials and User Enumeration: "
                "login is federated SSO / identity-provider (not applicable)"
            )
        results.append(
            _not_applicable_auth_result(
                "default_credentials",
                "Default Credentials",
                auth_skip,
            )
        )
        results.append(
            _not_applicable_auth_result(
                "user_enumeration",
                "User Enumeration",
                auth_skip,
            )
        )
        return results

    results.append(run_default_credentials(
        target=target,
        login_path=login_path,
        credential_pairs=credential_pairs or [],
        max_attempts=max_credential_attempts,
        verify_tls=verify_tls,
        progress=progress,
    ))

    results.append(run_user_enumeration(
        target=target,
        login_path=login_path,
        candidate_usernames=candidate_usernames or [],
        probe_password=probe_password,
        progress=progress,
    ))

    return results


def overall_status(results: list[ScanResult]) -> str:
    statuses = {r.status for r in results if r.status != "SKIPPED"}
    if "UNSAFE" in statuses:
        return "UNSAFE"
    if "REVIEW REQUIRED" in statuses:
        return "REVIEW REQUIRED"
    if statuses & _INCOMPLETE_STATUSES:
        return "INCOMPLETE"
    if statuses and statuses <= {"SAFE"}:
        return "SAFE"
    return "INCOMPLETE"