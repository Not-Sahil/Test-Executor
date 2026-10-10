"""Persist one run of the configured security checks as JSON and HTML.

Folder names and report contents are derived from the caller-supplied target
URL. Do not hardcode hostnames, environments, or site-specific findings.
"""

from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from integrated_scanner import ScanResult, BASE_DIR

OUTPUT_ROOT = BASE_DIR / "output"

TEST_FILE_SLUGS = {
    "banner_grabbing": "01_banner_disclosure",
    "security_header_scanner": "02_security_headers",
    "ip_access_scanner": "03_website_ip_access",
    "host_header_inj": "04_host_header_injection",
    "known_components": "05_known_components",
    "default_credentials": "06_default_credentials",
    "user_enumeration": "07_user_enumeration",
    "helpful_error_messages": "08_helpful_error_messages",
}


def domain_from_target(target: str) -> str:
    """Return a filesystem-safe hostname taken from the supplied target URL."""
    raw = (target or "").strip()
    if not raw:
        return "unknown-target"
    if "://" not in raw:
        raw = "https://" + raw

    host = urlparse(raw).hostname or raw
    host = host.strip(".").lower()
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", host).strip("._-")
    return safe or "unknown-target"


def _test_filename(result: ScanResult, index: int) -> str:
    slug = TEST_FILE_SLUGS.get(result.key)
    if not slug:
        key = re.sub(r"[^a-z0-9]+", "_", (result.key or "test").lower()).strip("_")
        slug = f"{index:02d}_{key or 'test'}"
    return f"{slug}.json"


def create_run_directory(target: str, timestamp: datetime | None = None) -> Path:
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = (timestamp or datetime.now()).strftime("%Y%m%d_%H%M%S")
    domain = domain_from_target(target)
    run_dir = OUTPUT_ROOT / f"{domain}_{stamp}"
    suffix = 2
    while run_dir.exists():
        run_dir = OUTPUT_ROOT / f"{domain}_{stamp}_{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def build_compiled_payload(
    target: str,
    results: Iterable[ScanResult],
    overall: str,
    timestamp: datetime,
    run_dir: Path,
) -> dict:
    result_list = list(results)
    return {
        "target": target,
        "domain": domain_from_target(target),
        "timestamp": timestamp.isoformat(timespec="seconds"),
        "overall_status": overall,
        "run_folder": str(run_dir),
        "tests": [result.as_dict() for result in result_list],
    }


def _status_class(status: str) -> str:
    mapping = {
        "SAFE": "safe",
        "UNSAFE": "unsafe",
        "REVIEW REQUIRED": "review",
        "SKIPPED": "skipped",
        "INCOMPLETE": "incomplete",
        "ERROR": "incomplete",
        "UNKNOWN": "incomplete",
    }
    return mapping.get(status, "incomplete")


def render_compiled_html(payload: dict) -> str:
    target = html.escape(str(payload.get("target", "")))
    domain = html.escape(str(payload.get("domain", "")))
    timestamp = html.escape(str(payload.get("timestamp", "")))
    overall = html.escape(str(payload.get("overall_status", "")))
    overall_class = _status_class(str(payload.get("overall_status", "")))

    rows = []
    sections = []
    for index, test in enumerate(payload.get("tests") or [], start=1):
        name = html.escape(str(test.get("name") or test.get("key") or f"Test {index}"))
        status = html.escape(str(test.get("status", "")))
        summary = html.escape(str(test.get("summary", "")))
        status_class = _status_class(str(test.get("status", "")))
        rows.append(
            "<tr>"
            f"<td>{index}</td>"
            f"<td>{name}</td>"
            f"<td class='{status_class}'>{status}</td>"
            f"<td>{summary}</td>"
            "</tr>"
        )

        details = test.get("details")
        evidence = test.get("evidence") or []
        raw_output = test.get("raw_output") or ""
        extra = []
        if details:
            extra.append(
                "<h3>Structured evidence</h3>"
                f"<pre>{html.escape(json.dumps(details, indent=2, default=str))}</pre>"
            )
        if evidence:
            extra.append(
                "<h3>Evidence</h3>"
                f"<pre>{html.escape(json.dumps(evidence, indent=2, default=str))}</pre>"
            )
        if raw_output:
            extra.append(
                "<h3>Scanner output</h3>"
                f"<pre>{html.escape(str(raw_output))}</pre>"
            )
        extra_html = "\n".join(extra)
        sections.append(
            f"<section><h2>{index}. {name} — "
            f"<span class='{status_class}'>{status}</span></h2>"
            f"<p>{summary}</p>{extra_html}</section>"
        )

    compiled_json = html.escape(json.dumps(payload, indent=2, default=str))
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Test Executor report — {domain}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #1a1a1a; }}
    h1, h2 {{ margin-bottom: 8px; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }}
    th {{ background: #f3f3f3; }}
    pre {{ background: #f7f7f7; padding: 12px; overflow-x: auto; white-space: pre-wrap; }}
    .safe {{ color: #0b7a2b; font-weight: bold; }}
    .unsafe {{ color: #b00020; font-weight: bold; }}
    .review {{ color: #b36b00; font-weight: bold; }}
    .incomplete {{ color: #8a6d00; font-weight: bold; }}
    .skipped {{ color: #555; font-weight: bold; }}
    .banner {{ padding: 12px 16px; border-radius: 6px; background: #fff6d6; }}
  </style>
</head>
<body>
  <h1>Test Executor</h1>
  <div class="banner">OVERALL STATUS: <span class="{overall_class}">{overall}</span></div>
  <p>Target: {target}<br>Domain: {domain}<br>Timestamp: {timestamp}</p>
  <h2>Test summary</h2>
  <table>
    <thead>
      <tr><th>#</th><th>Security Test</th><th>Status</th><th>Summary</th></tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>
  {''.join(sections)}
  <h2>Compiled JSON</h2>
  <pre>{compiled_json}</pre>
</body>
</html>
"""


def save_run_output(
    target: str,
    results: list[ScanResult],
    overall: str,
    timestamp: datetime | None = None,
) -> Path:
    """Write one JSON per test result, plus compiled.json and compiled.html."""
    now = timestamp or datetime.now()
    run_dir = create_run_directory(target, timestamp=now)
    compiled = build_compiled_payload(target, results, overall, now, run_dir)

    for index, result in enumerate(results, start=1):
        path = run_dir / _test_filename(result, index)
        path.write_text(
            json.dumps(result.as_dict(), indent=2, default=str),
            encoding="utf-8",
        )

    (run_dir / "compiled.json").write_text(
        json.dumps(compiled, indent=2, default=str),
        encoding="utf-8",
    )
    (run_dir / "compiled.html").write_text(
        render_compiled_html(compiled),
        encoding="utf-8",
    )
    return run_dir
