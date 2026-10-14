"""Gray-Box Security Testing Report Generator.

Generates structured JSON, client-ready HTML, and Markdown reports
including payload execution coverage, evidence, CVSS risk levels, and remediation guidance.
"""
from __future__ import annotations

import html
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from graybox.artifacts import redact_text_secrets
from graybox.models import GrayBoxConfig, GrayBoxResult, ResultStatus
from graybox.runner import calculate_suite_metrics

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_ROOT = BASE_DIR / "output"


def _safe_domain(target: str) -> str:
    raw = (target or "").strip()
    if not raw:
        return "unknown_target"
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    raw = raw.split("/", 1)[0].split(":", 1)[0]
    safe = re.sub(r"[^a-zA-Z0-9._-]+", "_", raw).strip("._-")
    return safe or "target"


def create_graybox_run_directory(target: str, timestamp: datetime | None = None) -> Path:
    """Create a unique run directory in output/ for this Gray-Box scan."""
    OUTPUT_ROOT.mkdir(parents=True, exist_ok=True)
    stamp = (timestamp or datetime.now()).strftime("%Y%m%d_%H%M%S")
    domain = _safe_domain(target)
    run_dir = OUTPUT_ROOT / f"graybox_{domain}_{stamp}"
    suffix = 2
    while run_dir.exists():
        run_dir = OUTPUT_ROOT / f"graybox_{domain}_{stamp}_{suffix}"
        suffix += 1
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir


def sanitize_dict_secrets(val: Any) -> Any:
    """Recursively redact secrets in dicts, lists, and strings."""
    if isinstance(val, dict):
        out = {}
        for k, v in val.items():
            k_lower = str(k).lower().replace("-", "_")
            if any(s in k_lower for s in ("password", "token", "secret", "cookie", "auth")):
                out[k] = "[REDACTED]"
            else:
                out[k] = sanitize_dict_secrets(v)
        return out
    if isinstance(val, list):
        return [sanitize_dict_secrets(item) for item in val]
    if isinstance(val, str):
        return redact_text_secrets(val)
    return val


def render_graybox_html(report_data: dict[str, Any]) -> str:
    """Render a clean, professional HTML report for client-facing security assessments."""
    target = html.escape(str(report_data.get("target", "")))
    timestamp = html.escape(str(report_data.get("timestamp", "")))
    metrics = report_data.get("metrics", {})
    status_counts = metrics.get("status_counts", {})
    payload_cov = metrics.get("payload_coverage", {})
    coverage_pct = payload_cov.get("coverage_percentage", 100.0)

    unsafe_count = status_counts.get("UNSAFE", 0)
    safe_count = status_counts.get("SAFE", 0)
    review_count = status_counts.get("REVIEW REQUIRED", 0)
    not_assessed_count = status_counts.get("NOT ASSESSED", 0)
    incomplete_count = status_counts.get("INCOMPLETE", 0)

    overall_badge = "UNSAFE" if unsafe_count > 0 else ("REVIEW REQUIRED" if review_count > 0 else "SAFE")
    overall_color = "#e53e3e" if unsafe_count > 0 else ("#dd6b20" if review_count > 0 else "#38a169")

    # Build rows
    rows_html = []
    tests = report_data.get("results", [])
    for idx, test in enumerate(tests, start=1):
        tc_id = html.escape(test.get("testcase_id", ""))
        name = html.escape(test.get("name", ""))
        cat = html.escape(test.get("category", ""))
        status = html.escape(test.get("status", ""))
        summary = html.escape(test.get("summary", ""))

        status_class = "safe"
        if status == "UNSAFE":
            status_class = "unsafe"
        elif status == "REVIEW REQUIRED":
            status_class = "review"
        elif status in ("NOT ASSESSED", "INCOMPLETE", "ERROR"):
            status_class = "incomplete"

        rows_html.append(f"""
        <tr>
            <td>{idx}</td>
            <td><code>{tc_id}</code></td>
            <td><strong>{name}</strong><br><small style="color:#718096;">{cat}</small></td>
            <td><span class="badge badge-{status_class}">{status}</span></td>
            <td>{summary}</td>
        </tr>
        """)

    # Build detail accordions
    details_html = []
    for test in tests:
        tc_id = html.escape(test.get("testcase_id", ""))
        name = html.escape(test.get("name", ""))
        status = html.escape(test.get("status", ""))
        evidence_items = test.get("evidence", [])
        evidence_str = "".join(f"<li>{html.escape(str(e))}</li>" for e in evidence_items) or "<li>No evidence recorded.</li>"
        details_json = html.escape(json.dumps(test.get("details", {}), indent=2, default=str))

        details_html.append(f"""
        <div class="testcase-card">
            <div class="testcase-header">
                <strong>[{tc_id}] {name}</strong> — <span class="badge">{status}</span>
            </div>
            <p><strong>Summary:</strong> {html.escape(test.get("summary", ""))}</p>
            <h4>Observed Evidence</h4>
            <ul>{evidence_str}</ul>
            <h4>Technical Details</h4>
            <pre>{details_json}</pre>
        </div>
        """)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Gray-Box Security Assessment Report</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f7fafc;
            color: #2d3748;
            margin: 0;
            padding: 30px;
        }}
        .header {{
            background: #ffffff;
            padding: 24px 30px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 25px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }}
        .metric-card {{
            background: #ffffff;
            padding: 16px 20px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.06);
            border-left: 4px solid #cbd5e0;
        }}
        .metric-card.danger {{ border-left-color: #e53e3e; }}
        .metric-card.warning {{ border-left-color: #dd6b20; }}
        .metric-card.success {{ border-left-color: #38a169; }}
        .metric-card.info {{ border-left-color: #3182ce; }}
        .metric-number {{
            font-size: 28px;
            font-weight: 700;
            margin-top: 4px;
        }}
        .badge {{
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
        }}
        .badge-safe {{ background: #c6f6d5; color: #22543d; }}
        .badge-unsafe {{ background: #fed7d7; color: #742a2a; }}
        .badge-review {{ background: #feebc8; color: #7b341e; }}
        .badge-incomplete {{ background: #edf2f7; color: #4a5568; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            margin-bottom: 30px;
        }}
        th, td {{
            padding: 12px 16px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }}
        th {{
            background: #edf2f7;
            font-weight: 600;
            color: #4a5568;
        }}
        .progress-bar-container {{
            background: #e2e8f0;
            border-radius: 8px;
            height: 12px;
            width: 100%;
            overflow: hidden;
            margin: 8px 0;
        }}
        .progress-bar {{
            background: #3182ce;
            height: 100%;
            width: {coverage_pct}%;
        }}
        .testcase-card {{
            background: #ffffff;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 18px 24px;
            margin-bottom: 15px;
        }}
        .testcase-header {{
            font-size: 16px;
            margin-bottom: 8px;
            border-bottom: 1px solid #edf2f7;
            padding-bottom: 8px;
        }}
        pre {{
            background: #1a202c;
            color: #e2e8f0;
            padding: 12px;
            border-radius: 6px;
            overflow-x: auto;
            font-size: 13px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1 style="margin:0 0 10px 0;">Gray-Box Security Assessment Report</h1>
        <p style="margin:0; color:#718096;">
            Target: <strong>{target}</strong> | Generated: <strong>{timestamp}</strong> |
            Overall Finding: <span style="color:{overall_color}; font-weight:700;">{overall_badge}</span>
        </p>
    </div>

    <div class="metrics-grid">
        <div class="metric-card danger">
            <small style="color:#718096; text-transform:uppercase;">Confirmed Vulnerabilities</small>
            <div class="metric-number" style="color:#e53e3e;">{unsafe_count}</div>
        </div>
        <div class="metric-card warning">
            <small style="color:#718096; text-transform:uppercase;">Review Required</small>
            <div class="metric-number" style="color:#dd6b20;">{review_count}</div>
        </div>
        <div class="metric-card success">
            <small style="color:#718096; text-transform:uppercase;">Verified Safe</small>
            <div class="metric-number" style="color:#38a169;">{safe_count}</div>
        </div>
        <div class="metric-card info">
            <small style="color:#718096; text-transform:uppercase;">Not Assessed / Missing Prerequisites</small>
            <div class="metric-number" style="color:#4a5568;">{not_assessed_count + incomplete_count}</div>
        </div>
        <div class="metric-card">
            <small style="color:#718096; text-transform:uppercase;">Required Payload Coverage</small>
            <div class="metric-number" style="color:#3182ce;">{coverage_pct}%</div>
            <div class="progress-bar-container">
                <div class="progress-bar"></div>
            </div>
        </div>
    </div>

    <h2>Testcase Inventory Summary</h2>
    <table>
        <thead>
            <tr>
                <th>#</th>
                <th>ID</th>
                <th>Testcase & Category</th>
                <th>Status</th>
                <th>Assessment Summary</th>
            </tr>
        </thead>
        <tbody>
            {"".join(rows_html)}
        </tbody>
    </table>

    <h2>Detailed Findings and Evidence</h2>
    {"".join(details_html)}
</body>
</html>
"""


def save_graybox_run_output(
    target: str,
    results: list[GrayBoxResult],
    config: GrayBoxConfig,
    timestamp: datetime | None = None,
) -> Path:
    """Save complete Gray-Box execution output: individual JSONs, compiled JSON, HTML, and Markdown."""
    now = timestamp or datetime.now()
    run_dir = create_graybox_run_directory(target, timestamp=now)
    metrics = calculate_suite_metrics(results)

    report_data = {
        "schema_version": 1,
        "application": "Test Executor - Gray-Box Assessment Subsystem",
        "target": target,
        "domain": _safe_domain(target),
        "timestamp": now.isoformat(timespec="seconds"),
        "config": {
            "verify_tls": config.verify_tls,
            "request_budget_per_testcase": config.request_budget_per_testcase,
            "timeout_seconds": config.timeout_seconds,
            "active_categories": [
                c.value if hasattr(c, "value") else str(c) for c in config.active_categories
            ],
        },
        "metrics": metrics,
        "results": [r.as_dict() for r in results],
    }

    sanitized_report = sanitize_dict_secrets(report_data)

    # 1. Save individual testcase results
    for idx, r in enumerate(results, start=1):
        slug = re.sub(r"[^a-zA-Z0-9]+", "_", r.testcase_id).strip("_").lower()
        file_path = run_dir / f"{idx:02d}_{slug}.json"
        file_path.write_text(
            json.dumps(sanitize_dict_secrets(r.as_dict()), indent=2, default=str),
            encoding="utf-8",
        )

    # 2. Save compiled JSON
    (run_dir / "compiled_graybox.json").write_text(
        json.dumps(sanitized_report, indent=2, default=str),
        encoding="utf-8",
    )

    # 3. Save compiled HTML
    (run_dir / "compiled_graybox.html").write_text(
        render_graybox_html(sanitized_report),
        encoding="utf-8",
    )

    # 4. Save Markdown summary
    md_lines = [
        f"# Gray-Box Security Assessment Report: {target}",
        f"**Date:** {now.strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        "## Summary Metrics",
        f"- **Total Testcases:** {metrics['total_testcases']}",
        f"- **UNSAFE (Confirmed):** {metrics['status_counts'].get('UNSAFE', 0)}",
        f"- **SAFE:** {metrics['status_counts'].get('SAFE', 0)}",
        f"- **REVIEW REQUIRED:** {metrics['status_counts'].get('REVIEW REQUIRED', 0)}",
        f"- **NOT ASSESSED:** {metrics['status_counts'].get('NOT ASSESSED', 0)}",
        f"- **Payload Execution Coverage:** {metrics['payload_coverage']['coverage_percentage']}% ({metrics['payload_coverage']['executed']} executed / {metrics['payload_coverage']['total_required']} required)",
        "",
        "## Testcase Results",
        "| ID | Name | Category | Status | Summary |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        md_lines.append(f"| `{r.testcase_id}` | {r.name} | {r.category} | **{r.status}** | {r.summary} |")

    (run_dir / "report.md").write_text("\n".join(md_lines), encoding="utf-8")

    return run_dir
