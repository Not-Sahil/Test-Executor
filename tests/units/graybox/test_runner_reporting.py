"""Tests for Gray-Box suite runner, metrics calculation, and report generation."""
import json
from unittest.mock import MagicMock, patch
import requests

from graybox.models import (
    GrayBoxConfig,
    GrayBoxResult,
    PayloadExecutionSummary,
    ResultStatus,
    TestCategory,
)
from graybox.reporting import (
    render_graybox_html,
    save_graybox_run_output,
)
from graybox.runner import calculate_suite_metrics, run_graybox_suite


def test_calculate_suite_metrics_accuracy():
    results = [
        GrayBoxResult(
            testcase_id="GB-BASIC-01",
            name="Access through IP",
            category="Basic",
            status=ResultStatus.SAFE.value,
            assessment_state="NOT_A_FINDING",
            summary="Direct IP access refused.",
            automation_level="AUTOMATED",
            payload_coverage=PayloadExecutionSummary(total_required=2, executed=2),
        ),
        GrayBoxResult(
            testcase_id="GB-BASIC-06",
            name="Security headers",
            category="Basic",
            status=ResultStatus.UNSAFE.value,
            assessment_state="CONFIRMED",
            summary="Missing CSP and HSTS.",
            automation_level="AUTOMATED",
            payload_coverage=PayloadExecutionSummary(total_required=1, executed=1),
        ),
        GrayBoxResult(
            testcase_id="GB-SESSION-15",
            name="IDOR",
            category="Session Management",
            status=ResultStatus.NOT_ASSESSED.value,
            assessment_state="NOT_ASSESSED",
            summary="Missing User B.",
            automation_level="AUTOMATED",
            payload_coverage=PayloadExecutionSummary(total_required=2, executed=0, skipped=2),
        ),
    ]

    metrics = calculate_suite_metrics(results)
    assert metrics["total_testcases"] == 3
    assert metrics["status_counts"]["SAFE"] == 1
    assert metrics["status_counts"]["UNSAFE"] == 1
    assert metrics["status_counts"]["NOT ASSESSED"] == 1

    cov = metrics["payload_coverage"]
    assert cov["total_required"] == 5
    assert cov["executed"] == 3
    assert cov["skipped"] == 2
    assert cov["coverage_percentage"] == 60.0


def test_save_graybox_run_output_creates_expected_files(tmp_path):
    results = [
        GrayBoxResult(
            testcase_id="GB-BASIC-01",
            name="Access through IP",
            category="Basic",
            status=ResultStatus.SAFE.value,
            assessment_state="NOT_A_FINDING",
            summary="Direct IP access refused safely.",
            automation_level="AUTOMATED",
            evidence=["Host refused: 127.0.0.1"],
            payload_coverage=PayloadExecutionSummary(total_required=2, executed=2),
        )
    ]
    config = GrayBoxConfig(target_url="http://127.0.0.1:8000")

    with patch("graybox.reporting.OUTPUT_ROOT", tmp_path):
        run_dir = save_graybox_run_output("http://127.0.0.1:8000", results, config)
        assert run_dir.is_dir()

        compiled_json = run_dir / "compiled_graybox.json"
        compiled_html = run_dir / "compiled_graybox.html"
        report_md = run_dir / "report.md"

        assert compiled_json.is_file()
        assert compiled_html.is_file()
        assert report_md.is_file()

        data = json.loads(compiled_json.read_text(encoding="utf-8"))
        assert data["application"] == "Test Executor - Gray-Box Assessment Subsystem"
        assert len(data["results"]) == 1
        assert data["results"][0]["testcase_id"] == "GB-BASIC-01"

        html_text = compiled_html.read_text(encoding="utf-8")
        assert "Gray-Box Security Assessment Report" in html_text
        assert "GB-BASIC-01" in html_text
