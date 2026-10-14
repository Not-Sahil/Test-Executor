"""Gray-Box Test Runner and Orchestration Engine.

Orchestrates execution of Gray-Box security testcases with prerequisite checking,
role verification, payload execution tracking, safe error handling, and coverage metrics.
"""
from __future__ import annotations

import logging
import traceback
from typing import Any, Callable, Sequence

from graybox.accounts import GrayBoxAccountManager
from graybox.artifacts import GrayBoxArtifactManager, redact_text_secrets
from graybox.models import (
    AutomationLevel,
    GrayBoxConfig,
    GrayBoxResult,
    PayloadExecutionSummary,
    ResultStatus,
    TestCategory,
)
from graybox.payload_manager import GrayBoxPayloadManager
from graybox.registry import (
    GRAYBOX_REGISTRY,
    get_scanner_class,
    get_testcase,
)
from graybox.scanners.common import GrayBoxExecutionSession

logger = logging.getLogger(__name__)


def run_graybox_testcase(
    testcase_id: str,
    config: GrayBoxConfig,
    artifacts: GrayBoxArtifactManager | None = None,
    accounts: GrayBoxAccountManager | None = None,
    payload_manager: GrayBoxPayloadManager | None = None,
) -> GrayBoxResult:
    """Execute a single Gray-Box testcase with prerequisite checks and safety enforcement."""
    artifacts = artifacts or GrayBoxArtifactManager()
    accounts = accounts or GrayBoxAccountManager()
    payload_manager = payload_manager or GrayBoxPayloadManager()

    tc_def = get_testcase(testcase_id)
    if not tc_def:
        return GrayBoxResult(
            testcase_id=testcase_id,
            name="Unknown Testcase",
            category="Unknown",
            status=ResultStatus.ERROR.value,
            assessment_state="ERROR",
            summary=f"Testcase ID '{testcase_id}' is not registered in the Gray-Box inventory.",
            automation_level=AutomationLevel.AUTOMATED.value,
            evidence=[f"Unregistered testcase ID: {testcase_id}"],
        )

    cat_name = tc_def.category.value if hasattr(tc_def.category, "value") else str(tc_def.category)
    auto_level = tc_def.automation_level.value if hasattr(tc_def.automation_level, "value") else str(tc_def.automation_level)

    # 1. Check required account roles
    for role in tc_def.required_roles:
        if not accounts.has_role(role):
            role_name = role.value if hasattr(role, "value") else str(role)
            return GrayBoxResult(
                testcase_id=tc_def.id,
                name=tc_def.name,
                category=cat_name,
                status=ResultStatus.NOT_ASSESSED.value,
                assessment_state="NOT_ASSESSED",
                summary=f"Prerequisite account role '{role_name}' is not configured. Provide credentials/token to assess.",
                automation_level=auto_level,
                evidence=[f"Missing required test role: {role_name}"],
                details={"missing_role": role_name},
            )

    # 2. Check required artifacts
    for art in tc_def.required_artifacts:
        if not artifacts.has_artifact(art):
            art_name = art.value if hasattr(art, "value") else str(art)
            return GrayBoxResult(
                testcase_id=tc_def.id,
                name=tc_def.name,
                category=cat_name,
                status=ResultStatus.NOT_ASSESSED.value,
                assessment_state="NOT_ASSESSED",
                summary=f"Prerequisite artifact '{art_name}' is missing. Upload or configure this artifact to assess.",
                automation_level=auto_level,
                evidence=[f"Missing required artifact: {art_name}"],
                details={"missing_artifact": art_name},
            )

    # 3. Load payload library for this testcase
    payloads = payload_manager.get_payloads_for_testcase(tc_def.id)

    # 4. Resolve scanner class
    scanner_cls = get_scanner_class(tc_def.id)
    if not scanner_cls:
        return GrayBoxResult(
            testcase_id=tc_def.id,
            name=tc_def.name,
            category=cat_name,
            status=ResultStatus.ERROR.value,
            assessment_state="ERROR",
            summary=f"No scanner class bound to testcase {tc_def.id}.",
            automation_level=auto_level,
            evidence=["Scanner binding missing in registry."],
        )

    # 5. Execute scanner safely
    session = GrayBoxExecutionSession(config=config, artifacts=artifacts, accounts=accounts)
    try:
        scanner = scanner_cls(session=session, payloads=payloads)
        result = scanner.execute()
    except Exception as exc:
        logger.exception("Error executing Gray-Box testcase %s", tc_def.id)
        err_msg = redact_text_secrets(f"Execution exception: {type(exc).__name__}: {str(exc)}")
        tb_line = redact_text_secrets(traceback.format_exc().splitlines()[-2] if traceback.format_exc().splitlines() else "")
        return GrayBoxResult(
            testcase_id=tc_def.id,
            name=tc_def.name,
            category=cat_name,
            status=ResultStatus.ERROR.value,
            assessment_state="ERROR",
            summary=f"Unexpected error during scanner execution: {err_msg}",
            automation_level=auto_level,
            evidence=[err_msg, tb_line] if tb_line else [err_msg],
            details={"exception": str(exc)},
        )

    # Redact sensitive data from evidence & summary
    result.summary = redact_text_secrets(result.summary)
    result.evidence = [redact_text_secrets(e) for e in result.evidence]
    return result


def run_graybox_suite(
    config: GrayBoxConfig,
    artifacts: GrayBoxArtifactManager | None = None,
    accounts: GrayBoxAccountManager | None = None,
    payload_manager: GrayBoxPayloadManager | None = None,
    progress_callback: Callable[[int, int, GrayBoxResult], None] | None = None,
) -> list[GrayBoxResult]:
    """Execute all selected Gray-Box testcases according to config."""
    artifacts = artifacts or GrayBoxArtifactManager()
    accounts = accounts or GrayBoxAccountManager()
    payload_manager = payload_manager or GrayBoxPayloadManager()

    # Determine testcases to run
    selected_ids: list[str] = []
    if config.active_testcase_ids:
        selected_ids = [tid for tid in config.active_testcase_ids if tid in GRAYBOX_REGISTRY]
    else:
        active_cat_names = {
            c.value if hasattr(c, "value") else str(c) for c in config.active_categories
        }
        for tc in GRAYBOX_REGISTRY.values():
            cat_name = tc.category.value if hasattr(tc.category, "value") else str(tc.category)
            if cat_name in active_cat_names:
                selected_ids.append(tc.id)

    total = len(selected_ids)
    results: list[GrayBoxResult] = []

    for idx, tc_id in enumerate(selected_ids, start=1):
        result = run_graybox_testcase(
            testcase_id=tc_id,
            config=config,
            artifacts=artifacts,
            accounts=accounts,
            payload_manager=payload_manager,
        )
        results.append(result)
        if progress_callback:
            try:
                progress_callback(idx, total, result)
            except Exception:
                pass

    return results


def calculate_suite_metrics(results: list[GrayBoxResult]) -> dict[str, Any]:
    """Calculate summary and payload execution coverage metrics across a suite run."""
    total_testcases = len(results)
    status_counts: dict[str, int] = {
        ResultStatus.UNSAFE.value: 0,
        ResultStatus.SAFE.value: 0,
        ResultStatus.REVIEW_REQUIRED.value: 0,
        ResultStatus.INCOMPLETE.value: 0,
        ResultStatus.NOT_ASSESSED.value: 0,
        ResultStatus.SKIPPED.value: 0,
        ResultStatus.ERROR.value: 0,
    }
    category_breakdown: dict[str, dict[str, int]] = {}

    total_required_payloads = 0
    total_optional_payloads = 0
    total_executed_payloads = 0
    total_skipped_payloads = 0
    total_failed_payloads = 0

    for r in results:
        status_counts[r.status] = status_counts.get(r.status, 0) + 1

        cat = r.category
        if cat not in category_breakdown:
            category_breakdown[cat] = {"total": 0, "UNSAFE": 0, "SAFE": 0, "REVIEW_REQUIRED": 0, "OTHER": 0}
        category_breakdown[cat]["total"] += 1
        if r.status in category_breakdown[cat]:
            category_breakdown[cat][r.status] += 1
        else:
            category_breakdown[cat]["OTHER"] += 1

        cov = r.payload_coverage
        total_required_payloads += cov.total_required
        total_optional_payloads += cov.total_optional
        total_executed_payloads += cov.executed
        total_skipped_payloads += cov.skipped
        total_failed_payloads += cov.failed

    coverage_pct = (
        round((total_executed_payloads / total_required_payloads * 100), 1)
        if total_required_payloads > 0
        else 100.0
    )

    return {
        "total_testcases": total_testcases,
        "status_counts": status_counts,
        "category_breakdown": category_breakdown,
        "payload_coverage": {
            "total_required": total_required_payloads,
            "total_optional": total_optional_payloads,
            "executed": total_executed_payloads,
            "skipped": total_skipped_payloads,
            "failed": total_failed_payloads,
            "coverage_percentage": coverage_pct,
        },
    }
