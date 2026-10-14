"""Gray-Box Security Testing Framework."""
from __future__ import annotations

from graybox.models import (
    AccountRole,
    ArtifactType,
    AssessmentState,
    AutomationLevel,
    GrayBoxConfig,
    GrayBoxPayload,
    GrayBoxResult,
    GrayBoxTestcase,
    PayloadExecutionSummary,
    ResultStatus,
    TestCategory,
)

from graybox.accounts import GrayBoxAccountManager, TestAccount
from graybox.artifacts import GrayBoxArtifact, GrayBoxArtifactManager, redact_text_secrets
from graybox.payload_manager import GrayBoxPayloadManager
from graybox.registry import (
    GRAYBOX_REGISTRY,
    get_graybox_registry,
    get_scanner_class,
    get_testcase,
    get_testcases_by_category,
)
from graybox.reporting import (
    create_graybox_run_directory,
    render_graybox_html,
    save_graybox_run_output,
)
from graybox.runner import (
    calculate_suite_metrics,
    run_graybox_suite,
    run_graybox_testcase,
)

__all__ = [
    "AccountRole",
    "ArtifactType",
    "AssessmentState",
    "AutomationLevel",
    "GRAYBOX_REGISTRY",
    "GrayBoxAccountManager",
    "GrayBoxArtifact",
    "GrayBoxArtifactManager",
    "GrayBoxConfig",
    "GrayBoxPayload",
    "GrayBoxPayloadManager",
    "GrayBoxResult",
    "GrayBoxTestcase",
    "PayloadExecutionSummary",
    "ResultStatus",
    "TestAccount",
    "TestCategory",
    "calculate_suite_metrics",
    "create_graybox_run_directory",
    "get_graybox_registry",
    "get_scanner_class",
    "get_testcase",
    "get_testcases_by_category",
    "redact_text_secrets",
    "render_graybox_html",
    "run_graybox_suite",
    "run_graybox_testcase",
    "save_graybox_run_output",
]
