"""Canonical Status Definitions and Assessment Status Calculation.

Provides standard execution and assessment verdict statuses and calculates
overall assessment status ensuring inconclusive or skipped tests never
mask confirmed vulnerabilities.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Sequence


class ExecutionStatus(str, Enum):
    """The technical execution outcome of a testcase run."""
    COMPLETED = "COMPLETED"
    INCOMPLETE = "INCOMPLETE"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class ResultStatus(str, Enum):
    """The security assessment verdict of a testcase."""
    SAFE = "SAFE"
    UNSAFE = "UNSAFE"
    REVIEW_REQUIRED = "REVIEW REQUIRED"
    INCOMPLETE = "INCOMPLETE"
    SKIPPED = "SKIPPED"
    NOT_APPLICABLE = "NOT APPLICABLE"
    NOT_ASSESSED = "NOT ASSESSED"
    ERROR = "ERROR"


# Status classification sets
UNSAFE_STATUSES = {"UNSAFE"}
REVIEW_STATUSES = {"REVIEW REQUIRED"}
INCOMPLETE_STATUSES = {"INCOMPLETE", "ERROR", "UNKNOWN"}
NON_EXECUTED_STATUSES = {"SKIPPED", "NOT APPLICABLE", "NOT ASSESSED"}


def is_incomplete(status: str) -> bool:
    """Return True if the status represents an incomplete execution or error."""
    return str(status).strip().upper() in INCOMPLETE_STATUSES


def is_non_executed(status: str) -> bool:
    """Return True if the test was deliberately skipped or not applicable."""
    return str(status).strip().upper() in NON_EXECUTED_STATUSES


def calculate_overall_status(results: Iterable[Any]) -> str:
    """Calculate the overall security assessment verdict across all test results.

    Rules:
      1. If any testcase is UNSAFE -> UNSAFE.
      2. Else if any testcase is REVIEW REQUIRED -> REVIEW REQUIRED.
      3. Else if any testcase is INCOMPLETE/ERROR -> INCOMPLETE (communicates incomplete coverage).
      4. Else if all executed testcases are SAFE -> SAFE.
      5. If no testcases were executed (all SKIPPED/NOT APPLICABLE) -> INCOMPLETE.
    """
    statuses: set[str] = set()
    has_results = False

    for r in results:
        has_results = True
        status_val = getattr(r, "status", None)
        if status_val is None and isinstance(r, dict):
            status_val = r.get("status")
        if status_val:
            statuses.add(str(status_val).strip().upper())

    if not has_results:
        return ResultStatus.INCOMPLETE.value

    executed_statuses = {s for s in statuses if s not in NON_EXECUTED_STATUSES}

    if "UNSAFE" in executed_statuses:
        return ResultStatus.UNSAFE.value

    if "REVIEW REQUIRED" in executed_statuses:
        return ResultStatus.REVIEW_REQUIRED.value

    if executed_statuses & INCOMPLETE_STATUSES:
        return ResultStatus.INCOMPLETE.value

    if executed_statuses and executed_statuses <= {"SAFE"}:
        return ResultStatus.SAFE.value

    # If all testcases were skipped/not applicable, the assessment is incomplete
    return ResultStatus.INCOMPLETE.value
