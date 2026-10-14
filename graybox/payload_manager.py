"""Dedicated Payload and Scenario Library Manager for Gray-Box Testing.

Loads, validates, and manages structured test inputs and scenario definitions
from payloads/graybox/. Strictly isolates gray-box payload data from black-box files.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from graybox.models import GrayBoxPayload, PayloadExecutionSummary

GRAYBOX_PAYLOAD_DIR = Path(__file__).resolve().parents[1] / "payloads" / "graybox"
MANIFEST_PATH = GRAYBOX_PAYLOAD_DIR / "manifest.json"


class GrayBoxPayloadManager:
    """Manager for loading and validating Gray-Box payload libraries."""

    def __init__(self, base_dir: Path | None = None) -> None:
        self.base_dir = base_dir or GRAYBOX_PAYLOAD_DIR
        self.manifest_path = self.base_dir / "manifest.json"
        self._manifest: dict[str, Any] = {}
        self._payload_cache: dict[str, list[GrayBoxPayload]] = {}
        self.load_manifest()

    def load_manifest(self) -> dict[str, Any]:
        if not self.manifest_path.is_file():
            self._manifest = {"schema_version": 1, "testcases": {}}
            return self._manifest
        try:
            self._manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise RuntimeError(f"Failed to parse Gray-Box payload manifest at {self.manifest_path}: {exc}") from exc
        return self._manifest

    def get_testcase_manifest(self, testcase_id: str) -> dict[str, Any] | None:
        testcases = self._manifest.get("testcases", {})
        return testcases.get(testcase_id)

    def load_payloads_for_testcase(
        self,
        testcase_id: str,
        relative_path: str | None = None,
    ) -> list[GrayBoxPayload]:
        if testcase_id in self._payload_cache:
            return self._payload_cache[testcase_id]

        file_rel = relative_path
        if not file_rel:
            entry = self.get_testcase_manifest(testcase_id)
            if entry and "file" in entry:
                file_rel = entry["file"]

        if not file_rel:
            return []

        file_path = self.base_dir / file_rel
        if not file_path.is_file():
            return []

        try:
            data = json.loads(file_path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"Invalid JSON payload file {file_path}: {exc}") from exc

        if not isinstance(data, list):
            raise ValueError(f"Payload file {file_path} must contain a JSON array of payload records.")

        payloads = []
        for idx, item in enumerate(data, start=1):
            if not isinstance(item, dict):
                continue
            payload_obj = GrayBoxPayload(
                id=str(item.get("id") or f"{testcase_id}-P{idx:03d}"),
                testcase_id=testcase_id,
                name=str(item.get("name") or f"payload_{idx}"),
                category=str(item.get("category") or "general"),
                value=item.get("value"),
                encoding=str(item.get("encoding") or "plain"),
                purpose=str(item.get("purpose") or "Security test evaluation"),
                expected_secure_behavior=str(item.get("expected_secure_behavior") or "Application handles input safely"),
                required=bool(item.get("required", True)),
                risk_level=str(item.get("risk_level") or "low"),
                destructive=bool(item.get("destructive", False)),
                requires_authorization=bool(item.get("requires_authorization", True)),
                requires_test_environment=bool(item.get("requires_test_environment", False)),
                requires_account_role=list(item.get("requires_account_role") or []),
                evidence_type=str(item.get("evidence_type") or "response_inspection"),
                source=dict(item.get("source") or {}),
                tags=list(item.get("tags") or []),
            )
            payloads.append(payload_obj)

        self._payload_cache[testcase_id] = payloads
        return payloads

    def get_payloads_for_testcase(
        self,
        testcase_id: str,
        relative_path: str | None = None,
    ) -> list[GrayBoxPayload]:
        """Alias for load_payloads_for_testcase."""
        return self.load_payloads_for_testcase(testcase_id, relative_path)

    def validate_all_libraries(self) -> dict[str, Any]:
        """Validate all files registered in manifest and report any anomalies."""
        issues = []
        total_payloads = 0
        testcases_validated = 0

        manifest = self.load_manifest()
        testcase_entries = manifest.get("testcases", {})

        for t_id, entry in testcase_entries.items():
            testcases_validated += 1
            rel_file = entry.get("file")
            if not rel_file:
                issues.append(f"{t_id}: Missing 'file' key in manifest")
                continue
            full_path = self.base_dir / rel_file
            if not full_path.is_file():
                issues.append(f"{t_id}: Declared file does not exist: {rel_file}")
                continue

            try:
                payloads = self.load_payloads_for_testcase(t_id, rel_file)
                total_payloads += len(payloads)
                if not payloads:
                    issues.append(f"{t_id}: Payload file {rel_file} contains 0 records")
            except Exception as exc:
                issues.append(f"{t_id}: Validation error in {rel_file}: {exc}")

        return {
            "valid": len(issues) == 0,
            "testcases_validated": testcases_validated,
            "total_payloads": total_payloads,
            "issues": issues,
        }

    def compute_coverage_summary(
        self,
        results: list[Any],
    ) -> dict[str, Any]:
        """Produce an aggregated payload coverage report across executed testcases."""
        total_required = 0
        total_optional = 0
        total_executed = 0
        total_skipped = 0
        total_failed = 0
        skipped_reasons: dict[str, int] = {}
        per_testcase = {}

        for res in results:
            t_id = getattr(res, "testcase_id", getattr(res, "key", "unknown"))
            cov = getattr(res, "payload_coverage", None)
            if not cov:
                continue

            req = getattr(cov, "total_required", 0)
            opt = getattr(cov, "total_optional", 0)
            exc = getattr(cov, "executed", 0)
            skp = getattr(cov, "skipped", 0)
            fld = getattr(cov, "failed", 0)

            total_required += req
            total_optional += opt
            total_executed += exc
            total_skipped += skp
            total_failed += fld

            reasons = getattr(cov, "skipped_reasons", {})
            for r, c in reasons.items():
                skipped_reasons[r] = skipped_reasons.get(r, 0) + c

            exec_pct = (exc / req * 100.0) if req > 0 else 100.0
            per_testcase[t_id] = {
                "name": getattr(res, "name", t_id),
                "required": req,
                "optional": opt,
                "executed": exc,
                "skipped": skp,
                "failed": fld,
                "execution_coverage_pct": round(exec_pct, 1),
            }

        overall_pct = (total_executed / total_required * 100.0) if total_required > 0 else 100.0

        return {
            "total_required_scenarios": total_required,
            "total_optional_scenarios": total_optional,
            "total_executed": total_executed,
            "total_skipped": total_skipped,
            "total_failed": total_failed,
            "overall_execution_coverage_pct": round(overall_pct, 1),
            "skipped_reasons": skipped_reasons,
            "per_testcase": per_testcase,
        }
