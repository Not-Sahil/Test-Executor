"""Common scanner foundation, HTTP transport, and evidence utilities for Gray-Box testing."""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from graybox.artifacts import GrayBoxArtifactManager, redact_text_secrets
from graybox.accounts import GrayBoxAccountManager
from graybox.models import (
    GrayBoxConfig,
    GrayBoxPayload,
    GrayBoxResult,
    PayloadExecutionSummary,
    ResultStatus,
)


class GrayBoxExecutionSession:
    """Manages HTTP communications, safety budgets, evidence collection, and payload tracking."""

    def __init__(
        self,
        config: GrayBoxConfig,
        artifacts: GrayBoxArtifactManager | None = None,
        accounts: GrayBoxAccountManager | None = None,
    ) -> None:
        self.config = config
        self.artifacts = artifacts or GrayBoxArtifactManager()
        self.accounts = accounts or GrayBoxAccountManager()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.user_agent})
        self.request_count = 0
        self.budget = config.request_budget_per_testcase

    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        data: Any = None,
        json_data: Any = None,
        cookies: dict[str, str] | None = None,
        allow_redirects: bool = True,
        timeout: float | None = None,
    ) -> requests.Response | None:
        """Issue an HTTP request while strictly honoring the configured request budget."""
        if self.request_count >= self.budget:
            return None

        self.request_count += 1
        timeout = timeout or self.config.timeout_seconds

        req_headers = dict(headers or {})
        try:
            resp = self.session.request(
                method=method.upper(),
                url=url,
                headers=req_headers,
                params=params,
                data=data,
                json=json_data,
                cookies=cookies,
                allow_redirects=allow_redirects,
                timeout=timeout,
                verify=self.config.verify_tls,
            )
            if self.config.delay_between_requests > 0:
                time.sleep(self.config.delay_between_requests)
            return resp
        except Exception:
            return None

    def get(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("POST", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response | None:
        return self.request("OPTIONS", url, **kwargs)


class BaseGrayBoxScanner:
    """Base class for all Gray-Box testcase scanners."""

    testcase_id: str = ""
    name: str = ""
    category: str = ""

    def __init__(
        self,
        session: GrayBoxExecutionSession,
        payloads: list[GrayBoxPayload] | None = None,
    ) -> None:
        self.session = session
        self.config = session.config
        self.artifacts = session.artifacts
        self.accounts = session.accounts
        self.payloads = payloads or []
        self.evidence: list[str] = []
        self.details: dict[str, Any] = {}
        self.coverage = PayloadExecutionSummary(
            total_required=sum(1 for p in self.payloads if p.required),
            total_optional=sum(1 for p in self.payloads if not p.required),
        )

    def mark_payload_executed(self, payload: GrayBoxPayload) -> None:
        self.coverage.executed += 1
        self.coverage.executed_payload_ids.append(payload.id)

    def mark_payload_skipped(self, payload: GrayBoxPayload, reason: str) -> None:
        self.coverage.skipped += 1
        self.coverage.skipped_reasons[reason] = self.coverage.skipped_reasons.get(reason, 0) + 1

    def mark_payload_failed(self, payload: GrayBoxPayload, reason: str) -> None:
        self.coverage.failed += 1
        self.coverage.skipped_reasons[reason] = self.coverage.skipped_reasons.get(reason, 0) + 1

    def add_evidence(self, item: str) -> None:
        safe_item = redact_text_secrets(str(item))
        if safe_item and safe_item not in self.evidence:
            self.evidence.append(safe_item)

    def build_result(
        self,
        status: ResultStatus | str,
        summary: str,
        automation_level: str = "AUTOMATED",
    ) -> GrayBoxResult:
        status_val = status.value if hasattr(status, "value") else str(status)
        assessment_state = {
            ResultStatus.UNSAFE.value: "CONFIRMED",
            ResultStatus.SAFE.value: "NOT_A_FINDING",
            ResultStatus.REVIEW_REQUIRED.value: "REVIEW_REQUIRED",
            ResultStatus.INCOMPLETE.value: "INCOMPLETE",
            ResultStatus.NOT_ASSESSED.value: "NOT_ASSESSED",
            ResultStatus.SKIPPED.value: "SKIPPED",
            ResultStatus.ERROR.value: "ERROR",
        }.get(status_val, "REVIEW_REQUIRED")

        return GrayBoxResult(
            testcase_id=self.testcase_id,
            name=self.name,
            category=self.category,
            status=status_val,
            assessment_state=assessment_state,
            summary=summary,
            automation_level=automation_level,
            evidence=self.evidence[:50],
            details=self.details,
            payload_coverage=self.coverage,
        )

    def execute(self) -> GrayBoxResult:
        raise NotImplementedError("Each scanner must implement execute().")
