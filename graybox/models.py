"""Data models and enums for the Gray-Box Security Testing Framework."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Sequence


class AutomationLevel(str, Enum):
    AUTOMATED = "AUTOMATED"
    ASSISTED = "ASSISTED"
    MANUAL = "MANUAL"


class TestCategory(str, Enum):
    BASIC = "Basic"
    ENCRYPTION = "Encryption"
    FORM_AUTHENTICATION = "Form Field and Authentication"
    SESSION_MANAGEMENT = "Session Management"
    INJECTION = "Injection"
    SSRF = "SSRF"


TestCategory.__test__ = False


class AssessmentState(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_A_FINDING = "NOT_A_FINDING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    INCOMPLETE = "INCOMPLETE"
    NOT_ASSESSED = "NOT_ASSESSED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class ResultStatus(str, Enum):
    UNSAFE = "UNSAFE"
    SAFE = "SAFE"
    REVIEW_REQUIRED = "REVIEW REQUIRED"
    INCOMPLETE = "INCOMPLETE"
    NOT_ASSESSED = "NOT ASSESSED"
    SKIPPED = "SKIPPED"
    ERROR = "ERROR"


class AccountRole(str, Enum):
    ANONYMOUS = "ANONYMOUS"
    USER_A = "USER_A"
    USER_B = "USER_B"
    PRIVILEGED_USER = "PRIVILEGED_USER"
    ADMINISTRATOR = "ADMINISTRATOR"


class ArtifactType(str, Enum):
    OPENAPI_SPEC = "OPENAPI_SPEC"
    SOURCE_CODE = "SOURCE_CODE"
    SBOM = "SBOM"
    DATABASE_SCHEMA = "DATABASE_SCHEMA"
    ROLE_MATRIX = "ROLE_MATRIX"
    AUTH_FLOW_DOC = "AUTH_FLOW_DOC"
    COOKIE_CONFIG = "COOKIE_CONFIG"
    TLS_CONFIG = "TLS_CONFIG"
    API_AUTHORIZATION_RULES = "API_AUTHORIZATION_RULES"
    SERVER_LOGS = "SERVER_LOGS"
    ARCHITECTURE_DOC = "ARCHITECTURE_DOC"


@dataclass
class GrayBoxPayload:
    id: str
    testcase_id: str
    name: str
    category: str
    value: Any
    purpose: str
    expected_secure_behavior: str
    encoding: str = "plain"
    required: bool = True
    risk_level: str = "low"
    destructive: bool = False
    requires_authorization: bool = True
    requires_test_environment: bool = False
    requires_account_role: list[str] = field(default_factory=list)
    evidence_type: str = "response_inspection"
    source: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "testcase_id": self.testcase_id,
            "name": self.name,
            "category": self.category,
            "value": self.value,
            "encoding": self.encoding,
            "purpose": self.purpose,
            "expected_secure_behavior": self.expected_secure_behavior,
            "required": self.required,
            "risk_level": self.risk_level,
            "destructive": self.destructive,
            "requires_authorization": self.requires_authorization,
            "requires_test_environment": self.requires_test_environment,
            "requires_account_role": self.requires_account_role,
            "evidence_type": self.evidence_type,
            "source": self.source,
            "tags": self.tags,
        }


@dataclass
class GrayBoxTestcase:
    id: str
    name: str
    category: TestCategory
    objective: str
    description: str
    automation_level: AutomationLevel
    payload_file: str
    required_roles: list[AccountRole] = field(default_factory=list)
    required_artifacts: list[ArtifactType] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    execution_procedure: list[str] = field(default_factory=list)
    expected_secure_behavior: str = ""
    failure_conditions: str = ""
    evidence_requirements: list[str] = field(default_factory=list)
    remediation_guidance: str = ""
    security_references: list[str] = field(default_factory=list)
    scanner_module: str = ""
    scanner_callable: str = "scan"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category.value if isinstance(self.category, Enum) else self.category,
            "objective": self.objective,
            "description": self.description,
            "automation_level": self.automation_level.value if isinstance(self.automation_level, Enum) else self.automation_level,
            "payload_file": self.payload_file,
            "required_roles": [r.value if isinstance(r, Enum) else r for r in self.required_roles],
            "required_artifacts": [a.value if isinstance(a, Enum) else a for a in self.required_artifacts],
            "preconditions": self.preconditions,
            "execution_procedure": self.execution_procedure,
            "expected_secure_behavior": self.expected_secure_behavior,
            "failure_conditions": self.failure_conditions,
            "evidence_requirements": self.evidence_requirements,
            "remediation_guidance": self.remediation_guidance,
            "security_references": self.security_references,
            "scanner_module": self.scanner_module,
            "scanner_callable": self.scanner_callable,
        }


@dataclass
class GrayBoxConfig:
    target_url: str
    login_path: str = "/login"
    verify_tls: bool = True
    allow_private_targets: bool = True
    request_budget_per_testcase: int = 50
    timeout_seconds: float = 10.0
    delay_between_requests: float = 0.1
    max_redirects: int = 5
    user_agent: str = "TestExecutor-GrayBox-Auditor/1.0"
    active_categories: list[TestCategory] = field(default_factory=lambda: list(TestCategory))
    active_testcase_ids: list[str] = field(default_factory=list)
    operator_authorized: bool = False
    interactive_session: bool = False


@dataclass
class PayloadExecutionSummary:
    total_required: int = 0
    total_optional: int = 0
    executed: int = 0
    skipped: int = 0
    failed: int = 0
    skipped_reasons: dict[str, int] = field(default_factory=dict)
    executed_payload_ids: list[str] = field(default_factory=list)


@dataclass
class GrayBoxResult:
    testcase_id: str
    name: str
    category: str
    status: str
    assessment_state: str
    summary: str
    automation_level: str
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    payload_coverage: PayloadExecutionSummary = field(default_factory=PayloadExecutionSummary)
    raw_output: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.testcase_id,
            "testcase_id": self.testcase_id,
            "name": self.name,
            "category": self.category,
            "status": self.status,
            "assessment_state": self.assessment_state,
            "summary": self.summary,
            "automation_level": self.automation_level,
            "evidence": self.evidence,
            "details": self.details,
            "payload_coverage": {
                "total_required": self.payload_coverage.total_required,
                "total_optional": self.payload_coverage.total_optional,
                "executed": self.payload_coverage.executed,
                "skipped": self.payload_coverage.skipped,
                "failed": self.payload_coverage.failed,
                "skipped_reasons": self.payload_coverage.skipped_reasons,
                "executed_payload_ids": self.payload_coverage.executed_payload_ids,
            },
            "raw_output": self.raw_output,
        }

    def to_scan_result(self) -> Any:
        """Convert to core.models.ScanResult for unified display/reporting if needed."""
        from core.models import ScanResult
        return ScanResult(
            key=self.testcase_id,
            name=f"[{self.category}] {self.name}",
            status=self.status,
            summary=self.summary,
            raw_output=self.raw_output,
            evidence=list(self.evidence),
            details=dict(self.details),
        )
