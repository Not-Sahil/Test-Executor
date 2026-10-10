from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ScanResult:
    """Shared structured result used by every security testcase."""

    key: str
    name: str
    status: str
    summary: str
    raw_output: str = ""
    evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "raw_output": self.raw_output,
            "evidence": self.evidence,
            "details": self.details,
        }
