"""Gray-Box Knowledge and Artifact Manager.

Manages approved gray-box artifacts (OpenAPI specifications, source snippets,
SBOMs, database schemas, role matrices, session configs) and provides safe,
read-only access without executing or leaking sensitive content.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from graybox.models import ArtifactType


# Patterns used to redact credentials or secrets in artifact content
SECRET_REDACT_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd|secret(?:[_-]?key)?|api[_-]?key|access[_-]?token|bearer|token)\s*[:=]\s*["\']?([^"\'\s,;\r\n]+)["\']?'), r'\1="[REDACTED]"'),
    (re.compile(r'(?i)(authorization:\s*bearer\s+)([A-Za-z0-9_\-\.+=]+)'), r'\1[REDACTED]'),
    (re.compile(r'(?i)([a-z0-9+.-]+://[^:\s/]+:)([^@\s/]+)(@)'), r'\1[REDACTED]\3'),
]


def redact_text_secrets(text: str) -> str:
    """Safely redact credentials, API keys, and session tokens from text."""
    redacted = str(text)
    for pattern, repl in SECRET_REDACT_PATTERNS:
        redacted = pattern.sub(repl, redacted)
    return redacted


@dataclass
class GrayBoxArtifact:
    artifact_type: ArtifactType
    name: str
    content: str
    metadata: dict[str, Any] = field(default_factory=dict)
    is_valid: bool = True
    parsed_data: Any = None

    def safe_content(self, max_length: int = 5000) -> str:
        text = redact_text_secrets(self.content)
        if len(text) > max_length:
            return text[:max_length] + f"\n... [Truncated {len(text) - max_length} bytes]"
        return text


class GrayBoxArtifactManager:
    """In-memory and file-backed manager for approved Gray-Box assessment artifacts."""

    def __init__(self) -> None:
        self._artifacts: dict[ArtifactType, list[GrayBoxArtifact]] = {
            t: [] for t in ArtifactType
        }

    def register_artifact(
        self,
        artifact_type: ArtifactType | str,
        name: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> GrayBoxArtifact:
        if isinstance(artifact_type, str):
            artifact_type = ArtifactType(artifact_type)

        parsed_data = None
        is_valid = True

        # Attempt structured parse if JSON or YAML-like
        content_stripped = content.strip()
        if content_stripped.startswith("{") or content_stripped.startswith("["):
            try:
                parsed_data = json.loads(content_stripped)
            except Exception:
                is_valid = False

        artifact = GrayBoxArtifact(
            artifact_type=artifact_type,
            name=name,
            content=content,
            metadata=metadata or {},
            is_valid=is_valid,
            parsed_data=parsed_data,
        )
        self._artifacts[artifact_type].append(artifact)
        return artifact

    def get_artifacts(self, artifact_type: ArtifactType | str) -> list[GrayBoxArtifact]:
        if isinstance(artifact_type, str):
            artifact_type = ArtifactType(artifact_type)
        return list(self._artifacts.get(artifact_type, []))

    def has_artifact(self, artifact_type: ArtifactType | str) -> bool:
        return len(self.get_artifacts(artifact_type)) > 0

    def get_first_parsed(self, artifact_type: ArtifactType | str) -> Any | None:
        for art in self.get_artifacts(artifact_type):
            if art.parsed_data is not None:
                return art.parsed_data
        return None

    def get_first_content(self, artifact_type: ArtifactType | str) -> str | None:
        artifacts = self.get_artifacts(artifact_type)
        if artifacts:
            return artifacts[0].content
        return None

    def get_endpoints_from_openapi(self) -> list[dict[str, Any]]:
        """Extract path and method information from OpenAPI/Swagger artifacts."""
        endpoints = []
        for art in self.get_artifacts(ArtifactType.OPENAPI_SPEC):
            spec = art.parsed_data
            if isinstance(spec, dict) and "paths" in spec and isinstance(spec["paths"], dict):
                for path, methods in spec["paths"].items():
                    if isinstance(methods, dict):
                        for method, details in methods.items():
                            if method.lower() in {"get", "post", "put", "delete", "patch", "options", "head"}:
                                endpoints.append({
                                    "path": path,
                                    "method": method.upper(),
                                    "summary": details.get("summary", "") if isinstance(details, dict) else "",
                                    "parameters": details.get("parameters", []) if isinstance(details, dict) else [],
                                    "security": details.get("security", spec.get("security", [])) if isinstance(details, dict) else [],
                                })
        return endpoints

    def get_role_matrix(self) -> dict[str, list[str]]:
        """Extract role-to-permission mapping from role matrix artifact."""
        for art in self.get_artifacts(ArtifactType.ROLE_MATRIX):
            if isinstance(art.parsed_data, dict):
                return art.parsed_data
        return {}

    def add_artifact(
        self,
        artifact_type: ArtifactType | str,
        name: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> GrayBoxArtifact:
        """Alias for register_artifact."""
        return self.register_artifact(artifact_type, name, content, metadata)

    def get_openapi_endpoints(self) -> list[str]:
        """Return list of URL paths declared in registered OpenAPI specifications."""
        return [ep["path"] for ep in self.get_endpoints_from_openapi()]

    def get_redacted_artifacts(self) -> list[GrayBoxArtifact]:
        """Return all registered artifacts with sensitive strings redacted."""
        return [
            GrayBoxArtifact(
                artifact_type=a.artifact_type,
                name=a.name,
                content=a.safe_content(),
                metadata=dict(a.metadata),
                is_valid=a.is_valid,
                parsed_data=a.parsed_data,
            )
            for items in self._artifacts.values()
            for a in items
        ]

    @property
    def artifacts(self) -> list[GrayBoxArtifact]:
        """Return flat list of all currently registered artifacts."""
        return [a for items in self._artifacts.values() for a in items]

    def summary(self) -> dict[str, Any]:
        result = {}
        for artifact_type, items in self._artifacts.items():
            result[artifact_type.value] = {
                "count": len(items),
                "names": [item.name for item in items],
            }
        return result

    def clear(self) -> None:
        for t in self._artifacts:
            self._artifacts[t].clear()
