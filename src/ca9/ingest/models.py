from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ca9.core.models import Finding


@dataclass(frozen=True)
class ToolRun:
    name: str
    version: str | None = None
    information_uri: str | None = None
    result_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "result_count": self.result_count,
        }
        if self.version:
            data["version"] = self.version
        if self.information_uri:
            data["information_uri"] = self.information_uri
        return data


@dataclass(frozen=True)
class EvidenceReport:
    source_path: str
    target_key: str
    target_path: str | None = None
    tool_runs: tuple[ToolRun, ...] = ()
    findings: tuple[Finding, ...] = ()
    warnings: tuple[str, ...] = ()
    metadata: dict[str, Any] | None = None

    def summary(self) -> dict[str, Any]:
        by_severity: dict[str, int] = {}
        by_signal: dict[str, int] = {}
        for finding in self.findings:
            by_severity[finding.severity] = by_severity.get(finding.severity, 0) + 1
            by_signal[finding.signal_type] = by_signal.get(finding.signal_type, 0) + 1
        return {
            "findings": len(self.findings),
            "tools": len(self.tool_runs),
            "warnings": len(self.warnings),
            "by_severity": dict(sorted(by_severity.items())),
            "by_signal": dict(sorted(by_signal.items())),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "ca9.evidence.v1",
            "source_path": self.source_path,
            "target_key": self.target_key,
            "target_path": self.target_path,
            "summary": self.summary(),
            "tool_runs": [run.to_dict() for run in self.tool_runs],
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata or {}),
        }
