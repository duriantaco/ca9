from __future__ import annotations

import enum
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AffectedComponent:
    package_import_name: str
    submodule_paths: tuple[str, ...] = ()
    file_hints: tuple[str, ...] = ()
    confidence: str = "low"
    extraction_source: str = ""
    warnings: tuple[str, ...] = ()


class Verdict(enum.Enum):
    REACHABLE = "reachable"
    UNREACHABLE_STATIC = "unreachable_static"
    UNREACHABLE_DYNAMIC = "unreachable_dynamic"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class VersionRange:
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""


@dataclass(frozen=True)
class Vulnerability:
    id: str
    package_name: str
    package_version: str
    severity: str
    title: str
    description: str = ""
    affected_ranges: tuple[VersionRange, ...] = ()
    references: tuple[str, ...] = ()


@dataclass(frozen=True)
class ApiTarget:
    package: str
    fqname: str
    kind: str = "function"  # function, class, method, attribute, module
    module: str | None = None
    symbol: str | None = None
    aliases: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    rule_id: str = ""


@dataclass(frozen=True)
class ApiUsageHit:
    file_path: str
    line: int
    col: int | None = None
    match_type: str = "direct_call"  # direct_call, attribute_call, imported_symbol_call, class_instantiation, symbol_reference
    matched_target: str = ""
    code_snippet: str | None = None
    confidence: int = 80
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    version_in_range: bool | None = None
    dependency_kind: str | None = None  # direct, transitive, none
    package_imported: bool = False
    submodule_imported: bool | None = None  # none = not checked
    affected_component_source: str = ""
    affected_component_confidence: int = 0  # 0-100
    coverage_seen: bool | None = None  # none = no coverage data
    coverage_files: tuple[str, ...] = ()
    external_fetch_warnings: tuple[str, ...] = ()
    api_targets: tuple[str, ...] = ()
    api_usage_hits: tuple[ApiUsageHit, ...] = ()
    api_usage_seen: bool | None = None  # none = not checked
    api_usage_confidence: int | None = None
    api_call_sites_covered: bool | None = None  # none = not checked / no coverage
    intel_rule_ids: tuple[str, ...] = ()
    coverage_completeness_pct: float | None = None  # 0-100, from coverage.json totals


@dataclass
class VerdictResult:
    vulnerability: Vulnerability
    verdict: Verdict
    reason: str
    imported_as: str | None = None
    executed_files: list[str] = field(default_factory=list)
    dependency_of: str | None = None
    affected_component: AffectedComponent | None = None
    evidence: Evidence | None = None
    confidence_score: int = 0  # 0-100


def finding_key(vuln_id: str, package_name: str, package_version: str) -> tuple[str, str, str]:
    return (vuln_id, package_name.lower(), package_version)


@dataclass
class Report:
    results: list[VerdictResult]
    repo_path: str
    coverage_path: str | None = None

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def reachable_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.REACHABLE)

    @property
    def unreachable_count(self) -> int:
        return sum(
            1
            for r in self.results
            if r.verdict in (Verdict.UNREACHABLE_STATIC, Verdict.UNREACHABLE_DYNAMIC)
        )

    @property
    def inconclusive_count(self) -> int:
        return sum(1 for r in self.results if r.verdict == Verdict.INCONCLUSIVE)

    @property
    def exit_code(self) -> int:
        if self.reachable_count > 0:
            return 1
        if self.inconclusive_count > 0:
            return 2
        return 0
