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
    report_dependency_kind: str | None = None
    report_dependency_chain: tuple[str, ...] = ()
    ecosystem: str = "pypi"
    aliases: tuple[str, ...] = ()
    cwes: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()
    advisory_source: str = ""
    advisory_url: str = ""
    published_at: str | None = None
    modified_at: str | None = None
    fetched_at: str | None = None
    cache_stale: bool | None = None
    malicious: bool = False


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
    match_type: str = "direct_call"
    matched_target: str = ""
    code_snippet: str | None = None
    confidence: int = 80
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class Evidence:
    version_in_range: bool | None = None
    dependency_kind: str | None = None
    dependency_graph_available: bool = False
    dependency_graph_source: str = ""
    declared_direct_dependency: bool = False
    package_imported: bool = False
    submodule_imported: bool | None = None
    report_dependency_chain: tuple[str, ...] = ()
    affected_component_source: str = ""
    affected_component_confidence: int = 0
    coverage_seen: bool | None = None
    coverage_files: tuple[str, ...] = ()
    external_fetch_warnings: tuple[str, ...] = ()
    api_targets: tuple[str, ...] = ()
    api_usage_hits: tuple[ApiUsageHit, ...] = ()
    api_usage_seen: bool | None = None  # none = not checked
    api_usage_confidence: int | None = None
    api_call_sites_covered: bool | None = None  # none = not checked / no coverage
    intel_rule_ids: tuple[str, ...] = ()
    coverage_completeness_pct: float | None = None  # 0-100, from coverage.json totals
    threat_intel: ThreatIntelData | None = None
    production_observed: bool | None = None
    production_trace_count: int = 0
    # Presence in the coverage report is not proof of complete instrumentation.
    coverage_scope: str = "unavailable"
    coverage_measured_files: tuple[str, ...] = ()
    coverage_unmeasured_targets: tuple[str, ...] = ()
    # "metadata" or "curated" mappings can prove an import is absent; "guessed" cannot.
    import_names: tuple[str, ...] = ()
    import_name_source: str = ""
    package_installed: bool | None = None  # none = not checked
    # Ways the package may run without an import: CLI, plugin, config string.
    indirect_use_signals: tuple[str, ...] = ()
    # Packages whose absence of imports rests on a guessed import name.
    unproven_import_mappings: tuple[str, ...] = ()
    submodule_evidence: str = ""
    # Imported modules no installed distribution provides; they leave the
    # environment dependency graph incomplete.
    dependency_graph_unresolved: tuple[str, ...] = ()


@dataclass(frozen=True)
class PathStep:
    file_path: str
    function_name: str
    line: int
    col: int | None = None
    code_snippet: str | None = None


@dataclass(frozen=True)
class ExploitPath:
    entry_point: PathStep
    steps: tuple[PathStep, ...]
    vulnerable_call: PathStep
    vulnerable_target: str
    confidence: int = 80


@dataclass(frozen=True)
class ThreatIntelData:
    epss_score: float | None = None  # 0.0-1.0
    epss_percentile: float | None = None  # 0.0-1.0
    in_kev: bool | None = False
    kev_due_date: str | None = None
    epss_status: str = "unknown"
    epss_score_date: str | None = None
    epss_retrieved_at: str | None = None
    kev_status: str = "unknown"
    kev_date_added: str | None = None
    kev_catalog_date: str | None = None
    kev_retrieved_at: str | None = None

    def to_dict(self) -> dict:
        from dataclasses import asdict

        return asdict(self)

    @property
    def current_high_epss(self) -> bool:
        from ca9 import risk_context as risk

        now = risk.dt.datetime.now(risk.dt.timezone.utc)
        record = risk._epss_record(
            {
                "score": self.epss_score,
                "percentile": self.epss_percentile,
                "score_date": self.epss_score_date,
                "retrieved_at": self.epss_retrieved_at,
            },
            now,
        )
        return bool(
            self.epss_status == "current"
            and record
            and record["score"] >= 0.5
            and risk._fresh(record, now, "score_date")
        )

    @property
    def current_kev(self) -> bool:
        from ca9 import risk_context as risk

        now = risk.dt.datetime.now(risk.dt.timezone.utc)
        catalog = risk._date(self.kev_catalog_date, now.date())
        added = risk._date(self.kev_date_added, now.date())
        due = risk._date(self.kev_due_date, now.date(), future=True)
        retrieved = risk._instant(self.kev_retrieved_at, now)
        return bool(
            self.kev_status == "current"
            and self.in_kev is True
            and catalog
            and added
            and due
            and retrieved
            and added <= catalog <= retrieved.astimezone(risk.dt.timezone.utc).date().isoformat()
            and added <= due
            and risk._fresh(
                {"catalog_date": catalog, "retrieved_at": self.kev_retrieved_at},
                now,
                "catalog_date",
            )
        )


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
    original_verdict: Verdict | None = None
    policy_adjustment: str | None = None
    blast_radius: object | None = None
    runtime_mitigations: list[str] = field(default_factory=list)
    runtime_adjusted_priority: str | None = None
    exploit_paths: list[ExploitPath] = field(default_factory=list)
    threat_intel: ThreatIntelData | None = None


@dataclass
class PolicyIgnoredResult:
    result: VerdictResult
    policy: str
    reason: str
    owner: str = ""
    expires: str | None = None


def finding_key(vuln_id: str, package_name: str, package_version: str) -> tuple[str, str, str]:
    return (vuln_id, package_name.lower(), package_version)


@dataclass
class Report:
    results: list[VerdictResult]
    repo_path: str
    coverage_path: str | None = None
    proof_standard: str = "strict"
    warnings: list[str] = field(default_factory=list)
    ignored_results: list[PolicyIgnoredResult] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def ignored_count(self) -> int:
        return len(self.ignored_results)

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
