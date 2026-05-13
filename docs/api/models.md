# ca9.models

Core data models used by the parser, engine, policy, and report layers.

Most leaf models are frozen dataclasses so they can be passed around safely. `VerdictResult`, `PolicyIgnoredResult`, and `Report` are mutable dataclasses because later pipeline stages attach policy, runtime, threat-intel, and output metadata.

## `AffectedComponent`

Identifies the specific package module, submodule, file hint, or extraction strategy associated with a vulnerability.

```python
@dataclass(frozen=True)
class AffectedComponent:
    package_import_name: str
    submodule_paths: tuple[str, ...] = ()
    file_hints: tuple[str, ...] = ()
    confidence: str = "low"
    extraction_source: str = ""
    warnings: tuple[str, ...] = ()
```

## `Verdict`

Internal verdict enum values use stable machine-readable strings. Human-readable labels such as `UNREACHABLE (static)` are rendered by the reporting layer.

```python
class Verdict(Enum):
    REACHABLE = "reachable"
    UNREACHABLE_STATIC = "unreachable_static"
    UNREACHABLE_DYNAMIC = "unreachable_dynamic"
    INCONCLUSIVE = "inconclusive"
```

## `VersionRange`

Represents one affected range from OSV or parser-normalized advisory data.

```python
@dataclass(frozen=True)
class VersionRange:
    introduced: str = ""
    fixed: str = ""
    last_affected: str = ""
```

## `Vulnerability`

Normalized vulnerability input from an SCA report or OSV scan.

```python
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
```

## API Usage Models

Curated rules can identify vulnerable functions, methods, classes, attributes, or modules. Matching call sites are stored as evidence.

```python
@dataclass(frozen=True)
class ApiTarget:
    package: str
    fqname: str
    kind: str = "function"
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
```

## `Evidence`

Structured proof signals used to derive the verdict and confidence score.

```python
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
    api_usage_seen: bool | None = None
    api_usage_confidence: int | None = None
    api_call_sites_covered: bool | None = None
    intel_rule_ids: tuple[str, ...] = ()
    coverage_completeness_pct: float | None = None
    threat_intel: ThreatIntelData | None = None
    production_observed: bool | None = None
    production_trace_count: int = 0
```

## Runtime And Enrichment Models

```python
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
    epss_score: float | None = None
    epss_percentile: float | None = None
    in_kev: bool = False
    kev_due_date: str | None = None
```

## `VerdictResult`

The verdict and all evidence for one vulnerability.

```python
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
    confidence_score: int = 0
    original_verdict: Verdict | None = None
    policy_adjustment: str | None = None
    blast_radius: object | None = None
    runtime_mitigations: list[str] = field(default_factory=list)
    runtime_adjusted_priority: str | None = None
    exploit_paths: list[ExploitPath] = field(default_factory=list)
    threat_intel: ThreatIntelData | None = None
```

## `PolicyIgnoredResult`

Tracks findings suppressed by accepted-risk or baseline policy without removing them from report output.

```python
@dataclass
class PolicyIgnoredResult:
    result: VerdictResult
    policy: str
    reason: str
    owner: str = ""
    expires: str | None = None
```

## `Report`

Full analysis report returned by the engine and consumed by output writers.

```python
@dataclass
class Report:
    results: list[VerdictResult]
    repo_path: str
    coverage_path: str | None = None
    proof_standard: str = "strict"
    warnings: list[str] = field(default_factory=list)
    ignored_results: list[PolicyIgnoredResult] = field(default_factory=list)
```

Important computed properties:

| Property | Description |
|---|---|
| `total` | Number of active findings in `results`. |
| `ignored_count` | Number of policy-ignored findings in `ignored_results`. |
| `reachable_count` | Count of active `REACHABLE` findings. |
| `unreachable_count` | Count of active static or dynamic unreachable findings. |
| `inconclusive_count` | Count of active `INCONCLUSIVE` findings. |
| `exit_code` | `1` for reachable findings, `2` for inconclusive-only findings, otherwise `0`. |
