# ca9.models

Core data models. All are frozen (immutable) dataclasses.

## `AffectedComponent`

Identifies the specific submodule or function affected by a CVE.

```python
@dataclass(frozen=True)
class AffectedComponent:
    package_import_name: str
    submodule_paths: tuple[str, ...]
    file_hints: tuple[str, ...]
    confidence: str           # "high", "medium", or "low"
    extraction_source: str    # which strategy produced this
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `package_import_name` | `str` | Python import name of the package |
| `submodule_paths` | `tuple[str, ...]` | Dotted paths to affected submodules (e.g., `("jinja2.sandbox",)`) |
| `file_hints` | `tuple[str, ...]` | Filenames associated with the vulnerability |
| `confidence` | `str` | Extraction confidence: `"high"`, `"medium"`, or `"low"` |
| `extraction_source` | `str` | Which strategy produced this component |

---

## `Verdict`

Enum of possible verdicts.

```python
class Verdict(Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE_STATIC = "UNREACHABLE (static)"
    UNREACHABLE_DYNAMIC = "UNREACHABLE (dynamic)"
    INCONCLUSIVE = "INCONCLUSIVE"
```

---

## `VersionRange`

A single affected version range from OSV data.

```python
@dataclass(frozen=True)
class VersionRange:
    introduced: str | None
    fixed: str | None
    last_affected: str | None
```

---

## `Vulnerability`

A single vulnerability from an SCA report.

```python
@dataclass(frozen=True)
class Vulnerability:
    id: str
    package_name: str
    package_version: str
    severity: str
    title: str
    description: str
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

---

## `VerdictResult`

The verdict for a single vulnerability, including reasoning.

```python
@dataclass(frozen=True)
class VerdictResult:
    vulnerability: Vulnerability
    verdict: Verdict
    reason: str
    imported_as: str | None = None
    executed_files: tuple[str, ...] = ()
    dependency_of: str | None = None
    affected_component: AffectedComponent | None = None
```

**Fields:**

| Field | Type | Description |
|---|---|---|
| `vulnerability` | `Vulnerability` | The vulnerability being analyzed |
| `verdict` | `Verdict` | The assigned verdict |
| `reason` | `str` | Human-readable explanation of the verdict |
| `imported_as` | `str \| None` | How the package was imported (if applicable) |
| `executed_files` | `tuple[str, ...]` | Files from the package that were executed |
| `dependency_of` | `str \| None` | Root package if this is a transitive dependency |
| `affected_component` | `AffectedComponent \| None` | Extracted affected component |

---

## `Report`

Full analysis report.

```python
@dataclass(frozen=True)
class Report:
    results: tuple[VerdictResult, ...]
    repo_path: str
    coverage_path: str | None = None
```

**Properties:**

| Property | Type | Description |
|---|---|---|
| `total` | `int` | Total number of vulnerabilities analyzed |
| `reachable_count` | `int` | Count of REACHABLE verdicts |
| `unreachable_count` | `int` | Count of UNREACHABLE (static + dynamic) verdicts |
| `inconclusive_count` | `int` | Count of INCONCLUSIVE verdicts |
