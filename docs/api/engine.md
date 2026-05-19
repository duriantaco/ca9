# ca9.engine

The verdict engine — orchestrates analysis and assigns verdicts.

## `analyze()`

```python
def analyze(
    vulnerabilities: list[Vulnerability],
    repo_path: Path,
    coverage_path: Path | None = None,
    proof_standard: str = "strict",
    scan_capabilities: bool = False,
    trace_exploit_paths: bool = False,
    threat_intel: bool = False,
    otel_traces_path: Path | None = None,
) -> Report
```

Main entry point for reachability analysis.

**Parameters:**

| Parameter | Type | Description |
|---|---|---|
| `vulnerabilities` | `list[Vulnerability]` | Vulnerabilities to analyze |
| `repo_path` | `Path` | Path to the project repository |
| `coverage_path` | `Path \| None` | Path to `coverage.json` (optional) |
| `proof_standard` | `str` | Suppression policy, either `strict` or `balanced` |
| `scan_capabilities` | `bool` | Attach AI capability blast-radius data to reachable findings |
| `trace_exploit_paths` | `bool` | Trace paths from entry points to vulnerable API call sites |
| `threat_intel` | `bool` | Enrich CVEs with EPSS and CISA KEV data |
| `otel_traces_path` | `Path \| None` | OTLP JSON export for production runtime evidence |

**Returns:** `Report` with a `VerdictResult` for each vulnerability.

**Behavior:**

For each vulnerability, the engine:

1. Checks if the package version falls within affected ranges
2. Extracts the affected component using `vuln_matcher`
3. Checks if the package is imported (static analysis)
4. Checks transitive dependency relationships
5. If high/medium confidence: performs submodule-level analysis
6. If coverage available: performs dynamic execution check
7. If enabled, attaches API exploit paths, threat intelligence, production trace evidence, and AI capability blast radius
8. Applies the selected proof standard, assigns a verdict, and records the reasoning

**Example:**

```python
from pathlib import Path
from ca9.engine import analyze
from ca9.parsers import detect_parser
import json

# Parse an SCA report
parser = detect_parser(Path("snyk-report.json"))
data = json.loads(Path("snyk-report.json").read_text())
vulns = parser.parse(data)

# Analyze
report = analyze(
    vulnerabilities=vulns,
    repo_path=Path("."),
    coverage_path=Path("coverage.json"),
    proof_standard="strict",
)

# Inspect results
for result in report.results:
    print(f"{result.vulnerability.id}: {result.verdict.value}")
    print(f"  Reason: {result.reason}")
```
