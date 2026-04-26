<p align="center">
  <img src="https://raw.githubusercontent.com/duriantaco/ca9/main/assets/ca9.png" alt="ca9 — CVE reachability analysis for Python" width="400">
</p>

<h1 align="center">ca9</h1>

<p align="center"><strong>Stop fixing CVEs that don't affect you.</strong></p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://mozilla.org/MPL/2.0/"><img src="https://img.shields.io/badge/license-MPL--2.0-blue.svg" alt="License: MPL-2.0"></a>
  <a href="https://pypi.org/project/ca9/"><img src="https://img.shields.io/badge/pypi-ca9-orange.svg" alt="PyPI"></a>
  <a href="#zero-heavy-dependencies"><img src="https://img.shields.io/badge/minimal--deps-brightgreen.svg" alt="Minimal Dependencies"></a>
  <img src="https://img.shields.io/badge/Skylos-A%2B%20%2899%29-brightgreen" alt="Skylos A+ (99)">
</p>

---

## The problem

Your SCA tool (Snyk, Dependabot, Trivy, Grype) flags every CVE in your dependency tree. You get 60 alerts. Your team scrambles. But most of those CVEs are in code your application **never imports, never calls, and never executes**.

You're patching vulnerabilities in functions you don't use, in packages you didn't know you had, in code paths your app will never reach.

That's wasted engineering time. That's alert fatigue. That's how real vulnerabilities get ignored.

## What ca9 does

ca9 takes your CVE list and answers one question per vulnerability: **is this code actually reachable from your application?**

```bash
pip install ca9[cli]
ca9 scan --repo . --coverage coverage.json
```

```
CVE ID               Package   Severity  Verdict
--------------------------------------------------------------
GHSA-cpwx-vrp4-4pq7  Jinja2    high      REACHABLE
GHSA-frmv-pr5f-9mcr  Django    critical  UNREACHABLE (static)
GHSA-mrwq-x4v8-fh7p  Pygments  medium    UNREACHABLE (dynamic)
--------------------------------------------------------------
Total: 61  |  Reachable: 25  |  Unreachable: 36  |  Inconclusive: 0

59% of flagged CVEs are unreachable — only 25 of 61 require action
```

36 CVEs eliminated. No manual triage. No guessing.

## How it works

ca9 combines three techniques to prove whether vulnerable code is reachable:

**1. Static analysis (AST import tracing)** — Parses every Python file in your repo and traces `import` statements. If a vulnerable package is never imported, it's unreachable.

**2. Transitive dependency resolution** — Uses `importlib.metadata` to walk the dependency tree. If `urllib3` is only installed because `requests` pulled it in, and `requests` is never imported, both are unreachable.

**3. Dynamic analysis (coverage.py)** — Checks whether vulnerable code was actually *executed* during your test suite. A package might be imported but the specific vulnerable function might never be called.

```
For each CVE:
  Is the package imported?
  ├── NO  → UNREACHABLE (static)
  └── YES → Was vulnerable code executed in tests?
      ├── NO  → UNREACHABLE (dynamic)
      ├── YES → REACHABLE
      └── No coverage data → INCONCLUSIVE
```

ca9 is **conservative** — it only marks something unreachable when it can prove it. Every verdict comes with an evidence trail and a confidence score so you can see exactly why ca9 reached its conclusion.

## Where ca9 fits

ca9 does not replace your SCA tool. It adds local, evidence-first reachability analysis to the vulnerability data you already have.

| | ca9 | Alert-only SCA output | Hosted reachability platforms |
|---|---|---|---|
| **Local analysis** | Runs in your repo/CI | Varies | Often requires source upload or hosted project import |
| **Direct OSV scan** | Yes — `ca9 scan` queries OSV.dev directly | Not always | Varies |
| **SCA report ingestion** | Snyk, Dependabot, Trivy, pip-audit | Native to each tool | Platform-specific |
| **Static + dynamic evidence** | Imports, dependency graph, coverage, API usage | Usually package-level alerts | Varies by vendor and integration |
| **Open outputs** | JSON, SARIF, OpenVEX, Markdown, HTML, remediation, action plan | Vendor-specific | Platform-specific |
| **Confidence/evidence trail** | Structured evidence per verdict | Limited | Varies |
| **Runtime dependencies** | `packaging` core dependency; optional CLI/MCP extras | Varies | Hosted service |

**Use ca9 when you want an open, local Python reachability layer for CVE triage, CI gates, SARIF upload, OpenVEX generation, or SBOM enrichment.**

## Real-world results

### Django REST Framework — 37 CVEs, 19% noise

A focused library that genuinely uses most of its deps. Even here, ca9 found 7 CVEs in packages that are installed but never imported (redis, sentry-sdk, pip):

```
$ ca9 scan --repo /path/to/drf -v

GHSA-g92j-qhmh-64v2  sentry-sdk  low       UNREACHABLE (static)
                      -> 'sentry-sdk' is not imported and not a dependency of any imported package
GHSA-8fww-64cx-x8p5  redis       high      UNREACHABLE (static)
                      -> 'redis' is not imported and not a dependency of any imported package
...
Total: 37  |  Reachable: 0  |  Unreachable: 7  |  Inconclusive: 30
```

### Flask app with bloated deps — 61 CVEs, 59% noise

A Flask app that imports 4 packages but has 19 pinned in `requirements.txt` (Django, tornado, Pygments added "just in case"):

```
$ ca9 scan --repo demo/ --coverage demo/coverage.json

Total: 61  |  Reachable: 25  |  Unreachable: 36  |  Inconclusive: 0

59% of flagged CVEs are unreachable — only 25 of 61 require action
```

Django alone brought 21 CVEs that were pure noise.

**The pattern:** ca9's value scales with how bloated your dependency list is — which in enterprise codebases is typically *very*.

## Quick start

### Scan installed packages (no SCA tool needed)

```bash
pip install ca9[cli]
ca9 scan --repo .
```

This queries [OSV.dev](https://osv.dev) for vulnerabilities in your installed packages. Works with **any** Python project. No Snyk, no Dependabot, no config files.

### Add dynamic analysis for better results

```bash
coverage run --source=.,$(python -c "import site; print(site.getsitepackages()[0])") -m pytest
coverage json -o coverage.json
ca9 scan --repo . --coverage coverage.json
```

### Analyze an existing SCA report

```bash
ca9 check snyk.json --repo . --coverage coverage.json
ca9 check dependabot.json --repo .
```

Format is auto-detected. Supports **Snyk**, **Dependabot**, **Trivy**, and **pip-audit**:

```bash
ca9 check snyk.json --repo .
ca9 check dependabot.json --repo .
ca9 check trivy.json --repo .
ca9 check pip-audit.json --repo .
```

## Verdicts

| Verdict | What it means | What to do |
|---------|---------------|------------|
| `REACHABLE` | Vulnerable code is imported and was executed in tests | **Fix this** |
| `UNREACHABLE (static)` | Package is never imported — not even transitively | Suppress with confidence |
| `UNREACHABLE (dynamic)` | Package is imported but vulnerable code was never executed | Likely safe — monitor |
| `INCONCLUSIVE` | Imported but no coverage data to prove execution | Add coverage or review manually |

## Evidence and confidence

Every verdict is backed by structured evidence. Use `--show-confidence` to see scores in table output, or inspect the `evidence` object in JSON/SARIF output.

| Signal | What it checks |
|--------|----------------|
| `version_in_range` | Is the installed version within the affected range (PEP 440)? |
| `package_imported` | Is the package imported anywhere in the repo? |
| `submodule_imported` | Is the specific vulnerable submodule imported? |
| `coverage_seen` | Was the vulnerable code executed during tests? |
| `api_call_sites_covered` | Were specific vulnerable API call sites executed in tests? |
| `coverage_completeness_pct` | Overall test coverage percentage — weights dynamic absence signals |
| `affected_component_source` | How was the vulnerable component identified (commit analysis, curated mapping, regex, class scan)? |

Confidence scoring is **verdict-directional** — evidence that supports the verdict boosts the score, evidence that contradicts it lowers it. A high confidence UNREACHABLE is different from a high confidence REACHABLE.

| Bucket | Score | Meaning |
|--------|-------|---------|
| High | 80-100 | Strong evidence supports the verdict |
| Medium | 60-79 | Moderate evidence, reasonable certainty |
| Low | 40-59 | Weak evidence, treat with caution |
| Weak | 0-39 | Very little evidence, manual review recommended |

## CLI reference

```
ca9 scan [OPTIONS]              Scan installed packages via OSV.dev
ca9 check SCA_REPORT [OPTIONS]  Analyze a Snyk/Dependabot/Trivy/pip-audit report

Common options:
  -r, --repo PATH                  Path to the project repository  [default: .]
  -c, --coverage PATH              Path to coverage.json for dynamic analysis
  -f, --format [table|json|sarif|vex|remediation|action-plan|markdown|html]
                                      Output format  [default: table]
  -o, --output PATH                Write output to file instead of stdout
  -v, --verbose                    Show reasoning trace for each verdict
  --no-auto-coverage               Disable automatic coverage discovery
  --show-confidence                Show confidence score in table output
  --show-evidence-source           Show evidence extraction source in table output
  --proof-standard [strict|balanced]
                                      Proof policy for suppressions
  --capabilities                   Attach AI capability blast radius
  --runtime-context PATH           Deployment-aware severity adjustment
  --trace-paths                    Trace exploit paths
  --threat-intel                   Enrich with EPSS and CISA KEV data
  --otel-traces PATH               Production runtime evidence from OTLP JSON
  --accepted-risks PATH            Accepted-risk TOML/JSON file
  --baseline PATH                  Previous ca9 JSON report for new-only gating
  --new-only                       Only gate on new reachable/inconclusive findings

Scan-only options:
  --offline                        Use only cached OSV data, no network requests
  --refresh-cache                  Clear OSV cache before fetching
  --max-osv-workers N              Max concurrent OSV detail fetches  [default: 8]

Exit codes:
  0  Clean — no reachable CVEs
  1  Reachable CVEs found — action needed
  2  Inconclusive only — need more coverage data
```

### Config file

Create a `.ca9.toml` in your project root to set defaults:

```toml
repo = "src"
coverage = "coverage.json"
format = "json"
verbose = true
accepted_risks = "accepted-risks.toml"
baseline = "ca9-baseline.json"
new_only = true
```

Config is auto-discovered from the current directory upward. CLI flags override config values.
Accepted-risk and baseline options keep ignored findings visible in report output while excluding them from exit-code decisions.

### Caching and offline mode

ca9 caches OSV vulnerability details (`~/.cache/ca9/osv/`, 24h TTL) and GitHub commit file lists (`~/.cache/ca9/commits/`, 7-day TTL) to reduce API calls.

```bash
ca9 scan --repo . --offline           # use cached data only, no network
ca9 scan --repo . --refresh-cache     # clear cache and re-fetch
```

Set `GITHUB_TOKEN` to avoid GitHub API rate limits when ca9 fetches commit data for affected component analysis:

```bash
export GITHUB_TOKEN=ghp_...
ca9 check snyk.json --repo .
```

## MCP server

ca9 ships an MCP server so LLM-powered tools (Claude Code, Cursor, etc.) can run reachability analysis directly.

```bash
pip install ca9[mcp]
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "ca9": {
      "command": "ca9-mcp"
    }
  }
}
```

Available tools:

| Tool | What it does |
|------|-------------|
| `check_reachability` | Analyze an SCA report (Snyk, Dependabot, Trivy, pip-audit) |
| `scan_dependencies` | Scan installed packages via OSV.dev |
| `check_coverage_quality` | Assess how reliable your coverage data is |
| `explain_verdict` | Deep-dive a specific CVE's verdict with full evidence |
| `generate_vex` | Generate OpenVEX exploitability statements |
| `generate_remediation_plan` | Generate prioritized remediation actions |
| `scan_capabilities` | Scan AI capabilities and emit an AI-BOM |
| `check_blast_radius` | Attach capability blast radius to reachable CVEs |
| `trace_exploit_path` | Trace paths to vulnerable API call sites |
| `lookup_threat_intel` | Look up EPSS and CISA KEV data |
| `enrich_sbom` | Enrich CycloneDX or SPDX SBOM JSON |

## Library usage

```python
import json
from pathlib import Path
from ca9.parsers.snyk import SnykParser
from ca9.engine import analyze

data = json.loads(Path("snyk.json").read_text())
vulns = SnykParser().parse(data)

report = analyze(
    vulnerabilities=vulns,
    repo_path=Path("./my-project"),
    coverage_path=Path("coverage.json"),
)

for result in report.results:
    print(f"{result.vulnerability.id}: {result.verdict.value} (confidence: {result.confidence_score})")
    print(f"  reason: {result.reason}")
    if result.evidence:
        print(f"  source: {result.evidence.affected_component_source}")
```

## Zero heavy dependencies

ca9's core library depends only on `packaging` (PEP 440 version parsing) and the Python standard library. The `click` package is optional — only needed if you use the CLI. This means you can embed ca9 in CI pipelines, security toolchains, or other Python tools without pulling in a large dependency tree.

## Limitations

- Static analysis traces `import` statements and `importlib.metadata` dependency trees. Dynamic imports (`importlib.import_module`, `__import__`) are not detected.
- Coverage quality directly impacts dynamic analysis. If your tests don't exercise a code path, ca9 can't detect it dynamically.
- Transitive dependency resolution requires packages to be installed. Without installed deps, ca9 falls back to direct-import-only checking.
- Python only (for now).

## Development

```bash
git clone https://github.com/duriantaco/ca9.git
cd ca9
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

## License

[MPL-2.0](LICENSE)
