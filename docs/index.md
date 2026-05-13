---
title: ca9 | Python CVE Reachability Analysis for SCA Triage
description: Open source Python CVE reachability analysis for evidence-backed SCA triage. Parse Snyk, Dependabot, Trivy, and pip-audit reports or query OSV; emit JSON, SARIF, and OpenVEX evidence.
---

# ca9

**Evidence-backed Python CVE triage to cut SCA noise.**

<p align="center">
  <img src="assets/ca9.png" alt="ca9 - Python CVE reachability analysis" width="400">
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://mozilla.org/MPL/2.0/"><img src="https://img.shields.io/badge/license-MPL--2.0-blue.svg" alt="License: MPL-2.0"></a>
  <a href="https://pypi.org/project/ca9/"><img src="https://img.shields.io/badge/pypi-ca9-orange.svg" alt="PyPI"></a>
  <img src="https://img.shields.io/badge/Skylos-A%2B%20%2899%29-brightgreen" alt="Skylos A+ (99)">
</p>

SCA tools such as Snyk, Dependabot, Trivy, pip-audit, and OSV report vulnerable packages in your dependency tree. **ca9** adds local reachability evidence and advisory metadata so Python teams can decide what to fix, suppress, or investigate.

## What ca9 checks

ca9 combines conservative static and runtime signals for each vulnerability:

1. **Static imports** - parses Python ASTs to see whether a vulnerable package or submodule is imported.
2. **Dependency inventory** - scans declared dependencies, installed packages, and transitive relationships.
3. **Coverage evidence** - reads `coverage.py` JSON to see whether vulnerable package code or known API call sites executed in tests.
4. **Affected component extraction** - maps CVE metadata, advisories, commits, and curated rules to specific modules where possible.
5. **Advisory metadata** - preserves aliases, CWE/CPE IDs, source URLs, timestamps, and cache freshness where inputs provide them.
6. **Context enrichment** - can add confidence scores, OpenTelemetry production traces, EPSS/KEV threat intelligence, AI capability blast radius, and exploit path traces.

## Key features

- **Direct OSV scanning** with `ca9 scan`, so you can analyze installed or declared Python packages without a separate SCA report.
- **SCA report parsing** for Snyk, Dependabot, Trivy, and pip-audit JSON.
- **CI-friendly outputs** including table, JSON, SARIF, OpenVEX, Markdown, HTML, remediation plans, and machine-readable action plans.
- **SBOM enrichment** for CycloneDX and SPDX documents.
- **MCP server** for running reachability checks from LLM-powered tools.
- **Small core dependency footprint**: the core package depends on `packaging`; CLI and MCP dependencies are optional extras.

## Quick example

```bash
pip install ca9[cli]
ca9 scan --repo . --coverage coverage.json
```

```
CVE ID               Package   Severity  Verdict
--------------------------------------------------------------
GHSA-abcd-1234       jinja2    high      UNREACHABLE (static)
CVE-2024-5678        django    critical  REACHABLE
GHSA-efgh-9012       urllib3   medium    UNREACHABLE (dynamic)
--------------------------------------------------------------
Total: 3  |  Reachable: 1  |  Unreachable: 2  |  Inconclusive: 0
```

## Common workflows

| Workflow | Command |
|---|---|
| Scan declared or installed dependencies with OSV | `ca9 scan --repo .` |
| Analyze Snyk, Dependabot, Trivy, or pip-audit JSON | `ca9 check report.json --repo .` |
| Add dynamic evidence | `ca9 check report.json --coverage coverage.json` |
| Upload GitHub code scanning results | `ca9 check report.json -f sarif -o ca9.sarif` |
| Generate OpenVEX statements | `ca9 check report.json -f vex -o openvex.json` |
| Generate a human report | `ca9 check report.json -f markdown -o ca9-report.md` |
| Enrich an SBOM | `ca9 enrich-sbom sbom.json --repo . -o sbom.ca9.json` |
| Scan AI capabilities | `ca9 capabilities --repo . -f json -o aibom.json` |

## Verdicts

| Verdict | Meaning |
|---|---|
| `REACHABLE` | The vulnerable package, component, or known API usage is reachable from your application evidence. |
| `UNREACHABLE (static)` | ca9 found enough static evidence to prove the package or affected submodule is not used. |
| `UNREACHABLE (dynamic)` | The package is imported, but coverage evidence did not execute the affected package/component. |
| `INCONCLUSIVE` | ca9 does not have enough evidence to prove reachable or unreachable. |

## Next steps

- [Install ca9](getting-started/installation.md)
- [Run your first scan](getting-started/quickstart.md)
- [Review CLI options](guide/cli.md)
- [Understand supported formats](guide/formats.md)
- [Improve coverage evidence](guide/coverage.md)
