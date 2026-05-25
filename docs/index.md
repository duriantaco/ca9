---
title: ca9 | Python Package Security and Evidence-Backed SCA Triage
description: Open source Python package security for evidence-backed SCA triage, supply-chain vetting, package inventory, malicious package behavior, and dependency policy gates.
---

# ca9

**Local, evidence-backed security for Python packages and SCA alerts.**

<p align="center">
  <img src="assets/ca9.png" alt="ca9 - Python package security" width="400">
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://mozilla.org/MPL/2.0/"><img src="https://img.shields.io/badge/license-MPL--2.0-blue.svg" alt="License: MPL-2.0"></a>
  <a href="https://pypi.org/project/ca9/"><img src="https://img.shields.io/badge/pypi-ca9-orange.svg" alt="PyPI"></a>
  <img src="https://img.shields.io/badge/Skylos-A%2B%20%2899%29-brightgreen" alt="Skylos A+ (99)">
</p>

SCA tools such as Snyk, Dependabot, Trivy, pip-audit, and OSV report vulnerable packages in your dependency tree. **ca9** adds local package evidence, reachability analysis, supply-chain checks, and advisory metadata so Python teams can decide what to fix, block, suppress, or investigate.

## What ca9 checks

ca9 combines conservative static and runtime signals for each vulnerability:

1. **Static imports** - parses Python ASTs to see whether a vulnerable package or submodule is imported.
2. **Dependency inventory** - scans declared dependencies, installed packages, and transitive relationships.
3. **Supply-chain vetting** - checks lockfile evidence, package indexes, artifact hashes, malicious advisories, artifact static analysis, internal package policy, and license policy.
4. **Coverage evidence** - reads `coverage.py` JSON to see whether vulnerable package code or known API call sites executed in tests.
5. **Affected component extraction** - maps CVE metadata, advisories, commits, and curated rules to specific modules where possible.
6. **Advisory metadata** - preserves aliases, CWE/CPE IDs, source URLs, timestamps, and cache freshness where inputs provide them.
7. **Context enrichment** - can add confidence scores, OpenTelemetry production traces, EPSS/KEV threat intelligence, AI capability blast radius, and exploit path traces.

## Key features

- **Direct OSV scanning** with `ca9 scan`, so you can analyze installed or declared Python packages without a separate SCA report.
- **Package inventory** with `ca9 inventory`, including native `fyn.lock` and npm `package-lock.json` support for resolved packages, artifacts, hashes/integrity values, groups, and dependency edges.
- **Supply-chain gates** with `ca9 vet` for untrusted indexes, dependency confusion, malicious package advisories, artifact static analysis, and license policy.
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
| Scan repository dependency versions with OSV | `ca9 scan --repo .` |
| Inspect normalized package inventory | `ca9 inventory --repo . -f json` |
| Run supply-chain risk checks | `ca9 vet --repo . --scan-artifacts` |
| Gate internal package resolution | `ca9 vet --repo . --internal-package 'acme-*' --private-index https://packages.acme.internal/simple` |
| Gate denied licenses | `ca9 vet --repo . --deny-license AGPL-3.0 --deny-license GPL-3.0` |
| Run the supply-chain demo | `bash demo/supply_chain/run_demo.sh` |
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
- [Try the demos](demo.md)
- [Review CLI options](guide/cli.md)
- [Run supply-chain vetting](guide/supply-chain.md)
- [Understand supported formats](guide/formats.md)
- [Improve coverage evidence](guide/coverage.md)
