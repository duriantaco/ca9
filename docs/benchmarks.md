---
title: Benchmarks
description: Reproducible ca9 benchmark methodology for Python CVE reachability analysis and false-positive reduction claims.
---

# Benchmarks

ca9 benchmark claims should be reproducible from public commands and pinned inputs. Keep benchmark pages tied to fixtures, reports, coverage files, and exact command lines.

## Recommended benchmark shape

Each benchmark should record:

- Repository or fixture name.
- Dependency manifest and lockfile state.
- SCA source: OSV scan, Snyk, Dependabot, Trivy, or pip-audit.
- Coverage command and coverage percentage.
- ca9 command and version.
- Total, reachable, unreachable, and inconclusive counts.
- Notes explaining why unreachable findings are considered noise.

## Demo benchmark

The repository includes a demo app designed to show dependency noise reduction.

```bash
cd demo
./setup_demo.sh
./run_demo.sh
```

Or run the core commands directly:

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 scan --repo . --coverage coverage.json --show-confidence
```

## Reporting template

Use this table when adding benchmark results:

| Benchmark | SCA source | Coverage | Total | Reachable | Unreachable | Inconclusive | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Demo Flask app | OSV | `coverage.json` | TBD | TBD | TBD | TBD | `ca9 scan --repo demo --coverage demo/coverage.json` |

Do not publish a benchmark number without the command needed to reproduce it.
