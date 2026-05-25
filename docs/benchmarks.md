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

## Real-Repo Validation Gate

Before publishing reachability or supply-chain claims, run the pinned public-repo
validation harness:

```bash
python scripts/real_repo_validation.py --output-dir /tmp/ca9-real-repo-validation
```

The harness clones public repositories at fixed commits, runs `ca9 inventory` and
`ca9 scan --no-auto-coverage`, writes per-case JSON artifacts, and fails on safety
regressions. It is not a marketing benchmark. It is a guardrail for claims that ca9
does not leak ambient environment packages into repository scans and does not emit
unsafe unreachable suppressions when evidence is incomplete.

Current validation set:

| Case | Commit | Purpose | Expected contract |
|---|---|---|---|
| Flask | `954f5684e4841aad84a8eec7ace7b81a0d3f6831` | Real Python project with resolvable dependency inventory | Inventory resolves from repo evidence with no environment fallback |
| Django REST Framework | `7433faa98f27c200e34c04586c20024d4d6aa935` | Real Python project with unresolved dependency versions | Scan skips unresolved versions instead of using the ambient environment |
| SafeDep vet | `d4491496daec6f445803a039524ddab714be01b2` | Real non-Python supply-chain scanner repository | Scan reports no Python CVEs from the current environment |
| PinTrace | `04b343779b49faf1691823a225858ef93c52c747` | Real Python repo with pinned vulnerable dependencies | Vulnerable imports remain inconclusive without coverage, not suppressed as unreachable |

Latest local run:

| Case | Inventory Packages | Scan Total | Reachable | Unreachable | Inconclusive | Safety Result |
|---|---:|---:|---:|---:|---:|---|
| Flask | 8 | 0 | 0 | 0 | 0 | Pass |
| Django REST Framework | 1 | 0 | 0 | 0 | 0 | Pass |
| SafeDep vet | 0 | 0 | 0 | 0 | 0 | Pass |
| PinTrace | 11 | 2 | 0 | 0 | 2 | Pass |

Do not interpret this table as proof that ca9 catches every vulnerability. The stronger
claim is narrower: when ca9 lacks enough evidence, it should prefer `INCONCLUSIVE` over
an unsafe `UNREACHABLE` verdict.

## npm Lockfile Inventory Validation

Before publishing npm inventory claims, run the pinned public-repo lockfile validation
harness:

```bash
python scripts/npm_real_repo_validation.py --output-dir /tmp/ca9-npm-real-repo-validation
```

The harness downloads real `package-lock.json` files at fixed commits, builds an
independent baseline directly from each lockfile, then compares ca9 inventory output
against that baseline. The baseline checks package keys, dependency edges, direct package
count, and artifact/tarball count. It does not install packages or execute JavaScript.

Current npm validation set:

| Case | Commit | Lockfile | Packages | Edges | Direct | Artifacts | Result |
|---|---|---:|---:|---:|---:|---:|---|
| axios | `979918445324cb9150134d068ba06f8cc9723346` | 3 | 686 | 1277 | 43 | 716 | Pass |
| Mocha | `6695fba397a6d1ca2d7cd4de86d9dda2d3fba342` | 3 | 809 | 1431 | 63 | 846 | Pass |
| npm CLI | `c97b39b1e3436cd20a67ab5f4012a5f395c538b9` | 3 | 971 | 2151 | 70 | 312 | Pass |
| Socket.IO | `5257ef9adfa02a4e8f8eaa5f6810565f979ccc48` | 3 | 1140 | 2131 | 59 | 1271 | Pass |

Do not interpret this as proof of npm malware detection. It proves the narrower
inventory contract: ca9 can read real npm lockfiles and preserve the package, dependency,
registry, and tarball evidence needed by later advisory and artifact analyzers.

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
