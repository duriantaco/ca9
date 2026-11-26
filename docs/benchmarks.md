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
- SCA source: OSV scan, Snyk, Dependabot, Trivy, Grype, OSV-Scanner, or pip-audit.
- Coverage command and coverage percentage.
- ca9 command and version.
- Total, reachable, unreachable, and inconclusive counts.
- Notes explaining why unreachable findings are considered noise.

## Python triage on public projects

The benchmark checks strict JSON verdicts and OpenVEX statements against six
reviewed cases, then runs live OSV scans separately. Run these commands from a
ca9 development checkout with the CLI dependencies installed.

```bash
PYTHONPATH=src python scripts/real_repo_validation.py --output-dir /tmp/ca9-real
PYTHONPATH=src python scripts/real_repo_validation.py --replay-only --output-dir /tmp/ca9-replay
```

Both commands verify the pinned upstream commits. The replay uses frozen OSV
identity, title when available, and version evidence. It uses no live advisory
lookup. Each case writes the input, ca9 JSON and OpenVEX under `artifacts/`.
The full run also writes the live inventory and scan. A checkout or scan error
is recorded in `summary.json` and causes a failing exit status.

### Reviewed decisions

Tested on 2026-11-26 with CPython 3.13.18 on arm64 macOS. The comparison uses
the same inputs and interpreter with the engine from `ad2c629` and the updated
engine. Each row counts once and passes only if both output formats agree with
the expected decision.

| Project and input | Evidence available | Expected | Previous | Updated |
|---|---|---|---|---|
| Flask 3.1.3, Werkzeug 3.1.5 | Pinned source only, no recorded execution | Investigate | Investigate | Investigate |
| Same release, `send_file` | A normal file read, trace shows zero calls to the named `safe_join` function | Investigate | Reachable | Investigate |
| Same release, `send_from_directory` | The same file served successfully, trace confirms the named function ran | Reachable | Reachable | Reachable |
| Docker Compose 1.29.2, PyYAML 5.4.1 | Project pin is past the advisory's 5.4 fix | Unaffected version | Unaffected version | Unaffected version |
| Same release, Requests 2.24.0 | Version falls in range. The application imports Requests exceptions. No coverage establishes the affected call | Investigate | Investigate | Investigate |
| Same release, certifi 2020.6.20 | The advisory's explicit affected list includes the equivalent `2020.06.20`, while its release range starts in 2021 | Investigate | Unaffected version | Investigate |

The updated engine matched **6/6** reviewed decisions, up from **4/6**.
Four of the six call for investigation. The Flask positive establishes that the
named routine ran on an ordinary file read. Deployment exposure also depends on
the operating system and inputs. These six deliberately selected cases measure
specific decisions. Estimating overall accuracy would require a representative sample.
[Werkzeug advisory](https://osv.dev/vulnerability/GHSA-g6x2-hccm-hh4m) ·
[PyYAML advisory](https://osv.dev/vulnerability/GHSA-8q59-q68h-6hv4) ·
[Requests advisory](https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q) ·
[certifi advisory](https://osv.dev/vulnerability/PYSEC-2024-230)

The Flask observations were collected after import. Each call served the same
local `hello.txt`. The capture checks the response body, records executed lines
in the two relevant Werkzeug modules and independently checks the function's
code-object identity. To regenerate them with the pinned Flask checkout from
the full run and a fresh Python 3.13 environment:

```bash
flask_repo=/tmp/ca9-real/repos/flask-release
python3.13 -m venv /tmp/ca9-flask-probe
uv export --project "$flask_repo" --frozen --offline --no-default-groups --no-dev --no-emit-project --no-annotate --format requirements.txt --python /tmp/ca9-flask-probe/bin/python --output-file /tmp/ca9-flask-requirements.txt
/tmp/ca9-flask-probe/bin/python -m pip install --no-deps --only-binary=:all: --require-hashes -r /tmp/ca9-flask-requirements.txt
PYTHONPATH="$flask_repo/src" /tmp/ca9-flask-probe/bin/python tests/fixtures/triage_benchmark/capture_flask.py > /tmp/flask_calls.json
diff tests/fixtures/triage_benchmark/flask_calls.json /tmp/flask_calls.json
```

### Held-out version decisions

After freezing the engine, we labelled two additional cases from pip 23.2.1
before running either check. Its vendoring manifest pins Requests 2.31.0 and
urllib3 1.26.16. The respective fixes shipped in 2.31.0 and 1.26.5. Both
reports should therefore say `not_affected` on version grounds. The strict
JSON verdicts and OpenVEX statements matched both labels. This check supplies
the package versions and measures the decision after an alert is received.
[pip manifest](https://github.com/pypa/pip/blob/4a79e65cb6aac84505ad92d272a29f0c3c1aedce/src/pip/_vendor/vendor.txt)
· [Requests advisory](https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q)
· [urllib3 advisory](https://github.com/urllib3/urllib3/security/advisories/GHSA-q2q7-5pp4-w6pg)

```bash
git clone --branch 23.2.1 --depth 1 https://github.com/pypa/pip /tmp/ca9-pip
git -C /tmp/ca9-pip rev-parse HEAD
PYTHONPATH=src python -m ca9.cli check tests/fixtures/triage_benchmark/pip_holdout.json --repo /tmp/ca9-pip --proof-standard strict -f vex
```

### Live scans without runtime coverage

| Project | Pinned commit | Package versions checked | Returned findings | Interpretation |
|---|---|---:|---:|---|
| Flask development snapshot | `954f5684e4841aad84a8eec7ace7b81a0d3f6831` | 8 | 1 | Inconclusive |
| Django REST Framework | `7433faa98f27c200e34c04586c20024d4d6aa935` | 0 | 0 | Partial, declared version unresolved |
| SafeDep vet | `d4491496daec6f445803a039524ddab714be01b2` | 0 | 0 | Partial, no supported Python declarations |
| Docker Compose 1.29.2 | `5becea4ca9f68875334c92f191a13482bcd6e5cf` | 54 | 149 | All inconclusive |
| Flask 3.1.3 | `22d924701a6ae2e4cd01e9a15bbaf3946094af65` | 8 | 5 | All inconclusive |

The live run generated 155 findings. Without runtime coverage the engine left
all 155 inconclusive. The reported reasons cite missing dependency source in
42 cases and an unverified distribution-to-import name in 35. Determining
deployment impact in these cases requires additional evidence. Counts can change
as OSV records change. The former PinTrace commit
`04b343779b49faf1691823a225858ef93c52c747` was unavailable upstream during
this run. Its historical results are excluded.

### Package selection and Python call matching

| Independent check | Previous | Updated |
|---|---:|---:|
| Production versions selected by uv across Skylos and Ravage | 24/85 | 85/85 |
| Applicable Compose requirements on macOS, Python 3.13 | 54 matched, 4 extra | 54 matched, 0 extra |
| Six reviewed Python call sites in Flask and packaging | 3/6 | 6/6 |

The uv reference uses frozen, offline exports on macOS arm64 with Python 3.12.16
and uv 0.13.10. Skylos contributed 71 production pins and Ravage 14. ca9 also
checked five versions explicitly declared in Skylos optional dependencies. The
lock benchmark verifies the commits inside each local checkout.

```bash
git clone https://github.com/duriantaco/skylos /tmp/ca9-skylos
git clone https://github.com/duriantaco/ravage /tmp/ca9-ravage
PYTHONPATH=src python3.12 scripts/validate_uv_scan.py --skylos /tmp/ca9-skylos --ravage /tmp/ca9-ravage
PYTHONPATH=src python scripts/source_evidence_validation.py
```

The source benchmark verifies upstream file hashes, checks four actual calls
and two references that resolve elsewhere at runtime, and checks how a parser
reports unsupported syntax using unmodified CPython 3.14 source. That last
check uses a synthetic advisory solely to test incomplete evidence.

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
