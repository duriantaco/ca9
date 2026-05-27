---
title: Supply-Chain Vetting
description: Use ca9 inventory and ca9 vet to inspect Python/npm package inventory, lockfile evidence, malicious package behavior, dependency confusion, artifact integrity, and license policy.
---

# Supply-Chain Vetting

`ca9 vet` is the broader package-security command. It builds on normalized inventory and
checks dependency risk beyond CVE reachability.

The current implementation is intentionally local-first:

- fyn is optional; ca9 reads `fyn.lock` natively when present.
- npm projects can be inventoried from `package-lock.json`.
- package code is never installed, imported, or executed.
- artifact downloads are explicit and hash-verified by default.
- OSV malware advisory queries are opt-in.
- Real incident replay fixtures track current coverage and gaps.

## Incident Replay

Replay recent real incidents against ca9's current supported surfaces:

```bash
python scripts/incident_replay.py --strict --format table
```

The fixtures live in `tests/fixtures/incidents/` and currently cover May 2026 npm package
compromise, PyPI import-time malware, and GitHub token/codebase exfiltration patterns. See
`docs/proof/incident-coverage.md` for the current matrix.

## Demo Fixture

For a screenshot-ready report, run the local supply-chain fixture:

```bash
bash demo/supply_chain/run_demo.sh
```

The fixture generates a `fyn.lock` with local hash-pinned wheels and shows three blocking
findings: dependency confusion, suspicious `.pth` startup execution, and a denied license.
It also writes `demo/supply_chain/ca9-vet.json` for docs or CI artifact screenshots.

```text
ca9 supply-chain report for .../demo/supply_chain/repo
Packages: 4 | Edges: 3 | Findings: 3 | Block: 3 | Warn: 0
Artifact scans: 3 | Skipped artifacts: 0
```

## Inventory

Inspect the normalized package inventory:

```bash
ca9 inventory --repo . -f json
```

When a repository has `fyn.lock` or npm `package-lock.json`, inventory includes:

- resolved package names and versions
- direct/transitive/project dependency kind
- dependency edges
- groups, markers, extras, and npm dependency classes where available
- artifact URLs, hashes/integrity values, upload times, sizes, and registries
- source evidence for each package and edge

Without lockfiles, ca9 falls back to native Python manifest readers for `pyproject.toml`,
`requirements*.txt`, `Pipfile`, `uv.lock`, and `poetry.lock`.

## Basic Vetting

Run local metadata checks:

```bash
ca9 vet --repo .
```

This checks:

- untrusted package indexes
- missing artifact hashes
- missing artifact metadata
- source-only install risk
- mutable package sources

Direct dependencies from untrusted indexes are blocking findings by default. Weaker local
metadata signals are warnings unless policy support is expanded.

## Artifact Static Analysis

Run artifact-based malicious package heuristics:

```bash
ca9 vet --repo . --scan-artifacts
```

By default, ca9 only downloads artifacts that have hashes in the inventory. It verifies the
hash, safely unpacks wheels/sdists, rejects path traversal or unsafe archive links, and
scans files statically.

Current blocking rules include:

- `.pth` startup execution
- `sitecustomize.py` / `usercustomize.py` suspicious startup behavior
- install-time `setup.py` process/network/eval/exec behavior
- encoded payload decode plus execution
- credential access near outbound network code
- top-level import-time risky behavior

Suspicious process execution outside setup/import startup paths is marked for investigation.

Use this only if you want ca9 to download package artifacts:

```bash
ca9 vet --repo . --scan-artifacts --max-artifact-mb 100
```

Artifacts without hashes are skipped unless you explicitly opt in:

```bash
ca9 vet --repo . --scan-artifacts --allow-unhashed-downloads
```

## Malicious Advisory Query

Query OSV for known malicious-package advisories:

```bash
ca9 vet --repo . --malware-query
```

ca9 treats OSV `MAL-*`, `PYSEC-MAL-*`, explicit malicious-package metadata, and
malware-labeled GHSA/OSV advisories as blocking malware findings for PyPI and npm. Use
`--offline` to restrict the query path to cached OSV data.

## GitHub Actions Workflow Scanning

Scan workflow files for risky token and trust-boundary patterns:

```bash
ca9 vet --repo . --scan-workflows
```

The workflow scanner flags:

- `pull_request_target` workflows that check out pull request-controlled code
- broad write-capable `GITHUB_TOKEN` permissions
- `id-token: write` OIDC token minting
- mutable action references such as `@main`
- cache use across `pull_request_target` trust boundaries
- source-clone commands such as `gh repo clone`

High-risk combinations such as pull request-code checkout, broad write permissions, and
source-clone commands with write-capable token scope are blocking by default.
Lower-confidence cases such as OIDC write scope alone are marked for investigation.

## Dependency Confusion

Protect internal package names from resolving from public or unexpected indexes:

```bash
ca9 vet --repo . \
  --internal-package 'acme-*' \
  --private-index https://packages.acme.internal/simple
```

An internal direct dependency that resolves outside the configured private indexes is a
blocking dependency-confusion finding. Transitive matches are marked for investigation.

Use `--trusted-index` to define package indexes that are generally trusted:

```bash
ca9 vet --repo . \
  --trusted-index https://pypi.org/simple \
  --trusted-index https://packages.acme.internal/simple
```

## License Policy

Gate denied licenses from wheel/sdist metadata:

```bash
ca9 vet --repo . \
  --deny-license AGPL-3.0 \
  --deny-license GPL-3.0
```

ca9 reads:

- wheel `.dist-info/METADATA`
- sdist `PKG-INFO`
- `License-Expression`
- `License`
- `Classifier: License :: ...`

Denied licenses on direct dependencies are blocking findings. Denied licenses on transitive
dependencies are investigation findings until richer policy configuration lands.

Warn when scanned artifacts do not declare a known license:

```bash
ca9 vet --repo . --require-known-license
```

License checks require artifact metadata, so `--deny-license` and `--require-known-license`
implicitly enable artifact collection. The same safe artifact rules apply: hashes are
required by default, archives are safely unpacked, and package code is not executed.

## JSON Output

```bash
ca9 vet --repo . --scan-artifacts -f json -o ca9-vet.json
```

The JSON schema includes:

- inventory summary
- findings with signal type, severity, package key, evidence, and metadata
- decisions with action, policy ID, and reason
- artifact scan counts and skipped artifact counts

Example signal types:

- `untrusted_registry`
- `dependency_confusion`
- `malware`
- `github_actions_pull_request_target_checkout`
- `github_actions_oidc_write`
- `github_actions_write_permissions`
- `python-startup-pth-exec`
- `python-startup-customize-exec`
- `setup-install-exec`
- `encoded-execution`
- `credential-network-exfiltration`
- `import-time-risky-behavior`
- `silent-process-execution`
- `denied_license`
- `unknown_license`

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No blocking supply-chain findings. |
| `1` | Blocking supply-chain findings were found. |

Warnings and investigation findings remain visible in output but do not currently fail the
default gate unless they are represented as blocking decisions.

## Current Limits

ca9 does not yet implement every dependency attack class. The current `vet` path covers
the core local gates first: malicious package behavior, dependency confusion/internal
source policy, artifact integrity basics, OSV/GHSA malware advisory matching, GitHub
Actions workflow risk patterns, and license policy.

Still planned:

- typosquatting and namespace confusion
- lockfile poisoning diffs
- PyPI release-age/yanked/project metadata
- maintainer or repository hijack signals
- provenance/Sigstore/SLSA checks
- richer policy files
