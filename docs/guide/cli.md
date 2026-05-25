---
title: CLI Reference
description: Complete ca9 CLI reference for Python CVE reachability analysis, package inventory, supply-chain vetting, OSV scanning, SARIF, OpenVEX, SBOM enrichment, and AI capability checks.
---

# CLI Reference

ca9 provides reachability-aware CVE triage and local Python package security checks. The core commands are `check` for existing SCA reports, `scan` for direct OSV.dev scanning, `inventory` for normalized package evidence, `vet` for supply-chain risk checks, and `ingest-sarif` for normalizing static-analysis evidence from other tools.

## Global options

```bash
ca9 --version
ca9 --help
```

You can omit the `check` command when passing a report path:

```bash
ca9 snyk-report.json --repo .
```

## `ca9 check`

Analyze an existing SCA report for reachability.

```bash
ca9 check SCA_REPORT [OPTIONS]
```

Supported input reports are auto-detected:

- Snyk JSON
- Dependabot alerts JSON
- Trivy JSON
- pip-audit JSON

Common options:

| Option | Description |
|---|---|
| `-r, --repo PATH` | Project repository path. Defaults to `.`. |
| `-c, --coverage PATH` | `coverage.py` JSON file for dynamic reachability evidence. |
| `-f, --format FORMAT` | `table`, `json`, `sarif`, `vex`, `remediation`, `action-plan`, `markdown`, or `html`. |
| `-o, --output PATH` | Write output to a file. |
| `-v, --verbose` | Show reasoning trace in table output. |
| `--no-auto-coverage` | Disable automatic coverage discovery/generation. |
| `--show-confidence` | Show confidence scores in table output. |
| `--show-evidence-source` | Show affected component extraction source in table output. |
| `--proof-standard strict\|balanced` | Controls how aggressively ca9 allows suppressions. Defaults to `strict`. |
| `--capabilities` | Attach AI capability blast radius to reachable CVEs. |
| `--runtime-context PATH` | Apply deployment-aware context such as auth and network isolation. |
| `--trace-paths` | Trace exploit paths from entry points to vulnerable call sites. |
| `--threat-intel` | Enrich CVEs with EPSS and CISA KEV data. |
| `--otel-traces PATH` | Add production runtime evidence from an OTLP JSON export. |
| `--accepted-risks PATH` | TOML or JSON file listing findings that should not affect gates. |
| `--baseline PATH` | Previous ca9 JSON report for baseline comparison. |
| `--new-only` | Only gate on reachable or inconclusive findings not present in `--baseline`. |

Examples:

```bash
ca9 check snyk-report.json --repo .
ca9 check dependabot.json --repo . --coverage coverage.json --show-confidence
ca9 check trivy.json --repo . -f sarif -o ca9.sarif
ca9 check pip-audit.json --repo . -f vex -o openvex.json
ca9 check snyk-report.json --repo . --capabilities --trace-paths --threat-intel
ca9 check snyk-report.json --repo . --accepted-risks accepted-risks.toml
ca9 check snyk-report.json --repo . --baseline previous-ca9.json --new-only
```

## `ca9 scan`

Scan exact repository dependency versions directly through OSV.dev.

```bash
ca9 scan [OPTIONS]
```

`scan` resolves dependency inventory from the target repository. Dependencies without
exact versions are skipped by default so CI scans do not accidentally analyze the
ambient Python environment. Use `--allow-env-fallback` only when you intentionally
want to scan installed package versions for unresolved dependencies.

Additional scan options:

| Option | Description |
|---|---|
| `--offline` | Use cached OSV vulnerability details only. |
| `--refresh-cache` | Clear the OSV cache before fetching. |
| `--allow-env-fallback` | Use installed package versions when repo versions cannot be resolved. |
| `--max-osv-workers N` | Maximum concurrent OSV detail fetches. Defaults to `8`. |

Examples:

```bash
ca9 scan --repo .
ca9 scan --repo . --coverage coverage.json -f json
ca9 scan --repo . --offline --show-confidence
```

## `ca9 inventory`

Show normalized package inventory.

```bash
ca9 inventory [PATH] [OPTIONS]
```

Options:

| Option | Description |
|---|---|
| `-r, --repo PATH` | Project repository path. Defaults to `.`. |
| `-f, --format table\|json` | Output format. Defaults to `table`. |
| `-o, --output PATH` | Write output to a file. |

`inventory` reads `fyn.lock` and npm `package-lock.json` natively when present. It
otherwise falls back to ca9's native Python manifest readers.

Examples:

```bash
ca9 inventory --repo .
ca9 inventory --repo . -f json -o ca9-inventory.json
```

## `ca9 vet`

Run package supply-chain risk checks.

```bash
ca9 vet [PATH] [OPTIONS]
```

Options:

| Option | Description |
|---|---|
| `-r, --repo PATH` | Project repository path. Defaults to `.`. |
| `-f, --format table\|json` | Output format. Defaults to `table`. |
| `-o, --output PATH` | Write output to a file. |
| `--trusted-index URL` | Trusted package index. Can be repeated. Defaults to PyPI and npmjs. |
| `--private-index URL` | Private package index allowed for internal package names. Can be repeated. |
| `--internal-package PATTERN` | Internal package name or glob pattern, e.g. `acme-*`. Can be repeated. |
| `--malware-query` | Query OSV for known malicious-package advisories. |
| `--scan-artifacts` | Hash-verify, unpack, and statically inspect package artifacts. |
| `--allow-unhashed-downloads` | Allow artifact scanning when the lockfile has no artifact hash. |
| `--max-artifact-mb N` | Maximum artifact download size for `--scan-artifacts`. Defaults to `100`. |
| `--deny-license ID` | Denied license identifier. Can be repeated. |
| `--require-known-license` | Warn when scanned artifact metadata has no known license. |
| `--offline` | Use cached OSV data only for `--malware-query`. |
| `--refresh-cache` | Clear OSV cache before `--malware-query`. |
| `--max-osv-workers N` | Maximum concurrent OSV detail fetches. Defaults to `8`. |

Examples:

```bash
ca9 vet --repo .
ca9 vet --repo . --scan-artifacts
ca9 vet --repo . --malware-query --offline
ca9 vet --repo . --internal-package 'acme-*' --private-index https://packages.acme.internal/simple
ca9 vet --repo . --deny-license AGPL-3.0 --deny-license GPL-3.0
```

See [Supply-Chain Vetting](supply-chain.md) for details on current findings and limits.

## `ca9 ingest-sarif`

Normalize SARIF 2.1.0 scanner output into ca9 evidence findings.

```bash
ca9 ingest-sarif SARIF_INPUT [OPTIONS]
```

Options:

| Option | Description |
|---|---|
| `-r, --repo PATH` | Project repository path. Defaults to `.`. |
| `-f, --format table\|json` | Output format. Defaults to `table`. |
| `-o, --output PATH` | Write output to a file. |

Examples:

```bash
ca9 ingest-sarif codeql.sarif --repo . -f json -o ca9-evidence.json
ca9 ingest-sarif semgrep.sarif --repo . -f table
```

The JSON output uses `ca9.evidence.v1` and preserves tool, rule, location,
fingerprint, severity, and confidence metadata for agentic triage.

## Output formats

| Format | Use case |
|---|---|
| `table` | Human-readable terminal output. |
| `json` | Machine-readable report with evidence and summary fields. |
| `sarif` | GitHub code scanning and SARIF-compatible security tools. |
| `vex` | OpenVEX exploitability statements. |
| `markdown` | Human-readable report for PR comments or artifacts. |
| `html` | Standalone human-readable report artifact. |
| `remediation` | Prioritized remediation actions and compensating controls. |
| `action-plan` | CI/CD decision output for block, PR, revoke, or notify workflows. |

## Proof standards

| Standard | Behavior |
|---|---|
| `strict` | Downgrades weak suppressions to `INCONCLUSIVE` when dependency graph or coverage evidence is not strong enough. This is the default. |
| `balanced` | Preserves more `UNREACHABLE` verdicts when evidence points that way, even if coverage or graph quality is weaker. |

Use `strict` for CI gates and security reviews. Use `balanced` when exploring noise reduction locally.

## Accepted risks and baselines

Accepted risks are useful for temporary exceptions that should not fail CI while a fix is tracked elsewhere.
When these policy options are used, ca9 keeps ignored findings visible in `ignored_results` while excluding them from exit-code decisions.
Create baseline reports without `--accepted-risks` or `--new-only` when you need a full inventory snapshot.

```toml
[[risk]]
id = "CVE-2024-1234"
package = "requests"
version = "2.31.0"
reason = "Compensating control deployed while waiting for upstream fix"
expires = "2026-06-30"
owner = "security"
```

Apply the file:

```bash
ca9 check report.json --repo . --accepted-risks accepted-risks.toml
```

For baseline gating, first save a full JSON report:

```bash
ca9 check report.json --repo . -f json -o ca9-baseline.json
```

Then gate only on new reachable or inconclusive findings:

```bash
ca9 check report.json --repo . --baseline ca9-baseline.json --new-only
```

## Other commands

### `ca9 capabilities`

Scan a repository for AI capabilities and emit an AI-BOM summary or JSON.

```bash
ca9 capabilities --repo .
ca9 capabilities --repo . -f json -o aibom.json
```

### `ca9 hunt`

Find local unknown-bug research targets by ranking parser-like functions, exposed
handlers, risky sinks, and complexity. The command can also generate reviewable
Atheris harness skeletons for targets with a single fuzzable input and private
researcher handoff packets for human validation.

```bash
ca9 hunt --repo .
ca9 hunt --repo . -f json -o hunt.json
ca9 hunt --repo . --generate-harnesses fuzz_harnesses
ca9 hunt --repo . --research-packet-dir research_packets
ca9 hunt --repo . --fuzz-introspector-summary summary.json
```

Current flags:

| Flag | Purpose |
| --- | --- |
| `-r, --repo PATH` | Path to the project repository. |
| `-f, --format [table\|json]` | Output format. |
| `-o, --output PATH` | Write output to file instead of stdout. |
| `--limit N` | Maximum targets to report. |
| `--include-tests` | Include tests, docs examples, and demo files in target discovery. |
| `--generate-harnesses PATH` | Write Atheris harness skeletons for directly fuzzable targets. |
| `--harness-limit N` | Maximum harness skeletons to generate. |
| `--fuzz-introspector-summary PATH` | Merge Fuzz Introspector `summary.json` sink/reachability evidence. |
| `--research-packet-dir PATH` | Write private researcher handoff packets for reported candidates. |
| `--help` | Show command help. |

Hunt output is local-only. The public package contains the workflow code, not the
user's private findings. The command does not phone home, publish findings, or
probe remote systems. Generated harness directories include a `.gitignore` guard
and best-effort private permissions. Researcher packet directories use the same
private artifact guard and are intended for authorized disclosure workflows.
Reports and packets do not include raw fuzzing inputs or exploit payloads.

When a Fuzz Introspector `summary.json` is available, ca9 can merge its sink and
fuzzer reachability evidence into the hunt ranking.

### `ca9 cap-diff`

Compare two AI-BOM documents and summarize added, removed, or widened capabilities.

```bash
ca9 cap-diff --base base-aibom.json --head head-aibom.json --md capability-diff.md
```

### `ca9 cap-gate`

Evaluate a capability diff against a policy file.

```bash
ca9 cap-gate --diff capability-diff.json --policy ca9-policy.yaml
```

### `ca9 vex-diff`

Compare two OpenVEX documents and fail when vulnerabilities become affected or newly require attention.

```bash
ca9 vex-diff --base previous.openvex.json --head current.openvex.json
```

### `ca9 action-plan`

Generate a machine-readable CI/CD action plan from an SCA report.

```bash
ca9 action-plan snyk-report.json --repo . --coverage coverage.json -o action-plan.json
```

### `ca9 trace`

Trace exploit paths from project entry points to vulnerable API call sites.

```bash
ca9 trace snyk-report.json --repo . --coverage coverage.json --vuln-id CVE-2024-1234
```

### `ca9 enrich-sbom`

Enrich a CycloneDX or SPDX SBOM with reachability verdicts.

```bash
ca9 enrich-sbom sbom.json --repo . --coverage coverage.json -o sbom.ca9.json
```

## Exit codes

| Code | Meaning |
|---|---|
| `0` | No reachable CVEs were found, or the command completed without an action-blocking result. |
| `1` | Reachable CVEs, VEX regressions, or blocking supply-chain findings require attention. |
| `2` | Only inconclusive findings remain, or a capability/action policy produced a blocking decision. |

Input errors such as invalid JSON, missing files, or unsupported formats also return a non-zero exit code with a Click error message.
