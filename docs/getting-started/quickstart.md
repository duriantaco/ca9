# Quick Start

This guide walks you through your first ca9 analysis in under 5 minutes.

## Option A: Scan installed packages (zero setup)

The fastest way to try ca9 — no SCA report needed:

```bash
ca9 scan
```

This queries [OSV.dev](https://osv.dev) for known vulnerabilities in your currently installed packages and checks reachability via static analysis.

### Add dynamic analysis

For more precise verdicts, generate coverage data first:

```bash
# Run your tests with coverage
pip install coverage
coverage run -m pytest
coverage json

# Scan with coverage data
ca9 scan --coverage coverage.json
```

## Option B: Analyze an existing SCA report

If you already have a Snyk, Dependabot, Trivy, or pip-audit report:

=== "Snyk"

    ```bash
    # Generate a Snyk report
    snyk test --json > snyk-report.json

    # Analyze it
    ca9 check snyk-report.json
    ```

=== "Dependabot"

    ```bash
    # Export Dependabot alerts via GitHub API
    gh api repos/{owner}/{repo}/dependabot/alerts > dependabot.json

    # Analyze it
    ca9 check dependabot.json
    ```

=== "Trivy"

    ```bash
    trivy fs --format json --output trivy.json .
    ca9 check trivy.json
    ```

=== "pip-audit"

    ```bash
    pip-audit --format json --output pip-audit.json
    ca9 check pip-audit.json
    ```

## Understanding the output

ca9 produces a table by default:

```bash
ca9 check snyk-report.json --repo . --coverage coverage.json
```

```
┌──────────────────┬──────────┬──────────────────────────┬──────────┐
│ CVE              │ Package  │ Verdict                  │ Severity │
├──────────────────┼──────────┼──────────────────────────┼──────────┤
│ GHSA-abcd-1234   │ jinja2   │ UNREACHABLE (static)     │ high     │
│ CVE-2024-5678    │ django   │ REACHABLE                │ critical │
└──────────────────┴──────────┴──────────────────────────┴──────────┘
```

Add `--verbose` for the reasoning trace behind each verdict:

```bash
ca9 check snyk-report.json --verbose
```

### Output for automation

```bash
ca9 check snyk-report.json --format json --output results.json
ca9 check snyk-report.json --format sarif --output ca9.sarif
ca9 check snyk-report.json --format vex --output openvex.json
```

## Next steps

- [CLI Reference](../guide/cli.md) — all commands and options
- [Dynamic Analysis Guide](../guide/coverage.md) — get the most out of coverage data
- [Proof Standards](../guide/proof-standards.md) — strict gates, accepted risks, and baselines
- [Architecture Overview](../architecture/overview.md) — understand how ca9 works under the hood
