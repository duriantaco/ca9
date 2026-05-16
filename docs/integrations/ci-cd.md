---
title: CI/CD Workflows
description: Copy-paste CI examples for ca9 Python CVE reachability analysis, SARIF upload, OpenVEX artifacts, and strict release gates.
---

# CI/CD

This page shows minimal CI patterns for ca9.

For the reusable composite action, see [GitHub Action](github-action.md).

## GitHub code scanning

```yaml
name: ca9

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  reachability:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install ca9[cli]
      - run: ca9 scan --repo . --proof-standard strict -f sarif -o ca9.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ca9.sarif
```

## OpenVEX artifact

```yaml
- run: ca9 scan --repo . --proof-standard strict -f vex -o openvex.json
- uses: actions/upload-artifact@v4
  with:
    name: ca9-openvex
    path: openvex.json
```

## Existing SCA report

```yaml
- run: snyk test --json > snyk.json
- run: ca9 check snyk.json --repo . --coverage coverage.json -f action-plan -o action-plan.json
```

Use `--proof-standard strict` when the output will block releases or suppress alerts.

## Supply-chain gate

Use `ca9 vet` to gate dependency source, artifact, malware advisory, and license policy.
Artifact scanning is opt-in and does not execute or install packages.

```yaml
jobs:
  dependency-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install ca9[cli]
      - run: |
          ca9 vet --repo . \
            --scan-artifacts \
            --malware-query \
            --internal-package 'acme-*' \
            --private-index https://packages.acme.internal/simple \
            --deny-license AGPL-3.0 \
            --deny-license GPL-3.0 \
            -f json -o ca9-vet.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: ca9-vet
          path: ca9-vet.json
```

Keep `--scan-artifacts` off if the CI environment should not download package artifacts.
Without it, `ca9 vet` still performs lockfile and metadata checks from local inventory.

## New findings only

Save a baseline on `main`, then gate pull requests only on new reachable or inconclusive findings:

```yaml
- run: ca9 check snyk.json --repo . -f json -o ca9-current.json --baseline ca9-baseline.json --new-only
```

## Accepted risk file

```toml
[[risk]]
id = "CVE-2024-1234"
package = "requests"
version = "2.31.0"
reason = "Temporary exception while upgrade is being validated"
expires = "2026-06-30"
owner = "security"
```

```yaml
- run: ca9 check snyk.json --repo . --accepted-risks accepted-risks.toml
```
