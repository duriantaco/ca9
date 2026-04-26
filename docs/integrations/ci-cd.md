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
