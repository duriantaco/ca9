---
title: GitHub Action
description: Use the ca9 GitHub Action to run Python CVE reachability analysis, upload SARIF, and generate OpenVEX or action-plan artifacts.
---

# GitHub Action

ca9 includes a composite GitHub Action for running reachability analysis in CI.

## Direct OSV scan with SARIF upload

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
      - uses: duriantaco/ca9@main
        with:
          command: scan
          repo: .
          format: sarif
          output: ca9.sarif
          upload-sarif: "true"
```

## Existing SCA report

```yaml
- run: snyk test --json > snyk.json
- uses: duriantaco/ca9@main
  with:
    command: check
    report: snyk.json
    repo: .
    coverage: coverage.json
    format: sarif
    output: ca9.sarif
```

## Strict release gate

By default, the action records ca9's exit code but does not fail before uploading SARIF. Turn on `fail-on-findings` when you want reachable or inconclusive findings to block the workflow:

```yaml
- uses: duriantaco/ca9@main
  with:
    command: scan
    repo: .
    proof-standard: strict
    fail-on-findings: "true"
```

## Accepted risks and new-only gates

```yaml
- uses: duriantaco/ca9@main
  with:
    command: check
    report: snyk.json
    repo: .
    accepted-risks: accepted-risks.toml
    baseline: ca9-baseline.json
    new-only: "true"
    fail-on-findings: "true"
```

## OpenVEX artifact

```yaml
- uses: duriantaco/ca9@main
  with:
    command: scan
    repo: .
    format: vex
    output: openvex.json
    upload-sarif: "false"
- uses: actions/upload-artifact@v4
  with:
    name: ca9-openvex
    path: openvex.json
```
