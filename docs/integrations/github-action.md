---
title: GitHub Action
description: Use the ca9 GitHub Action to check dependency protection posture, run Python CVE reachability analysis, and upload SARIF.
---

# GitHub Action

ca9 includes a composite GitHub Action for dependency posture and reachability
analysis in CI.

## Dependency protection posture

```yaml
name: ca9 dependency posture

on:
  pull_request:

permissions:
  contents: read
  security-events: write

jobs:
  protect:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - uses: duriantaco/ca9@main
        with:
          command: protect
          repo: .
          policy: ca9.toml
          scan-workflows: "true"
          format: sarif
          output: ca9-protect.sarif
          upload-sarif: "true"
          fail-on-findings: "true"
```

`protect` validates enforceable npm/pip install workflows, reports unsupported
managers, checks feed and exception hygiene, and combines package-policy and
local Actions findings. Omit `policy` to use normal policy discovery. Set
`scan-workflows: "false"` to restrict the report to dependency posture.

Before `protect`, the action installs the hosted malware feed with
`ca9 feed update --require-attestation`, using the job's `github.token` for
`gh attestation verify`. The step fails when the bundle's attestation from the
ca9 feed workflow cannot be verified. Set `update-feed: "false"` to skip it and
manage the feed yourself.

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

The action never runs your test suite unless you set `auto-coverage: "true"`, which lets
ca9 discover `coverage.json` or generate it by running pytest. That executes repository
code, so only enable it on trusted refs. Pass a `coverage` file you produced yourself
instead when you can.

## Strict release gate

By default, the action records ca9's exit code but does not fail before
uploading SARIF. Turn on `fail-on-findings` when you want blocking protection
posture, reachable findings, or inconclusive findings to block the workflow:

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
