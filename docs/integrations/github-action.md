---
title: GitHub Action
description: Review npm dependency updates on pull requests, check install protection, and run Python CVE reachability analysis in GitHub Actions.
---

# GitHub Action

## Review dependency updates on pull requests

Use `command: review` to see whether an npm update introduces an install hook,
changes an executable, or adds other behavior that deserves a closer look. ca9
compares the lockfiles from the PR head and its common ancestor with the base
branch. It verifies published tarballs against their lockfile hashes before
inspecting their contents. Package code is read as data.

```yaml
name: Dependency update review

on: pull_request
permissions:
  contents: read

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: duriantaco/ca9@main
        id: review
        with:
          command: review
```

The job summary shows new behavior that needs review and any gaps in inspection.
A PR with no changed `package-lock.json` files gets a one-line result. The full
report is written to `ca9-review.json` in the workspace. A later step can save
it with `actions/upload-artifact` using `${{ steps.review.outputs.output-path }}`.
Set `format: markdown` for a detailed Markdown file or set `output` to choose
its path. The job summary is available in either format.

The action finds changed npm v2/v3 lockfiles in nested projects. Use `repo`
to limit it to a checkout subdirectory. When a project first adds a lockfile,
the report identifies a missing baseline if its manifest already existed.
The checkout needs both event commits and their common ancestor. A missing
commit fails the step with instructions for fetching the history.

By default, reviews are advisory. Set `fail-on-findings: "true"` to enforce
the result after the report is written. The `exit-code` output is `0` for a
complete pass, `1` for a complete review or a block, and `2` for incomplete
inspection without a block. To limit the review to lock metadata, use
`extra-args: --no-scan-artifacts`. Artifact comparisons then remain incomplete.
To allow a private artifact registry, use `extra-args: --trusted-registry https://registry.example.org`.

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

By default, completed checks publish their report and record ca9's `exit-code`
even when they find issues. A missing input, invalid report, or other execution
error fails the step and skips SARIF upload. The `output-path` output is populated
only after this run writes a report.

Turn on `fail-on-findings` when you want blocking protection posture, reachable
findings, or inconclusive scans to block the workflow after upload.

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
