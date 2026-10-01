---
title: Darkmoon DAST and Pentest Evidence
description: Ingest Darkmoon SARIF findings into ca9 as generic, provenance-preserving evidence for unified triage.
---

# Darkmoon

[Darkmoon](https://github.com/ASCIT31/Dark-Moon) is an open source (GPL-3.0)
autonomous AI penetration testing engine. An LLM orchestrates specialist agents
and offensive tools, runs on a local model, and proves each finding with a real
exploit. Its findings are dynamic (DAST) and runtime oriented, so they complement
ca9's static Python CVE reachability analysis instead of overlapping with it.

Darkmoon can emit SARIF 2.1.0, and ca9's generic SARIF adapter normalizes any
SARIF into the `ca9.evidence.v1` evidence schema. This lets Darkmoon's proven,
exploitation-backed findings sit alongside your SCA and SAST evidence in one
audit trail, with tool provenance, rule metadata, source locations, severity,
confidence and fingerprints preserved.

!!! note
    ca9's `check` command performs Python dependency CVE reachability analysis and
    expects an SCA report (Trivy, Snyk, OSV, ...). Darkmoon produces dynamic
    exploitation findings, so they are brought in through `ingest-sarif` as
    evidence, not through `check`.

## Ingest Darkmoon SARIF

```bash
ca9 ingest-sarif darkmoon.sarif --repo . -f json -o darkmoon.evidence.json
```

Other output formats work too:

```bash
ca9 ingest-sarif darkmoon.sarif --repo . -f table
```

SARIF run/result indexes, rule ids, locations, severity, confidence and
fingerprints are preserved so MCP clients and ca9 agents can triage the findings
without losing the raw audit trail.

## Produce the SARIF in CI

The maintained [Darkmoon GitHub Action](https://github.com/marketplace/actions/darkmoon-pentest)
synthesizes SARIF from the findings and exposes the file path as an output. Run
it against a target you are authorised to assess, then ingest the result with
ca9:

```yaml
name: darkmoon + ca9

on:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  pentest-evidence:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.13"
      - run: pip install "ca9[cli]"

      - id: dm
        uses: ASCIT31/darkmoon-action@v1
        with:
          target: https://staging.example.test
          report-format: sarif

      - run: ca9 ingest-sarif "${{ steps.dm.outputs.report-path }}" --repo . -f json -o darkmoon.evidence.json
```

## Editions

The Darkmoon engine and CLI are open source under GPL-3.0. The web dashboard and
the remediation-to-pull-request workflow are Darkmoon Pro features and are not
part of the open source distribution. The SARIF produced for ca9 is redaction
safe by default.

## Links

- Source: <https://github.com/ASCIT31/Dark-Moon>
- Documentation: <https://docs.dark-moon.org>
