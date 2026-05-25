---
title: SARIF Output For Python CVE Reachability
description: Generate ca9 SARIF output for GitHub code scanning and security dashboards.
---

# SARIF

ca9 can emit SARIF 2.1.0 for GitHub code scanning and SARIF-compatible security tooling.

```bash
ca9 check snyk-report.json --repo . -f sarif -o ca9.sarif
```

SARIF output includes:

- One result per vulnerability.
- Stable fingerprints.
- Severity mapping.
- Confidence score and verdict evidence in properties.
- Policy adjustments and report warnings where available.
- Optional blast-radius and threat-intel properties.

## GitHub upload

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.13"
  - run: pip install ca9[cli]
  - run: ca9 scan --repo . -f sarif -o ca9.sarif
  - uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: ca9.sarif
```

## Ingest SARIF as evidence

ca9 can also read SARIF produced by other tools and normalize it into the
`ca9.evidence.v1` evidence schema:

```bash
ca9 ingest-sarif codeql.sarif --repo . -f json
ca9 ingest-sarif semgrep.sarif --repo . -f table
```

This is the first generic evidence adapter for agentic security workflows. It preserves
tool provenance, SARIF run/result indexes, rule metadata, primary source locations,
severity, confidence, and fingerprints so MCP clients and future ca9 agents can triage
findings without losing the raw audit trail.
