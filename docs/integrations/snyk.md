---
title: Snyk Reachability Analysis For Python
description: Add ca9 Python CVE reachability analysis to Snyk JSON reports with coverage evidence, SARIF output, and OpenVEX generation.
---

# Snyk

Use ca9 to add local Python reachability evidence to Snyk JSON output.

```bash
snyk test --json > snyk-report.json
ca9 check snyk-report.json --repo .
```

## With test coverage

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 check snyk-report.json --repo . --coverage coverage.json --show-confidence
```

## CI artifacts

```bash
ca9 check snyk-report.json --repo . -f sarif -o ca9.sarif
ca9 check snyk-report.json --repo . -f vex -o openvex.json
ca9 check snyk-report.json --repo . -f remediation -o remediation.json
```

For release gates, prefer `--proof-standard strict`.
