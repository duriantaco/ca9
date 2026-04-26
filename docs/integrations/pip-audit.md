---
title: pip-audit Reachability Analysis
description: Use ca9 with pip-audit JSON to add Python CVE reachability verdicts, dynamic coverage evidence, SARIF, and OpenVEX output.
---

# pip-audit

Generate a pip-audit JSON report, then run ca9.

```bash
pip-audit --format json --output pip-audit.json
ca9 check pip-audit.json --repo .
```

## With dynamic evidence

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 check pip-audit.json --repo . --coverage coverage.json --show-confidence
```

## Output options

```bash
ca9 check pip-audit.json --repo . -f json -o ca9-report.json
ca9 check pip-audit.json --repo . -f sarif -o ca9.sarif
ca9 check pip-audit.json --repo . -f vex -o openvex.json
```
