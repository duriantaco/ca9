---
title: Trivy Python Reachability Analysis
description: Generate Trivy JSON and use ca9 to add Python CVE reachability analysis, confidence scores, SARIF output, and OpenVEX.
---

# Trivy

Generate a Trivy filesystem report, then analyze it with ca9.

```bash
trivy fs --format json --output trivy.json .
ca9 check trivy.json --repo .
```

## Recommended command

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 check trivy.json --repo . --coverage coverage.json --show-confidence
```

## Automation outputs

```bash
ca9 check trivy.json --repo . -f json -o ca9-report.json
ca9 check trivy.json --repo . -f sarif -o ca9.sarif
ca9 check trivy.json --repo . -f vex -o openvex.json
```
