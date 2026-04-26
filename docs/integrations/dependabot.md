---
title: Dependabot Reachability Analysis For Python
description: Export GitHub Dependabot alerts and use ca9 to add Python CVE reachability evidence, SARIF upload, and OpenVEX output.
---

# Dependabot

Export Dependabot alerts from GitHub, then run ca9 reachability analysis locally or in CI.

```bash
gh api repos/{owner}/{repo}/dependabot/alerts > dependabot.json
ca9 check dependabot.json --repo .
```

## With coverage

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 check dependabot.json --repo . --coverage coverage.json
```

## Upload to GitHub code scanning

```bash
ca9 check dependabot.json --repo . -f sarif -o ca9.sarif
```

Upload `ca9.sarif` with `github/codeql-action/upload-sarif`.
