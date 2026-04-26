---
title: OSV Python Vulnerability Scan
description: Use ca9 scan to query OSV.dev and add Python CVE reachability analysis without a separate SCA report.
---

# OSV Scan

`ca9 scan` queries OSV.dev for Python package vulnerabilities and then runs reachability analysis.

```bash
pip install ca9[cli]
ca9 scan --repo .
```

ca9 first looks for dependency inventory in the repository. Supported sources include `requirements*.txt`, nested requirement files, constraints, `pyproject.toml` dependencies and optional extras, Poetry metadata, `uv.lock`, `poetry.lock`, `Pipfile`, and `Pipfile.lock`.

If ca9 cannot resolve a usable inventory, it falls back to installed packages in the current Python environment.

## Add coverage evidence

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 scan --repo . --coverage coverage.json --show-confidence
```

## Offline and cached scans

```bash
ca9 scan --repo . --offline
ca9 scan --repo . --refresh-cache
```

Use `--offline` for repeatable local checks when OSV data was already cached.
