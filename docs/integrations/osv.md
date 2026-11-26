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

ca9 first looks for exact dependency versions in the repository. Supported sources include `requirements*.txt`, nested requirement files, constraints, `pyproject.toml` dependencies and optional extras, Poetry metadata, `uv.lock`, `poetry.lock`, `Pipfile`, and `Pipfile.lock`.

If ca9 cannot resolve exact versions, it skips those dependencies by default. Use
`--allow-env-fallback` only when you intentionally want unresolved dependencies to use
versions from the current Python environment.

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

An online scan saves the advisory IDs returned for each exact package and version, including empty results. Offline scans reuse those results for 24 hours. A missing or expired query leaves advisory coverage partial. Previously cached advisories can still produce findings.

Scan JSON includes `scan_coverage` with the inventory source and counts of declared, resolved, checked, and unresolved packages. `checked` counts resolved packages with a complete OSV query for that version. The scope is the Python dependencies ca9 discovers in the selected inventory. With no resolved packages, skipped declarations, or missing current advisory results, the scan exits `2` unless a reachable finding requires exit `1`. A complete scan with zero findings exits `0`.

OSV detail records are cached locally and each finding carries freshness metadata in JSON, SARIF, and OpenVEX outputs. ca9 records when advisory data was fetched, whether the cache entry was stale at read time, and the OSV published/modified timestamps when OSV provides them.
