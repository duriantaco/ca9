---
title: OSV-Scanner Python Reachability Analysis
description: Analyze native OSV-Scanner JSON with ca9 while preserving OSV advisory metadata and the original scan artifact.
---

# OSV-Scanner

When OSV-Scanner already owns dependency discovery, write its native JSON output and use
ca9 as the local Python reachability layer:

```bash
osv-scanner scan --format json . > osv-scanner.json
ca9 check osv-scanner.json --repo .
```

ca9 reads the official `results[].packages[]` layout. It preserves package identity,
ecosystem, aliases, affected ranges, severity, references, and advisory timestamps.
Only Python/PyPI packages receive Python reachability verdicts; other ecosystems remain
explicitly `INCONCLUSIVE`.

## When to use this instead of `ca9 scan`

- Use `ca9 scan --repo .` for ca9's direct OSV query path.
- Use `osv-scanner ... > report.json` followed by `ca9 check` when OSV-Scanner owns
  manifest/SBOM discovery, offline database use, or the original scanner report must be
  retained.

## Add coverage and CI output

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 check osv-scanner.json --repo . --coverage coverage.json \
  --proof-standard strict -f sarif -o ca9-osv-scanner.sarif
```

The OSV-Scanner input is not queried again by `ca9 check`; its embedded advisory records
are the input evidence for the analysis.

See OSV-Scanner's [JSON output documentation](https://google.github.io/osv-scanner/output/)
for the upstream report structure ca9 consumes.
