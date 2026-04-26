---
title: Where ca9 Fits
description: How ca9 compares with SCA reports, hosted reachability platforms, SARIF upload, OpenVEX, SBOM enrichment, and local Python CVE triage workflows.
---

# Where ca9 Fits

ca9 is an open, local reachability layer for Python vulnerability triage. It works with Snyk, Dependabot, Trivy, pip-audit, OSV.dev, SARIF, OpenVEX, CycloneDX, and SPDX workflows.

Some commercial security platforms also provide reachability analysis. ca9 is different in where it runs and what it emits: it runs locally in your repo or CI job and produces open artifacts you can inspect, diff, upload, or archive.

## Best fit

ca9 is useful when you need:

- Local Python CVE reachability analysis without importing a project into a hosted platform.
- Evidence-backed suppressions for noisy SCA reports.
- SARIF output for GitHub code scanning.
- OpenVEX output for exploitability statements.
- SBOM enrichment for CycloneDX or SPDX.
- CI action plans that can block, warn, or create follow-up actions.
- AI capability blast-radius context for reachable CVEs.

## Not a replacement for SCA

ca9 does not try to replace package vulnerability databases or SCA scanners. Instead, it consumes their output or queries OSV.dev directly, then adds reachability evidence.

Typical flow:

```bash
snyk test --json > snyk.json
ca9 check snyk.json --repo . --coverage coverage.json --show-confidence
```

## Open artifact strategy

ca9 favors artifacts that work across tools:

| Artifact | Why it matters |
|---|---|
| JSON | Complete machine-readable evidence for internal tooling. |
| SARIF | GitHub code scanning and security dashboards. |
| OpenVEX | Exploitability statements that can be archived and diffed. |
| Enriched SBOM | Reachability verdicts attached to CycloneDX or SPDX inventories. |
| Action plan | CI/CD decision object for automated response. |
