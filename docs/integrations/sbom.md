---
title: SBOM Enrichment With CVE Reachability
description: Enrich CycloneDX and SPDX SBOM JSON with ca9 Python CVE reachability verdicts and evidence.
---

# SBOM Enrichment

ca9 can enrich CycloneDX or SPDX JSON with reachability verdicts.

```bash
ca9 enrich-sbom sbom.json --repo . --coverage coverage.json -o sbom.ca9.json
```

Use this when you already produce SBOMs and want reachability evidence attached to the inventory.

## Typical workflow

```bash
cyclonedx-py environment -o sbom.json
coverage run -m pytest
coverage json -o coverage.json
ca9 enrich-sbom sbom.json --repo . --coverage coverage.json -o sbom.ca9.json
```

The enriched output keeps the original SBOM structure and adds ca9 reachability metadata where supported.
