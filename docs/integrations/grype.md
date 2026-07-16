---
title: Grype Python Reachability Analysis
description: Add conservative Python reachability evidence to native Grype JSON vulnerability reports with ca9.
---

# Grype

Use Grype for package and vulnerability discovery, then pass its native JSON report to
ca9 for local Python reachability evidence:

```bash
grype dir:. --output json > grype.json
ca9 check grype.json --repo .
```

The input format is auto-detected. ca9 preserves the matched package version,
ecosystem, severity, aliases, references, and Grype advisory source. Only Python/PyPI
matches receive Python import, dependency, API-usage, and coverage analysis. Findings
from other ecosystems remain visible with an `INCONCLUSIVE` verdict.

## Add coverage evidence

```bash
coverage run -m pytest
coverage json -o coverage.json
ca9 check grype.json --repo . --coverage coverage.json --show-confidence
```

## CI outputs

```bash
ca9 check grype.json --repo . -f sarif -o ca9-grype.sarif
ca9 check grype.json --repo . -f vex -o ca9-grype.openvex.json
ca9 check grype.json --repo . -f action-plan -o ca9-grype-actions.json
```

Keep the original `grype.json` beside the ca9 result when an auditable chain from
scanner match to reachability decision is required.

See Grype's [native JSON output documentation](https://oss.anchore.com/docs/guides/vulnerability/json/)
for the upstream report fields ca9 consumes.
