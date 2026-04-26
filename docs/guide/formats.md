---
title: Supported Formats
description: Input and output formats supported by ca9 for Python CVE reachability analysis, including Snyk, Dependabot, Trivy, pip-audit, OSV, SARIF, OpenVEX, CycloneDX, and SPDX.
---

# Supported Formats

ca9 supports two kinds of input:

- Existing SCA reports from tools such as Snyk, Dependabot, Trivy, and pip-audit.
- Repository or environment dependency inventory scanned directly against OSV.dev with `ca9 scan`.

It can also emit multiple output formats for humans, CI systems, code scanning, VEX workflows, and SBOM enrichment.

## Input: SCA reports

### Snyk

Generate a Snyk report:

```bash
snyk test --json > snyk-report.json
ca9 check snyk-report.json --repo .
```

Supported layouts:

- Single-project JSON with a `vulnerabilities` array.
- Multi-project JSON with an array of project objects, each containing `vulnerabilities`.

### Dependabot

Export Dependabot alerts with the GitHub CLI:

```bash
gh api repos/{owner}/{repo}/dependabot/alerts > dependabot.json
ca9 check dependabot.json --repo .
```

ca9 extracts advisory IDs, package names, vulnerable ranges, severities, titles, and dependency relationship data where present.

### Trivy

Generate a Trivy JSON report:

```bash
trivy fs --format json --output trivy.json .
ca9 check trivy.json --repo .
```

ca9 reads package vulnerability findings from Trivy result entries and preserves dependency metadata when the report contains it.

### pip-audit

Generate a pip-audit JSON report:

```bash
pip-audit --format json --output pip-audit.json
ca9 check pip-audit.json --repo .
```

ca9 maps pip-audit vulnerability entries into its common `Vulnerability` model for reachability analysis.

## Input: Direct OSV scanning

`ca9 scan` queries OSV.dev without requiring a separate SCA tool:

```bash
ca9 scan --repo .
```

The scanner prefers dependency inventory from the repository. If no resolvable dependency inventory is available, it falls back to installed packages in the current Python environment.

Useful scan options:

```bash
ca9 scan --repo . --offline
ca9 scan --repo . --refresh-cache
ca9 scan --repo . --max-osv-workers 16
```

## Output formats

### Table

Default human-readable terminal output:

```bash
ca9 check snyk-report.json --repo .
```

Add more evidence columns with:

```bash
ca9 check snyk-report.json --repo . --show-confidence --show-evidence-source
```

### JSON

Machine-readable report with summary, verdicts, evidence, warnings, confidence scores, optional enrichment data, and `ignored_results` for accepted-risk or baseline findings that did not affect the gate:

```bash
ca9 check snyk-report.json --repo . -f json -o ca9-report.json
```

### SARIF

Use SARIF for GitHub code scanning or SARIF-compatible security tools. Accepted-risk and baseline findings are emitted as suppressed SARIF results so audit tools can still see them:

```bash
ca9 check snyk-report.json --repo . -f sarif -o ca9.sarif
```

### OpenVEX

Generate OpenVEX exploitability statements. Policy-ignored findings remain in the VEX document with `ca9.policy_ignored` metadata:

```bash
ca9 check snyk-report.json --repo . -f vex -o openvex.json
```

Compare VEX documents over time:

```bash
ca9 vex-diff --base previous.openvex.json --head current.openvex.json
```

### Markdown and HTML

Generate human-readable reports for pull request comments, build artifacts, or internal review:

```bash
ca9 check snyk-report.json --repo . -f markdown -o ca9-report.md
ca9 check snyk-report.json --repo . -f html -o ca9-report.html
```

### Remediation plan

Generate prioritized remediation actions:

```bash
ca9 check snyk-report.json --repo . -f remediation -o remediation.json
```

### Action plan

Generate a CI/CD decision object:

```bash
ca9 check snyk-report.json --repo . -f action-plan -o action-plan.json
ca9 action-plan snyk-report.json --repo . -o action-plan.json
```

### SBOM enrichment

Enrich CycloneDX or SPDX JSON with ca9 reachability verdicts:

```bash
ca9 enrich-sbom sbom.json --repo . --coverage coverage.json -o sbom.ca9.json
```

### AI-BOM capability output

Scan for AI assets and capabilities:

```bash
ca9 capabilities --repo . -f json -o aibom.json
```

Diff and gate capability changes:

```bash
ca9 cap-diff --base base-aibom.json --head head-aibom.json --md cap-diff.md
ca9 cap-gate --diff cap-diff.json --policy ca9-policy.yaml
```

## Adding a new parser

ca9 uses a protocol-based parser architecture. To add support for another SCA tool:

1. Create a new file in `src/ca9/parsers/`.
2. Implement the `SCAParser` protocol.
3. Register the parser class in `src/ca9/parsers/__init__.py`.

```python
from typing import Any

from ca9.models import Vulnerability


class MyToolParser:
    def can_parse(self, data: Any) -> bool:
        return isinstance(data, dict) and "my_tool_version" in data

    def parse(self, data: Any) -> list[Vulnerability]:
        return [
            Vulnerability(
                id=item["id"],
                package_name=item["package"],
                package_version=item["version"],
                severity=item.get("severity", "unknown"),
                title=item.get("title", ""),
                description=item.get("description", ""),
            )
            for item in data["findings"]
        ]
```
