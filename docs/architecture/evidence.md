---
title: Evidence Layer
description: Normalize security tool output into ca9 evidence findings for agentic triage.
---

# Evidence Layer

ca9's agentic path starts with a strict evidence layer. Agents can summarize, rank,
and ask follow-up questions, but every claim should trace back to structured evidence
from a repository, scanner, runtime trace, artifact, or human review.

The first generic evidence input is SARIF 2.1.0 because it is the standard exchange
format used by many static-analysis and security tools. CodeQL, Semgrep, Trivy, and
many CI security dashboards can either emit or consume SARIF.

```bash
ca9 ingest-sarif codeql.sarif --repo . -f json
```

The output schema is `ca9.evidence.v1` and contains:

- `tool_runs`: source tool name, version, URI, and result count.
- `findings`: normalized `Finding`, `RiskSignal`, and `Evidence` records.
- `summary`: finding counts by severity and signal type.
- `metadata`: source format and version.

Each normalized finding preserves:

- Source file and parser provenance.
- SARIF run and result indexes.
- Tool name and version.
- Rule ID, descriptions, tags, precision, and security severity.
- Primary file location, line, and column where available.
- SARIF fingerprints and partial fingerprints where available.

## Agentic Workflow

The evidence layer is intentionally below the agent layer:

1. Run scanners and analyzers in a scoped repository or lab target.
2. Normalize their output with `ca9 ingest-sarif` or future evidence adapters.
3. Let agents triage only the normalized evidence plus bounded code context.
4. Require agents to produce report claims that cite evidence fingerprints, locations,
   and tool provenance.
5. Add human review, regression tests, fixes, and disclosure artifacts on top.

This keeps the system useful for vulnerability research without letting agent narratives
replace reproducible data.

## Execution Plan

Phase 1 is the evidence foundation:

- SARIF ingestion for CodeQL, Semgrep, Trivy, and other static-analysis tools.
- MCP access through `ingest_sarif` for AI clients.
- Stable finding fingerprints for deduplication and later baselines.

Phase 2 should add tool runners and native adapters:

- CodeQL database/query orchestration.
- Semgrep rulesets and custom rule packs.
- OSV-Scanner and SafeDep/vet JSON ingestion.
- TruffleHog and Gitleaks secret evidence.
- Syft/Grype/Trivy SBOM and container evidence.

Phase 3 should add agent taskflows:

- Scope and rules-of-engagement task.
- Attack-surface map task.
- Static-analysis triage task.
- Reachability and exploit-path validation task.
- Fuzz-target recommendation task.
- Report and remediation task.

Phase 4 should add unknown-bug discovery loops:

- Harness suggestion from parser/API/entry-point evidence.
- Fuzz target generation for Python first.
- Crash/minimization evidence ingestion.
- Regression test generation after confirmed bugs.
