---
title: ca9 MCP Server
description: Run ca9 Python CVE reachability analysis from MCP clients and LLM-powered developer tools.
---

# MCP Server

ca9 ships an optional MCP server for running reachability analysis from MCP clients.

```bash
pip install ca9[mcp]
```

Example MCP client configuration:

```json
{
  "mcpServers": {
    "ca9": {
      "command": "ca9-mcp"
    }
  }
}
```

## Available tools

| Tool | Purpose |
|---|---|
| `check_reachability` | Analyze an SCA report. |
| `scan_dependencies` | Scan dependencies through OSV.dev. |
| `check_coverage_quality` | Evaluate coverage evidence quality. |
| `explain_verdict` | Explain a specific vulnerability verdict. |
| `generate_vex` | Generate OpenVEX output. |
| `generate_remediation_plan` | Generate remediation actions. |
| `scan_capabilities` | Emit an AI-BOM. |
| `hunt_zero_days` | Find local unknown-bug research targets, fuzz harnesses, and private researcher packets. |
| `check_blast_radius` | Add capability blast radius to reachable CVEs. |
| `trace_exploit_path` | Trace paths to vulnerable API call sites. |
| `lookup_threat_intel` | Look up EPSS and CISA KEV data. |
| `enrich_sbom` | Enrich a CycloneDX or SPDX SBOM. |
| `ingest_sarif` | Normalize SARIF scanner output into ca9 evidence findings. |

For MCP use, `hunt_zero_days` only writes generated harness and researcher packet
artifacts inside the requested repository. Normal responses contain target
metadata, not raw fuzzing inputs or exploit payloads.

If a Fuzz Introspector `summary.json` already exists in the repository, pass it as
`fuzz_introspector_summary_path` to merge sink and fuzzer-reachability evidence.
