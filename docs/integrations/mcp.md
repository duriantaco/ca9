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
| `check_blast_radius` | Add capability blast radius to reachable CVEs. |
| `trace_exploit_path` | Trace paths to vulnerable API call sites. |
| `lookup_threat_intel` | Look up EPSS and CISA KEV data. |
| `enrich_sbom` | Enrich a CycloneDX or SPDX SBOM. |
