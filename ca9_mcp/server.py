from __future__ import annotations

import io
import json
import os
import sys
from pathlib import Path

try:
    from mcp.server.fastmcp import FastMCP
except ImportError as exc:
    FastMCP = None
    _MCP_IMPORT_ERROR = exc
else:
    _MCP_IMPORT_ERROR = None

if FastMCP is not None:
    mcp = FastMCP(
        "ca9",
        instructions="CVE reachability analysis for Python projects",
    )
else:
    mcp = None


def _tool():
    if mcp is None:
        return lambda func: func
    return mcp.tool()


def _json_response(payload: object) -> str:
    return json.dumps(payload, indent=2)


def _json_error(message: str, *, error_type: str | None = None, **extra: object) -> str:
    payload: dict[str, object] = {"error": message}
    if error_type:
        payload["error_type"] = error_type
    payload.update(extra)
    return _json_response(payload)


def _resolve_repo(repo_path: str) -> tuple[Path | None, str | None]:
    repo = Path(repo_path)
    if not repo.is_dir():
        return None, _json_error(f"Repository not found: {repo_path}")
    return repo, None


def _resolve_coverage_path(
    repo: Path,
    coverage_path: str | None,
) -> tuple[Path | None, str | None]:
    from ca9.coverage_provider import resolve_coverage

    cov_path = Path(coverage_path) if coverage_path else None
    if cov_path is not None and not cov_path.is_file():
        return None, _json_error(f"Coverage file not found: {coverage_path}")

    try:
        resolved = resolve_coverage(cov_path, repo, auto_generate=False)
    except Exception as exc:
        return None, _json_error(
            f"Failed to resolve coverage data: {exc}",
            error_type=type(exc).__name__,
        )

    return resolved, None


def _load_json_file(path: Path, label: str) -> tuple[object | None, str | None]:
    try:
        raw = path.read_text()
    except OSError as exc:
        return None, _json_error(
            f"Cannot read {label}: {exc}",
            error_type=type(exc).__name__,
        )

    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        return None, _json_error(
            f"Invalid JSON in {label}: {exc}",
            error_type=type(exc).__name__,
        )


def _load_report_vulnerabilities(report_path: str) -> tuple[list | None, str | None]:
    from ca9.parsers import detect_parser

    report_file = Path(report_path)
    if not report_file.is_file():
        return None, _json_error(f"Report file not found: {report_path}")

    data, error = _load_json_file(report_file, f"report file {report_path}")
    if error:
        return None, error

    try:
        parser = detect_parser(report_file)
    except ValueError as exc:
        return None, _json_error(str(exc), error_type=type(exc).__name__)

    try:
        return parser.parse(data), None
    except Exception as exc:
        return None, _json_error(
            f"Failed to parse report {report_path}: {exc}",
            error_type=type(exc).__name__,
        )


@_tool()
def check_reachability(
    report_path: str,
    repo_path: str = ".",
    coverage_path: str | None = None,
    format: str = "json",
    proof_standard: str = "strict",
) -> str:
    from ca9.engine import analyze
    from ca9.report import report_to_dict, write_table

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    vulnerabilities, error = _load_report_vulnerabilities(report_path)
    if error:
        return error

    if format not in ("json", "table"):
        return _json_error("Unsupported format. Use 'json' or 'table'.", error_type="ValueError")

    if not vulnerabilities:
        return _json_response({"results": [], "summary": {"total": 0}})

    try:
        report = analyze(vulnerabilities, repo, cov_path, proof_standard=proof_standard)
    except Exception as exc:
        return _json_error(
            f"Reachability analysis failed: {exc}",
            error_type=type(exc).__name__,
        )

    if format == "table":
        buf = io.StringIO()
        write_table(report, buf, verbose=True, show_confidence=True)
        return buf.getvalue()

    return _json_response(report_to_dict(report))


@_tool()
def scan_dependencies(
    repo_path: str = ".",
    coverage_path: str | None = None,
    proof_standard: str = "strict",
) -> str:
    from ca9.engine import analyze
    from ca9.report import report_to_dict
    from ca9.scanner import scan_repository

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    try:
        vulnerabilities, inventory = scan_repository(repo)
    except (ConnectionError, ValueError) as exc:
        return _json_error(str(exc), error_type=type(exc).__name__)

    if not vulnerabilities:
        return _json_response(
            {
                "message": "No known vulnerabilities found in scanned packages.",
                "packages_scanned": len(inventory.packages),
                "inventory_source": inventory.source,
                "inventory_warnings": list(inventory.warnings),
            }
        )

    try:
        report = analyze(vulnerabilities, repo, cov_path, proof_standard=proof_standard)
    except Exception as exc:
        return _json_error(
            f"Reachability analysis failed: {exc}",
            error_type=type(exc).__name__,
        )
    if inventory.warnings:
        report.warnings = list(inventory.warnings) + report.warnings
    result = report_to_dict(report)
    result["packages_scanned"] = len(inventory.packages)
    result["inventory_source"] = inventory.source
    result["inventory_warnings"] = list(inventory.warnings)
    return _json_response(result)


@_tool()
def check_coverage_quality(
    coverage_path: str | None = None,
    repo_path: str = ".",
) -> str:
    from ca9.analysis.coverage_reader import (
        get_coverage_completeness,
        get_covered_files,
        load_coverage,
    )

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    if cov_path is None or not cov_path.is_file():
        return _json_response(
            {
                "error": "No coverage data found. Run pytest with pytest-cov or provide a coverage.json path.",
            }
        )

    coverage_data = load_coverage(cov_path)
    pct = get_coverage_completeness(coverage_data)
    covered_files = get_covered_files(coverage_data)

    if pct is None:
        trust_tier = "unknown"
        recommendation = "Coverage file lacks totals — cannot assess quality."
    elif pct >= 80:
        trust_tier = "high"
        recommendation = "Dynamic absence signals are highly reliable."
    elif pct >= 50:
        trust_tier = "moderate"
        recommendation = (
            "Dynamic absence signals are moderately reliable. Increase coverage for better results."
        )
    elif pct >= 30:
        trust_tier = "low"
        recommendation = "Coverage is sparse. Dynamic absence signals have limited reliability."
    else:
        trust_tier = "very_low"
        recommendation = "Coverage is very sparse. Dynamic absence signals are almost meaningless."

    return _json_response(
        {
            "coverage_path": str(cov_path),
            "percent_covered": pct,
            "trust_tier": trust_tier,
            "files_with_execution": len(covered_files),
            "recommendation": recommendation,
        }
    )


@_tool()
def explain_verdict(
    vuln_id: str,
    package_name: str,
    repo_path: str = ".",
    proof_standard: str = "strict",
) -> str:
    from ca9.engine import analyze
    from ca9.report import report_to_dict
    from ca9.scanner import get_installed_packages, query_osv_batch

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path=None)
    if error:
        return error

    packages = get_installed_packages()
    try:
        vulnerabilities = query_osv_batch(packages)
    except (ConnectionError, ValueError) as exc:
        return _json_error(str(exc), error_type=type(exc).__name__)

    matching = [
        v
        for v in vulnerabilities
        if v.id == vuln_id or v.package_name.lower() == package_name.lower()
    ]

    if not matching:
        return _json_response(
            {
                "error": f"No vulnerability found matching id='{vuln_id}' and package='{package_name}'.",
                "hint": "Run scan_dependencies first to see all known vulnerabilities.",
            }
        )

    try:
        report = analyze(matching, repo, cov_path, proof_standard=proof_standard)
    except Exception as exc:
        return _json_error(
            f"Reachability analysis failed: {exc}",
            error_type=type(exc).__name__,
        )
    data = report_to_dict(report)

    for result in data.get("results", []):
        if result["id"] == vuln_id:
            return _json_response(result)

    if data.get("results"):
        return _json_response(data["results"][0])

    return _json_response({"error": "Analysis produced no results for the given vulnerability."})


@_tool()
def generate_vex(
    report_path: str,
    repo_path: str = ".",
    coverage_path: str | None = None,
    proof_standard: str = "strict",
) -> str:
    """Generate an OpenVEX document with reachability-backed exploitability statements."""
    from ca9.engine import analyze
    from ca9.vex import write_openvex

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    vulnerabilities, error = _load_report_vulnerabilities(report_path)
    if error:
        return error
    if not vulnerabilities:
        return _json_response({"statements": []})

    try:
        report = analyze(vulnerabilities, repo, cov_path, proof_standard=proof_standard)
    except Exception as exc:
        return _json_error(
            f"Reachability analysis failed: {exc}",
            error_type=type(exc).__name__,
        )
    return write_openvex(report)


@_tool()
def generate_remediation_plan(
    report_path: str,
    repo_path: str = ".",
    coverage_path: str | None = None,
    proof_standard: str = "strict",
    scan_caps: bool = False,
) -> str:
    """Generate prioritized remediation actions with compensating controls for reachable CVEs."""
    from ca9.engine import analyze
    from ca9.remediation import generate_remediation_plan as _gen_plan
    from ca9.remediation import remediation_plan_to_dict

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    vulnerabilities, error = _load_report_vulnerabilities(report_path)
    if error:
        return error
    if not vulnerabilities:
        return _json_response({"summary": {"total": 0}, "actions": []})

    try:
        report = analyze(
            vulnerabilities,
            repo,
            cov_path,
            proof_standard=proof_standard,
            scan_capabilities=scan_caps,
        )
    except Exception as exc:
        return _json_error(
            f"Reachability analysis failed: {exc}",
            error_type=type(exc).__name__,
        )
    plan = _gen_plan(report)
    return _json_response(remediation_plan_to_dict(plan))


@_tool()
def scan_capabilities(
    repo_path: str = ".",
) -> str:
    """Scan a repository for AI capabilities (MCP servers, LLM providers, agent tools, egress, etc.)."""
    from ca9.capabilities.scanner import scan_repository

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    try:
        aibom = scan_repository(repo, quiet=True)
    except Exception as exc:
        return _json_error(
            f"Capability scan failed: {exc}",
            error_type=type(exc).__name__,
        )
    bom_dict = aibom.to_dict()
    bom_dict["summary"] = {
        "components": len(aibom.components),
        "capabilities": sum(len(s.properties) for s in aibom.services),
    }
    return _json_response(bom_dict)


@_tool()
def check_blast_radius(
    report_path: str,
    repo_path: str = ".",
    coverage_path: str | None = None,
    proof_standard: str = "strict",
) -> str:
    """Analyze CVE reachability WITH capability blast radius for reachable vulns."""
    from ca9.engine import analyze
    from ca9.report import report_to_dict

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    vulnerabilities, error = _load_report_vulnerabilities(report_path)
    if error:
        return error

    if not vulnerabilities:
        return _json_response({"results": [], "summary": {"total": 0}})

    try:
        report = analyze(
            vulnerabilities,
            repo,
            cov_path,
            proof_standard=proof_standard,
            scan_capabilities=True,
        )
    except Exception as exc:
        return _json_error(
            f"Reachability analysis failed: {exc}",
            error_type=type(exc).__name__,
        )
    return _json_response(report_to_dict(report))


@_tool()
def trace_exploit_path(
    report_path: str,
    repo_path: str = ".",
    coverage_path: str | None = None,
    vuln_id: str | None = None,
) -> str:
    """Trace exploit paths from entry points to vulnerable API call sites for reachable CVEs."""
    from ca9.engine import analyze

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    vulnerabilities, error = _load_report_vulnerabilities(report_path)
    if error:
        return error
    if not vulnerabilities:
        return _json_response({"paths": []})

    try:
        report = analyze(
            vulnerabilities,
            repo,
            cov_path,
            proof_standard="balanced",
            trace_exploit_paths=True,
        )
    except Exception as exc:
        return _json_error(
            f"Exploit path tracing failed: {exc}",
            error_type=type(exc).__name__,
        )

    results = report.results
    if vuln_id:
        results = [r for r in results if r.vulnerability.id == vuln_id]

    output = []
    for r in results:
        if not r.exploit_paths:
            continue
        output.append(
            {
                "vuln_id": r.vulnerability.id,
                "package": r.vulnerability.package_name,
                "paths": [
                    {
                        "entry": f"{p.entry_point.file_path}:{p.entry_point.line}",
                        "target": p.vulnerable_target,
                        "depth": len(p.steps) + 2,
                        "confidence": p.confidence,
                    }
                    for p in r.exploit_paths
                ],
            }
        )

    return _json_response(output)


@_tool()
def lookup_threat_intel(
    cve_ids: str,
) -> str:
    """Look up EPSS scores and CISA KEV status for CVE IDs (comma-separated)."""
    from ca9.threat_intel import fetch_threat_intel_batch

    ids = [c.strip() for c in cve_ids.split(",") if c.strip()]
    if not ids:
        return _json_response({"error": "No CVE IDs provided"})

    try:
        data = fetch_threat_intel_batch(ids)
    except Exception as exc:
        return _json_error(
            f"Threat intel lookup failed: {exc}",
            error_type=type(exc).__name__,
        )
    result = {}
    for cve_id, ti in data.items():
        result[cve_id] = {
            "epss_score": ti.epss_score,
            "epss_percentile": ti.epss_percentile,
            "in_kev": ti.in_kev,
            "kev_due_date": ti.kev_due_date,
        }

    return _json_response(result)


@_tool()
def enrich_sbom(
    sbom_path: str,
    repo_path: str = ".",
    coverage_path: str | None = None,
) -> str:
    """Enrich a CycloneDX or SPDX SBOM with ca9 reachability verdicts."""
    from ca9.sbom import enrich_sbom as _enrich

    sbom_file = Path(sbom_path)
    if not sbom_file.is_file():
        return _json_response({"error": f"SBOM file not found: {sbom_path}"})

    repo, error = _resolve_repo(repo_path)
    if error:
        return error

    cov_path, error = _resolve_coverage_path(repo, coverage_path)
    if error:
        return error

    sbom_data, error = _load_json_file(sbom_file, f"SBOM file {sbom_path}")
    if error:
        return error

    try:
        enriched = _enrich(sbom_data, repo, cov_path)
    except ValueError as exc:
        return _json_error(str(exc), error_type=type(exc).__name__)
    except Exception as exc:
        return _json_error(
            f"SBOM enrichment failed: {exc}",
            error_type=type(exc).__name__,
        )
    return _json_response(enriched)


def main():
    if mcp is None:
        print(
            "ca9-mcp requires the optional MCP dependency. Install with: pip install ca9[mcp]",
            file=sys.stderr,
        )
        if _MCP_IMPORT_ERROR is not None:
            print(f"Import error: {_MCP_IMPORT_ERROR}", file=sys.stderr)
        raise SystemExit(1)

    transport = os.environ.get("MCP_TRANSPORT", "stdio")
    if transport == "sse":
        mcp.run(transport="sse")
    else:
        mcp.run(transport="stdio")
