from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import TextIO

from ca9.models import Report, Verdict

_VERDICT_LABELS = {
    Verdict.REACHABLE: "REACHABLE",
    Verdict.UNREACHABLE_STATIC: "UNREACHABLE (static)",
    Verdict.UNREACHABLE_DYNAMIC: "UNREACHABLE (dynamic)",
    Verdict.INCONCLUSIVE: "INCONCLUSIVE",
}

_SARIF_LEVELS = {
    Verdict.REACHABLE: "error",
    Verdict.INCONCLUSIVE: "warning",
    Verdict.UNREACHABLE_STATIC: "note",
    Verdict.UNREACHABLE_DYNAMIC: "note",
}

_SEVERITY_RANKS = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "4.0",
    "low": "1.0",
    "unknown": "0.0",
}


def _evidence_to_dict(evidence) -> dict | None:
    if evidence is None:
        return None
    d = {
        "version_in_range": evidence.version_in_range,
        "dependency_kind": evidence.dependency_kind,
        "dependency_graph_available": evidence.dependency_graph_available,
        "dependency_graph_source": evidence.dependency_graph_source,
        "declared_direct_dependency": evidence.declared_direct_dependency,
        "package_imported": evidence.package_imported,
        "submodule_imported": evidence.submodule_imported,
        "report_dependency_chain": list(evidence.report_dependency_chain),
        "affected_component_source": evidence.affected_component_source,
        "affected_component_confidence": evidence.affected_component_confidence,
        "coverage_seen": evidence.coverage_seen,
        "coverage_files": list(evidence.coverage_files),
        "external_fetch_warnings": list(evidence.external_fetch_warnings),
    }
    if evidence.api_targets:
        d["api_targets"] = list(evidence.api_targets)
    if evidence.api_usage_seen is not None:
        d["api_usage_seen"] = evidence.api_usage_seen
    if evidence.api_usage_confidence is not None:
        d["api_usage_confidence"] = evidence.api_usage_confidence
    if evidence.api_usage_hits:
        d["api_usage_hits"] = [
            {
                "file": h.file_path,
                "line": h.line,
                "target": h.matched_target,
                "type": h.match_type,
                "snippet": h.code_snippet,
            }
            for h in evidence.api_usage_hits
        ]
    if evidence.api_call_sites_covered is not None:
        d["api_call_sites_covered"] = evidence.api_call_sites_covered
    if evidence.intel_rule_ids:
        d["intel_rule_ids"] = list(evidence.intel_rule_ids)
    if evidence.coverage_completeness_pct is not None:
        d["coverage_completeness_pct"] = evidence.coverage_completeness_pct
    if evidence.threat_intel is not None:
        ti = evidence.threat_intel
        d["threat_intel"] = {
            "epss_score": ti.epss_score,
            "epss_percentile": ti.epss_percentile,
            "in_kev": ti.in_kev,
            "kev_due_date": ti.kev_due_date,
        }
    if evidence.production_observed is not None:
        d["production_observed"] = evidence.production_observed
        d["production_trace_count"] = evidence.production_trace_count
    return d


def _component_to_dict(component) -> dict | None:
    if component is None:
        return None
    return {
        "submodule_paths": list(component.submodule_paths),
        "confidence": component.confidence,
        "extraction_source": component.extraction_source,
    }


def report_to_dict(report: Report) -> dict:
    return {
        "repo_path": report.repo_path,
        "coverage_path": report.coverage_path,
        "proof_standard": report.proof_standard,
        "warnings": list(report.warnings),
        "summary": {
            "total": report.total,
            "reachable": report.reachable_count,
            "unreachable": report.unreachable_count,
            "inconclusive": report.inconclusive_count,
        },
        "results": [
            {
                "id": r.vulnerability.id,
                "package": r.vulnerability.package_name,
                "version": r.vulnerability.package_version,
                "severity": r.vulnerability.severity,
                "title": r.vulnerability.title,
                "verdict": r.verdict.value,
                "reason": r.reason,
                "imported_as": r.imported_as,
                "dependency_of": r.dependency_of,
                "executed_files": r.executed_files,
                "confidence_score": r.confidence_score,
                "original_verdict": r.original_verdict.value if r.original_verdict else None,
                "policy_adjustment": r.policy_adjustment,
                "blast_radius": r.blast_radius.to_dict()
                if r.blast_radius and hasattr(r.blast_radius, "to_dict")
                else None,
                "runtime_mitigations": r.runtime_mitigations,
                "runtime_adjusted_priority": r.runtime_adjusted_priority,
                "exploit_paths": [
                    {
                        "entry_point": {
                            "file": p.entry_point.file_path,
                            "function": p.entry_point.function_name,
                            "line": p.entry_point.line,
                        },
                        "steps": [
                            {
                                "file": s.file_path,
                                "function": s.function_name,
                                "line": s.line,
                            }
                            for s in p.steps
                        ],
                        "vulnerable_call": {
                            "file": p.vulnerable_call.file_path,
                            "function": p.vulnerable_call.function_name,
                            "line": p.vulnerable_call.line,
                            "snippet": p.vulnerable_call.code_snippet,
                        },
                        "vulnerable_target": p.vulnerable_target,
                        "confidence": p.confidence,
                    }
                    for p in r.exploit_paths
                ]
                if r.exploit_paths
                else [],
                "threat_intel": {
                    "epss_score": r.threat_intel.epss_score,
                    "epss_percentile": r.threat_intel.epss_percentile,
                    "in_kev": r.threat_intel.in_kev,
                    "kev_due_date": r.threat_intel.kev_due_date,
                }
                if r.threat_intel
                else None,
                "affected_component": _component_to_dict(r.affected_component),
                "evidence": _evidence_to_dict(r.evidence),
            }
            for r in report.results
        ],
    }


def write_json(report: Report, output: Path | TextIO | None = None) -> str:
    data = report_to_dict(report)
    text = json.dumps(data, indent=2)

    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)

    return text


def write_table(
    report: Report,
    output: TextIO | None = None,
    verbose: bool = False,
    show_confidence: bool = False,
    show_evidence_source: bool = False,
) -> str:
    if output is None:
        output = sys.stdout

    def _col_width(label: str, getter) -> int:
        if not report.results:
            return len(label)
        return max(len(label), *(len(getter(r)) for r in report.results))

    id_w = _col_width("CVE ID", lambda r: r.vulnerability.id)
    pkg_w = _col_width("Package", lambda r: r.vulnerability.package_name)
    sev_w = _col_width("Severity", lambda r: r.vulnerability.severity)
    ver_w = _col_width("Verdict", lambda r: _VERDICT_LABELS[r.verdict])

    header_parts = [
        f"{'CVE ID':<{id_w}}",
        f"{'Package':<{pkg_w}}",
        f"{'Severity':<{sev_w}}",
        f"{'Verdict':<{ver_w}}",
    ]
    if show_confidence:
        header_parts.append(f"{'Conf':>4}")
    if show_evidence_source:
        header_parts.append(f"{'Source':<20}")

    header = "  ".join(header_parts)
    sep = "-" * len(header)

    lines = [
        "",
        header,
        sep,
    ]

    seen_vuln_pkg: set[tuple[str, str]] = set()

    for r in report.results:
        label = _VERDICT_LABELS[r.verdict]
        group_key = (r.vulnerability.id, r.vulnerability.package_name.lower())
        is_repeat = group_key in seen_vuln_pkg
        seen_vuln_pkg.add(group_key)

        if is_repeat:
            ditto = '"'
            row_parts = [
                f"{'  +' + r.vulnerability.package_version:<{id_w}}",
                f"{ditto:<{pkg_w}}",
                f"{ditto:<{sev_w}}",
                f"{ditto:<{ver_w}}",
            ]
            if show_confidence:
                row_parts.append(f"{r.confidence_score:>4}")
            if show_evidence_source:
                row_parts.append(f"{'':<20}")
            row = "  ".join(row_parts)
            lines.append(row)
        else:
            row_parts = [
                f"{r.vulnerability.id:<{id_w}}",
                f"{r.vulnerability.package_name:<{pkg_w}}",
                f"{r.vulnerability.severity:<{sev_w}}",
                f"{label:<{ver_w}}",
            ]
            if show_confidence:
                row_parts.append(f"{r.confidence_score:>4}")
            if show_evidence_source:
                source = ""
                if r.evidence:
                    source = r.evidence.affected_component_source[:20]
                row_parts.append(f"{source:<20}")

            row = "  ".join(row_parts)
            lines.append(row)
            if verbose:
                lines.append(f"  {'':>{id_w}} -> {r.reason}")
                br = r.blast_radius
                if br and hasattr(br, "capabilities") and br.capabilities:
                    caps = ", ".join(br.capabilities)
                    lines.append(
                        f"  {'':>{id_w}} -> blast radius: {caps} [risk: {br.risk_level.upper()}]"
                    )
                    if br.risk_reasons:
                        for br_reason in br.risk_reasons[:3]:
                            lines.append(f"  {'':>{id_w}}    {br_reason}")
                if r.exploit_paths:
                    for ep in r.exploit_paths[:3]:
                        chain_parts = [f"{ep.entry_point.function_name}"]
                        for step in ep.steps:
                            chain_parts.append(step.function_name)
                        chain_parts.append(ep.vulnerable_call.function_name)
                        chain = " -> ".join(chain_parts)
                        lines.append(f"  {'':>{id_w}} -> exploit path: {chain}")
                if r.threat_intel:
                    ti = r.threat_intel
                    ti_parts = []
                    if ti.epss_score is not None:
                        pctl = f" ({ti.epss_percentile:.0%}ile)" if ti.epss_percentile else ""
                        ti_parts.append(f"EPSS: {ti.epss_score:.2f}{pctl}")
                    if ti.in_kev:
                        kev_info = "CISA KEV"
                        if ti.kev_due_date:
                            kev_info += f" (due {ti.kev_due_date})"
                        ti_parts.append(kev_info)
                    if ti_parts:
                        lines.append(f"  {'':>{id_w}} -> {', '.join(ti_parts)}")

    lines.append(sep)
    lines.append(
        f"Total: {report.total}  |  "
        f"Reachable: {report.reachable_count}  |  "
        f"Unreachable: {report.unreachable_count}  |  "
        f"Inconclusive: {report.inconclusive_count}"
    )
    lines.append(f"Proof: {report.proof_standard}")
    if report.warnings:
        lines.append("")
        for warning in report.warnings:
            lines.append(f"Warning: {warning}")

    if report.total > 0 and report.unreachable_count > 0:
        pct = round(report.unreachable_count / report.total * 100)
        actionable = report.reachable_count + report.inconclusive_count
        lines.append("")
        lines.append(
            f"{pct}% of flagged CVEs are unreachable "
            f"— only {actionable} of {report.total} require action"
        )

    lines.append("")

    text = "\n".join(lines)
    output.write(text)
    return text


def _stable_fingerprint(vuln_id: str, package: str, version: str, verdict: str) -> str:
    data = f"{vuln_id}|{package}|{version}|{verdict}"
    return hashlib.sha256(data.encode()).hexdigest()[:32]


def write_sarif(report: Report, output: Path | TextIO | None = None) -> str:
    rules = []
    results = []
    seen_rule_ids: set[str] = set()

    for r in report.results:
        vuln = r.vulnerability
        rule_id = vuln.id

        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rule = {
                "id": rule_id,
                "shortDescription": {"text": vuln.title or rule_id},
                "helpUri": f"https://osv.dev/vulnerability/{rule_id}",
                "properties": {
                    "security-severity": _SEVERITY_RANKS.get(vuln.severity.lower(), "0.0"),
                    "tags": ["security", "vulnerability"],
                },
            }
            if vuln.description:
                rule["fullDescription"] = {"text": vuln.description}
            rules.append(rule)

        message_parts = [
            f"{vuln.package_name}@{vuln.package_version}: {vuln.title}",
            f"Verdict: {_VERDICT_LABELS[r.verdict]}",
            f"Reason: {r.reason}",
        ]

        fingerprint = _stable_fingerprint(
            vuln.id, vuln.package_name, vuln.package_version, r.verdict.value
        )

        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVELS[r.verdict],
            "message": {"text": "\n".join(message_parts)},
            "fingerprints": {
                "ca9/v1": fingerprint,
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": r.imported_as or vuln.package_name,
                            "uriBaseId": "%SRCROOT%",
                        },
                    },
                },
            ],
            "properties": {
                "verdict": r.verdict.value,
                "package": vuln.package_name,
                "version": vuln.package_version,
                "severity": vuln.severity,
                "confidence_score": r.confidence_score,
                "proof_standard": report.proof_standard,
            },
        }

        if r.evidence:
            result["properties"]["evidence"] = _evidence_to_dict(r.evidence)

        if r.dependency_of:
            result["properties"]["dependency_of"] = r.dependency_of
        if r.original_verdict:
            result["properties"]["original_verdict"] = r.original_verdict.value
        if r.policy_adjustment:
            result["properties"]["policy_adjustment"] = r.policy_adjustment
        if r.blast_radius and hasattr(r.blast_radius, "to_dict"):
            result["properties"]["blast_radius"] = r.blast_radius.to_dict()
        if r.exploit_paths:
            result["properties"]["exploit_path_count"] = len(r.exploit_paths)
        if r.threat_intel:
            ti = r.threat_intel
            result["properties"]["threat_intel"] = {
                "epss_score": ti.epss_score,
                "in_kev": ti.in_kev,
            }
        results.append(result)

    run = {
        "tool": {
            "driver": {
                "name": "ca9",
                "informationUri": "https://github.com/oha/ca9",
                "version": "0.3.0",
                "rules": rules,
            },
        },
        "results": results,
    }
    if report.warnings:
        run["properties"] = {"warnings": list(report.warnings)}

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }

    text = json.dumps(sarif, indent=2)

    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)

    return text
