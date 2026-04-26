from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from ca9 import __version__
from ca9.models import Report, Verdict, VerdictResult

_VEX_STATUS = {
    Verdict.REACHABLE: "affected",
    Verdict.UNREACHABLE_STATIC: "not_affected",
    Verdict.UNREACHABLE_DYNAMIC: "not_affected",
    Verdict.INCONCLUSIVE: "under_investigation",
}


def _derive_justification(result: VerdictResult) -> str | None:
    if result.verdict not in (Verdict.UNREACHABLE_STATIC, Verdict.UNREACHABLE_DYNAMIC):
        return None

    ev = result.evidence

    if result.verdict == Verdict.UNREACHABLE_DYNAMIC:
        return "vulnerable_code_not_in_execute_path"

    # UNREACHABLE_STATIC cases
    if ev is None:
        return "component_not_present"

    if ev.version_in_range is False:
        return "component_not_present"

    if not ev.package_imported:
        return "component_not_present"

    if ev.submodule_imported is False:
        return "vulnerable_code_not_present"

    return "component_not_present"


def _get_blast_radius(result: VerdictResult):
    br = result.blast_radius
    if br is None:
        return None
    if not hasattr(br, "capabilities"):
        return None
    return br


def _build_impact_statement(result: VerdictResult) -> str | None:
    if result.verdict != Verdict.REACHABLE:
        return None

    lines: list[str] = [f"Vulnerability is reachable: {result.reason}"]

    br = _get_blast_radius(result)
    if br:
        if br.capabilities:
            lines.append(f"Blast radius: {', '.join(br.capabilities)}")
        if br.risk_level and br.risk_level != "low":
            lines.append(f"Impact risk: {br.risk_level}")
        for reason in br.risk_reasons or ():
            lines.append(f"  - {reason}")

    if len(lines) == 1:
        return lines[0]
    return "\n".join(lines)


def _build_statement(result: VerdictResult, now: str) -> dict:
    vuln = result.vulnerability
    status = _VEX_STATUS[result.verdict]

    purl = f"pkg:pypi/{vuln.package_name.lower()}@{vuln.package_version}"

    statement: dict = {
        "vulnerability": {
            "name": vuln.id,
            "@id": f"https://osv.dev/vulnerability/{vuln.id}",
        },
        "products": [{"@id": purl, "identifiers": {"purl": purl}}],
        "status": status,
        "timestamp": now,
    }

    justification = _derive_justification(result)
    if justification:
        statement["justification"] = justification

    impact = _build_impact_statement(result)
    if impact:
        statement["impact_statement"] = impact

    ca9_meta: dict = {
        "verdict": result.verdict.value,
        "confidence_score": result.confidence_score,
        "reason": result.reason,
    }

    if result.original_verdict:
        ca9_meta["original_verdict"] = result.original_verdict.value
    if result.policy_adjustment:
        ca9_meta["policy_adjustment"] = result.policy_adjustment

    br = _get_blast_radius(result)
    if br and hasattr(br, "to_dict"):
        ca9_meta["blast_radius"] = br.to_dict()

    if result.exploit_paths:
        ca9_meta["exploit_path_count"] = len(result.exploit_paths)
        ca9_meta["exploit_paths"] = [
            {
                "entry": f"{p.entry_point.file_path}:{p.entry_point.function_name}",
                "target": p.vulnerable_target,
                "depth": len(p.steps) + 2,
            }
            for p in result.exploit_paths[:5]
        ]

    if result.threat_intel:
        ti = result.threat_intel
        ca9_meta["threat_intel"] = {
            "epss_score": ti.epss_score,
            "epss_percentile": ti.epss_percentile,
            "in_kev": ti.in_kev,
            "kev_due_date": ti.kev_due_date,
        }

    if result.runtime_mitigations:
        ca9_meta["runtime_mitigations"] = result.runtime_mitigations
    if result.runtime_adjusted_priority:
        ca9_meta["runtime_adjusted_priority"] = result.runtime_adjusted_priority

    ev = result.evidence
    if ev:
        ca9_meta["evidence_summary"] = {
            "version_in_range": ev.version_in_range,
            "package_imported": ev.package_imported,
            "dependency_kind": ev.dependency_kind,
            "dependency_graph_source": ev.dependency_graph_source,
            "coverage_seen": ev.coverage_seen,
            "coverage_completeness_pct": ev.coverage_completeness_pct,
            "submodule_imported": ev.submodule_imported,
        }

    statement["ca9"] = ca9_meta
    return statement


def write_openvex(report: Report, output: Path | TextIO | None = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    statements = [_build_statement(r, now) for r in report.results]

    doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://ca9.dev/vex/{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "author": "ca9",
        "role": "tool",
        "timestamp": now,
        "version": 1,
        "tooling": {
            "name": "ca9",
            "version": __version__,
            "proof_standard": report.proof_standard,
        },
        "statements": statements,
    }

    text = json.dumps(doc, indent=2)

    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)

    return text
