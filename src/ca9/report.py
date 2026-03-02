from __future__ import annotations

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


def report_to_dict(report: Report) -> dict:
    return {
        "repo_path": report.repo_path,
        "coverage_path": report.coverage_path,
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
                "affected_component": (
                    {
                        "submodule_paths": list(r.affected_component.submodule_paths),
                        "confidence": r.affected_component.confidence,
                        "extraction_source": r.affected_component.extraction_source,
                    }
                    if r.affected_component
                    else None
                ),
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
) -> str:
    if output is None:
        output = sys.stdout

    id_w = (
        max(len("CVE ID"), *(len(r.vulnerability.id) for r in report.results))
        if report.results
        else len("CVE ID")
    )
    pkg_w = (
        max(len("Package"), *(len(r.vulnerability.package_name) for r in report.results))
        if report.results
        else len("Package")
    )
    sev_w = (
        max(len("Severity"), *(len(r.vulnerability.severity) for r in report.results))
        if report.results
        else len("Severity")
    )
    ver_w = (
        max(len("Verdict"), *(len(_VERDICT_LABELS[r.verdict]) for r in report.results))
        if report.results
        else len("Verdict")
    )

    header = (
        f"{'CVE ID':<{id_w}}  {'Package':<{pkg_w}}  {'Severity':<{sev_w}}  {'Verdict':<{ver_w}}"
    )
    sep = "-" * len(header)

    lines = [
        "",
        header,
        sep,
    ]

    for r in report.results:
        label = _VERDICT_LABELS[r.verdict]
        row = f"{r.vulnerability.id:<{id_w}}  {r.vulnerability.package_name:<{pkg_w}}  {r.vulnerability.severity:<{sev_w}}  {label:<{ver_w}}"
        lines.append(row)
        if verbose:
            lines.append(f"  {'':>{id_w}} -> {r.reason}")

    lines.append(sep)
    lines.append(
        f"Total: {report.total}  |  "
        f"Reachable: {report.reachable_count}  |  "
        f"Unreachable: {report.unreachable_count}  |  "
        f"Inconclusive: {report.inconclusive_count}"
    )

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


def write_sarif(report: Report, output: Path | TextIO | None = None) -> str:
    """Write report in SARIF 2.1.0 format for GitHub Security tab integration."""
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

        result = {
            "ruleId": rule_id,
            "level": _SARIF_LEVELS[r.verdict],
            "message": {"text": "\n".join(message_parts)},
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
            },
        }
        if r.dependency_of:
            result["properties"]["dependency_of"] = r.dependency_of
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ca9",
                        "informationUri": "https://github.com/oha/ca9",
                        "version": "0.1.1",
                        "rules": rules,
                    },
                },
                "results": results,
            },
        ],
    }

    text = json.dumps(sarif, indent=2)

    if isinstance(output, Path):
        output.write_text(text)
    elif output is not None:
        output.write(text)

    return text
