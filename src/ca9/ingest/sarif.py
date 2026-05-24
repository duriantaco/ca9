from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ca9.core.models import Evidence, Finding, RiskSignal, SourceEvidence, package_key
from ca9.ingest.models import EvidenceReport, ToolRun


def load_sarif_report(path: Path, *, repo_path: Path | None = None) -> EvidenceReport:
    data = json.loads(path.read_text())
    return sarif_to_evidence_report(data, source_path=path, repo_path=repo_path)


def sarif_to_evidence_report(
    data: dict[str, Any],
    *,
    source_path: Path | None = None,
    repo_path: Path | None = None,
) -> EvidenceReport:
    if not isinstance(data, dict):
        raise ValueError("SARIF input must be a JSON object.")

    source = str(source_path) if source_path is not None else "<memory>"
    target_name = _target_name(repo_path, source_path)
    target_key = package_key("repo", target_name)
    target_path = str(repo_path) if repo_path is not None else None

    version = data.get("version")
    warnings: list[str] = []
    if version and version != "2.1.0":
        warnings.append(f"SARIF version {version!r} is not 2.1.0; parsed best-effort.")

    runs = data.get("runs")
    if not isinstance(runs, list):
        raise ValueError("SARIF input is missing a 'runs' array.")

    tool_runs: list[ToolRun] = []
    findings: list[Finding] = []
    for run_index, run in enumerate(runs):
        if not isinstance(run, dict):
            warnings.append(f"Skipped non-object run at index {run_index}.")
            continue

        tool = _tool_run(run)
        results = run.get("results", [])
        if not isinstance(results, list):
            warnings.append(f"Run {run_index} has non-array results; skipped.")
            results = []
        tool_runs.append(
            ToolRun(
                name=tool["name"],
                version=tool.get("version"),
                information_uri=tool.get("information_uri"),
                result_count=len(results),
            )
        )

        for result_index, result in enumerate(results):
            if not isinstance(result, dict):
                warnings.append(f"Skipped non-object result at run {run_index}, index {result_index}.")
                continue
            rule = _rule_for_result(run, result)
            findings.append(
                _finding_from_result(
                    result,
                    rule,
                    source_path=source,
                    target_key=target_key,
                    tool=tool,
                    sarif_version=version,
                    run_index=run_index,
                    result_index=result_index,
                )
            )

    return EvidenceReport(
        source_path=source,
        target_key=target_key,
        target_path=target_path,
        tool_runs=tuple(tool_runs),
        findings=tuple(findings),
        warnings=tuple(warnings),
        metadata={"format": "sarif", "version": version},
    )


def evidence_report_to_json(report: EvidenceReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def evidence_report_to_table(report: EvidenceReport) -> str:
    summary = report.summary()
    severity = summary["by_severity"]
    severity_text = ", ".join(f"{key}: {value}" for key, value in severity.items()) or "none"
    tools = ", ".join(run.name for run in report.tool_runs) or "none"
    lines = [
        f"ca9 evidence report for {report.target_path or report.target_key}",
        f"Findings: {summary['findings']} | Tools: {tools} | Severity: {severity_text}",
    ]
    if report.warnings:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"  - {warning}" for warning in report.warnings)
    if report.findings:
        lines.append("")
        lines.append("Findings:")
        for finding in report.findings:
            location = finding.metadata.get("location", {})
            location_text = _format_location(location)
            rule_id = finding.metadata.get("rule", {}).get("id", "unknown-rule")
            tool = finding.metadata.get("tool", {}).get("name", "unknown-tool")
            lines.append(f"  [{finding.severity.upper()}] {tool} {rule_id} {location_text}")
            lines.append(f"    {finding.title}")
    return "\n".join(lines)


def _finding_from_result(
    result: dict[str, Any],
    rule: dict[str, Any] | None,
    *,
    source_path: str,
    target_key: str,
    tool: dict[str, str],
    sarif_version: Any,
    run_index: int,
    result_index: int,
) -> Finding:
    rule_id = _rule_id(result, rule)
    message = _message_text(result.get("message")) or _rule_title(rule) or rule_id
    location = _primary_location(result)
    severity = _severity_for_result(result, rule)
    confidence = _confidence_for_rule(rule)
    tags = _rule_tags(rule)

    source = SourceEvidence(
        source=f"sarif:{tool['name']}",
        path=source_path,
        reader="sarif",
        detail=f"run={run_index} result={result_index} rule={rule_id}",
    )
    evidence_metadata = {
        "rule_id": rule_id,
        "tool": tool,
        "location": location,
        "level": result.get("level"),
        "kind": result.get("kind"),
    }
    evidence = Evidence(
        kind="sarif_result",
        description=message,
        source=source,
        metadata=_drop_empty(evidence_metadata),
    )
    metadata = _drop_empty(
        {
            "tool": tool,
            "rule": _rule_metadata(rule, rule_id, tags),
            "location": location,
            "sarif": _drop_empty(
                {
                    "version": sarif_version,
                    "run_index": run_index,
                    "result_index": result_index,
                    "rule_id": rule_id,
                    "rule_index": result.get("ruleIndex"),
                    "level": result.get("level"),
                    "kind": result.get("kind"),
                    "fingerprints": result.get("fingerprints"),
                    "partial_fingerprints": result.get("partialFingerprints"),
                    "baseline_state": result.get("baselineState"),
                }
            ),
        }
    )
    signal_metadata = _stable_signal_metadata(metadata)
    signal = RiskSignal(
        signal_type="static_analysis",
        package_key=target_key,
        severity=severity,
        confidence=confidence,
        evidence=(evidence,),
        metadata=signal_metadata,
    )
    return Finding(
        title=message,
        signal_type="static_analysis",
        package_key=target_key,
        severity=severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata=metadata,
    )


def _tool_run(run: dict[str, Any]) -> dict[str, str]:
    driver = run.get("tool", {}).get("driver", {})
    if not isinstance(driver, dict):
        driver = {}
    name = driver.get("name") or "unknown-tool"
    return _drop_empty(
        {
            "name": str(name),
            "version": _optional_str(driver.get("version") or driver.get("semanticVersion")),
            "information_uri": _optional_str(driver.get("informationUri")),
        }
    )


def _rule_for_result(run: dict[str, Any], result: dict[str, Any]) -> dict[str, Any] | None:
    component = _rule_component(run, result)
    rules = _rules_for_component(component)
    rule_ref = result.get("rule")
    if not isinstance(rule_ref, dict):
        rule_ref = {}

    rule_index = rule_ref.get("index")
    if not isinstance(rule_index, int):
        rule_index = result.get("ruleIndex")
    if isinstance(rule_index, int) and 0 <= rule_index < len(rules):
        return rules[rule_index]

    rule_guid = rule_ref.get("guid")
    if rule_guid is not None:
        for rule in rules:
            if rule.get("guid") == rule_guid:
                return rule

    rule_id = rule_ref.get("id") or result.get("ruleId")
    if rule_id is None:
        return None
    for rule in rules:
        if rule.get("id") == rule_id:
            return rule
    return None


def _rule_component(run: dict[str, Any], result: dict[str, Any]) -> dict[str, Any] | None:
    tool = run.get("tool")
    if not isinstance(tool, dict):
        return None

    driver = tool.get("driver")
    if not isinstance(driver, dict):
        driver = None

    rule_ref = result.get("rule")
    if not isinstance(rule_ref, dict):
        return driver

    component_ref = rule_ref.get("toolComponent")
    if not isinstance(component_ref, dict):
        return driver

    component = _component_from_reference(tool, component_ref)
    return component or driver


def _component_from_reference(
    tool: dict[str, Any],
    component_ref: dict[str, Any],
) -> dict[str, Any] | None:
    driver = tool.get("driver")
    extensions = tool.get("extensions", [])
    if not isinstance(extensions, list):
        extensions = []

    candidates: list[dict[str, Any]] = []
    if isinstance(driver, dict):
        candidates.append(driver)
    candidates.extend(extension for extension in extensions if isinstance(extension, dict))

    for field in ("guid", "name"):
        value = component_ref.get(field)
        if value is None:
            continue
        for candidate in candidates:
            if candidate.get(field) == value:
                return candidate

    index = component_ref.get("index")
    if isinstance(index, int) and 0 <= index < len(extensions):
        extension = extensions[index]
        if isinstance(extension, dict):
            return extension
    return None


def _rules_for_component(component: dict[str, Any] | None) -> list[dict[str, Any]]:
    rules = component.get("rules", []) if isinstance(component, dict) else []
    if not isinstance(rules, list):
        return []
    return [rule for rule in rules if isinstance(rule, dict)]


def _rule_id(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    if result.get("ruleId"):
        return str(result["ruleId"])
    rule_ref = result.get("rule")
    if isinstance(rule_ref, dict) and rule_ref.get("id"):
        return str(rule_ref["id"])
    if rule and rule.get("id"):
        return str(rule["id"])
    return "unknown-rule"


def _rule_title(rule: dict[str, Any] | None) -> str | None:
    if not rule:
        return None
    return (
        _message_text(rule.get("fullDescription"))
        or _message_text(rule.get("shortDescription"))
        or _optional_str(rule.get("name"))
        or _optional_str(rule.get("id"))
    )


def _rule_metadata(
    rule: dict[str, Any] | None,
    rule_id: str,
    tags: tuple[str, ...],
) -> dict[str, Any]:
    if not rule:
        return {"id": rule_id}
    properties = rule.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
    return _drop_empty(
        {
            "id": rule_id,
            "name": rule.get("name"),
            "short_description": _message_text(rule.get("shortDescription")),
            "full_description": _message_text(rule.get("fullDescription")),
            "help_uri": rule.get("helpUri"),
            "precision": properties.get("precision"),
            "tags": list(tags),
            "security_severity": properties.get("security-severity"),
        }
    )


def _message_text(message: Any) -> str | None:
    if isinstance(message, str):
        return message
    if not isinstance(message, dict):
        return None
    text = message.get("text") or message.get("markdown")
    return str(text) if text is not None else None


def _primary_location(result: dict[str, Any]) -> dict[str, Any]:
    locations = result.get("locations")
    if not isinstance(locations, list) or not locations:
        return {}
    first = locations[0]
    if not isinstance(first, dict):
        return {}
    physical = first.get("physicalLocation")
    if not isinstance(physical, dict):
        return {}
    artifact = physical.get("artifactLocation")
    region = physical.get("region")
    if not isinstance(artifact, dict):
        artifact = {}
    if not isinstance(region, dict):
        region = {}
    return _drop_empty(
        {
            "uri": artifact.get("uri"),
            "uri_base_id": artifact.get("uriBaseId"),
            "start_line": region.get("startLine"),
            "start_column": region.get("startColumn"),
            "end_line": region.get("endLine"),
            "end_column": region.get("endColumn"),
            "snippet": _message_text(region.get("snippet")),
        }
    )


def _severity_for_result(result: dict[str, Any], rule: dict[str, Any] | None) -> str:
    for props in (_properties(result), _properties(rule)):
        security_severity = _cvss_like(props.get("security-severity"))
        if security_severity:
            return security_severity
        severity = _named_severity(props.get("severity"))
        if severity:
            return severity

    level = result.get("level")
    if level is None and rule:
        config = rule.get("defaultConfiguration")
        if isinstance(config, dict):
            level = config.get("level")
    if level is None:
        level = "warning"
    return {
        "error": "high",
        "warning": "medium",
        "note": "low",
        "none": "unknown",
    }.get(str(level).lower(), "unknown")


def _confidence_for_rule(rule: dict[str, Any] | None) -> str:
    precision = _properties(rule).get("precision")
    value = str(precision).lower() if precision is not None else ""
    if value in {"very-high", "high"}:
        return "high"
    if value == "medium":
        return "medium"
    if value == "low":
        return "low"
    return "medium"


def _rule_tags(rule: dict[str, Any] | None) -> tuple[str, ...]:
    tags = _properties(rule).get("tags")
    if not isinstance(tags, list):
        return ()
    return tuple(str(tag) for tag in tags)


def _properties(item: dict[str, Any] | None) -> dict[str, Any]:
    if not item:
        return {}
    props = item.get("properties")
    return props if isinstance(props, dict) else {}


def _cvss_like(value: Any) -> str | None:
    try:
        score = float(value)
    except (TypeError, ValueError):
        return None
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "unknown"


def _named_severity(value: Any) -> str | None:
    if value is None:
        return None
    normalized = str(value).lower()
    if normalized in {"critical", "high", "medium", "low", "unknown"}:
        return normalized
    if normalized == "error":
        return "high"
    if normalized == "warning":
        return "medium"
    if normalized == "note":
        return "low"
    return None


def _format_location(location: dict[str, Any]) -> str:
    uri = location.get("uri")
    if not uri:
        return ""
    line = location.get("start_line")
    column = location.get("start_column")
    if line and column:
        return f"{uri}:{line}:{column}"
    if line:
        return f"{uri}:{line}"
    return str(uri)


def _stable_signal_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    tool = metadata.get("tool")
    rule = metadata.get("rule")
    sarif = metadata.get("sarif")
    stable_tool = {}
    stable_rule = {}
    stable_sarif = {}

    if isinstance(tool, dict) and tool.get("name"):
        stable_tool["name"] = tool["name"]

    if isinstance(rule, dict):
        stable_rule = _drop_empty(
            {
                "id": rule.get("id"),
                "tags": rule.get("tags"),
            }
        )

    if isinstance(sarif, dict):
        stable_sarif = _drop_empty(
            {
                "rule_id": sarif.get("rule_id"),
                "fingerprints": sarif.get("fingerprints"),
                "partial_fingerprints": sarif.get("partial_fingerprints"),
            }
        )

    return _drop_empty(
        {
            "tool": stable_tool,
            "rule": stable_rule,
            "location": _stable_location_metadata(metadata.get("location"), stable_sarif),
            "sarif": stable_sarif,
        }
    )


def _stable_location_metadata(location: Any, stable_sarif: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(location, dict):
        return {}
    if stable_sarif.get("fingerprints") or stable_sarif.get("partial_fingerprints"):
        return _drop_empty(
            {
                "uri": location.get("uri"),
                "uri_base_id": location.get("uri_base_id"),
            }
        )
    return _drop_empty(
        {
            "uri": location.get("uri"),
            "uri_base_id": location.get("uri_base_id"),
            "start_line": location.get("start_line"),
            "start_column": location.get("start_column"),
            "end_line": location.get("end_line"),
            "end_column": location.get("end_column"),
        }
    )


def _target_name(repo_path: Path | None, source_path: Path | None) -> str:
    if repo_path is not None:
        return repo_path.resolve().name or "repository"
    if source_path is not None and source_path.parent.name:
        return source_path.parent.name
    return "repository"


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _drop_empty(data: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in data.items() if value not in (None, "", [], {}, ())}
