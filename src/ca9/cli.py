from __future__ import annotations

import json
import sys
from pathlib import Path

try:
    import click
    from click.core import ParameterSource
except ImportError:
    print("ca9 CLI requires 'click'. Install with: pip install ca9[cli]", file=sys.stderr)
    sys.exit(1)

from ca9.config import find_config, load_config
from ca9.coverage_provider import resolve_coverage
from ca9.engine import analyze
from ca9.parsers import detect_parser
from ca9.report import write_json, write_sarif, write_table
from ca9.vex import write_openvex


def _output_report(
    report,
    output_format: str,
    output_path: Path | None,
    verbose: bool = False,
    show_confidence: bool = False,
    show_evidence_source: bool = False,
) -> None:
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        text = write_json(report)
        if output_path:
            output_path.write_text(text)
        else:
            click.echo(text)
    elif output_format == "sarif":
        text = write_sarif(report)
        if output_path:
            output_path.write_text(text)
        else:
            click.echo(text)
    elif output_format == "vex":
        text = write_openvex(report)
        if output_path:
            output_path.write_text(text)
        else:
            click.echo(text)
    elif output_format == "remediation":
        from ca9.remediation import generate_remediation_plan, remediation_plan_to_dict

        plan = generate_remediation_plan(report)
        text = json.dumps(remediation_plan_to_dict(plan), indent=2)
        if output_path:
            output_path.write_text(text)
        else:
            click.echo(text)
    elif output_format == "action-plan":
        from ca9.action_plan import generate_action_plan, write_action_plan

        plan = generate_action_plan(report)
        text = write_action_plan(plan)
        if output_path:
            output_path.write_text(text)
        else:
            click.echo(text)
    else:
        if output_path:
            with open(output_path, "w") as f:
                write_table(
                    report,
                    f,
                    verbose=verbose,
                    show_confidence=show_confidence,
                    show_evidence_source=show_evidence_source,
                )
        else:
            write_table(
                report,
                sys.stdout,
                verbose=verbose,
                show_confidence=show_confidence,
                show_evidence_source=show_evidence_source,
            )


class DefaultGroup(click.Group):
    def parse_args(self, ctx, args):
        if args and args[0] not in self.commands and not args[0].startswith("-"):
            args = ["check"] + args
        return super().parse_args(ctx, args)


def _load_cli_config() -> dict:
    config_path = find_config()
    if not config_path:
        return {}
    raw = load_config(config_path)
    mapping = {
        "repo": "repo_path",
        "coverage": "coverage_path",
        "format": "output_format",
        "output": "output_path",
        "verbose": "verbose",
        "no_auto_coverage": "no_auto_coverage",
        "proof_standard": "proof_standard",
    }
    result = {}
    for toml_key, param_name in mapping.items():
        if toml_key in raw:
            val = raw[toml_key]
            if toml_key in ("repo", "coverage", "output"):
                val = (config_path.parent / val).resolve()
            result[param_name] = val
    return result


@click.group(cls=DefaultGroup)
@click.pass_context
def main(ctx):
    ctx.ensure_object(dict)
    ctx.obj["config"] = _load_cli_config()


def _get_config_default(ctx: click.Context, param_name: str, fallback):
    if ctx.obj:
        config = ctx.obj.get("config", {})
    else:
        config = {}
    return config.get(param_name, fallback)


def _resolve_option(ctx: click.Context, option_name: str, current_value):
    if ctx.get_parameter_source(option_name) == ParameterSource.DEFAULT:
        return _get_config_default(ctx, option_name, current_value)
    return current_value


@main.command()
@click.argument("sca_report", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-c",
    "--coverage",
    "coverage_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to coverage.json for dynamic analysis.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif", "vex", "remediation", "action-plan"]),
    default="table",
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "-v", "--verbose", is_flag=True, default=False, help="Show reasoning trace for each verdict."
)
@click.option(
    "--no-auto-coverage",
    is_flag=True,
    default=False,
    help="Disable automatic coverage discovery and generation.",
)
@click.option(
    "--show-confidence",
    is_flag=True,
    default=False,
    help="Show confidence score in table output.",
)
@click.option(
    "--show-evidence-source",
    is_flag=True,
    default=False,
    help="Show evidence source in table output.",
)
@click.option(
    "--proof-standard",
    type=click.Choice(["strict", "balanced"]),
    default="strict",
    help="Proof policy for suppressions.",
)
@click.option(
    "--capabilities",
    is_flag=True,
    default=False,
    help="Scan for AI capabilities and attach blast radius to reachable CVEs.",
)
@click.option(
    "--runtime-context",
    "runtime_ctx_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Runtime context JSON for deployment-aware severity adjustment.",
)
@click.option(
    "--trace-paths",
    is_flag=True,
    default=False,
    help="Trace exploit paths from entry points to vulnerable call sites.",
)
@click.option(
    "--threat-intel",
    "threat_intel",
    is_flag=True,
    default=False,
    help="Enrich with EPSS scores and CISA KEV data.",
)
@click.option(
    "--otel-traces",
    "otel_traces_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="OTLP JSON export for production runtime evidence.",
)
@click.pass_context
def check(
    ctx: click.Context,
    sca_report: Path,
    repo_path: Path,
    coverage_path: Path | None,
    output_format: str,
    output_path: Path | None,
    verbose: bool,
    no_auto_coverage: bool,
    show_confidence: bool,
    show_evidence_source: bool,
    proof_standard: str,
    capabilities: bool,
    runtime_ctx_path: Path | None,
    trace_paths: bool,
    threat_intel: bool,
    otel_traces_path: Path | None,
) -> None:
    repo_path = _resolve_option(ctx, "repo_path", repo_path)
    coverage_path = _resolve_option(ctx, "coverage_path", coverage_path)
    output_format = _resolve_option(ctx, "output_format", output_format)
    output_path = _resolve_option(ctx, "output_path", output_path)
    verbose = _resolve_option(ctx, "verbose", verbose)
    no_auto_coverage = _resolve_option(ctx, "no_auto_coverage", no_auto_coverage)
    proof_standard = _resolve_option(ctx, "proof_standard", proof_standard)

    coverage_path = resolve_coverage(coverage_path, repo_path, auto_generate=not no_auto_coverage)

    try:
        data = json.loads(sca_report.read_text())
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON in {sca_report}: {e}") from None
    except OSError as e:
        raise click.ClickException(f"Cannot read {sca_report}: {e}") from None

    try:
        parser = detect_parser(sca_report)
    except ValueError as e:
        raise click.ClickException(str(e)) from None

    vulnerabilities = parser.parse(data)

    if not vulnerabilities:
        click.echo("No vulnerabilities found in the report.")
        return

    report = analyze(
        vulnerabilities,
        repo_path,
        coverage_path,
        proof_standard=proof_standard,
        scan_capabilities=capabilities,
        trace_exploit_paths=trace_paths,
        threat_intel=threat_intel,
        otel_traces_path=otel_traces_path,
    )

    if runtime_ctx_path:
        from ca9.runtime_context import apply_runtime_context, load_runtime_context

        runtime_ctx = load_runtime_context(runtime_ctx_path)
        report = apply_runtime_context(report, runtime_ctx)

    _output_report(
        report,
        output_format,
        output_path,
        verbose=verbose,
        show_confidence=show_confidence,
        show_evidence_source=show_evidence_source,
    )
    sys.exit(report.exit_code)


@main.command()
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-c",
    "--coverage",
    "coverage_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to coverage.json for dynamic analysis.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["table", "json", "sarif", "vex", "remediation", "action-plan"]),
    default="table",
    help="Output format.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "-v", "--verbose", is_flag=True, default=False, help="Show reasoning trace for each verdict."
)
@click.option(
    "--no-auto-coverage",
    is_flag=True,
    default=False,
    help="Disable automatic coverage discovery and generation.",
)
@click.option(
    "--offline",
    is_flag=True,
    default=False,
    help="Use only cached OSV data, do not make network requests.",
)
@click.option(
    "--refresh-cache",
    is_flag=True,
    default=False,
    help="Clear OSV cache before fetching.",
)
@click.option(
    "--max-osv-workers",
    type=int,
    default=8,
    help="Max concurrent OSV detail fetches.",
)
@click.option(
    "--show-confidence",
    is_flag=True,
    default=False,
    help="Show confidence score in table output.",
)
@click.option(
    "--show-evidence-source",
    is_flag=True,
    default=False,
    help="Show evidence source in table output.",
)
@click.option(
    "--proof-standard",
    type=click.Choice(["strict", "balanced"]),
    default="strict",
    help="Proof policy for suppressions.",
)
@click.option(
    "--capabilities",
    is_flag=True,
    default=False,
    help="Scan for AI capabilities and attach blast radius to reachable CVEs.",
)
@click.option(
    "--runtime-context",
    "runtime_ctx_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Runtime context JSON for deployment-aware severity adjustment.",
)
@click.option(
    "--trace-paths",
    is_flag=True,
    default=False,
    help="Trace exploit paths from entry points to vulnerable call sites.",
)
@click.option(
    "--threat-intel",
    "threat_intel",
    is_flag=True,
    default=False,
    help="Enrich with EPSS scores and CISA KEV data.",
)
@click.option(
    "--otel-traces",
    "otel_traces_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="OTLP JSON export for production runtime evidence.",
)
@click.pass_context
def scan(
    ctx: click.Context,
    repo_path: Path,
    coverage_path: Path | None,
    output_format: str,
    output_path: Path | None,
    verbose: bool,
    no_auto_coverage: bool,
    offline: bool,
    refresh_cache: bool,
    max_osv_workers: int,
    show_confidence: bool,
    show_evidence_source: bool,
    proof_standard: str,
    capabilities: bool,
    runtime_ctx_path: Path | None,
    trace_paths: bool,
    threat_intel: bool,
    otel_traces_path: Path | None,
) -> None:
    from ca9.scanner import query_osv_batch, resolve_scan_inventory

    repo_path = _resolve_option(ctx, "repo_path", repo_path)
    coverage_path = _resolve_option(ctx, "coverage_path", coverage_path)
    output_format = _resolve_option(ctx, "output_format", output_format)
    output_path = _resolve_option(ctx, "output_path", output_path)
    verbose = _resolve_option(ctx, "verbose", verbose)
    no_auto_coverage = _resolve_option(ctx, "no_auto_coverage", no_auto_coverage)
    proof_standard = _resolve_option(ctx, "proof_standard", proof_standard)

    coverage_path = resolve_coverage(coverage_path, repo_path, auto_generate=not no_auto_coverage)

    inventory = resolve_scan_inventory(repo_path)

    if inventory.source == "repo":
        click.echo(
            "Scanning repo dependency inventory "
            f"({len(inventory.packages)} package(s), {inventory.pinned_dependencies} exact pin(s), "
            f"{inventory.environment_fallbacks} environment fallback(s))...",
            err=True,
        )
    else:
        click.echo(
            f"No resolvable repo inventory found. Falling back to {len(inventory.packages)} installed package(s)...",
            err=True,
        )

    for warning in inventory.warnings:
        click.echo(f"ca9: {warning}", err=True)

    try:
        vulnerabilities = query_osv_batch(
            list(inventory.packages),
            offline=offline,
            refresh_cache=refresh_cache,
            max_workers=max_osv_workers,
        )
    except (ConnectionError, ValueError) as e:
        raise click.ClickException(str(e)) from None

    if not vulnerabilities:
        click.echo("No known vulnerabilities found in scanned packages.")
        return

    click.echo(
        f"Found {len(vulnerabilities)} known vulnerabilities. Analyzing reachability...", err=True
    )
    report = analyze(
        vulnerabilities,
        repo_path,
        coverage_path,
        proof_standard=proof_standard,
        scan_capabilities=capabilities,
        trace_exploit_paths=trace_paths,
        threat_intel=threat_intel,
        otel_traces_path=otel_traces_path,
    )
    if inventory.warnings:
        report.warnings = list(inventory.warnings) + report.warnings

    if runtime_ctx_path:
        from ca9.runtime_context import apply_runtime_context, load_runtime_context

        runtime_ctx = load_runtime_context(runtime_ctx_path)
        report = apply_runtime_context(report, runtime_ctx)

    _output_report(
        report,
        output_format,
        output_path,
        verbose=verbose,
        show_confidence=show_confidence,
        show_evidence_source=show_evidence_source,
    )
    sys.exit(report.exit_code)


@main.command(name="capabilities")
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "summary"]),
    default="summary",
    help="Output format.",
)
def capabilities_cmd(repo_path: Path, output_path: Path | None, output_format: str) -> None:
    """Scan repository for AI capabilities (MCP servers, LLM providers, agent tools, etc.)."""
    from ca9.capabilities.scanner import scan_repository

    aibom = scan_repository(repo_path, quiet=(output_format == "json"))

    if output_format == "json":
        bom_hash = aibom.calculate_hash()
        from ca9.capabilities.models import Property

        aibom.metadata.properties.append(Property(name="ca9.bom.hash", value=bom_hash))
        text = aibom.to_json()
    else:
        lines = [f"ca9 AI-BOM for {repo_path}"]
        lines.append(f"Components: {len(aibom.components)}")
        cap_count = 0
        for svc in aibom.services:
            cap_count += len(svc.properties)
        lines.append(f"Capabilities: {cap_count}")
        lines.append("")
        for comp in aibom.components:
            kind = comp.get_property("ca9.ai.asset.kind") or comp.type
            if kind == "repo":
                continue
            lines.append(f"  [{kind}] {comp.name}")
        if cap_count:
            lines.append("")
            lines.append("Capabilities:")
            for svc in aibom.services:
                for prop in svc.properties:
                    if prop.name == "ca9.capability.record":
                        import json as _json

                        try:
                            data = _json.loads(prop.value)
                            lines.append(
                                f"  {data['cap']}  scope={data['scope']}  asset={data['asset']}"
                            )
                        except Exception:
                            lines.append(f"  {prop.value}")
        text = "\n".join(lines)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        click.echo(f"Written to {output_path}", err=True)
    else:
        click.echo(text)


@main.command(name="cap-diff")
@click.option(
    "--base",
    "base_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Base AI-BOM JSON.",
)
@click.option(
    "--head",
    "head_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Head AI-BOM JSON.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write diff JSON to file.",
)
@click.option(
    "--md",
    "md_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write markdown diff to file.",
)
def cap_diff_cmd(
    base_path: Path, head_path: Path, output_path: Path | None, md_path: Path | None
) -> None:
    """Compute capability diff between two AI-BOM scans."""
    from ca9.capabilities.diff import compute_diff
    from ca9.capabilities.emit import emit_markdown_diff

    base_bom = json.loads(base_path.read_text())
    head_bom = json.loads(head_path.read_text())

    diff = compute_diff(base_bom, head_bom)

    text = diff.to_json()
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        click.echo(f"Diff written to {output_path}", err=True)
    else:
        click.echo(text)

    if md_path:
        md_text = emit_markdown_diff(diff)
        md_path.parent.mkdir(parents=True, exist_ok=True)
        md_path.write_text(md_text)
        click.echo(f"Markdown diff written to {md_path}", err=True)

    click.echo(f"Risk: {diff.risk.level.upper()}", err=True)
    click.echo(
        f"Assets added: {len(diff.assets_added)}, removed: {len(diff.assets_removed)}, changed: {len(diff.assets_changed)}",
        err=True,
    )
    click.echo(
        f"Capabilities added: {len(diff.capabilities_added)}, removed: {len(diff.capabilities_removed)}, widened: {len(diff.capabilities_widened)}",
        err=True,
    )


@main.command(name="cap-gate")
@click.option(
    "--diff",
    "diff_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Capability diff JSON.",
)
@click.option(
    "--policy", "policy_path", type=click.Path(exists=True), required=True, help="Policy YAML file."
)
def cap_gate_cmd(diff_path: Path, policy_path: str) -> None:
    """Evaluate capability diff against a policy file."""
    from ca9.capabilities.policy import evaluate_policy

    diff_data = json.loads(diff_path.read_text())
    result = evaluate_policy(diff_data, policy_path)

    if result.get("error"):
        raise click.ClickException(result["error"])

    for rule in result.get("triggered_rules", []):
        symbol = "FAIL" if rule["action"] == "block" else "WARN"
        click.echo(f"  [{symbol}] {rule['id']}: {rule['message']}", err=True)

    decision = result["decision"]
    if decision == "block":
        click.echo("Decision: BLOCKED", err=True)
        sys.exit(2)
    elif decision == "warn":
        click.echo("Decision: WARN (passed with warnings)", err=True)
    else:
        click.echo("Decision: PASSED", err=True)


@main.command(name="vex-diff")
@click.option(
    "--base",
    "base_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Base VEX document.",
)
@click.option(
    "--head",
    "head_path",
    type=click.Path(exists=True, path_type=Path),
    required=True,
    help="Head VEX document.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Output file.",
)
def vex_diff_cmd(base_path: Path, head_path: Path, output_path: Path | None) -> None:
    """Compare two VEX documents and show what changed (continuous VEX)."""
    from ca9.vex_diff import compute_vex_diff, write_vex_diff

    base_vex = json.loads(base_path.read_text())
    head_vex = json.loads(head_path.read_text())

    diff = compute_vex_diff(base_vex, head_vex)
    text = write_vex_diff(diff)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
    else:
        click.echo(text)

    click.echo(
        f"Became affected: {len(diff.became_affected)}, "
        f"became safe: {len(diff.became_safe)}, "
        f"new: {len(diff.new_vulns)}, "
        f"unchanged: {diff.unchanged_count}",
        err=True,
    )

    if diff.has_regressions:
        click.echo(
            f"WARNING: {len(diff.became_affected) + len(diff.new_vulns)} "
            f"vulnerabilities require attention",
            err=True,
        )
        sys.exit(1)


@main.command(name="action-plan")
@click.argument("sca_report", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-c",
    "--coverage",
    "coverage_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to coverage.json.",
)
@click.option(
    "--proof-standard",
    type=click.Choice(["strict", "balanced"]),
    default="strict",
    help="Proof policy.",
)
@click.option(
    "--capabilities",
    is_flag=True,
    default=False,
    help="Include capability scanning for blast radius.",
)
@click.option(
    "--runtime-context",
    "runtime_ctx_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Runtime context JSON (auth, network isolation, etc.).",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write action plan to file.",
)
def action_plan_cmd(
    sca_report: Path,
    repo_path: Path,
    coverage_path: Path | None,
    proof_standard: str,
    capabilities: bool,
    runtime_ctx_path: Path | None,
    output_path: Path | None,
) -> None:
    """Generate a machine-readable action plan for CI/CD (block, PR, revoke, notify)."""
    from ca9.action_plan import generate_action_plan, write_action_plan

    coverage_path = resolve_coverage(coverage_path, repo_path, auto_generate=False)

    try:
        data = json.loads(sca_report.read_text())
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON: {e}") from None

    try:
        parser = detect_parser(sca_report)
    except ValueError as e:
        raise click.ClickException(str(e)) from None

    vulnerabilities = parser.parse(data)
    if not vulnerabilities:
        click.echo(json.dumps({"decision": "pass", "actions": [], "summary": "No vulnerabilities"}))
        return

    report = analyze(
        vulnerabilities,
        repo_path,
        coverage_path,
        proof_standard=proof_standard,
        scan_capabilities=capabilities,
    )

    if runtime_ctx_path:
        from ca9.runtime_context import apply_runtime_context, load_runtime_context

        runtime_ctx = load_runtime_context(runtime_ctx_path)
        report = apply_runtime_context(report, runtime_ctx)

    plan = generate_action_plan(report)
    text = write_action_plan(plan)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        click.echo(f"Action plan written to {output_path}", err=True)
    else:
        click.echo(text)

    click.echo(f"Decision: {plan.decision.upper()} | Actions: {len(plan.actions)}", err=True)
    sys.exit(plan.exit_code)


@main.command(name="trace")
@click.argument("sca_report", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-c",
    "--coverage",
    "coverage_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to coverage.json.",
)
@click.option("--vuln-id", default=None, help="Filter to a specific CVE ID.")
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file.",
)
def trace_cmd(
    sca_report: Path,
    repo_path: Path,
    coverage_path: Path | None,
    vuln_id: str | None,
    output_path: Path | None,
) -> None:
    """Trace exploit paths from entry points to vulnerable API call sites."""
    coverage_path = resolve_coverage(coverage_path, repo_path, auto_generate=False)

    try:
        data = json.loads(sca_report.read_text())
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON: {e}") from None

    try:
        parser = detect_parser(sca_report)
    except ValueError as e:
        raise click.ClickException(str(e)) from None

    vulnerabilities = parser.parse(data)
    if not vulnerabilities:
        click.echo("No vulnerabilities found.")
        return

    report = analyze(
        vulnerabilities,
        repo_path,
        coverage_path,
        proof_standard="balanced",
        trace_exploit_paths=True,
    )

    results = report.results
    if vuln_id:
        results = [r for r in results if r.vulnerability.id == vuln_id]

    output_data = []
    for r in results:
        if not r.exploit_paths:
            continue
        entry = {
            "vuln_id": r.vulnerability.id,
            "package": r.vulnerability.package_name,
            "paths": [
                {
                    "entry": f"{p.entry_point.file_path}:{p.entry_point.line} ({p.entry_point.function_name})",
                    "chain": [f"{s.file_path}:{s.line} ({s.function_name})" for s in p.steps],
                    "vulnerable_call": f"{p.vulnerable_call.file_path}:{p.vulnerable_call.line} ({p.vulnerable_target})",
                    "confidence": p.confidence,
                }
                for p in r.exploit_paths
            ],
        }
        output_data.append(entry)

    text = json.dumps(output_data, indent=2)
    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        click.echo(f"Trace written to {output_path}", err=True)
    else:
        click.echo(text)

    total_paths = sum(len(e["paths"]) for e in output_data)
    click.echo(
        f"Found {total_paths} exploit path(s) across {len(output_data)} vulnerability(ies)",
        err=True,
    )


@main.command(name="enrich-sbom")
@click.argument("sbom_input", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-r",
    "--repo",
    "repo_path",
    type=click.Path(exists=True, path_type=Path),
    default=".",
    help="Path to the project repository.",
)
@click.option(
    "-c",
    "--coverage",
    "coverage_path",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to coverage.json.",
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(path_type=Path),
    default=None,
    help="Output enriched SBOM file.",
)
def enrich_sbom_cmd(
    sbom_input: Path,
    repo_path: Path,
    coverage_path: Path | None,
    output_path: Path | None,
) -> None:
    """Enrich a CycloneDX or SPDX SBOM with ca9 reachability verdicts."""
    from ca9.sbom import enrich_sbom

    coverage_path = resolve_coverage(coverage_path, repo_path, auto_generate=False)

    try:
        sbom_data = json.loads(sbom_input.read_text())
    except json.JSONDecodeError as e:
        raise click.ClickException(f"Invalid JSON: {e}") from None

    try:
        enriched = enrich_sbom(sbom_data, repo_path, coverage_path)
    except ValueError as e:
        raise click.ClickException(str(e)) from None
    text = json.dumps(enriched, indent=2)

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(text)
        click.echo(f"Enriched SBOM written to {output_path}", err=True)
    else:
        click.echo(text)


if __name__ == "__main__":
    main()
