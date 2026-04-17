from __future__ import annotations

import sys
from pathlib import Path

from packaging.utils import canonicalize_name

from ca9.analysis.api_usage import find_api_usage
from ca9.analysis.ast_scanner import (
    collect_imports_from_repo,
    discover_declared_dependencies,
    is_package_imported,
    is_submodule_imported,
    pypi_to_import_name,
    resolve_transitive_deps,
)
from ca9.analysis.coverage_reader import (
    are_call_sites_covered,
    get_coverage_completeness,
    get_covered_files,
    is_package_executed,
    is_submodule_executed,
    load_coverage,
)
from ca9.analysis.vuln_matcher import extract_affected_component
from ca9.intel_rules import VulnIntelResolution, resolve_vuln_intel
from ca9.models import (
    AffectedComponent,
    ApiUsageHit,
    Evidence,
    Report,
    Verdict,
    VerdictResult,
    Vulnerability,
)
from ca9.scoring import compute_confidence
from ca9.version import check_version

STRICT_DYNAMIC_MIN_COVERAGE = 80.0


def _report_dependency_kind(vuln: Vulnerability) -> str | None:
    if vuln.report_dependency_kind in ("direct", "transitive"):
        return vuln.report_dependency_kind

    if vuln.report_dependency_chain:
        if len(vuln.report_dependency_chain) == 1:
            return "direct"
        return "transitive"

    return None


def _report_dependency_root(vuln: Vulnerability) -> str | None:
    kind = _report_dependency_kind(vuln)
    if kind != "transitive" or not vuln.report_dependency_chain:
        return None
    return vuln.report_dependency_chain[0]


def _apply_proof_standard(result: VerdictResult, proof_standard: str) -> VerdictResult:
    if proof_standard != "strict":
        return result

    evidence = result.evidence
    if evidence is None:
        return result

    adjustment: str | None = None

    if result.verdict == Verdict.UNREACHABLE_STATIC:
        if (
            evidence.version_in_range is not False
            and not evidence.declared_direct_dependency
            and evidence.submodule_imported is not False
            and evidence.dependency_graph_source == "environment"
        ):
            adjustment = (
                "strict proof downgraded this suppression because the dependency graph "
                "came from the ambient environment rather than the report"
            )
    elif result.verdict == Verdict.UNREACHABLE_DYNAMIC:
        if evidence.coverage_completeness_pct is None:
            adjustment = (
                "strict proof downgraded this suppression because coverage completeness is unknown"
            )
        elif evidence.coverage_completeness_pct < STRICT_DYNAMIC_MIN_COVERAGE:
            adjustment = (
                "strict proof downgraded this suppression because coverage completeness "
                f"is below {STRICT_DYNAMIC_MIN_COVERAGE:.0f}%"
            )
        elif (
            evidence.dependency_kind == "transitive"
            and evidence.dependency_graph_source == "environment"
        ):
            adjustment = (
                "strict proof downgraded this suppression because the transitive dependency "
                "graph came from the ambient environment rather than the report"
            )

    if adjustment is None:
        return result

    return VerdictResult(
        vulnerability=result.vulnerability,
        verdict=Verdict.INCONCLUSIVE,
        reason=f"{result.reason}; {adjustment}",
        imported_as=result.imported_as,
        executed_files=list(result.executed_files),
        dependency_of=result.dependency_of,
        affected_component=result.affected_component,
        evidence=result.evidence,
        original_verdict=result.verdict,
        policy_adjustment=adjustment,
    )


def collect_evidence(
    vuln: Vulnerability,
    import_name: str,
    repo_imports: set[str],
    transitive_deps: dict[str, str],
    dependency_graph_available: bool,
    declared_direct_deps: set[str],
    covered_files: dict[str, list[int]] | None,
    component: AffectedComponent | None = None,
    intel: VulnIntelResolution | None = None,
    api_hits: list[ApiUsageHit] | None = None,
    coverage_completeness: float | None = None,
    threat_intel_data: object | None = None,
    production_observed: bool | None = None,
    production_trace_count: int = 0,
    global_warnings: tuple[str, ...] = (),
) -> Evidence:
    warnings: list[str] = list(global_warnings)

    version_result = check_version(vuln.package_version, vuln.affected_ranges)
    version_in_range = version_result.affected
    if version_result.error:
        warnings.append(version_result.error)

    vuln_name_key = canonicalize_name(vuln.package_name)
    report_dep_kind = _report_dependency_kind(vuln)
    report_dep_root = _report_dependency_root(vuln)
    direct = is_package_imported(vuln.package_name, repo_imports)
    declared_direct_dependency = (
        vuln_name_key in declared_direct_deps or report_dep_kind == "direct"
    )
    report_graph_available = report_dep_kind == "direct" or report_dep_root is not None
    dependency_graph_source = ""
    if not direct:
        if report_dep_root is not None:
            if is_package_imported(report_dep_root, repo_imports):
                dep_of = report_dep_root
            else:
                dep_of = None
            dependency_graph_source = "report"
        else:
            dep_of = transitive_deps.get(vuln_name_key)
            if dep_of is not None:
                dependency_graph_source = "environment"
    else:
        dep_of = None
    package_imported = direct or dep_of is not None

    if direct:
        dependency_kind = "direct"
    elif dep_of is not None:
        dependency_kind = "transitive"
    else:
        dependency_kind = None

    if not dependency_graph_source:
        if report_graph_available:
            dependency_graph_source = "report"
        elif dependency_graph_available:
            dependency_graph_source = "environment"

    if component is None:
        component = extract_affected_component(vuln)
    affected_component_source = component.extraction_source
    affected_component_confidence = _confidence_str_to_int(component.confidence)

    submodule_imported: bool | None = None
    has_submodule_info = component.submodule_paths and component.confidence in ("high", "medium")

    if has_submodule_info and package_imported:
        sub_imported, _matched = is_submodule_imported(component.submodule_paths, repo_imports)
        if sub_imported:
            submodule_imported = True
        else:
            has_dotted_imports = any(
                imp.lower().startswith(import_name.lower() + ".") for imp in repo_imports
            )
            if has_dotted_imports:
                submodule_imported = False
            else:
                submodule_imported = None

    coverage_seen: bool | None = None
    coverage_files: tuple[str, ...] = ()

    if covered_files is not None and package_imported:
        if has_submodule_info:
            executed, matching_files = is_submodule_executed(
                component.submodule_paths, component.file_hints, covered_files
            )
        else:
            executed, matching_files = is_package_executed(vuln.package_name, covered_files)
        coverage_seen = executed
        if matching_files:
            coverage_files = tuple(matching_files)
        else:
            coverage_files = ()

    if component.warnings:
        warnings.extend(component.warnings)

    api_targets_fqnames: tuple[str, ...] = ()
    api_usage_hits: tuple[ApiUsageHit, ...] = ()
    api_usage_seen: bool | None = None
    api_usage_confidence: int | None = None
    api_call_sites_covered: bool | None = None
    intel_rule_ids: tuple[str, ...] = ()

    if intel and intel.matched_rules:
        intel_rule_ids = tuple(intel.rule_ids)
        if intel.api_targets:
            api_targets_fqnames = tuple(t.fqname for t in intel.api_targets)

        if api_hits is not None:
            api_usage_hits = tuple(api_hits)
            call_hits = [h for h in api_hits if h.match_type != "symbol_reference"]
            api_usage_seen = len(call_hits) > 0
            if api_hits:
                api_usage_confidence = max(h.confidence for h in api_hits)

                if covered_files is not None:
                    call_sites = [(h.file_path, h.line) for h in api_hits]
                    sites_covered, _cov_count, _total = are_call_sites_covered(
                        call_sites, covered_files
                    )
                    api_call_sites_covered = sites_covered
        elif intel.api_targets:
            api_usage_seen = None

    return Evidence(
        version_in_range=version_in_range,
        dependency_kind=dependency_kind,
        dependency_graph_available=dependency_graph_available or report_graph_available,
        dependency_graph_source=dependency_graph_source,
        declared_direct_dependency=declared_direct_dependency,
        package_imported=package_imported,
        submodule_imported=submodule_imported,
        report_dependency_chain=vuln.report_dependency_chain,
        affected_component_source=affected_component_source,
        affected_component_confidence=affected_component_confidence,
        coverage_seen=coverage_seen,
        coverage_files=coverage_files,
        external_fetch_warnings=tuple(warnings),
        api_targets=api_targets_fqnames,
        api_usage_hits=api_usage_hits,
        api_usage_seen=api_usage_seen,
        api_usage_confidence=api_usage_confidence,
        api_call_sites_covered=api_call_sites_covered,
        intel_rule_ids=intel_rule_ids,
        coverage_completeness_pct=coverage_completeness,
        threat_intel=threat_intel_data,
        production_observed=production_observed,
        production_trace_count=production_trace_count,
    )


def _confidence_str_to_int(confidence: str) -> int:
    return {"high": 80, "medium": 55, "low": 25}.get(confidence, 10)


def derive_verdict(
    vuln: Vulnerability,
    evidence: Evidence,
    import_name: str,
    component,
    dep_of: str | None,
    has_coverage: bool,
) -> VerdictResult:
    if evidence.version_in_range is False:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_STATIC,
            reason=(
                f"'{vuln.package_name}' {vuln.package_version} is outside "
                f"the affected version range"
            ),
            imported_as=import_name,
            affected_component=component,
            evidence=evidence,
        )

    if not evidence.package_imported:
        if evidence.declared_direct_dependency:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_STATIC,
                reason=f"'{vuln.package_name}' is declared as a direct dependency but never imported",
                imported_as=import_name,
                affected_component=component,
                evidence=evidence,
            )

        if not evidence.dependency_graph_available:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=(
                    f"'{vuln.package_name}' is not directly imported, but no dependency graph "
                    f"is available to prove it is unused transitively"
                ),
                imported_as=import_name,
                affected_component=component,
                evidence=evidence,
            )

        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_STATIC,
            reason=(
                f"'{vuln.package_name}' is not imported and not a "
                f"dependency of any imported package"
            ),
            imported_as=import_name,
            affected_component=component,
            evidence=evidence,
        )

    if evidence.dependency_kind == "direct":
        trace = f"'{import_name}' is directly imported"
    else:
        trace = f"'{vuln.package_name}' is a dependency of {dep_of}"

    has_submodule_info = component.submodule_paths and component.confidence in ("high", "medium")

    if has_submodule_info:
        if evidence.submodule_imported is False:
            submod_list = ", ".join(component.submodule_paths)
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_STATIC,
                reason=f"{trace}, but affected submodule {submod_list} is not imported",
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if not has_coverage:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"{trace}, but no coverage data to confirm execution",
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if evidence.coverage_seen:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.REACHABLE,
                reason=(
                    f"{trace} and submodule code was executed "
                    f"in {len(evidence.coverage_files)} file(s)"
                ),
                imported_as=import_name,
                executed_files=list(evidence.coverage_files),
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )
        else:
            submod_list = ", ".join(component.submodule_paths)
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.UNREACHABLE_DYNAMIC,
                reason=(f"{trace}, {submod_list} imported but 0 files executed in tests"),
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

    if evidence.api_usage_seen is True:
        api_detail = f"{len(evidence.api_usage_hits)} vulnerable API call(s) found"

        if has_coverage and evidence.api_call_sites_covered is True:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.REACHABLE,
                reason=f"{trace}, {api_detail}, and call sites executed in tests",
                imported_as=import_name,
                executed_files=list(evidence.coverage_files),
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if has_coverage and evidence.api_call_sites_covered is False:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.INCONCLUSIVE,
                reason=f"{trace}, {api_detail}, but call sites not executed in tests",
                imported_as=import_name,
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        if has_coverage and evidence.coverage_seen:
            return VerdictResult(
                vulnerability=vuln,
                verdict=Verdict.REACHABLE,
                reason=f"{trace}, {api_detail}, and code executed in {len(evidence.coverage_files)} file(s)",
                imported_as=import_name,
                executed_files=list(evidence.coverage_files),
                dependency_of=dep_of,
                affected_component=component,
                evidence=evidence,
            )

        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.REACHABLE,
            reason=f"{trace} and {api_detail}",
            imported_as=import_name,
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )

    if not has_coverage:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.INCONCLUSIVE,
            reason=f"{trace}, but no coverage data to confirm execution",
            imported_as=import_name,
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )

    if evidence.coverage_seen:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.REACHABLE,
            reason=(f"{trace} and code was executed in {len(evidence.coverage_files)} file(s)"),
            imported_as=import_name,
            executed_files=list(evidence.coverage_files),
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )
    else:
        return VerdictResult(
            vulnerability=vuln,
            verdict=Verdict.UNREACHABLE_DYNAMIC,
            reason=f"{trace}, but no code was executed in tests",
            imported_as=import_name,
            dependency_of=dep_of,
            affected_component=component,
            evidence=evidence,
        )


def analyze(
    vulnerabilities: list[Vulnerability],
    repo_path: Path,
    coverage_path: Path | None = None,
    proof_standard: str = "strict",
    scan_capabilities: bool = False,
    trace_exploit_paths: bool = False,
    threat_intel: bool = False,
    otel_traces_path: Path | None = None,
) -> Report:
    repo_imports = collect_imports_from_repo(repo_path)
    declared_direct_deps = discover_declared_dependencies(repo_path)
    transitive_deps, dependency_graph_available = resolve_transitive_deps(repo_imports)
    analysis_warnings: list[str] = []

    covered_files: dict[str, list[int]] | None = None
    coverage_completeness: float | None = None
    if coverage_path:
        coverage_data = load_coverage(coverage_path)
        covered_files = get_covered_files(coverage_data)
        coverage_completeness = get_coverage_completeness(coverage_data)

    vuln_intel: dict[str, VulnIntelResolution] = {}
    all_api_targets = []
    seen_fqnames: set[str] = set()

    for vuln in vulnerabilities:
        intel = resolve_vuln_intel(vuln)
        vuln_intel[vuln.id] = intel
        for t in intel.api_targets:
            if t.fqname not in seen_fqnames:
                seen_fqnames.add(t.fqname)
                all_api_targets.append(t)

    hits_by_target: dict[str, list[ApiUsageHit]] = {}
    if all_api_targets:
        all_hits = find_api_usage(repo_path, all_api_targets)
        for hit in all_hits:
            hits_by_target.setdefault(hit.matched_target, []).append(hit)

    threat_intel_data: dict[str, object] = {}
    if threat_intel:
        try:
            from ca9.threat_intel import fetch_threat_intel_batch

            cve_ids = [v.id for v in vulnerabilities if v.id.startswith("CVE-")]
            threat_intel_data = fetch_threat_intel_batch(cve_ids)
        except Exception as exc:
            analysis_warnings.append(f"threat intelligence enrichment unavailable: {exc}")

    otel_modules: dict[str, int] | None = None
    if otel_traces_path:
        try:
            from ca9.analysis.otel_reader import load_otel_traces

            otel_modules = load_otel_traces(otel_traces_path)
        except Exception as exc:
            analysis_warnings.append(f"production trace ingestion unavailable: {exc}")

    results: list[VerdictResult] = []

    for vuln in vulnerabilities:
        import_name = pypi_to_import_name(vuln.package_name)
        component = extract_affected_component(vuln)

        intel = vuln_intel.get(vuln.id)

        vuln_api_hits: list[ApiUsageHit] | None = None
        if intel and intel.api_targets:
            vuln_api_hits = []
            for t in intel.api_targets:
                vuln_api_hits.extend(hits_by_target.get(t.fqname, []))

        ti_data = threat_intel_data.get(vuln.id) if threat_intel_data else None

        prod_observed: bool | None = None
        prod_count = 0
        if otel_modules is not None:
            import_lower = import_name.lower()
            for mod, count in otel_modules.items():
                if mod.lower() == import_lower or mod.lower().startswith(import_lower + "."):
                    prod_observed = True
                    prod_count += count
            if prod_observed is None:
                prod_observed = False

        evidence = collect_evidence(
            vuln,
            import_name,
            repo_imports,
            transitive_deps,
            dependency_graph_available,
            declared_direct_deps,
            covered_files,
            component,
            intel=intel,
            api_hits=vuln_api_hits,
            coverage_completeness=coverage_completeness,
            threat_intel_data=ti_data,
            production_observed=prod_observed,
            production_trace_count=prod_count,
            global_warnings=tuple(analysis_warnings),
        )

        if evidence.dependency_kind == "transitive":
            dep_of = _report_dependency_root(vuln)
            if dep_of is None:
                dep_of = transitive_deps.get(canonicalize_name(vuln.package_name))
        else:
            dep_of = None

        result = derive_verdict(
            vuln,
            evidence,
            import_name,
            component,
            dep_of,
            has_coverage=covered_files is not None,
        )
        result = _apply_proof_standard(result, proof_standard)

        if ti_data is not None:
            result.threat_intel = ti_data

        result.confidence_score = compute_confidence(evidence, result.verdict)
        results.append(result)

    if scan_capabilities:
        warning = _attach_blast_radius(results, repo_path)
        if warning:
            analysis_warnings.append(warning)

    if trace_exploit_paths:
        try:
            from ca9.analysis.exploit_path import build_and_trace

            build_and_trace(repo_path, results)
            for r in results:
                if r.exploit_paths:
                    r.confidence_score = compute_confidence(r.evidence, r.verdict, result=r)
        except Exception as exc:
            warning = f"exploit path tracing unavailable: {exc}"
            analysis_warnings.append(warning)
            print(f"ca9: {warning}", file=sys.stderr)

    if coverage_path:
        coverage_path_str = str(coverage_path)
    else:
        coverage_path_str = None

    return Report(
        results=results,
        repo_path=str(repo_path),
        coverage_path=coverage_path_str,
        proof_standard=proof_standard,
        warnings=analysis_warnings,
    )


def _attach_blast_radius(results: list[VerdictResult], repo_path: Path) -> str | None:
    from ca9.capabilities.models import BlastRadius, CapabilityHit
    from ca9.capabilities.risk import assess_blast_radius_risk
    from ca9.capabilities.scanner import scan_capabilities as _scan_caps

    try:
        cap_hits = _scan_caps(repo_path)
    except Exception as exc:
        warning = f"capability scan unavailable: {exc}"
        print(f"ca9: {warning}", file=sys.stderr)
        return warning
    if not cap_hits:
        return None

    hits_by_file: dict[str, list[CapabilityHit]] = {}
    global_hits: list[CapabilityHit] = []

    for hit in cap_hits:
        if hit.name in ("exec.shell", "db.read", "db.write") or hit.asset_ref.startswith(
            "mcp_server:"
        ):
            global_hits.append(hit)
        if hit.source_file:
            hits_by_file.setdefault(hit.source_file, []).append(hit)

    for result in results:
        if result.verdict != Verdict.REACHABLE:
            continue

        matched: list[CapabilityHit] = list(global_hits)

        for exec_file in result.executed_files:
            normalized = _normalize_path_for_match(exec_file)
            for file_key, file_hits in hits_by_file.items():
                normalized_key = _normalize_path_for_match(file_key)
                if _paths_match(normalized, normalized_key):
                    matched.extend(file_hits)

        seen: set[tuple[str, str]] = set()
        unique: list[CapabilityHit] = []
        for hit in matched:
            key = (hit.name, hit.scope)
            if key not in seen:
                seen.add(key)
                unique.append(hit)

        if unique:
            risk = assess_blast_radius_risk(unique)
            result.blast_radius = BlastRadius(
                capabilities=tuple(sorted({h.name for h in unique})),
                details=tuple(unique),
                risk_level=risk.level,
                risk_reasons=tuple(risk.reasons),
            )
    return None


def _normalize_path_for_match(path: str) -> str:
    path = path.replace("\\", "/")
    if path.startswith("./"):
        path = path[2:]
    return path


def _paths_match(exec_path: str, cap_path: str) -> bool:
    if exec_path == cap_path:
        return True

    if len(exec_path) > len(cap_path):
        longer, shorter = exec_path, cap_path
    else:
        longer, shorter = cap_path, exec_path

    if longer.endswith(shorter):
        pos = len(longer) - len(shorter)
        if pos == 0 or longer[pos - 1] == "/":
            return True

    return False
