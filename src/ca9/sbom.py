from __future__ import annotations

from pathlib import Path

from ca9.models import Verdict


def detect_sbom_format(data: dict) -> str:
    if "bomFormat" in data:
        return "cyclonedx"
    if "spdxVersion" in data:
        return "spdx"
    raise ValueError("Unknown SBOM format: expected CycloneDX (bomFormat) or SPDX (spdxVersion)")


def _extract_cyclonedx_components(data: dict) -> list[dict]:
    components = []
    for comp in data.get("components", []):
        purl = comp.get("purl", "")
        if purl.startswith("pkg:pypi/") or not purl and comp.get("type") == "library":
            components.append(comp)
    return components


def _extract_spdx_packages(data: dict) -> list[dict]:
    packages = []
    for pkg in data.get("packages", []):
        for ref in pkg.get("externalRefs", []):
            ref_loc = ref.get("referenceLocator", "")
            if ref_loc.startswith("pkg:pypi/"):
                packages.append(pkg)
                break
        else:
            if pkg.get("name"):
                packages.append(pkg)
    return packages


def _parse_purl(purl: str) -> tuple[str, str]:
    if not purl.startswith("pkg:pypi/"):
        return "", ""
    rest = purl[len("pkg:pypi/") :]
    if "?" in rest:
        rest = rest.split("?")[0]
    if "#" in rest:
        rest = rest.split("#")[0]
    if "@" in rest:
        name, version = rest.split("@", 1)
        return name, version
    return rest, ""


def _get_component_name_version(comp: dict, fmt: str) -> tuple[str, str]:
    if fmt == "cyclonedx":
        purl = comp.get("purl", "")
        if purl:
            return _parse_purl(purl)
        return comp.get("name", ""), comp.get("version", "")
    else:
        for ref in comp.get("externalRefs", []):
            loc = ref.get("referenceLocator", "")
            if loc.startswith("pkg:pypi/"):
                return _parse_purl(loc)
        return comp.get("name", ""), comp.get("versionInfo", "")


def _annotate_warning(data: dict, fmt: str, message: str) -> dict:
    if fmt == "cyclonedx":
        enriched = dict(data)
        metadata = enriched.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        else:
            metadata = dict(metadata)

        properties = metadata.get("properties", [])
        if not isinstance(properties, list):
            properties = []
        else:
            properties = list(properties)

        properties.append({"name": "ca9:warning", "value": message})
        metadata["properties"] = properties
        enriched["metadata"] = metadata
        return enriched

    enriched = dict(data)
    annotations = enriched.get("annotations", [])
    if not isinstance(annotations, list):
        annotations = []
    else:
        annotations = list(annotations)

    annotations.append(
        {
            "annotationType": "REVIEW",
            "annotator": "Tool: ca9",
            "comment": f"ca9:warning={message}",
        }
    )
    enriched["annotations"] = annotations
    return enriched


def enrich_sbom(
    sbom_data: dict,
    repo_path: Path,
    coverage_path: Path | None = None,
) -> dict:
    from ca9.engine import analyze
    from ca9.scanner import query_osv_batch

    fmt = detect_sbom_format(sbom_data)

    if fmt == "cyclonedx":
        components = _extract_cyclonedx_components(sbom_data)
    else:
        components = _extract_spdx_packages(sbom_data)

    pkg_list: list[tuple[str, str]] = []
    for comp in components:
        name, version = _get_component_name_version(comp, fmt)
        if name and version:
            pkg_list.append((name, version))

    if not pkg_list:
        return sbom_data

    try:
        vulnerabilities = query_osv_batch(pkg_list)
    except (ConnectionError, ValueError) as exc:
        return _annotate_warning(sbom_data, fmt, f"OSV enrichment failed: {exc}")

    if vulnerabilities:
        report = analyze(vulnerabilities, repo_path, coverage_path, proof_standard="balanced")
        verdicts_by_pkg: dict[str, list] = {}
        for r in report.results:
            key = r.vulnerability.package_name.lower()
            verdicts_by_pkg.setdefault(key, []).append(r)
    else:
        verdicts_by_pkg = {}

    if fmt == "cyclonedx":
        return _enrich_cyclonedx(sbom_data, verdicts_by_pkg)
    else:
        return _enrich_spdx(sbom_data, verdicts_by_pkg)


def _enrich_cyclonedx(data: dict, verdicts_by_pkg: dict) -> dict:
    enriched = dict(data)
    enriched_components = []

    for comp in enriched.get("components", []):
        comp = dict(comp)
        purl = comp.get("purl", "")
        name, version = _parse_purl(purl) if purl else (comp.get("name", ""), "")
        name_lower = name.lower()

        results = verdicts_by_pkg.get(name_lower, [])
        if results:
            props = comp.get("properties", [])
            if not isinstance(props, list):
                props = []

            verdicts = [r.verdict for r in results]
            worst = _worst_verdict(verdicts)
            max_conf = max(r.confidence_score for r in results) if results else 0
            path_count = sum(len(r.exploit_paths) for r in results)

            props.append({"name": "ca9:reachability_verdict", "value": worst.value})
            props.append({"name": "ca9:confidence_score", "value": str(max_conf)})
            props.append({"name": "ca9:exploit_path_count", "value": str(path_count)})
            props.append({"name": "ca9:vuln_count", "value": str(len(results))})

            comp["properties"] = props

        enriched_components.append(comp)

    enriched["components"] = enriched_components
    return enriched


def _enrich_spdx(data: dict, verdicts_by_pkg: dict) -> dict:
    enriched = dict(data)
    enriched_packages = []

    for pkg in enriched.get("packages", []):
        pkg = dict(pkg)
        name = pkg.get("name", "").lower()

        results = verdicts_by_pkg.get(name, [])
        if results:
            annotations = pkg.get("annotations", [])
            if not isinstance(annotations, list):
                annotations = []

            verdicts = [r.verdict for r in results]
            worst = _worst_verdict(verdicts)
            max_conf = max(r.confidence_score for r in results) if results else 0
            path_count = sum(len(r.exploit_paths) for r in results)

            annotations.append(
                {
                    "annotationType": "REVIEW",
                    "annotator": "Tool: ca9",
                    "comment": (
                        f"ca9:reachability_verdict={worst.value}, "
                        f"ca9:confidence_score={max_conf}, "
                        f"ca9:exploit_path_count={path_count}, "
                        f"ca9:vuln_count={len(results)}"
                    ),
                }
            )

            pkg["annotations"] = annotations

        enriched_packages.append(pkg)

    enriched["packages"] = enriched_packages
    return enriched


_VERDICT_SEVERITY = {
    Verdict.REACHABLE: 0,
    Verdict.INCONCLUSIVE: 1,
    Verdict.UNREACHABLE_DYNAMIC: 2,
    Verdict.UNREACHABLE_STATIC: 3,
}


def _worst_verdict(verdicts: list[Verdict]) -> Verdict:
    if not verdicts:
        return Verdict.INCONCLUSIVE
    return min(verdicts, key=lambda v: _VERDICT_SEVERITY.get(v, 4))
