from __future__ import annotations

import json
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from ca9.advisory import advisory_ids_for_matching, normalize_advisory_id
from ca9.models import ApiTarget, Vulnerability


@dataclass(frozen=True)
class VulnIntelRule:
    id: str
    package: str
    advisory_ids: frozenset[str] = frozenset()
    version_specifiers: tuple[SpecifierSet, ...] = ()
    affected_modules: tuple[str, ...] = ()
    api_targets: tuple[ApiTarget, ...] = ()
    confidence_prior: int = 75
    notes: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    keywords: tuple[str, ...] = ()


@dataclass
class VulnIntelResolution:
    matched_rules: list[VulnIntelRule] = field(default_factory=list)
    affected_modules: list[str] = field(default_factory=list)
    api_targets: list[ApiTarget] = field(default_factory=list)
    confidence_prior: int = 0
    rule_ids: list[str] = field(default_factory=list)
    source: str = ""


def _parse_version_specifiers(ranges: list[str]) -> tuple[SpecifierSet, ...]:
    specs = []
    for r in ranges:
        try:
            specs.append(SpecifierSet(r))
        except InvalidSpecifier:
            continue
    return tuple(specs)


def _parse_api_targets(
    raw_targets: list[dict], package: str, rule_id: str
) -> tuple[ApiTarget, ...]:
    targets = []
    for t in raw_targets:
        fqname = t.get("fqname", "")
        if not fqname:
            continue

        parts = fqname.rsplit(".", 1)
        if len(parts) > 1:
            module = parts[0]
        else:
            module = None

        if len(parts) > 1:
            symbol = parts[1]
        else:
            symbol = fqname

        targets.append(
            ApiTarget(
                package=package,
                fqname=fqname,
                kind=t.get("kind", "function"),
                module=module,
                symbol=symbol,
                aliases=tuple(t.get("aliases", [])),
                notes=tuple(t.get("notes", [])),
                rule_id=rule_id,
            )
        )
    return tuple(targets)


def load_rule_from_dict(data: dict) -> list[VulnIntelRule]:
    package = data.get("package", "").lower()
    if not package:
        return []

    rules = []
    for raw in data.get("rules", []):
        rule_id = raw.get("id", "")
        if not rule_id:
            continue

        advisory_ids = frozenset(
            value
            for value in (normalize_advisory_id(v) for v in raw.get("advisory_ids", []))
            if value
        )
        applies_to = raw.get("applies_to", {})
        version_ranges = applies_to.get("version_ranges", [])
        version_specifiers = _parse_version_specifiers(version_ranges)

        affected_modules = tuple(raw.get("affected_modules", []))
        api_targets = _parse_api_targets(raw.get("api_targets", []), package, rule_id)
        confidence_prior = raw.get("confidence_prior", 75)

        signals = raw.get("signals", {})
        keywords = tuple(signals.get("keywords", []))

        rules.append(
            VulnIntelRule(
                id=rule_id,
                package=package,
                advisory_ids=advisory_ids,
                version_specifiers=version_specifiers,
                affected_modules=affected_modules,
                api_targets=api_targets,
                confidence_prior=confidence_prior,
                notes=tuple(raw.get("notes", [])),
                references=tuple(raw.get("references", [])),
                keywords=keywords,
            )
        )
    return rules


class RuleFileError(ValueError):
    """A rule file could not be read or parsed."""


def _parse_rule_data(path: Path, data: object) -> list[VulnIntelRule]:
    if not isinstance(data, dict):
        raise RuleFileError(f"{path}: rule file must contain a mapping at the top level")
    return load_rule_from_dict(data)


def load_rules_from_json(path: Path) -> list[VulnIntelRule]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleFileError(f"{path}: cannot read rule file: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RuleFileError(f"{path}: invalid JSON rule file: {exc}") from exc
    return _parse_rule_data(path, data)


def load_rules_from_file(path: Path) -> list[VulnIntelRule]:
    """Load a rule file, raising RuleFileError instead of returning no rules."""
    if path.suffix.lower() == ".json":
        return load_rules_from_json(path)

    try:
        import yaml
    except ImportError:
        raise RuleFileError(
            f"{path}: YAML rule files require PyYAML (pip install pyyaml), "
            "or convert the file to JSON"
        ) from None

    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise RuleFileError(f"{path}: cannot read rule file: {exc}") from exc
    except yaml.YAMLError as exc:
        raise RuleFileError(f"{path}: invalid YAML rule file: {exc}") from exc
    return _parse_rule_data(path, data)


def load_rules_from_yaml(path: Path) -> list[VulnIntelRule]:
    """Load a user-supplied YAML rule file; failures warn rather than vanish."""
    try:
        return load_rules_from_file(path)
    except RuleFileError as exc:
        warnings.warn(f"ca9: ignoring rule file: {exc}", RuntimeWarning, stacklevel=2)
        return []


_BUILTIN_RULES: list[VulnIntelRule] = []
_RULES_BY_PACKAGE: dict[str, list[VulnIntelRule]] = {}
_RULES_LOADED = False


def _ensure_rules_loaded() -> None:
    global _RULES_LOADED
    if _RULES_LOADED:
        return
    _RULES_LOADED = True
    _load_builtin_rules()


def _load_builtin_rules() -> None:
    # Built-in rules are JSON so they load with the stdlib alone; PyYAML is
    # not a runtime dependency.
    rules_dir = Path(__file__).parent / "rules"
    paths = sorted(rules_dir.glob("*.json")) if rules_dir.is_dir() else []
    if not paths:
        warnings.warn(
            f"ca9: built-in vulnerable-API rules are missing from {rules_dir}",
            RuntimeWarning,
            stacklevel=2,
        )

    for path in paths:
        try:
            rules = load_rules_from_json(path)
        except RuleFileError as exc:
            warnings.warn(f"ca9: built-in rule file skipped: {exc}", RuntimeWarning, stacklevel=2)
            continue
        _BUILTIN_RULES.extend(rules)
        for rule in rules:
            _RULES_BY_PACKAGE.setdefault(rule.package, []).append(rule)


def resolve_vuln_intel(vuln: Vulnerability) -> VulnIntelResolution:
    _ensure_rules_loaded()

    pkg = vuln.package_name.lower()
    candidates = _RULES_BY_PACKAGE.get(pkg, [])
    if not candidates:
        return VulnIntelResolution()

    matched: list[VulnIntelRule] = []
    vuln_advisory_ids = advisory_ids_for_matching(vuln)

    for rule in candidates:
        if rule.advisory_ids and vuln_advisory_ids.intersection(rule.advisory_ids):
            matched.append(rule)
            continue

        if rule.version_specifiers:
            version_ok = any(vuln.package_version in spec for spec in rule.version_specifiers)
            if not version_ok:
                continue

        if rule.keywords:
            text = f"{vuln.title} {vuln.description}".lower()
            if any(kw.lower() in text for kw in rule.keywords):
                matched.append(rule)

    if not matched:
        return VulnIntelResolution()

    all_modules: list[str] = []
    all_targets: list[ApiTarget] = []
    all_rule_ids: list[str] = []
    max_prior = 0

    seen_modules: set[str] = set()
    seen_fqnames: set[str] = set()

    for rule in matched:
        all_rule_ids.append(rule.id)
        if rule.confidence_prior > max_prior:
            max_prior = rule.confidence_prior

        for mod in rule.affected_modules:
            if mod not in seen_modules:
                seen_modules.add(mod)
                all_modules.append(mod)

        for target in rule.api_targets:
            if target.fqname not in seen_fqnames:
                seen_fqnames.add(target.fqname)
                all_targets.append(target)

    return VulnIntelResolution(
        matched_rules=matched,
        affected_modules=all_modules,
        api_targets=all_targets,
        confidence_prior=max_prior,
        rule_ids=all_rule_ids,
        source="rulepack",
    )
