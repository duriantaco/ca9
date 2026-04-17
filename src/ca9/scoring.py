from __future__ import annotations

from ca9.models import Evidence, Verdict, VerdictResult


def _coverage_trust(ev: Evidence) -> float:
    if ev.coverage_completeness_pct is None:
        return 0.5
    pct = ev.coverage_completeness_pct
    if pct >= 80:
        return 1.0  # high trust
    if pct >= 50:
        return 0.7
    if pct >= 30:
        return 0.4  # low trust
    return 0.2


def _api_usage_boost(ev: Evidence) -> int:
    if ev.api_usage_seen is True:
        if ev.api_usage_confidence and ev.api_usage_confidence >= 70:
            base = 15
        else:
            base = 10
        if ev.api_call_sites_covered is True:
            base += 5
        elif ev.api_call_sites_covered is False:
            base -= 8
        return base
    if ev.api_usage_seen is False and ev.api_targets:
        return -5
    return 0


def _intel_rule_boost(ev: Evidence) -> int:
    if ev.intel_rule_ids:
        return 3
    return 0


def _threat_intel_boost(ev: Evidence) -> int:
    ti = ev.threat_intel
    if ti is None:
        return 0
    boost = 0
    has_high_epss = ti.epss_score is not None and ti.epss_score >= 0.5
    if has_high_epss and ti.in_kev:
        boost = 15
    elif has_high_epss or ti.in_kev:
        boost = 10
    return boost


def _production_boost(ev: Evidence) -> int:
    if ev.production_observed is True:
        return 20
    return 0


def _score_reachable(ev: Evidence) -> int:
    score = 60

    if ev.version_in_range is True:
        score += 10
    elif ev.version_in_range is None:
        pass
    else:
        score -= 15

    if ev.package_imported:
        score += 10
    else:
        score -= 20

    if ev.dependency_kind == "direct":
        score += 5

    if ev.coverage_seen is True:
        score += 15
    elif ev.coverage_seen is False:
        score -= int(15 * _coverage_trust(ev))
    elif ev.coverage_seen is None:
        score -= 5

    if ev.submodule_imported is True:
        score += 5
    elif ev.submodule_imported is None and ev.package_imported:
        pass

    if ev.affected_component_confidence >= 75:
        score += 5
    elif ev.affected_component_confidence < 25:
        score -= 3

    score += _api_usage_boost(ev)
    score += _intel_rule_boost(ev)
    score += _threat_intel_boost(ev)
    score += _production_boost(ev)

    if ev.external_fetch_warnings:
        score -= 3 * min(len(ev.external_fetch_warnings), 3)

    return score


def _score_unreachable_static(ev: Evidence) -> int:
    score = 60

    if not ev.package_imported:
        score += 25
    else:
        score -= 10

    if ev.version_in_range is False:
        score += 20
    elif ev.version_in_range is True:
        score += 5
    elif ev.version_in_range is None:
        pass

    if ev.submodule_imported is False:
        score += 10
    elif ev.submodule_imported is True:
        score -= 10

    if ev.affected_component_confidence >= 75:
        score += 5
    elif ev.affected_component_confidence < 25:
        score -= 3

    if ev.api_usage_seen is False and ev.api_targets:
        score += 8
    elif ev.api_usage_seen is True:
        score -= 10
    score += _intel_rule_boost(ev)

    if ev.external_fetch_warnings:
        score -= 3 * min(len(ev.external_fetch_warnings), 3)

    return score


def _score_unreachable_dynamic(ev: Evidence) -> int:
    score = 60

    if ev.coverage_seen is False:
        score += int(15 * _coverage_trust(ev))
    elif ev.coverage_seen is True:
        score -= 20

    if ev.package_imported:
        score += 5

    if ev.submodule_imported is True:
        score += 5
    elif ev.submodule_imported is False:
        score += 10

    if ev.affected_component_confidence >= 75:
        score += 10
    elif ev.affected_component_confidence >= 40:
        score += 5
    elif ev.affected_component_confidence < 25:
        score -= 5

    if ev.dependency_kind == "direct":
        score += 3
    elif ev.dependency_kind == "transitive":
        score -= 3

    if ev.api_usage_seen is False and ev.api_targets:
        score += 8
    elif ev.api_usage_seen is True:
        score -= 10
    score += _intel_rule_boost(ev)

    if ev.external_fetch_warnings:
        score -= 3 * min(len(ev.external_fetch_warnings), 3)

    return score


def _score_inconclusive(ev: Evidence) -> int:
    score = 40

    if ev.package_imported:
        score += 5

    if ev.affected_component_confidence >= 75:
        score += 10
    elif ev.affected_component_confidence >= 40:
        score += 5

    if ev.dependency_kind == "direct":
        score += 5
    elif ev.dependency_kind == "transitive":
        score -= 5

    if ev.api_usage_seen is True:
        score += 10
        if ev.api_call_sites_covered is False:
            score += 3
    elif ev.api_usage_seen is False and ev.api_targets:
        score += 5
    score += _intel_rule_boost(ev)

    if ev.external_fetch_warnings:
        score -= 3 * min(len(ev.external_fetch_warnings), 3)

    return score


def compute_confidence(
    evidence: Evidence,
    verdict: Verdict,
    result: VerdictResult | None = None,
) -> int:
    if verdict == Verdict.REACHABLE:
        raw = _score_reachable(evidence)
    elif verdict == Verdict.UNREACHABLE_STATIC:
        raw = _score_unreachable_static(evidence)
    elif verdict == Verdict.UNREACHABLE_DYNAMIC:
        raw = _score_unreachable_dynamic(evidence)
    else:
        raw = _score_inconclusive(evidence)

    if result is not None and verdict == Verdict.REACHABLE and result.exploit_paths:
        raw += 10

    return max(0, min(100, raw))


def confidence_bucket(score: int) -> str:
    if score >= 80:
        return "high"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "low"
    return "weak"
