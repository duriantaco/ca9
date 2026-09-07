from __future__ import annotations

from dataclasses import replace

import pytest

from ca9.models import Evidence, Verdict
from ca9.scoring import compute_confidence, confidence_bucket


class TestComputeConfidence:
    def test_strong_reachable_high_confidence(self):
        evidence = Evidence(
            version_in_range=True,
            dependency_kind="direct",
            package_imported=True,
            submodule_imported=True,
            affected_component_confidence=85,
            coverage_seen=True,
            coverage_files=("file1.py",),
        )
        score = compute_confidence(evidence, Verdict.REACHABLE)
        assert score >= 85

    def test_reachable_fallback_matcher_still_high_with_runtime(self):
        evidence = Evidence(
            version_in_range=True,
            dependency_kind="direct",
            package_imported=True,
            coverage_seen=True,
            coverage_files=("api.py", "sessions.py"),
            affected_component_confidence=25,
        )
        score = compute_confidence(evidence, Verdict.REACHABLE)
        assert score >= 80

    def test_reachable_no_coverage_lower(self):
        evidence = Evidence(
            version_in_range=True,
            dependency_kind="direct",
            package_imported=True,
            coverage_seen=None,
            affected_component_confidence=50,
        )
        score = compute_confidence(evidence, Verdict.REACHABLE)
        assert 55 <= score <= 80

    def test_strong_unreachable_static_not_imported(self):
        evidence = Evidence(
            version_in_range=True,
            package_imported=False,
            affected_component_confidence=80,
        )
        score = compute_confidence(evidence, Verdict.UNREACHABLE_STATIC)
        assert score >= 85

    def test_unreachable_static_version_out_of_range(self):
        evidence = Evidence(
            version_in_range=False,
            package_imported=False,
            affected_component_confidence=80,
        )
        score = compute_confidence(evidence, Verdict.UNREACHABLE_STATIC)
        assert score >= 90

    def test_unreachable_dynamic_with_coverage(self):
        evidence = Evidence(
            version_in_range=True,
            dependency_kind="direct",
            package_imported=True,
            submodule_imported=True,
            affected_component_confidence=80,
            coverage_seen=False,
            coverage_scope="reported",
        )
        score = compute_confidence(evidence, Verdict.UNREACHABLE_DYNAMIC)
        assert score >= 85

    def test_unreachable_dynamic_fallback_matcher_lower(self):
        evidence = Evidence(
            package_imported=True,
            coverage_seen=False,
            affected_component_confidence=10,
        )
        score = compute_confidence(evidence, Verdict.UNREACHABLE_DYNAMIC)
        assert 60 <= score <= 80

    def test_inconclusive_moderate(self):
        evidence = Evidence(
            version_in_range=True,
            dependency_kind="direct",
            package_imported=True,
            affected_component_confidence=50,
            coverage_seen=None,
        )
        score = compute_confidence(evidence, Verdict.INCONCLUSIVE)
        assert 40 <= score < 70

    def test_warnings_degrade_confidence(self):
        base = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            coverage_seen=True,
        )
        with_warnings = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            coverage_seen=True,
            external_fetch_warnings=("warn1", "warn2"),
        )
        assert compute_confidence(with_warnings, Verdict.REACHABLE) < compute_confidence(
            base, Verdict.REACHABLE
        )

    def test_score_clamped_0_100(self):
        worst = Evidence(
            external_fetch_warnings=("w1", "w2", "w3", "w4", "w5"),
            package_imported=True,
            dependency_kind="transitive",
            coverage_seen=None,
            affected_component_confidence=5,
        )
        score = compute_confidence(worst, Verdict.INCONCLUSIVE)
        assert 0 <= score <= 100

    def test_verdict_matters_for_same_evidence(self):
        evidence = Evidence(
            version_in_range=False,
            package_imported=False,
        )
        unreachable = compute_confidence(evidence, Verdict.UNREACHABLE_STATIC)
        reachable = compute_confidence(evidence, Verdict.REACHABLE)
        assert unreachable > reachable

    def test_imported_boosts_reachable_not_unreachable(self):
        evidence = Evidence(
            package_imported=True,
            dependency_kind="direct",
            version_in_range=True,
            coverage_seen=True,
        )
        reachable = compute_confidence(evidence, Verdict.REACHABLE)
        unreachable = compute_confidence(evidence, Verdict.UNREACHABLE_STATIC)
        assert reachable > unreachable

    def test_not_imported_boosts_unreachable_not_reachable(self):
        evidence = Evidence(
            package_imported=False,
        )
        unreachable = compute_confidence(evidence, Verdict.UNREACHABLE_STATIC)
        reachable = compute_confidence(evidence, Verdict.REACHABLE)
        assert unreachable > reachable

    def test_coverage_seen_boosts_reachable(self):
        with_coverage = Evidence(
            package_imported=True,
            coverage_seen=True,
        )
        without_coverage = Evidence(
            package_imported=True,
            coverage_seen=False,
        )
        assert compute_confidence(with_coverage, Verdict.REACHABLE) > compute_confidence(
            without_coverage, Verdict.REACHABLE
        )

    def test_coverage_not_seen_boosts_unreachable_dynamic(self):
        with_coverage = Evidence(
            package_imported=True,
            coverage_seen=True,
        )
        without_coverage = Evidence(
            package_imported=True,
            coverage_seen=False,
            coverage_scope="reported",
        )
        assert compute_confidence(
            without_coverage, Verdict.UNREACHABLE_DYNAMIC
        ) > compute_confidence(with_coverage, Verdict.UNREACHABLE_DYNAMIC)


class TestApiUsageScoring:
    def test_api_usage_boosts_reachable(self):
        base = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            coverage_seen=None,
            affected_component_confidence=50,
        )
        with_api = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            coverage_seen=None,
            affected_component_confidence=50,
            api_usage_seen=True,
            api_usage_confidence=80,
            api_targets=("requests.get",),
            intel_rule_ids=("CA9-TEST-001",),
        )
        assert compute_confidence(with_api, Verdict.REACHABLE) > compute_confidence(
            base, Verdict.REACHABLE
        )

    def test_no_api_usage_penalizes_reachable(self):
        base = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            affected_component_confidence=80,
        )
        no_api = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            affected_component_confidence=80,
            api_usage_seen=False,
            api_targets=("requests.get",),
        )
        assert compute_confidence(no_api, Verdict.REACHABLE) < compute_confidence(
            base, Verdict.REACHABLE
        )

    def test_no_api_usage_boosts_unreachable_static(self):
        base = Evidence(
            package_imported=False,
            affected_component_confidence=80,
        )
        no_api = Evidence(
            package_imported=False,
            affected_component_confidence=80,
            api_usage_seen=False,
            api_targets=("requests.get",),
        )
        assert compute_confidence(no_api, Verdict.UNREACHABLE_STATIC) > compute_confidence(
            base, Verdict.UNREACHABLE_STATIC
        )

    def test_api_usage_contradicts_unreachable(self):
        unreachable_with_api = Evidence(
            package_imported=False,
            affected_component_confidence=80,
            api_usage_seen=True,
            api_targets=("requests.get",),
        )
        unreachable_no_api = Evidence(
            package_imported=False,
            affected_component_confidence=80,
        )
        assert compute_confidence(
            unreachable_with_api, Verdict.UNREACHABLE_STATIC
        ) < compute_confidence(unreachable_no_api, Verdict.UNREACHABLE_STATIC)

    def test_intel_rules_give_small_boost(self):
        base = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
        )
        with_rules = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            intel_rule_ids=("CA9-TEST-001",),
        )
        assert compute_confidence(with_rules, Verdict.REACHABLE) > compute_confidence(
            base, Verdict.REACHABLE
        )


class TestCallSiteCoverageScoring:
    def test_call_sites_covered_boosts_reachable(self):
        base = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_targets=("requests.get",),
        )
        with_sites = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_targets=("requests.get",),
            api_call_sites_covered=True,
        )
        assert compute_confidence(with_sites, Verdict.REACHABLE) > compute_confidence(
            base, Verdict.REACHABLE
        )

    def test_call_sites_not_covered_lowers_reachable(self):
        with_sites = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_targets=("requests.get",),
            api_call_sites_covered=True,
        )
        without_sites = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            api_usage_seen=True,
            api_usage_confidence=80,
            api_targets=("requests.get",),
            api_call_sites_covered=False,
        )
        assert compute_confidence(with_sites, Verdict.REACHABLE) > compute_confidence(
            without_sites, Verdict.REACHABLE
        )

    def test_call_sites_not_covered_inconclusive_still_gets_api_credit(self):
        base_inconclusive = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            affected_component_confidence=50,
        )
        with_api_not_covered = Evidence(
            version_in_range=True,
            package_imported=True,
            dependency_kind="direct",
            affected_component_confidence=50,
            api_usage_seen=True,
            api_usage_confidence=80,
            api_targets=("requests.get",),
            api_call_sites_covered=False,
        )
        assert compute_confidence(with_api_not_covered, Verdict.INCONCLUSIVE) > compute_confidence(
            base_inconclusive, Verdict.INCONCLUSIVE
        )


class TestCoverageCompleteness:
    @pytest.mark.parametrize("verdict", list(Verdict))
    @pytest.mark.parametrize(
        ("seen", "scope"), [(None, "not_reported"), (False, "reported"), (True, "reported")]
    )
    def test_global_percentage_cannot_change_confidence_in_identical_evidence(
        self, verdict, seen, scope
    ):
        evidence = Evidence(
            package_imported=True,
            coverage_seen=seen,
            coverage_scope=scope,
            affected_component_confidence=80,
        )

        scores = {
            compute_confidence(replace(evidence, coverage_completeness_pct=pct), verdict)
            for pct in (None, 0.0, 20.0, 80.0, 90.0, 100.0)
        }
        assert len(scores) == 1

    def test_measured_nonexecution_supplies_only_a_modest_dynamic_confidence_boost(self):
        unknown = Evidence(package_imported=True, coverage_scope="not_reported")
        measured = replace(unknown, coverage_seen=False, coverage_scope="reported")

        boost = compute_confidence(measured, Verdict.UNREACHABLE_DYNAMIC) - compute_confidence(
            unknown, Verdict.UNREACHABLE_DYNAMIC
        )
        assert 0 < boost <= 10

    @pytest.mark.parametrize("scope", ["unavailable", "not_reported", "no_statements", "partial"])
    def test_absence_without_reported_scope_cannot_boost_dynamic_confidence(self, scope):
        unknown = Evidence(package_imported=True, coverage_scope=scope)
        unsupported_negative = replace(unknown, coverage_seen=False, coverage_completeness_pct=100)

        assert compute_confidence(
            unsupported_negative, Verdict.UNREACHABLE_DYNAMIC
        ) == compute_confidence(unknown, Verdict.UNREACHABLE_DYNAMIC)


class TestConfidenceBucket:
    def test_high(self):
        assert confidence_bucket(80) == "high"
        assert confidence_bucket(100) == "high"

    def test_medium(self):
        assert confidence_bucket(60) == "medium"
        assert confidence_bucket(79) == "medium"

    def test_low(self):
        assert confidence_bucket(40) == "low"
        assert confidence_bucket(59) == "low"

    def test_weak(self):
        assert confidence_bucket(0) == "weak"
        assert confidence_bucket(39) == "weak"
