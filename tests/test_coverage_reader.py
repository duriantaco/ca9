from __future__ import annotations

import pytest

from ca9.analysis.coverage_reader import (
    FileCoverage,
    are_call_sites_covered,
    get_coverage_completeness,
    get_covered_files,
    get_measured_files,
    is_package_executed,
    is_submodule_executed,
    load_coverage,
    observe_coverage,
)


class TestGetCoveredFiles:
    def test_extracts_files_with_lines(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        assert len(files) == 3
        assert any("requests/api.py" in f for f in files)

    def test_excludes_empty_executed_lines(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        yaml_files = [f for f in files if "yaml" in f]
        assert len(yaml_files) == 0


class TestGetCoverageCompleteness:
    def test_get_coverage_completeness_with_totals(self):
        data = {"totals": {"percent_covered": 85.3}}
        assert get_coverage_completeness(data) == 85.3

    def test_get_coverage_completeness_no_totals(self):
        data = {"files": {}, "meta": {}}
        assert get_coverage_completeness(data) is None

    def test_get_coverage_completeness_empty_data(self):
        assert get_coverage_completeness({}) is None

    @pytest.mark.parametrize(
        "value",
        [
            None,
            True,
            False,
            "95",
            [],
            {},
            -1,
            101,
            float("nan"),
            float("inf"),
            -float("inf"),
            10**1000,
        ],
    )
    def test_invalid_percentages_are_unknown(self, value):
        assert get_coverage_completeness({"totals": {"percent_covered": value}}) is None

    @pytest.mark.parametrize("totals", [None, [], "invalid", 95])
    def test_malformed_totals_are_unknown(self, totals):
        assert get_coverage_completeness({"totals": totals}) is None

    @pytest.mark.parametrize("value", [0, 100, 37.5])
    def test_finite_percentages_in_range_are_retained(self, value):
        assert get_coverage_completeness({"totals": {"percent_covered": value}}) == value


class TestMeasuredCoverage:
    def test_zero_hit_statements_are_retained_without_becoming_execution(self):
        path = "/site-packages/samplelib/api.py"
        data = {"files": {path: {"executed_lines": [], "missing_lines": [1, 2]}}}

        measured = get_measured_files(data)
        assert measured[path] == FileCoverage(executed_lines=(), missing_lines=(1, 2))
        assert get_covered_files(data) == {}
        assert is_package_executed("samplelib", {path: []}) == (False, [])
        assert is_submodule_executed(("samplelib.api",), (), {path: []}) == (False, [])

    def test_excluded_statements_cannot_supply_call_site_absence(self):
        path = "/repo/app.py"
        measured = get_measured_files(
            {
                "files": {
                    path: {
                        "executed_lines": [],
                        "missing_lines": [10],
                        "excluded_lines": [10],
                    }
                }
            }
        )

        assert measured[path].missing_lines == ()
        assert are_call_sites_covered(
            [(path, 10)], {}, missing_files={path: list(measured[path].missing_lines)}
        ) == (None, 0, 0)

    @pytest.mark.parametrize("lines", [None, "1", [True], [0], [-1], [1.0], ["1"]])
    def test_malformed_line_records_do_not_establish_measurement(self, lines):
        path = "/site-packages/samplelib/api.py"
        measured = get_measured_files(
            {"files": {path: {"executed_lines": [], "missing_lines": lines}}}
        )

        observation = observe_coverage("samplelib", measured)
        assert observation.seen is None
        assert observation.measured_files == ()

    def test_file_hint_in_another_package_cannot_establish_execution(self):
        observation = observe_coverage(
            "samplelib",
            {"/site-packages/other/debugger.py": FileCoverage(executed_lines=(1,))},
            submodule_paths=("samplelib.debug",),
            file_hints=("debugger.py",),
        )

        assert observation.seen is None
        assert observation.executed_files == ()
        assert observation.unmeasured_targets == ("samplelib.debug",)

    def test_file_hint_cannot_replace_missing_target_for_negative_observation(self):
        observation = observe_coverage(
            "samplelib",
            {"/site-packages/samplelib/debugger.py": FileCoverage(missing_lines=(1,))},
            submodule_paths=("samplelib.debug",),
            file_hints=("debugger.py",),
        )

        assert observation.seen is None
        assert observation.unmeasured_targets == ("samplelib.debug",)

    def test_import_path_match_requires_a_file_boundary(self):
        observation = observe_coverage(
            "samplelib",
            {"/site-packages/samplelib.py.backup": FileCoverage(executed_lines=(1,))},
        )

        assert observation.seen is None
        assert observation.executed_files == ()


class TestIsPackageExecuted:
    def test_requests_executed(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        executed, matching = is_package_executed("requests", files)
        assert executed
        assert len(matching) == 2

    def test_yaml_not_executed(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        executed, matching = is_package_executed("PyYAML", files)
        assert not executed

    def test_unknown_package(self, coverage_path):
        data = load_coverage(coverage_path)
        files = get_covered_files(data)
        executed, matching = is_package_executed("nonexistent-pkg", files)
        assert not executed
        assert matching == []


class TestEdgeCases:
    def test_missing_files_key(self):
        files = get_covered_files({"meta": {}})
        assert files == {}

    def test_empty_coverage_data(self):
        files = get_covered_files({})
        assert files == {}

    def test_windows_paths(self):
        covered = {
            "C:\\Python39\\Lib\\site-packages\\requests\\api.py": [1, 2, 3],
        }
        executed, matching = is_package_executed("requests", covered)
        assert executed
        assert len(matching) == 1


class TestIsSubmoduleExecuted:
    def test_submodule_as_directory(self):
        covered = {
            "/site-packages/jinja2/sandbox/__init__.py": [1, 2],
            "/site-packages/jinja2/utils.py": [1],
        }
        executed, matching = is_submodule_executed(("jinja2.sandbox",), (), covered)
        assert executed
        assert len(matching) == 1
        assert "sandbox" in matching[0]

    def test_submodule_as_file(self):
        covered = {
            "/site-packages/jinja2/sandbox.py": [1, 2, 3],
        }
        executed, matching = is_submodule_executed(("jinja2.sandbox",), (), covered)
        assert executed

    def test_submodule_not_executed(self):
        covered = {
            "/site-packages/jinja2/utils.py": [1, 2],
            "/site-packages/jinja2/filters.py": [1],
        }
        executed, matching = is_submodule_executed(("jinja2.sandbox",), (), covered)
        assert not executed
        assert matching == []

    def test_file_hints(self):
        covered = {
            "/site-packages/werkzeug/debugger.py": [1, 2],
        }
        executed, matching = is_submodule_executed((), ("debugger.py",), covered)
        assert executed

    def test_multiple_submodule_paths(self):
        covered = {
            "/site-packages/django/contrib/admin/sites.py": [1],
            "/site-packages/django/db/models/query.py": [5],
        }
        executed, matching = is_submodule_executed(("django.contrib.admin",), (), covered)
        assert executed
        assert len(matching) == 1

    def test_empty_paths_and_hints(self):
        covered = {"/site-packages/jinja2/sandbox.py": [1]}
        executed, matching = is_submodule_executed((), (), covered)
        assert not executed

    def test_windows_paths(self):
        covered = {
            "C:\\Python39\\Lib\\site-packages\\werkzeug\\debug\\__init__.py": [1],
        }
        executed, matching = is_submodule_executed(("werkzeug.debug",), (), covered)
        assert executed


class TestAreCallSitesCovered:
    def test_call_site_covered(self):
        covered = {
            "/repo/app.py": [1, 5, 10, 15, 20],
            "/repo/utils.py": [1, 2, 3],
        }
        result, cov_count, total = are_call_sites_covered([("/repo/app.py", 10)], covered)
        assert result is True
        assert cov_count == 1
        assert total == 1

    def test_call_site_not_covered(self):
        covered = {
            "/repo/app.py": [1, 5, 10, 15, 20],
        }
        result, cov_count, total = are_call_sites_covered(
            [("/repo/app.py", 42)], covered, missing_files={"/repo/app.py": [42]}
        )
        assert result is False
        assert cov_count == 0
        assert total == 1

    def test_mixed_covered_and_uncovered(self):
        covered = {
            "/repo/app.py": [1, 5, 10],
            "/repo/views.py": [1, 2, 3],
        }
        result, cov_count, total = are_call_sites_covered(
            [("/repo/app.py", 5), ("/repo/views.py", 99)],
            covered,
            missing_files={"/repo/views.py": [99]},
        )
        assert result is True
        assert cov_count == 1
        assert total == 2

    def test_no_call_sites(self):
        covered = {"/repo/app.py": [1, 2]}
        result, cov_count, total = are_call_sites_covered([], covered)
        assert result is None
        assert cov_count == 0
        assert total == 0

    def test_call_site_file_not_in_coverage(self):
        covered = {"/repo/app.py": [1, 2, 3]}
        result, cov_count, total = are_call_sites_covered([("/repo/other.py", 1)], covered)
        assert result is None
        assert total == 0

    def test_suffix_path_matching(self):
        covered = {
            "/full/path/to/repo/app.py": [1, 5, 10],
        }
        result, cov_count, total = are_call_sites_covered([("repo/app.py", 5)], covered)
        assert result is True
        assert cov_count == 1

    def test_multiple_call_sites_all_covered(self):
        covered = {
            "/repo/app.py": [1, 5, 10, 20],
        }
        result, cov_count, total = are_call_sites_covered(
            [("/repo/app.py", 5), ("/repo/app.py", 10)], covered
        )
        assert result is True
        assert cov_count == 2
        assert total == 2

    def test_windows_path_normalization(self):
        covered = {
            "C:\\repo\\app.py": [1, 5, 10],
        }
        result, cov_count, total = are_call_sites_covered([("C:/repo/app.py", 5)], covered)
        assert result is True

    def test_absent_line_is_unknown_without_explicit_missing_statement(self):
        assert are_call_sites_covered([("/repo/app.py", 42)], {"/repo/app.py": [1, 2]}) == (
            None,
            0,
            0,
        )

    def test_empty_file_does_not_establish_negative_call_site_evidence(self):
        assert are_call_sites_covered([("/repo/app.py", 42)], {"/repo/app.py": []}) == (None, 0, 0)

    def test_explicit_missing_line_in_zero_hit_file_is_negative_evidence(self):
        assert are_call_sites_covered(
            [("/repo/app.py", 42)], {}, missing_files={"/repo/app.py": [42]}
        ) == (False, 0, 1)

    def test_partial_call_site_measurement_is_unknown(self):
        assert are_call_sites_covered(
            [("/repo/app.py", 42), ("/repo/other.py", 10)],
            {},
            missing_files={"/repo/app.py": [42]},
        ) == (None, 0, 1)

    def test_positive_call_site_survives_another_unmeasured_site(self):
        assert are_call_sites_covered(
            [("/repo/app.py", 42), ("/repo/other.py", 10)],
            {"/repo/app.py": [42]},
        ) == (True, 1, 1)

    def test_all_call_sites_need_explicit_missing_statements_for_negative(self):
        assert are_call_sites_covered(
            [("/repo/app.py", 42), ("/repo/other.py", 10)],
            {},
            missing_files={"/repo/app.py": [42], "/repo/other.py": [10]},
        ) == (False, 0, 2)

    def test_suffix_matching_requires_a_path_component_boundary(self):
        assert are_call_sites_covered([("bar.py", 42)], {"/repo/foobar.py": [42]}) == (None, 0, 0)

    def test_ambiguous_relative_path_cannot_supply_negative_evidence(self):
        assert are_call_sites_covered(
            [("app.py", 42)],
            {},
            missing_files={"/repo/service_a/app.py": [42], "/repo/service_b/app.py": [42]},
        ) == (None, 0, 0)

    def test_ambiguous_relative_path_cannot_attribute_positive_execution(self):
        assert are_call_sites_covered(
            [("app.py", 42)],
            {"/repo/service_a/app.py": [42], "/repo/service_b/app.py": [1]},
        ) == (None, 0, 0)

    def test_exact_path_takes_precedence_over_ambiguous_suffix(self):
        assert are_call_sites_covered(
            [("/repo/service_a/app.py", 42)],
            {"/repo/service_a/app.py": [42], "/repo/service_b/app.py": [1]},
        ) == (True, 1, 1)

    def test_normalized_aliases_retain_all_executed_statements(self):
        covered = {"/repo/app.py": [1], "/repo/./app.py": [2]}

        for line in (1, 2):
            assert are_call_sites_covered([("/repo/app.py", line)], covered) == (True, 1, 1)
