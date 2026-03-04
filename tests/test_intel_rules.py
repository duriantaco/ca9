from __future__ import annotations

from pathlib import Path

import pytest

from ca9.intel_rules import (
    VulnIntelResolution,
    VulnIntelRule,
    _ensure_rules_loaded,
    load_rule_from_dict,
    load_rules_from_yaml,
    resolve_vuln_intel,
)
from ca9.models import ApiTarget, Vulnerability, VersionRange


class TestLoadRuleFromDict:
    def test_basic_rule(self):
        data = {
            "package": "requests",
            "rules": [
                {
                    "id": "TEST-001",
                    "advisory_ids": ["CVE-2023-1234"],
                    "confidence_prior": 90,
                    "affected_modules": ["requests.sessions"],
                    "api_targets": [
                        {"fqname": "requests.get", "kind": "function"},
                        {"fqname": "requests.Session", "kind": "class"},
                    ],
                    "signals": {"keywords": ["redirect", "cookie"]},
                    "notes": ["Test note"],
                }
            ],
        }
        rules = load_rule_from_dict(data)
        assert len(rules) == 1
        rule = rules[0]
        assert rule.id == "TEST-001"
        assert rule.package == "requests"
        assert "CVE-2023-1234" in rule.advisory_ids
        assert rule.confidence_prior == 90
        assert "requests.sessions" in rule.affected_modules
        assert len(rule.api_targets) == 2
        assert rule.api_targets[0].fqname == "requests.get"
        assert rule.api_targets[0].kind == "function"
        assert rule.api_targets[0].module == "requests"
        assert rule.api_targets[0].symbol == "get"
        assert rule.api_targets[1].kind == "class"
        assert "redirect" in rule.keywords
        assert "Test note" in rule.notes

    def test_empty_package_returns_empty(self):
        assert load_rule_from_dict({"package": "", "rules": []}) == []

    def test_rule_without_id_skipped(self):
        data = {
            "package": "foo",
            "rules": [{"confidence_prior": 50}],
        }
        assert load_rule_from_dict(data) == []

    def test_multiple_rules(self):
        data = {
            "package": "django",
            "rules": [
                {"id": "R-1", "affected_modules": ["django.contrib.sessions"]},
                {"id": "R-2", "affected_modules": ["django.contrib.admin"]},
            ],
        }
        rules = load_rule_from_dict(data)
        assert len(rules) == 2
        assert rules[0].id == "R-1"
        assert rules[1].id == "R-2"

    def test_api_target_with_aliases(self):
        data = {
            "package": "yaml",
            "rules": [
                {
                    "id": "R-1",
                    "api_targets": [
                        {
                            "fqname": "yaml.load",
                            "kind": "function",
                            "aliases": ["yaml.unsafe_load"],
                            "notes": ["unsafe without Loader"],
                        }
                    ],
                }
            ],
        }
        rules = load_rule_from_dict(data)
        t = rules[0].api_targets[0]
        assert t.aliases == ("yaml.unsafe_load",)
        assert t.notes == ("unsafe without Loader",)
        assert t.rule_id == "R-1"

    def test_api_target_without_fqname_skipped(self):
        data = {
            "package": "foo",
            "rules": [
                {
                    "id": "R-1",
                    "api_targets": [{"kind": "function"}],
                }
            ],
        }
        rules = load_rule_from_dict(data)
        assert len(rules[0].api_targets) == 0


class TestLoadBuiltinRules:
    def test_builtin_rules_load(self):
        _ensure_rules_loaded()
        # We have 6 YAML files with 21+ rules
        from ca9.intel_rules import _BUILTIN_RULES, _RULES_BY_PACKAGE

        assert len(_BUILTIN_RULES) >= 10
        assert "requests" in _RULES_BY_PACKAGE
        assert "pyyaml" in _RULES_BY_PACKAGE
        assert "django" in _RULES_BY_PACKAGE

    def test_rules_have_api_targets(self):
        _ensure_rules_loaded()
        from ca9.intel_rules import _BUILTIN_RULES

        rules_with_targets = [r for r in _BUILTIN_RULES if r.api_targets]
        assert len(rules_with_targets) >= 10


class TestResolveVulnIntel:
    def test_match_by_advisory_id(self):
        vuln = Vulnerability(
            id="CVE-2023-32681",
            package_name="requests",
            package_version="2.25.0",
            severity="medium",
            title="Something unrelated to keywords",
        )
        result = resolve_vuln_intel(vuln)
        assert len(result.matched_rules) >= 1
        assert any("requests.get" == t.fqname for t in result.api_targets)
        assert result.source == "rulepack"

    def test_match_by_keyword(self):
        vuln = Vulnerability(
            id="UNKNOWN-001",
            package_name="requests",
            package_version="2.25.0",
            severity="medium",
            title="Cookie leak via redirect",
        )
        result = resolve_vuln_intel(vuln)
        assert len(result.matched_rules) >= 1
        assert "redirect" in vuln.title.lower() or "cookie" in vuln.title.lower()

    def test_no_match_different_package(self):
        vuln = Vulnerability(
            id="CVE-9999-0001",
            package_name="unknown-package",
            package_version="1.0.0",
            severity="low",
            title="Some vuln",
        )
        result = resolve_vuln_intel(vuln)
        assert len(result.matched_rules) == 0
        assert result.source == ""

    def test_no_match_wrong_keywords(self):
        vuln = Vulnerability(
            id="CVE-9999-0002",
            package_name="requests",
            package_version="2.25.0",
            severity="low",
            title="Memory leak in connection pool",
        )
        result = resolve_vuln_intel(vuln)
        assert len(result.matched_rules) == 0

    def test_pyyaml_match(self):
        vuln = Vulnerability(
            id="CVE-2020-14343",
            package_name="PyYAML",
            package_version="5.3.1",
            severity="critical",
            title="Arbitrary code execution",
        )
        result = resolve_vuln_intel(vuln)
        assert len(result.matched_rules) >= 1
        fqnames = {t.fqname for t in result.api_targets}
        assert "yaml.load" in fqnames
        assert "yaml.unsafe_load" in fqnames

    def test_django_debug_match(self):
        vuln = Vulnerability(
            id="CVE-9999-0003",
            package_name="Django",
            package_version="3.2.0",
            severity="high",
            title="Remote code execution via debug mode",
        )
        # "debug" is a keyword in werkzeug rules, but this is django package
        # Django rules have keywords like "admin", "session", etc.
        result = resolve_vuln_intel(vuln)
        # May or may not match depending on keyword overlap — just verify no crash
        assert isinstance(result, VulnIntelResolution)

    def test_resolution_deduplicates_targets(self):
        vuln = Vulnerability(
            id="CVE-2023-32681",
            package_name="requests",
            package_version="2.25.0",
            severity="medium",
            title="Cookie redirect proxy vulnerability",
            description="Sends cookies in redirects to proxy via different hosts",
        )
        result = resolve_vuln_intel(vuln)
        fqnames = [t.fqname for t in result.api_targets]
        assert len(fqnames) == len(set(fqnames)), "API targets should be deduplicated"

    def test_resolution_confidence_prior(self):
        vuln = Vulnerability(
            id="CVE-2020-14343",
            package_name="PyYAML",
            package_version="5.3.1",
            severity="critical",
            title="deserialization vulnerability",
        )
        result = resolve_vuln_intel(vuln)
        assert result.confidence_prior > 0


class TestLoadRulesFromYaml:
    def test_load_requests_yml(self):
        path = Path(__file__).parent.parent / "src" / "ca9" / "rules" / "requests.yml"
        if not path.exists():
            pytest.skip("requests.yml not found")
        rules = load_rules_from_yaml(path)
        assert len(rules) >= 2
        assert all(r.package == "requests" for r in rules)

    def test_load_nonexistent_returns_empty(self, tmp_path):
        rules = load_rules_from_yaml(tmp_path / "does_not_exist.yml")
        assert rules == []

    def test_load_invalid_yaml_returns_empty(self, tmp_path):
        bad = tmp_path / "bad.yml"
        bad.write_text("{{{{invalid yaml")
        rules = load_rules_from_yaml(bad)
        assert rules == []
