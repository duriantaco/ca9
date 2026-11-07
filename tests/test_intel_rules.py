from __future__ import annotations

import sys
from pathlib import Path

import pytest

import ca9.intel_rules as intel_rules
from ca9.intel_rules import (
    RuleFileError,
    VulnIntelResolution,
    _ensure_rules_loaded,
    load_rule_from_dict,
    load_rules_from_file,
    load_rules_from_json,
    load_rules_from_yaml,
    resolve_vuln_intel,
)
from ca9.models import Vulnerability


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
        assert any(t.fqname == "requests.get" for t in result.api_targets)
        assert result.source == "rulepack"

    def test_match_by_advisory_alias(self):
        vuln = Vulnerability(
            id="GHSA-9wx4-h78v-vm56",
            aliases=("CVE-2023-32681",),
            package_name="requests",
            package_version="2.25.0",
            severity="medium",
            title="Something unrelated to keywords",
        )
        result = resolve_vuln_intel(vuln)
        assert len(result.matched_rules) >= 1
        assert any(t.fqname == "requests.get" for t in result.api_targets)

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
        result = resolve_vuln_intel(vuln)
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


RULES_DIR = Path(__file__).parent.parent / "src" / "ca9" / "rules"


class TestLoadRulesFromYaml:
    def test_load_user_yaml_rules(self, tmp_path):
        pytest.importorskip("yaml")
        path = tmp_path / "custom.yml"
        path.write_text("package: requests\nrules:\n  - id: CUSTOM-1\n")
        rules = load_rules_from_yaml(path)
        assert [r.id for r in rules] == ["CUSTOM-1"]

    def test_load_nonexistent_warns_and_returns_empty(self, tmp_path):
        with pytest.warns(RuntimeWarning, match="cannot read rule file"):
            rules = load_rules_from_yaml(tmp_path / "does_not_exist.yml")
        assert rules == []

    def test_load_invalid_yaml_warns_and_returns_empty(self, tmp_path):
        pytest.importorskip("yaml")
        bad = tmp_path / "bad.yml"
        bad.write_text("{{{{invalid yaml")
        with pytest.warns(RuntimeWarning, match="invalid YAML rule file"):
            rules = load_rules_from_yaml(bad)
        assert rules == []

    def test_load_rules_from_file_raises_on_invalid_yaml(self, tmp_path):
        pytest.importorskip("yaml")
        bad = tmp_path / "bad.yml"
        bad.write_text("{{{{invalid yaml")
        with pytest.raises(RuleFileError):
            load_rules_from_file(bad)

    def test_yaml_rule_file_without_pyyaml_is_a_visible_error(self, tmp_path, monkeypatch):
        monkeypatch.setitem(sys.modules, "yaml", None)
        path = tmp_path / "custom.yml"
        path.write_text("package: requests\nrules:\n  - id: CUSTOM-1\n")
        with pytest.raises(RuleFileError, match="require PyYAML"):
            load_rules_from_file(path)
        with pytest.warns(RuntimeWarning, match="require PyYAML"):
            assert load_rules_from_yaml(path) == []


class TestBuiltinRulesWithoutPyYAML:
    def test_builtin_rules_are_json(self):
        assert sorted(p.name for p in RULES_DIR.glob("*.json")) == [
            "django.json",
            "jinja2.json",
            "pyyaml.json",
            "requests.json",
            "urllib3.json",
            "werkzeug.json",
        ]
        assert not list(RULES_DIR.glob("*.yml")) and not list(RULES_DIR.glob("*.yaml"))

    def test_load_requests_json(self):
        rules = load_rules_from_json(RULES_DIR / "requests.json")
        assert len(rules) >= 2
        assert all(r.package == "requests" for r in rules)

    def test_builtin_rules_load_when_yaml_import_is_blocked(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "yaml", None)
        monkeypatch.setattr(intel_rules, "_BUILTIN_RULES", [])
        monkeypatch.setattr(intel_rules, "_RULES_BY_PACKAGE", {})
        monkeypatch.setattr(intel_rules, "_RULES_LOADED", False)

        vuln = Vulnerability(
            id="CVE-2020-14343",
            package_name="PyYAML",
            package_version="5.3.1",
            severity="critical",
            title="Arbitrary code execution",
        )
        result = resolve_vuln_intel(vuln)

        assert len(intel_rules._BUILTIN_RULES) >= 10
        assert {"django", "jinja2", "pyyaml", "requests", "urllib3", "werkzeug"} <= set(
            intel_rules._RULES_BY_PACKAGE
        )
        assert "yaml.load" in {t.fqname for t in result.api_targets}

    def test_corrupt_builtin_rule_file_warns(self, tmp_path, monkeypatch):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "broken.json").write_text("{not json")
        monkeypatch.setattr(intel_rules, "__file__", str(tmp_path / "intel_rules.py"))
        monkeypatch.setattr(intel_rules, "_BUILTIN_RULES", [])
        monkeypatch.setattr(intel_rules, "_RULES_BY_PACKAGE", {})
        with pytest.warns(RuntimeWarning, match="invalid JSON rule file"):
            intel_rules._load_builtin_rules()
        assert intel_rules._BUILTIN_RULES == []
