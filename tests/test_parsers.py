from __future__ import annotations

import json

from ca9.parsers import detect_parser
from ca9.parsers.dependabot import DependabotParser
from ca9.parsers.pip_audit import PipAuditParser
from ca9.parsers.snyk import SnykParser
from ca9.parsers.trivy import TrivyParser


class TestSnykParser:
    def test_can_parse_snyk(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = SnykParser()
        assert parser.can_parse(data)

    def test_cannot_parse_dependabot(self, dependabot_path):
        data = json.loads(dependabot_path.read_text())
        parser = SnykParser()
        assert not parser.can_parse(data)

    def test_parse_snyk_vulns(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = SnykParser()
        vulns = parser.parse(data)
        assert len(vulns) == 4
        assert vulns[0].id == "SNYK-PYTHON-REQUESTS-1234567"
        assert vulns[0].package_name == "requests"
        assert vulns[0].severity == "high"

    def test_deduplicates(self):
        data = {
            "vulnerabilities": [
                {
                    "id": "V1",
                    "packageName": "foo",
                    "version": "1.0",
                    "severity": "low",
                    "title": "t",
                },
                {
                    "id": "V1",
                    "packageName": "foo",
                    "version": "1.0",
                    "severity": "low",
                    "title": "t",
                },
            ],
            "projectName": "test",
        }
        parser = SnykParser()
        vulns = parser.parse(data)
        assert len(vulns) == 1

    def test_parse_list_format(self):
        data = [
            {
                "vulnerabilities": [
                    {
                        "id": "V1",
                        "packageName": "a",
                        "version": "1",
                        "severity": "low",
                        "title": "t",
                    },
                ],
                "projectName": "p1",
            },
            {
                "vulnerabilities": [
                    {
                        "id": "V2",
                        "packageName": "b",
                        "version": "2",
                        "severity": "high",
                        "title": "t",
                    },
                ],
                "projectName": "p2",
            },
        ]
        parser = SnykParser()
        assert parser.can_parse(data)
        vulns = parser.parse(data)
        assert len(vulns) == 2

    def test_extracts_dependency_chain_from_from(self):
        data = {
            "vulnerabilities": [
                {
                    "id": "V1",
                    "packageName": "urllib3",
                    "version": "1.26.18",
                    "severity": "high",
                    "title": "t",
                    "from": ["my-project@1.0.0", "requests@2.31.0", "urllib3@1.26.18"],
                }
            ],
            "projectName": "my-project",
        }
        vulns = SnykParser().parse(data)
        assert vulns[0].report_dependency_kind == "transitive"
        assert vulns[0].report_dependency_chain == ("requests", "urllib3")


class TestDependabotParser:
    def test_can_parse_dependabot(self, dependabot_path):
        data = json.loads(dependabot_path.read_text())
        parser = DependabotParser()
        assert parser.can_parse(data)

    def test_cannot_parse_snyk(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = DependabotParser()
        assert not parser.can_parse(data)

    def test_parse_dependabot_vulns(self, dependabot_path):
        data = json.loads(dependabot_path.read_text())
        parser = DependabotParser()
        vulns = parser.parse(data)
        assert len(vulns) == 2
        assert vulns[0].id == "GHSA-1234-abcd-5678"
        assert vulns[0].package_name == "requests"
        assert vulns[1].severity == "critical"

    def test_parses_dependency_relationship(self):
        data = [
            {
                "number": 3,
                "security_advisory": {
                    "ghsa_id": "GHSA-9999-aaaa-bbbb",
                    "summary": "t",
                    "severity": "high",
                },
                "security_vulnerability": {
                    "package": {"ecosystem": "pip", "name": "urllib3"},
                    "vulnerable_version_range": "< 2.0",
                },
                "dependency": {
                    "package": {"ecosystem": "pip", "name": "urllib3"},
                    "relationship": "transitive",
                },
            }
        ]
        vulns = DependabotParser().parse(data)
        assert vulns[0].report_dependency_kind == "transitive"
        assert vulns[0].report_dependency_chain == ()


class TestSnykEdgeCases:
    def test_skips_empty_ids(self):
        data = {
            "vulnerabilities": [
                {"id": "", "packageName": "foo", "version": "1.0", "severity": "low", "title": "t"},
                {
                    "id": "V1",
                    "packageName": "bar",
                    "version": "1.0",
                    "severity": "low",
                    "title": "t",
                },
            ],
            "projectName": "test",
        }
        vulns = SnykParser().parse(data)
        assert len(vulns) == 1
        assert vulns[0].id == "V1"

    def test_skips_non_dict_entries(self):
        data = [
            "not a dict",
            {
                "vulnerabilities": [
                    {
                        "id": "V1",
                        "packageName": "a",
                        "version": "1",
                        "severity": "low",
                        "title": "t",
                    }
                ],
                "projectName": "p",
            },
        ]
        vulns = SnykParser().parse(data)
        assert len(vulns) == 1

    def test_skips_non_dict_vulns(self):
        data = {
            "vulnerabilities": [
                "not a dict",
                {"id": "V1", "packageName": "a", "version": "1", "severity": "low", "title": "t"},
            ],
            "projectName": "test",
        }
        vulns = SnykParser().parse(data)
        assert len(vulns) == 1

    def test_empty_vulnerabilities_list(self):
        data = {"vulnerabilities": [], "projectName": "test"}
        vulns = SnykParser().parse(data)
        assert vulns == []


class TestDependabotEdgeCases:
    def test_skips_non_dict_alerts(self):
        data = [
            "garbage",
            {
                "number": 1,
                "security_advisory": {"ghsa_id": "GHSA-1", "summary": "t", "severity": "high"},
                "security_vulnerability": {"package": {"name": "requests"}},
            },
        ]
        vulns = DependabotParser().parse(data)
        assert len(vulns) == 1

    def test_can_parse_empty_list(self):
        assert not DependabotParser().can_parse([])

    def test_can_parse_non_list(self):
        assert not DependabotParser().can_parse({"key": "val"})


class TestTrivyParser:
    def test_can_parse_trivy(self, trivy_path):
        data = json.loads(trivy_path.read_text())
        parser = TrivyParser()
        assert parser.can_parse(data)

    def test_cannot_parse_snyk(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = TrivyParser()
        assert not parser.can_parse(data)

    def test_parse_trivy_vulns(self, trivy_path):
        data = json.loads(trivy_path.read_text())
        parser = TrivyParser()
        vulns = parser.parse(data)
        assert len(vulns) == 3
        ids = {v.id for v in vulns}
        assert "CVE-2023-32681" in ids
        assert "CVE-2022-42969" in ids
        assert "CVE-2023-37920" in ids
        requests_vuln = next(v for v in vulns if v.package_name == "requests")
        assert requests_vuln.report_dependency_kind == "direct"
        assert requests_vuln.report_dependency_chain == ("requests",)

    def test_severity_lowercased(self, trivy_path):
        data = json.loads(trivy_path.read_text())
        vulns = TrivyParser().parse(data)
        for v in vulns:
            assert v.severity == v.severity.lower()

    def test_deduplicates(self):
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "foo",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH",
                            "Title": "t",
                        },
                    ],
                },
                {
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "foo",
                            "InstalledVersion": "1.0",
                            "Severity": "HIGH",
                            "Title": "t",
                        },
                    ],
                },
            ],
        }
        vulns = TrivyParser().parse(data)
        assert len(vulns) == 1

    def test_skips_empty_ids(self):
        data = {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"VulnerabilityID": "", "PkgName": "foo", "InstalledVersion": "1.0"},
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "bar",
                            "InstalledVersion": "2.0",
                            "Severity": "LOW",
                            "Title": "t",
                        },
                    ],
                },
            ],
        }
        vulns = TrivyParser().parse(data)
        assert len(vulns) == 1

    def test_can_parse_non_dict(self):
        assert not TrivyParser().can_parse([])
        assert not TrivyParser().can_parse("string")

    def test_empty_results(self):
        data = {"Results": []}
        vulns = TrivyParser().parse(data)
        assert vulns == []

    def test_extracts_dependency_chain_from_trivy_path(self):
        data = {
            "Results": [
                {
                    "Target": "poetry.lock",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-1",
                            "PkgName": "urllib3",
                            "InstalledVersion": "1.26.18",
                            "Severity": "HIGH",
                            "Title": "t",
                            "DependencyPath": ["requests@2.31.0", "urllib3@1.26.18"],
                        }
                    ],
                }
            ]
        }
        vulns = TrivyParser().parse(data)
        assert vulns[0].report_dependency_kind == "transitive"
        assert vulns[0].report_dependency_chain == ("requests", "urllib3")


class TestPipAuditParser:
    def test_can_parse_pip_audit(self, pip_audit_path):
        data = json.loads(pip_audit_path.read_text())
        parser = PipAuditParser()
        assert parser.can_parse(data)

    def test_cannot_parse_snyk(self, snyk_path):
        data = json.loads(snyk_path.read_text())
        parser = PipAuditParser()
        assert not parser.can_parse(data)

    def test_parse_pip_audit_vulns(self, pip_audit_path):
        data = json.loads(pip_audit_path.read_text())
        parser = PipAuditParser()
        vulns = parser.parse(data)
        assert len(vulns) == 3
        ids = {v.id for v in vulns}
        assert "PYSEC-2023-74" in ids
        assert "PYSEC-2023-135" in ids
        assert "PYSEC-2022-249" in ids

    def test_skips_deps_without_vulns(self, pip_audit_path):
        data = json.loads(pip_audit_path.read_text())
        vulns = PipAuditParser().parse(data)
        pkg_names = {v.package_name for v in vulns}
        assert "flask" not in pkg_names

    def test_includes_fix_versions_in_title(self, pip_audit_path):
        data = json.loads(pip_audit_path.read_text())
        vulns = PipAuditParser().parse(data)
        requests_vuln = next(v for v in vulns if v.id == "PYSEC-2023-74")
        assert "2.31.0" in requests_vuln.title

    def test_deduplicates_same_package(self):
        data = {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "vulns": [{"id": "V1", "description": "d"}, {"id": "V1", "description": "d"}],
                },
            ],
        }
        vulns = PipAuditParser().parse(data)
        assert len(vulns) == 1

    def test_same_cve_different_packages_preserved(self):
        """Same CVE affecting different packages should produce separate findings."""
        data = {
            "dependencies": [
                {
                    "name": "foo",
                    "version": "1.0",
                    "vulns": [{"id": "V1", "description": "d"}],
                },
                {
                    "name": "bar",
                    "version": "2.0",
                    "vulns": [{"id": "V1", "description": "d"}],
                },
            ],
        }
        vulns = PipAuditParser().parse(data)
        assert len(vulns) == 2
        pkg_names = {v.package_name for v in vulns}
        assert pkg_names == {"foo", "bar"}

    def test_can_parse_non_dict(self):
        assert not PipAuditParser().can_parse([])
        assert not PipAuditParser().can_parse("string")

    def test_empty_dependencies(self):
        data = {"dependencies": []}
        vulns = PipAuditParser().parse(data)
        assert vulns == []


class TestAutoDetect:
    def test_detects_snyk(self, snyk_path):
        parser = detect_parser(snyk_path)
        assert isinstance(parser, SnykParser)

    def test_detects_dependabot(self, dependabot_path):
        parser = detect_parser(dependabot_path)
        assert isinstance(parser, DependabotParser)

    def test_detects_trivy(self, trivy_path):
        parser = detect_parser(trivy_path)
        assert isinstance(parser, TrivyParser)

    def test_detects_pip_audit(self, pip_audit_path):
        parser = detect_parser(pip_audit_path)
        assert isinstance(parser, PipAuditParser)

    def test_unknown_format_raises(self, tmp_path):
        bad = tmp_path / "unknown.json"
        bad.write_text('{"random": "data"}')
        import pytest

        with pytest.raises(ValueError, match="Cannot detect SCA format"):
            detect_parser(bad)
