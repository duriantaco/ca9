from __future__ import annotations

import json
from pathlib import Path

from ca9.parsers import detect_parser
from ca9.parsers.grype import GrypeParser

FIXTURE = Path(__file__).parent / "fixtures" / "grype_sample.json"


def _grype_report(matches: list[object]) -> dict:
    return {
        "matches": matches,
        "descriptor": {"name": "grype", "version": "0.110.0"},
    }


class TestGrypeDetection:
    def test_detects_descriptor_identity(self):
        assert GrypeParser().can_parse(_grype_report([]))

    def test_registry_auto_detects_grype_report(self):
        assert isinstance(detect_parser(FIXTURE), GrypeParser)

    def test_detects_grype_owned_schema_identity(self):
        data = {
            "matches": [],
            "schema": {
                "version": "16.1.0",
                "url": (
                    "https://raw.githubusercontent.com/anchore/grype/"
                    "main/schema/json/schema-16.1.0.json"
                ),
            },
        }
        assert GrypeParser().can_parse(data)

    def test_detects_string_schema_identity(self):
        data = {
            "matches": [],
            "schema": "https://github.com/anchore/grype/blob/main/schema/json/schema.json",
        }
        assert GrypeParser().can_parse(data)

    def test_rejects_matches_without_grype_identity(self):
        assert not GrypeParser().can_parse({"matches": []})

    def test_rejects_other_descriptor(self):
        assert not GrypeParser().can_parse(
            {"matches": [], "descriptor": {"name": "syft", "version": "1.0"}}
        )

    def test_rejects_generic_schema_url(self):
        assert not GrypeParser().can_parse(
            {
                "matches": [],
                "schema": {"url": "https://example.test/schema/json/schema-16.1.0.json"},
            }
        )

    def test_rejects_missing_or_malformed_matches(self):
        parser = GrypeParser()
        assert not parser.can_parse({"descriptor": {"name": "grype"}})
        assert not parser.can_parse({"matches": {}, "descriptor": {"name": "grype"}})
        assert not parser.can_parse([])


class TestGrypeParsing:
    def test_accepts_current_native_empty_report(self):
        data = {
            "matches": [],
            "source": {"type": "unknown", "target": "unknown"},
            "distro": {"name": "centos", "version": "8.0", "idLike": ["rhel"]},
            "descriptor": {
                "name": "grype",
                "version": "[not provided]",
                "timestamp": "",
            },
        }

        parser = GrypeParser()
        assert parser.can_parse(data)
        assert parser.parse(data) == []

    def test_parses_current_grype_shape(self):
        data = json.loads(FIXTURE.read_text())
        vulns = GrypeParser().parse(data)

        assert len(vulns) == 3
        requests = vulns[0]
        assert requests.id == "CVE-2023-32681"
        assert requests.package_name == "requests"
        assert requests.package_version == "2.28.0"
        assert requests.ecosystem == "pypi"
        assert requests.severity == "high"
        assert requests.title == requests.description[:120]
        assert requests.aliases == ("GHSA-J8R2-6X86-Q33Q", "PYSEC-2023-74")
        assert requests.cwes == ("CWE-200",)
        assert requests.cpes == ("cpe:2.3:a:python-requests:requests:2.28.0:*:*:*:*:*:*:*",)
        assert requests.advisory_source == "grype"
        assert requests.advisory_url == ("https://github.com/advisories/GHSA-j8r2-6x86-q33q")
        assert requests.published_at == "2023-05-26T18:15:00Z"
        assert requests.modified_at == "2023-06-06T20:15:00Z"
        assert requests.references == (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
            "https://github.com/psf/requests/security/advisories/GHSA-j8r2-6x86-q33q",
            "https://osv.dev/vulnerability/PYSEC-2023-74",
            "https://github.com/advisories/GHSA-j8r2-6x86-q33q",
        )

    def test_uses_purl_as_identity_and_ecosystem_fallback(self):
        data = json.loads(FIXTURE.read_text())
        vuln = GrypeParser().parse(data)[1]

        assert vuln.package_name == "example-lib"
        assert vuln.package_version == "1.2.3"
        assert vuln.ecosystem == "pypi"
        assert vuln.title == "Example vulnerability with package identity supplied by purl"
        assert vuln.aliases == ("CVE-2024-0001",)

    def test_decodes_scoped_npm_purl_identity(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {"id": "CVE-2026-1005", "severity": "High"},
                    "artifact": {
                        "type": "UnknownPackage",
                        "purl": (
                            "pkg:npm/%40scope/example@1.2.3"
                            "?repository_url=https%3A%2F%2Fregistry.npmjs.org#src"
                        ),
                    },
                }
            ]
        )

        vuln = GrypeParser().parse(data)[0]
        assert vuln.package_name == "@scope/example"
        assert vuln.package_version == "1.2.3"
        assert vuln.ecosystem == "npm"

    def test_accepts_unencoded_scoped_npm_purl_without_version(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {"id": "CVE-2026-1006"},
                    "artifact": {
                        "type": "UnknownPackage",
                        "purl": "pkg:npm/@scope/example",
                    },
                }
            ]
        )

        vuln = GrypeParser().parse(data)[0]
        assert vuln.package_name == "@scope/example"
        assert vuln.package_version == ""
        assert vuln.ecosystem == "npm"

    def test_preserves_non_python_ecosystem(self):
        data = json.loads(FIXTURE.read_text())
        vuln = GrypeParser().parse(data)[2]

        assert vuln.package_name == "lodash"
        assert vuln.ecosystem == "npm"
        assert vuln.severity == "low"

    def test_missing_optional_fields_get_conservative_defaults(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {"id": "CVE-2026-1000"},
                    "artifact": {"name": "mystery", "version": "0.1"},
                }
            ]
        )
        vuln = GrypeParser().parse(data)[0]

        assert vuln.severity == "unknown"
        assert vuln.title == "CVE-2026-1000"
        assert vuln.description == ""
        assert vuln.ecosystem == ""
        assert vuln.aliases == ()
        assert vuln.references == ()
        assert vuln.advisory_url == ""
        assert vuln.published_at is None
        assert vuln.modified_at is None

    def test_reference_is_advisory_url_fallback(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {
                        "id": "CVE-2026-1001",
                        "urls": ["https://example.test/CVE-2026-1001"],
                    },
                    "artifact": {"name": "demo", "type": "python"},
                }
            ]
        )

        vuln = GrypeParser().parse(data)[0]
        assert vuln.advisory_url == "https://example.test/CVE-2026-1001"

    def test_conflicting_purl_and_type_do_not_default_to_pypi(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {"id": "CVE-2026-1002"},
                    "artifact": {
                        "name": "confused",
                        "version": "1.0",
                        "type": "python",
                        "purl": "pkg:npm/confused@1.0",
                    },
                }
            ]
        )

        assert GrypeParser().parse(data)[0].ecosystem == ""

    def test_malformed_empty_name_purl_is_not_ecosystem_evidence(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {"id": "CVE-2026-1007"},
                    "artifact": {
                        "name": "untyped-package",
                        "purl": "pkg:pypi/@1.0",
                    },
                }
            ]
        )

        vuln = GrypeParser().parse(data)[0]
        assert vuln.package_name == "untyped-package"
        assert vuln.package_version == ""
        assert vuln.ecosystem == ""

    def test_unknown_artifact_type_is_not_treated_as_ecosystem(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {"id": "CVE-2026-1008"},
                    "artifact": {
                        "name": "untyped-package",
                        "version": "1.0",
                        "type": "custom-python-ish-package",
                    },
                }
            ]
        )

        assert GrypeParser().parse(data)[0].ecosystem == ""

    def test_collects_current_known_exploited_urls(self):
        data = _grype_report(
            [
                {
                    "vulnerability": {
                        "id": "CVE-2026-1009",
                        "knownExploited": [
                            {
                                "cve": "CVE-2026-1009",
                                "urls": [
                                    "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                                    None,
                                ],
                            }
                        ],
                    },
                    "artifact": {"name": "demo", "type": "python"},
                }
            ]
        )

        vuln = GrypeParser().parse(data)[0]
        assert vuln.references == ("https://www.cisa.gov/known-exploited-vulnerabilities-catalog",)

    def test_deduplicates_finding_identity(self):
        match = {
            "vulnerability": {"id": "CVE-2026-1003", "severity": "High"},
            "artifact": {"name": "demo", "version": "1.0", "type": "python"},
        }
        assert len(GrypeParser().parse(_grype_report([match, match]))) == 1

    def test_malformed_entries_are_skipped(self):
        data = _grype_report(
            [
                None,
                "garbage",
                {},
                {"vulnerability": [], "artifact": {}},
                {"vulnerability": {"id": "CVE-1"}, "artifact": []},
                {"vulnerability": {"id": ""}, "artifact": {"name": "demo"}},
                {"vulnerability": {"id": "CVE-2"}, "artifact": {"name": ""}},
                {
                    "vulnerability": {
                        "id": "CVE-2026-1004",
                        "severity": {"level": "high"},
                        "description": ["not text"],
                        "urls": [None, 3, "https://example.test/CVE-2026-1004"],
                        "aliases": [None, 3, "GHSA-1111-2222-3333"],
                    },
                    "artifact": {
                        "name": "valid",
                        "version": 12,
                        "type": "python",
                    },
                },
            ]
        )

        vulns = GrypeParser().parse(data)
        assert len(vulns) == 1
        assert vulns[0].id == "CVE-2026-1004"
        assert vulns[0].package_version == ""
        assert vulns[0].severity == "unknown"
        assert vulns[0].description == ""
        assert vulns[0].references == ("https://example.test/CVE-2026-1004",)
        assert vulns[0].aliases == ("GHSA-1111-2222-3333",)

    def test_parse_rejects_non_report_shapes_without_raising(self):
        parser = GrypeParser()
        assert parser.parse([]) == []
        assert parser.parse({}) == []
        assert parser.parse({"matches": {}}) == []
