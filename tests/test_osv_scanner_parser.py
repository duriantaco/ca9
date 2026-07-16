from __future__ import annotations

import json
from pathlib import Path

from ca9.models import VersionRange
from ca9.parsers import detect_parser
from ca9.parsers.osv_scanner import OsvScannerParser

SAMPLE_PATH = Path(__file__).parent / "fixtures" / "osv_scanner_sample.json"


def _sample() -> dict:
    return json.loads(SAMPLE_PATH.read_text())


class TestOSVScannerDetection:
    def test_detects_official_osv_scanner_shape(self):
        assert OsvScannerParser().can_parse(_sample())

    def test_registry_auto_detects_osv_scanner_report(self):
        assert isinstance(detect_parser(SAMPLE_PATH), OsvScannerParser)

    def test_requires_nested_source_and_package_shape(self):
        parser = OsvScannerParser()
        assert not parser.can_parse({"results": [{"packages": []}]})
        assert not parser.can_parse(
            {
                "results": [
                    {
                        "source": "requirements.txt",
                        "packages": [],
                    }
                ]
            }
        )
        assert not parser.can_parse(
            {
                "results": [
                    {
                        "source": {"path": "requirements.txt", "type": "lockfile"},
                        "packages": [{"name": "requests"}],
                    }
                ]
            }
        )

    def test_accepts_official_result_with_no_affected_packages(self):
        data = {
            "results": [
                {
                    "source": {"path": "requirements.txt", "type": "lockfile"},
                    "packages": [],
                }
            ]
        }
        assert OsvScannerParser().can_parse(data)

    def test_accepts_native_all_packages_entry_without_vulnerabilities_key(self):
        data = {
            "results": [
                {
                    "source": {"path": "requirements.txt", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "requests",
                                "version": "2.32.4",
                                "ecosystem": "PyPI",
                            }
                        }
                    ],
                }
            ]
        }
        parser = OsvScannerParser()
        assert parser.can_parse(data)
        assert parser.parse(data) == []

    def test_requires_serialized_package_identity_fields(self):
        parser = OsvScannerParser()
        source = {"path": "requirements.txt", "type": "lockfile"}
        for package in (
            {"name": "requests", "ecosystem": "PyPI"},
            {"name": "requests", "version": "2.32.4"},
        ):
            assert not parser.can_parse(
                {
                    "results": [
                        {
                            "source": source,
                            "packages": [
                                {
                                    "package": package,
                                    "vulnerabilities": [{"id": "OSV-1"}],
                                }
                            ],
                        }
                    ]
                }
            )

    def test_rejects_ambiguous_empty_results(self):
        assert not OsvScannerParser().can_parse({"results": []})

    def test_does_not_collide_with_other_report_shapes(self):
        parser = OsvScannerParser()
        assert not parser.can_parse([])
        assert not parser.can_parse("json")
        assert not parser.can_parse({"Results": []})
        assert not parser.can_parse(
            {
                "results": [
                    {
                        "source": {"path": "report.json", "type": "scan"},
                        "packages": [
                            {
                                "package": {
                                    "name": "requests",
                                    "version": "2.19.0",
                                    "ecosystem": "PyPI",
                                },
                                "vulnerabilities": [{"VulnerabilityID": "CVE-1"}],
                            }
                        ],
                    }
                ]
            }
        )


class TestOSVScannerParsing:
    def test_parses_full_osv_records(self):
        vulnerabilities = OsvScannerParser().parse(_sample())

        assert len(vulnerabilities) == 2
        requests = vulnerabilities[0]
        assert requests.id == "GHSA-9wx4-h78v-vm56"
        assert requests.package_name == "requests"
        assert requests.package_version == "2.19.0"
        assert requests.ecosystem == "pypi"
        assert requests.severity == "critical"
        assert requests.title == "Requests leaks Authorization headers on redirects"
        assert requests.description.startswith("Requests may forward an Authorization header")
        assert requests.aliases == ("CVE-2018-18074", "PYSEC-2018-28")
        assert requests.cwes == ("CWE-200", "CWE-522")
        assert requests.cpes == ("cpe:2.3:a:python-requests:requests:*:*:*:*:*:*:*:*",)
        assert requests.affected_ranges == (VersionRange(introduced="0", fixed="2.20.0"),)
        assert requests.references == (
            "https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-18074",
        )
        assert requests.advisory_source == "osv-scanner"
        assert requests.advisory_url == "https://osv.dev/vulnerability/GHSA-9wx4-h78v-vm56"
        assert requests.published_at == "2018-10-09T00:00:00Z"
        assert requests.modified_at == "2024-11-18T16:27:27Z"
        assert not requests.malicious

    def test_groups_alias_records_into_one_finding(self):
        vulnerabilities = OsvScannerParser().parse(_sample())
        assert [vulnerability.id for vulnerability in vulnerabilities] == [
            "GHSA-9wx4-h78v-vm56",
            "MAL-2025-1234",
        ]

    def test_preserves_non_python_ecosystems_and_malware_signal(self):
        malicious = OsvScannerParser().parse(_sample())[1]
        assert malicious.package_name == "left-pad"
        assert malicious.package_version == "1.3.0"
        assert malicious.ecosystem == "npm"
        assert malicious.severity == "high"
        assert malicious.malicious
        assert malicious.affected_ranges == (
            VersionRange(introduced="1.3.0", last_affected="1.3.0"),
        )

    def test_preserves_commit_only_git_identity(self):
        commit = "d34db33fd34db33fd34db33fd34db33fd34db33f"
        data = {
            "results": [
                {
                    "source": {"path": ".git", "type": "git"},
                    "packages": [
                        {
                            "package": {
                                "name": "",
                                "version": "",
                                "ecosystem": "GIT",
                                "commit": commit,
                            },
                            "vulnerabilities": [
                                {
                                    "id": "OSV-2026-1",
                                    "summary": "Commit vulnerability",
                                    "affected": [
                                        {
                                            "package": {
                                                "name": "https://example.test/acme/library",
                                                "ecosystem": "GIT",
                                            },
                                            "ranges": [
                                                {
                                                    "type": "GIT",
                                                    "repo": "https://example.test/acme/library",
                                                    "events": [{"introduced": commit}],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                            "groups": [{"ids": ["OSV-2026-1"]}],
                        }
                    ],
                }
            ]
        }

        parser = OsvScannerParser()
        assert parser.can_parse(data)
        vulnerability = parser.parse(data)[0]
        assert vulnerability.package_name == "https://example.test/acme/library"
        assert vulnerability.package_version == commit
        assert vulnerability.ecosystem == "git"
        assert vulnerability.affected_ranges == ()

    def test_preserves_multiple_ecosystem_intervals(self):
        data = {
            "results": [
                {
                    "source": {"path": "requirements.txt", "type": "lockfile"},
                    "packages": [
                        {
                            "package": {
                                "name": "requests",
                                "version": "2.5.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "OSV-2026-2",
                                    "affected": [
                                        {
                                            "package": {
                                                "name": "requests",
                                                "ecosystem": "PyPI",
                                            },
                                            "ranges": [
                                                {
                                                    "type": "ECOSYSTEM",
                                                    "events": [
                                                        {"introduced": "0"},
                                                        {"fixed": "1.0"},
                                                        {"introduced": "2.0"},
                                                        {"fixed": "3.0"},
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }

        vulnerability = OsvScannerParser().parse(data)[0]
        assert vulnerability.affected_ranges == (
            VersionRange(introduced="0", fixed="1.0"),
            VersionRange(introduced="2.0", fixed="3.0"),
        )

    def test_preserves_same_advisory_for_different_packages(self):
        entry = {
            "source": {"path": "requirements.txt", "type": "lockfile"},
            "packages": [
                {
                    "package": {"name": name, "version": version, "ecosystem": "PyPI"},
                    "vulnerabilities": [{"id": "CVE-2026-12345", "summary": "Issue"}],
                }
                for name, version in (("alpha", "1.0"), ("beta", "2.0"))
            ],
        }
        vulnerabilities = OsvScannerParser().parse({"results": [entry]})
        assert [(v.package_name, v.package_version) for v in vulnerabilities] == [
            ("alpha", "1.0"),
            ("beta", "2.0"),
        ]

    def test_deduplicates_same_finding_across_sources(self):
        package = {
            "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
            "vulnerabilities": [{"id": "CVE-2026-12345", "summary": "Issue"}],
        }
        data = {
            "results": [
                {
                    "source": {"path": path, "type": "lockfile"},
                    "packages": [package],
                }
                for path in ("requirements.txt", "requirements-dev.txt")
            ]
        }
        assert len(OsvScannerParser().parse(data)) == 1

    def test_empty_ecosystem_does_not_default_to_pypi(self):
        data = {
            "results": [
                {
                    "source": {"path": "custom.lock", "type": "unknown"},
                    "packages": [
                        {
                            "package": {
                                "name": "custom",
                                "version": "1.0",
                                "ecosystem": "",
                            },
                            "vulnerabilities": [
                                {
                                    "id": "CUSTOM-1",
                                    "affected": [
                                        {
                                            "package": {
                                                "name": "custom",
                                                "ecosystem": "PyPI",
                                            },
                                            "ranges": [
                                                {
                                                    "type": "ECOSYSTEM",
                                                    "events": [
                                                        {"introduced": "0"},
                                                        {"fixed": "2.0"},
                                                    ],
                                                }
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                }
            ]
        }
        parser = OsvScannerParser()
        assert parser.can_parse(data)
        vulnerabilities = parser.parse(data)
        assert vulnerabilities[0].ecosystem == ""
        assert vulnerabilities[0].affected_ranges == ()

    def test_malformed_entries_are_skipped_or_degraded_safely(self):
        data = {
            "results": [
                None,
                {"packages": "not-a-list"},
                {
                    "packages": [
                        None,
                        {"package": None, "vulnerabilities": []},
                        {
                            "package": {"name": "", "version": "1.0", "ecosystem": "PyPI"},
                            "vulnerabilities": [{"id": "SKIP-1"}],
                        },
                        {
                            "package": {
                                "name": "requests",
                                "version": "2.19.0",
                                "ecosystem": "PyPI",
                            },
                            "vulnerabilities": [
                                None,
                                {"id": ""},
                                {
                                    "id": "CVE-2026-12345",
                                    "aliases": "not-a-list",
                                    "severity": ["not-an-object"],
                                    "affected": ["not-an-object"],
                                    "references": ["not-an-object"],
                                },
                            ],
                            "groups": [None, {"ids": "not-a-list"}],
                        },
                    ]
                },
            ]
        }

        vulnerabilities = OsvScannerParser().parse(data)
        assert len(vulnerabilities) == 1
        assert vulnerabilities[0].id == "CVE-2026-12345"
        assert vulnerabilities[0].severity == "unknown"
        assert vulnerabilities[0].references == ()
        assert vulnerabilities[0].affected_ranges == ()

    def test_non_report_input_returns_no_findings(self):
        parser = OsvScannerParser()
        assert parser.parse([]) == []
        assert parser.parse({}) == []
        assert parser.parse({"results": "invalid"}) == []
