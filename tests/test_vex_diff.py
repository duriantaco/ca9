from __future__ import annotations

from ca9.vex_diff import compute_vex_diff


def _make_statement(vuln_id: str, pkg: str, status: str, justification: str | None = None):
    stmt = {
        "vulnerability": {"name": vuln_id, "@id": f"https://osv.dev/vulnerability/{vuln_id}"},
        "products": [{"@id": f"pkg:pypi/{pkg}@1.0.0"}],
        "status": status,
    }
    if justification:
        stmt["justification"] = justification
    return stmt


def _make_vex(*statements, timestamp="2024-01-01T00:00:00Z"):
    return {"timestamp": timestamp, "statements": list(statements)}


class TestVEXDiff:
    def test_no_changes(self):
        stmt = _make_statement("CVE-1", "requests", "not_affected", "component_not_present")
        base = _make_vex(stmt, timestamp="2024-01-01T00:00:00Z")
        head = _make_vex(stmt, timestamp="2024-01-02T00:00:00Z")

        diff = compute_vex_diff(base, head)

        assert diff.unchanged_count == 1
        assert len(diff.became_affected) == 0
        assert not diff.has_regressions

    def test_became_affected(self):
        base = _make_vex(
            _make_statement("CVE-1", "requests", "not_affected", "component_not_present")
        )
        head = _make_vex(_make_statement("CVE-1", "requests", "affected"))

        diff = compute_vex_diff(base, head)

        assert len(diff.became_affected) == 1
        assert diff.became_affected[0].change_type == "became_affected"
        assert diff.became_affected[0].vuln_id == "CVE-1"
        assert diff.has_regressions

    def test_became_safe(self):
        base = _make_vex(_make_statement("CVE-1", "requests", "affected"))
        head = _make_vex(
            _make_statement(
                "CVE-1", "requests", "not_affected", "vulnerable_code_not_in_execute_path"
            )
        )

        diff = compute_vex_diff(base, head)

        assert len(diff.became_safe) == 1
        assert diff.became_safe[0].change_type == "became_safe"
        assert not diff.has_regressions

    def test_new_vulnerability(self):
        base = _make_vex()
        head = _make_vex(_make_statement("CVE-NEW", "flask", "affected"))

        diff = compute_vex_diff(base, head)

        assert len(diff.new_vulns) == 1
        assert diff.new_vulns[0].vuln_id == "CVE-NEW"
        assert diff.has_regressions

    def test_removed_vulnerability(self):
        base = _make_vex(_make_statement("CVE-OLD", "django", "affected"))
        head = _make_vex()

        diff = compute_vex_diff(base, head)

        assert len(diff.removed_vulns) == 1
        assert diff.removed_vulns[0].vuln_id == "CVE-OLD"
        assert not diff.has_regressions

    def test_under_investigation_to_affected(self):
        base = _make_vex(_make_statement("CVE-1", "requests", "under_investigation"))
        head = _make_vex(_make_statement("CVE-1", "requests", "affected"))

        diff = compute_vex_diff(base, head)

        assert len(diff.became_affected) == 1
        assert diff.has_regressions

    def test_mixed_changes(self):
        base = _make_vex(
            _make_statement("CVE-1", "requests", "not_affected", "component_not_present"),
            _make_statement("CVE-2", "flask", "affected"),
            _make_statement("CVE-3", "django", "under_investigation"),
        )
        head = _make_vex(
            _make_statement("CVE-1", "requests", "affected"),
            _make_statement(
                "CVE-2", "flask", "not_affected", "vulnerable_code_not_in_execute_path"
            ),
            _make_statement("CVE-4", "urllib3", "affected"),
        )

        diff = compute_vex_diff(base, head)

        assert len(diff.became_affected) == 1  # CVE-1
        assert len(diff.became_safe) == 1  # CVE-2
        assert len(diff.new_vulns) == 1  # CVE-4
        assert len(diff.removed_vulns) == 1  # CVE-3
        assert diff.has_regressions

    def test_to_dict_summary(self):
        base = _make_vex(
            _make_statement("CVE-1", "requests", "not_affected", "component_not_present")
        )
        head = _make_vex(_make_statement("CVE-1", "requests", "affected"))

        diff = compute_vex_diff(base, head)
        data = diff.to_dict()

        assert data["summary"]["became_affected"] == 1
        assert data["summary"]["requires_attention"] == 1

    def test_extracts_package_from_purl(self):
        base = _make_vex()
        head = _make_vex(_make_statement("CVE-1", "requests", "affected"))

        diff = compute_vex_diff(base, head)

        assert diff.new_vulns[0].package == "requests"
        assert diff.new_vulns[0].version == "1.0.0"


class TestVEXDiffWithEvidenceBasedJustifications:
    def test_justification_remap_is_a_status_change_not_a_regression(self):
        base = _make_vex(
            _make_statement("CVE-1", "gitpython", "not_affected", "component_not_present")
        )
        head = _make_vex(
            _make_statement(
                "CVE-1", "gitpython", "not_affected", "vulnerable_code_not_in_execute_path"
            )
        )

        diff = compute_vex_diff(base, head)

        assert diff.status_changed[0].old_justification == "component_not_present"
        assert diff.status_changed[0].new_justification == "vulnerable_code_not_in_execute_path"
        assert not diff.has_regressions

    def test_generated_documents_diff_by_verdict(self):
        import json

        from ca9.models import Evidence, Report, Verdict, VerdictResult, Vulnerability
        from ca9.vex import write_openvex

        vuln = Vulnerability("CVE-1", "gunicorn", "20.1.0", "high", "smuggling")
        static = VerdictResult(
            vuln,
            Verdict.UNREACHABLE_STATIC,
            "declared but never imported",
            evidence=Evidence(package_imported=False, declared_direct_dependency=True),
        )
        inconclusive = VerdictResult(vuln, Verdict.INCONCLUSIVE, "may be used via CLI")

        base = json.loads(write_openvex(Report([static], ".")))
        head = json.loads(write_openvex(Report([inconclusive], ".")))
        diff = compute_vex_diff(base, head)

        change = diff.status_changed[0]
        assert change.old_status == "not_affected"
        assert change.old_justification == "vulnerable_code_not_in_execute_path"
        assert change.new_status == "under_investigation"
        assert change.new_justification is None
