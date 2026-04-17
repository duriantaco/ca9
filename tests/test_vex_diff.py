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
