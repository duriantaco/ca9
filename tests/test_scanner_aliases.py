import json

import pytest

from ca9 import scanner
from ca9.remediation import common_fix_version


def _record(primary, alias, *, fixed="2", summary="Example advisory"):
    return {
        "id": primary,
        "aliases": [alias, "CVE-2024-1234"],
        "summary": summary,
        "references": [{"url": f"https://example.org/{primary}"}],
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "demo"},
                "ranges": [
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}
                ],
                "versions": ["1.0", "1.1"],
            }
        ],
    }


def _serve(monkeypatch, tmp_path, records):
    monkeypatch.setattr(scanner, "CACHE_DIR", tmp_path)
    for row in records:
        (tmp_path / (row["id"] + ".json")).write_text(json.dumps(row))
    monkeypatch.setattr(
        scanner,
        "_post_osv_batch",
        lambda queries: {
            "results": [{"vulns": [{"id": r["id"]} for r in records]} for _ in queries]
        },
    )


def test_equivalent_osv_records_retain_fixes_identity_and_links_online_and_offline(
    tmp_path, monkeypatch
):
    ghsa, pysec = "GHSA-2222-3333-4444", "PYSEC-2024-1"
    records = [_record(pysec, ghsa), _record(ghsa, pysec)]
    records[0]["database_specific"] = {"cwe_ids": ["CWE-20"]}
    _serve(monkeypatch, tmp_path, records)
    lookups = [("demo", "1.0"), ("demo", "1.1")]
    legacy = scanner.query_osv_batch(lookups, offline=True)
    online = scanner.query_osv_batch(lookups)
    offline = scanner.query_osv_batch(lookups, offline=True)

    for rows in (legacy, online, offline):
        assert [(row.id, row.package_version) for row in rows] == [(ghsa, "1.0"), (ghsa, "1.1")]
        for row in rows:
            assert row.aliases == ("CVE-2024-1234", pysec)
            assert row.cwes == ("CWE-20",)
            assert row.affected_versions == ("1.0", "1.1")
            assert common_fix_version([row]) == "2"
            for advisory in (ghsa, pysec):
                assert f"https://example.org/{advisory}" in row.references
                assert f"https://osv.dev/vulnerability/{advisory}" in row.references


@pytest.mark.parametrize(
    "difference", ["one_way", "related", "fixed", "scope", "description", "patch"]
)
def test_uncertain_or_conflicting_advisories_remain_separate(tmp_path, monkeypatch, difference):
    primary, alias = "TEST-1", "TEST-2"
    first = _record(primary, alias)
    second = _record(alias, primary)
    if difference == "one_way":
        second["aliases"] = ["CVE-2024-1234"]
    elif difference == "related":
        for row in (first, second):
            row["related"] = row.pop("aliases")
            row["aliases"] = ["CVE-2024-1234"]
    elif difference == "fixed":
        second = _record(alias, primary, fixed="3")
    elif difference == "scope":
        second["affected"][0]["versions"] = ["1.0"]
    elif difference == "description":
        second["details"] = "Different affected submodule"
    else:
        second["references"].append({"url": "https://github.com/example/demo/commit/aaaaaaa"})
    _serve(monkeypatch, tmp_path, [first, second])
    assert [row.id for row in scanner.query_osv_batch([("demo", "1.0")])] == [primary, alias]
