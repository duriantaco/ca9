from dataclasses import replace

import pytest

from ca9.scanner import resolve_scan_inventory, scan_repository

PUBLIC = '{ registry = "https://pypi.org/simple" }'


def package(name, version="1.0", *, source=PUBLIC, body=""):
    return f'\n[[package]]\nname = "{name}"\nversion = "{version}"\nsource = {source}\n{body}\n'


@pytest.mark.parametrize("filename", ["uv.lock", "fyn.lock"])
def test_scans_only_the_reachable_lock_edges_and_requested_extras(tmp_path, monkeypatch, filename):
    lock = "version = 1\n" + package(
        "app",
        source='{ editable = "." }',
        body='dependencies = [{ name = "requests", extra = ["cli"] }]\n'
        '[package.dev-dependencies]\ndev = [{ name = "pytest" }]\n'
        '[package.optional-dependencies]\nserver = [{ name = "optional" }]',
    )
    lock += package(
        "requests",
        body='dependencies = [{ name = "urllib3" }, { name = "other-os", marker = "sys_platform == \'not-this-os\'" }]\n'
        '[package.optional-dependencies]\ncli = [{ name = "click" }]',
    )
    lock += package("urllib3", body='dependencies = [{ name = "requests" }]')
    lock += "".join(package(name) for name in ("pytest", "optional", "other-os", "click", "unused"))
    (tmp_path / filename).write_text(lock)
    seen = []

    def query(queries):
        seen.extend((row["package"]["name"], row["version"]) for row in queries)
        return {"results": [{} for _ in queries]}

    monkeypatch.setattr("ca9.scanner.CACHE_DIR", tmp_path / "cache")
    monkeypatch.setattr("ca9.scanner._post_osv_batch", query)
    _, scan = scan_repository(tmp_path)
    assert sorted(seen) == [("click", "1.0"), ("requests", "1.0"), ("urllib3", "1.0")]
    assert scan.coverage().declared == 1
    assert scan.coverage().complete


def test_unambiguous_workspace_members_are_local_roots(tmp_path):
    lock = 'version = 1\n[manifest]\nmembers = ["app", "worker"]\n'
    lock += package(
        "app", source='{ editable = "apps/app" }', body='dependencies = [{ name = "worker" }]'
    )
    lock += package(
        "worker", source='{ editable = "apps/worker" }', body='dependencies = [{ name = "shared" }]'
    )
    lock += package("shared")
    lock += package("unrelated")
    (tmp_path / "uv.lock").write_text(lock)
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("shared", "1.0"),)
    assert not scan.warnings


def test_indeterminate_edges_never_become_public_lookup_or_complete(tmp_path):
    lock = "version = 1\n" + package(
        "app",
        source='{ virtual = "." }',
        body='dependencies = [{ name = "base" }, { name = "private" }, { name = "fork" }, '
        '{ name = "missing" }, { name = "malformed", marker = "not a marker" }]',
    )
    lock += package("base")
    lock += package(
        "private",
        source='{ registry = "https://packages.example.com/simple" }',
        body='dependencies = [{ name = "secondary" }]',
    )
    lock += package("secondary")
    lock += package("fork", version="1.1") + package("fork", version="1.2")
    lock += package("malformed")
    (tmp_path / "uv.lock").write_text(lock)
    scan = resolve_scan_inventory(tmp_path, allow_environment_fallback=True)
    assert scan.packages == (("base", "1.0"), ("secondary", "1.0"))
    assert scan.unresolved_dependencies == ("fork", "malformed", "missing", "private")
    assert not replace(scan, advisories_checked=2).coverage().complete


@pytest.mark.parametrize(
    "lock", ['version = "bad', "version = 42", 'version = 1\nrequires-python = "<2"\npackage = []']
)
def test_broken_or_incompatible_lock_keeps_independent_pins_and_marks_partial(tmp_path, lock):
    (tmp_path / "requirements.txt").write_text("base==1.0\n")
    (tmp_path / "uv.lock").write_text(lock)
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("base", "1.0"),)
    assert not replace(scan, advisories_checked=1).coverage().complete
    assert any("uv.lock" in warning for warning in scan.warnings)


def test_active_project_markers_and_locked_resolution_forks(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["base", "inactive; python_version < \'2\'"]\n'
        '[project.optional-dependencies]\ntest = ["explicit"]'
    )
    lock = "version = 1\n" + package(
        "app", source='{ editable = "." }', body='dependencies = [{ name = "base" }]'
    )
    lock += package("base", body='dependencies = [{ name = "fork" }]')
    lock += package("fork", version="1.0", body="resolution-markers = [\"python_version < '2'\"]")
    lock += package("fork", version="2.0", body="resolution-markers = [\"python_version >= '3'\"]")
    lock += package("explicit")
    (tmp_path / "uv.lock").write_text(lock)
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("base", "1.0"), ("explicit", "1.0"), ("fork", "2.0"))
    assert not scan.warnings


def test_unreadable_child_list_keeps_the_verified_parent_in_the_scan(tmp_path):
    lock = "version = 1\n" + package(
        "app", source='{ virtual = "." }', body='dependencies = [{ name = "base" }]'
    )
    lock += package("base", body='dependencies = "unknown"')
    (tmp_path / "uv.lock").write_text(lock)
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("base", "1.0"),)
    assert not replace(scan, advisories_checked=1).coverage().complete
    assert any("invalid dependency entries for base" in warning for warning in scan.warnings)


def test_unrelated_lock_root_does_not_supply_packages_or_versions(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["known==1.2"]'
    )
    lock = "version = 1\n" + package(
        "other", source='{ editable = "." }', body='dependencies = [{ name = "unrelated" }]'
    )
    (tmp_path / "uv.lock").write_text(lock + package("unrelated"))
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("known", "1.2"),)
    assert not replace(scan, advisories_checked=1).coverage().complete
    assert any("do not match app" in warning for warning in scan.warnings)


def test_committed_lock_must_satisfy_independent_manifest_range(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["sample>=2", "other"]'
    )
    lock = "version = 1\n" + package(
        "app",
        source='{ editable = "." }',
        body='dependencies = [{ name = "sample" }, { name = "other" }]',
    )
    lock += (
        package("sample", body='dependencies = [{ name = "old-helper" }]')
        + package("old-helper")
        + package("other")
    )
    (tmp_path / "uv.lock").write_text(lock)
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("other", "1.0"),)
    assert scan.unresolved_dependencies == ("sample",)
    assert not replace(scan, advisories_checked=1).coverage().complete


def test_equivalent_pep440_pins_match_both_the_manifest_and_lock_edge(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["sample==1.0.0"]'
    )
    lock = "version = 1\n" + package(
        "app",
        source='{ editable = "." }',
        body='dependencies = [{ name = "sample", version = "1.0.0" }]',
    )
    (tmp_path / "uv.lock").write_text(lock + package("sample", version="1.0"))
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("sample", "1.0"),)
    assert replace(scan, advisories_checked=1).coverage().complete


@pytest.mark.parametrize(
    "source", ["{}", '{ registry = "https://pypi.org/simple", path = "./internal" }']
)
def test_explicit_invalid_sources_cannot_use_the_legacy_missing_source_fallback(tmp_path, source):
    (tmp_path / "pyproject.toml").write_text('[project]\nname = "app"\ndependencies = ["internal"]')
    lock = "version = 1\n" + package(
        "app", source='{ editable = "." }', body='dependencies = [{ name = "internal" }]'
    )
    (tmp_path / "uv.lock").write_text(lock + package("internal", source=source))
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == ()
    assert scan.unresolved_dependencies == ("internal",)


def test_obsolete_public_release_cannot_override_a_local_project_source(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\ndependencies = ["internal"]\n[tool.uv.sources]\ninternal = { path = "../my-copy" }'
    )
    lock = "version = 1\n" + package(
        "app", source='{ editable = "." }', body='dependencies = [{ name = "internal" }]'
    )
    (tmp_path / "uv.lock").write_text(lock + package("internal"))
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == ()
    assert scan.unresolved_dependencies == ("internal",)


def test_fyn_requirement_edges_respect_specifiers_markers_and_requested_extras(tmp_path):
    lock = "version = 1\n" + package(
        "app", source='{ editable = "." }', body='dependencies = [{ requirement = "base[cli]>=1" }]'
    )
    lock += package(
        "base",
        body='dependencies = [{ requirement = "inactive; python_version < \'2\'" }, { requirement = "stale>4" }]\n'
        '[package.optional-dependencies]\ncli = [{ name = "click" }]',
    )
    lock += package("stale") + package("inactive") + package("click")
    (tmp_path / "fyn.lock").write_text(lock)
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("base", "1.0"), ("click", "1.0"))
    assert scan.unresolved_dependencies == ("stale",)


def test_requirements_and_nested_constraints_filter_markers_only_for_scan(tmp_path):
    from ca9.analysis.ast_scanner import discover_declared_dependency_inventory

    (tmp_path / "requirements.txt").write_text(
        "-r included.txt\n-c pins.txt\nconditional\nunavailable==1; sys_platform == 'not-this-os'\n"
    )
    (tmp_path / "included.txt").write_text(
        "choice==1; python_version < '2'\nchoice==2; python_version >= '3' --hash=sha256:abc\n"
    )
    (tmp_path / "pins.txt").write_text("-c nested-pins.txt\n")
    (tmp_path / "nested-pins.txt").write_text(
        "conditional==1; sys_platform == 'not-this-os'\nconditional==3; python_version >= '3'\n"
    )
    scan = resolve_scan_inventory(tmp_path)
    assert scan.packages == (("choice", "2"), ("conditional", "3"))
    assert not scan.warnings
    assert "unavailable" in discover_declared_dependency_inventory(tmp_path)
