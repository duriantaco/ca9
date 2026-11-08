"""UNREACHABLE must be a proof: regressions for import-name, indirect-use and submodule gaps."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ca9.analysis.ast_scanner import (
    PYPI_TO_IMPORT,
    collect_imports_from_source,
    pypi_to_import_name,
    resolve_transitive_deps,
)
from ca9.analysis.import_names import reset_environment_index, resolve_import_names
from ca9.engine import analyze
from ca9.models import AffectedComponent, Report, Verdict, Vulnerability
from ca9.vex import write_openvex


@pytest.fixture(autouse=True)
def _fresh_environment_index():
    reset_environment_index()
    yield
    reset_environment_index()


@pytest.fixture
def site(tmp_path, monkeypatch):
    """An isolated site-packages directory on sys.path for fake distributions."""
    site_dir = tmp_path / "site-packages"
    site_dir.mkdir()
    monkeypatch.syspath_prepend(str(site_dir))
    return site_dir


def install_dist(
    site_dir: Path,
    name: str,
    files: dict[str, str],
    *,
    version: str = "1.0.0",
    requires: tuple[str, ...] = (),
    entry_points: str | None = None,
    top_level: str | None = None,
) -> None:
    for rel, content in files.items():
        path = site_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    info = site_dir / f"{name.replace('-', '_')}-{version}.dist-info"
    info.mkdir()
    metadata = f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
    metadata += "".join(f"Requires-Dist: {req}\n" for req in requires)
    (info / "METADATA").write_text(metadata)
    record = [f"{rel},," for rel in files]
    if entry_points is not None:
        (info / "entry_points.txt").write_text(entry_points)
        record.append(f"{info.name}/entry_points.txt,,")
    if top_level is not None:
        (info / "top_level.txt").write_text(top_level)
        record.append(f"{info.name}/top_level.txt,,")
    record += [f"{info.name}/METADATA,,", f"{info.name}/RECORD,,"]
    (info / "RECORD").write_text("\n".join(record) + "\n")


def make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    for rel, content in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    return repo


def vuln(package: str, version: str = "1.0.0", **kwargs) -> Vulnerability:
    return Vulnerability(
        id=kwargs.pop("vuln_id", "V-1"),
        package_name=package,
        package_version=version,
        severity="high",
        title=kwargs.pop("title", f"Issue in {package}"),
        **kwargs,
    )


def no_installed_dists():
    return patch("ca9.analysis.ast_scanner.importlib.metadata.distributions", return_value=[])


class TestImportNameResolution:
    @pytest.mark.parametrize(
        ("package", "expected"),
        [
            ("GitPython", ("git",)),
            ("grpcio", ("grpc",)),
            ("psycopg2-binary", ("psycopg2",)),
            ("psycopg-binary", ("psycopg", "psycopg_binary")),
            ("beautifulsoup4", ("bs4",)),
            ("Pillow", ("PIL",)),
            ("opencv-python-headless", ("cv2",)),
            ("protobuf", ("google.protobuf",)),
            ("attrs", ("attr", "attrs")),
            ("pyzmq", ("zmq",)),
            ("pycryptodomex", ("Cryptodome",)),
            ("python-ldap", ("ldap", "ldif", "ldapurl")),
            ("mysqlclient", ("MySQLdb",)),
            ("discord.py", ("discord",)),
            ("faiss-cpu", ("faiss",)),
        ],
    )
    def test_curated_mapping_without_metadata(self, package, expected):
        with no_installed_dists():
            resolution = resolve_import_names(package)
        assert resolution.names == expected
        assert resolution.source == "curated"
        assert resolution.authoritative
        assert resolution.installed is False

    def test_unknown_package_is_guessed(self):
        with no_installed_dists():
            resolution = resolve_import_names("totally-unknown-dist")
        assert resolution.names == ("totally_unknown_dist",)
        assert resolution.source == "guessed"
        assert not resolution.authoritative

    def test_metadata_record_wins_over_guess(self, site):
        install_dist(site, "acme-tools", {"acmelib/__init__.py": "", "acmelib/core.py": ""})
        resolution = resolve_import_names("Acme_Tools")
        assert resolution.names == ("acmelib",)
        assert resolution.source == "metadata"
        assert resolution.installed

    def test_metadata_top_level_txt(self, site):
        install_dist(site, "xyz-dist", {"xyzmod/__init__.py": ""}, top_level="xyzmod\n")
        assert resolve_import_names("xyz-dist").names == ("xyzmod",)

    def test_namespace_package_is_refined_to_subpackage(self, site):
        install_dist(site, "nsco-widgets", {"nsco/widgets/__init__.py": ""}, top_level="nsco\n")
        assert resolve_import_names("nsco-widgets").names == ("nsco.widgets",)

    def test_private_and_test_modules_are_not_import_names(self, site):
        install_dist(
            site,
            "acme-fast",
            {"acmefast/__init__.py": "", "_acmefast_speedups.py": "", "tests/__init__.py": ""},
        )
        assert resolve_import_names("acme-fast").names == ("acmefast",)

    def test_compat_helpers(self):
        assert PYPI_TO_IMPORT["gitpython"] == "git"
        with no_installed_dists():
            assert pypi_to_import_name("GitPython") == "git"
            assert pypi_to_import_name("my-package") == "my_package"

    def test_transitive_graph_uses_metadata_import_names(self, site):
        install_dist(site, "Acme-Client", {"acmeclient/__init__.py": ""}, requires=("acme-dep>=1",))
        install_dist(site, "acme-dep", {"acmedep/__init__.py": ""})
        transitive, available = resolve_transitive_deps({"acmeclient"})
        assert available
        assert transitive.get("acme-dep") == "acme-client"


class TestImportCollection:
    def test_records_root_and_parent_packages(self):
        imports = collect_imports_from_source("from django.http import HttpResponse\n")
        assert {"django", "django.http", "django.http.HttpResponse"} <= imports

    def test_dotted_import_records_parents(self):
        imports = collect_imports_from_source("import google.protobuf.json_format\n")
        assert {"google", "google.protobuf", "google.protobuf.json_format"} <= imports

    def test_relative_imports_are_project_modules(self):
        imports = collect_imports_from_source("from .git import helpers\nfrom . import yaml\n")
        assert "git" not in imports
        assert "yaml" not in imports


class TestImportNameVerdicts:
    def test_gitpython_imported_as_git_is_not_never_imported(self, tmp_path):
        repo = make_repo(
            tmp_path,
            {"requirements.txt": "GitPython==3.1.0\n", "app.py": "import git\n"},
        )
        for standard in ("strict", "balanced"):
            with no_installed_dists():
                result = analyze([vuln("GitPython", "3.1.0")], repo, proof_standard=standard)
            r = result.results[0]
            assert r.verdict == Verdict.INCONCLUSIVE
            assert r.evidence.package_imported is True
            assert r.evidence.dependency_kind == "direct"
            assert r.imported_as == "git"

    def test_guessed_report_chain_root_is_inconclusive(self, tmp_path):
        repo = make_repo(tmp_path, {"app.py": "import acmewrapper\n"})
        v = vuln(
            "markupsafe",
            report_dependency_kind="transitive",
            report_dependency_chain=("acme-wrapper", "markupsafe"),
        )
        with no_installed_dists():
            result = analyze([v], repo, proof_standard="balanced").results[0]
        assert result.verdict == Verdict.INCONCLUSIVE
        assert "'acme-wrapper' was guessed" in result.reason


class TestIndirectUse:
    @pytest.mark.parametrize("standard", ["strict", "balanced"])
    def test_declared_server_without_import_is_inconclusive(self, tmp_path, standard):
        repo = make_repo(
            tmp_path,
            {"requirements.txt": "flask==2.2.0\ngunicorn==20.1.0\n", "app.py": "import flask\n"},
        )
        with no_installed_dists():
            result = analyze([vuln("gunicorn", "20.1.0")], repo, proof_standard=standard)
        r = result.results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert "command line" in r.reason

    def test_parser_named_by_string_is_inconclusive(self, tmp_path):
        repo = make_repo(
            tmp_path,
            {
                "requirements.txt": "beautifulsoup4==4.11.0\nlxml==4.6.0\n",
                "app.py": 'from bs4 import BeautifulSoup\nBeautifulSoup("<p/>", "lxml")\n',
            },
        )
        with no_installed_dists():
            r = analyze([vuln("lxml", "4.6.0")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert "'lxml' is named in app.py" in r.reason

    def _engine_repo(self, tmp_path, site, app_source: str, extra: dict[str, str] | None = None):
        install_dist(site, "acme-engine", {"acme_engine/__init__.py": ""})
        files = {"requirements.txt": "acme-engine==1.0.0\n", "app.py": app_source}
        files.update(extra or {})
        return make_repo(tmp_path, files)

    def test_authoritative_mapping_without_signals_is_unreachable_in_balanced(self, tmp_path, site):
        repo = self._engine_repo(tmp_path, site, "import json\n")
        report = analyze([vuln("acme-engine")], repo, proof_standard="balanced")
        r = report.results[0]
        assert r.verdict == Verdict.UNREACHABLE_STATIC
        assert r.evidence.import_name_source == "metadata"
        statement = json.loads(write_openvex(report))["statements"][0]
        # Installed and declared, just never imported: present but not executed.
        assert statement["justification"] == "vulnerable_code_not_in_execute_path"

        strict = analyze([vuln("acme-engine")], repo, proof_standard="strict").results[0]
        assert strict.verdict == Verdict.INCONCLUSIVE
        assert "declared but no import found" in strict.reason

    @pytest.mark.parametrize(
        "app_source",
        [
            'read_table("x.bin", engine="acme_engine")\n',
            'create_engine("postgresql+acme_engine://user@db/app")\n',
            'subprocess.run(["acme_engine", "--serve"])\n',
            'WORKER = "acme_engine.workers:Fast"\n',
        ],
    )
    def test_string_reference_in_python_is_inconclusive(self, tmp_path, site, app_source):
        repo = self._engine_repo(tmp_path, site, app_source)
        r = analyze([vuln("acme-engine")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert "named in app.py" in r.reason

    def test_docstrings_and_setup_requirements_are_not_references(self, tmp_path, site):
        repo = self._engine_repo(
            tmp_path,
            site,
            '"""acme_engine powers this."""\n',
            {"setup.py": 'setup(install_requires=["acme_engine"])\n'},
        )
        r = analyze([vuln("acme-engine")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.UNREACHABLE_STATIC

    @pytest.mark.parametrize(
        ("filename", "content"),
        [
            ("Procfile", "web: acme_engine app:app\n"),
            ("Dockerfile", 'CMD ["acme_engine", "app:app"]\n'),
            ("Dockerfile.prod", 'ENTRYPOINT ["/usr/local/bin/acme_engine", "-w", "4"]\n'),
            ("bin/start.sh", "exec python -m acme_engine --bind :8000\n"),
            ("deploy/server.ini", "[server]\nrunner = acme_engine\n"),
            ("pyproject.toml", '[tool.poe.tasks]\nserve = "acme_engine app:app"\n'),
        ],
    )
    def test_config_reference_is_inconclusive(self, tmp_path, site, filename, content):
        repo = self._engine_repo(tmp_path, site, "import json\n", {filename: content})
        r = analyze([vuln("acme-engine")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert f"named in {filename}" in r.reason

    def test_dependency_declarations_are_not_references(self, tmp_path, site):
        repo = self._engine_repo(
            tmp_path,
            site,
            "import json\n",
            {
                "pyproject.toml": '[project]\nname = "app"\ndependencies = ["acme_engine==1.0.0"]\n',
                "setup.cfg": "[options]\ninstall_requires =\n    acme_engine\n",
                "tox.ini": "[testenv]\ndeps = acme_engine\n",
            },
        )
        r = analyze([vuln("acme-engine")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.UNREACHABLE_STATIC

    def test_plugin_entry_points_make_it_inconclusive(self, tmp_path, site):
        install_dist(
            site,
            "acme-plugin",
            {"acme_plugin/__init__.py": ""},
            entry_points="[pytest11]\nacme = acme_plugin.hooks\n",
        )
        repo = make_repo(tmp_path, {"requirements.txt": "acme-plugin==1.0.0\n", "app.py": ""})
        r = analyze([vuln("acme-plugin")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert "declares entry points (pytest11: acme)" in r.reason

    @pytest.mark.parametrize(
        ("filename", "content"),
        [
            ("Makefile", "migrate:\n\tacme-run upgrade head\n"),
            (".github/workflows/deploy.yml", "steps:\n  - run: acme-run upgrade head\n"),
        ],
    )
    def test_invoked_console_script_makes_it_inconclusive(self, tmp_path, site, filename, content):
        install_dist(
            site,
            "acme-cli",
            {"acme_cli/__init__.py": ""},
            entry_points="[console_scripts]\nacme-run = acme_cli:main\n",
        )
        repo = make_repo(
            tmp_path,
            {"requirements.txt": "acme-cli==1.0.0\n", "app.py": "", filename: content},
        )
        r = analyze([vuln("acme-cli")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert f"installs a command: 'acme-run' is named in {filename}" in r.reason

    def test_unreferenced_console_script_stays_unreachable_in_balanced(self, tmp_path, site):
        install_dist(
            site,
            "acme-cli",
            {"acme_cli/__init__.py": ""},
            entry_points="[console_scripts]\nacme-run = acme_cli:main\n",
        )
        repo = make_repo(tmp_path, {"requirements.txt": "acme-cli==1.0.0\n", "app.py": ""})
        balanced = analyze([vuln("acme-cli")], repo, proof_standard="balanced").results[0]
        strict = analyze([vuln("acme-cli")], repo, proof_standard="strict").results[0]
        assert balanced.verdict == Verdict.UNREACHABLE_STATIC
        assert strict.verdict == Verdict.INCONCLUSIVE

    def test_optional_dependency_of_imported_package_is_inconclusive(self, tmp_path, site):
        install_dist(
            site,
            "acme-frames",
            {"acmeframes/__init__.py": ""},
            requires=('acme-xlsx; extra == "excel"',),
        )
        install_dist(site, "acme-xlsx", {"acmexlsx/__init__.py": ""})
        repo = make_repo(
            tmp_path,
            {
                "requirements.txt": "acme-frames==1.0.0\nacme-xlsx==1.0.0\n",
                "app.py": "import acmeframes\n",
            },
        )
        r = analyze([vuln("acme-xlsx")], repo, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert "optional dependency of imported 'acme-frames'" in r.reason

    def test_incomplete_environment_graph_cannot_prove_transitive_absence(self, tmp_path, site):
        install_dist(site, "acme-client", {"acmeclient/__init__.py": ""})
        install_dist(site, "acme-orphan", {"acmeorphan/__init__.py": ""})
        complete = make_repo(tmp_path, {"app.py": "import acmeclient\n"})
        r = analyze([vuln("acme-orphan")], complete, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.UNREACHABLE_STATIC

        # Optional imports of missing modules load nothing in this environment.
        (complete / "compat.py").write_text(
            "try:\n    import fastjsonlib\nexcept ImportError:\n    import slowjsonlib\n"
        )
        r = analyze([vuln("acme-orphan")], complete, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.UNREACHABLE_STATIC

        (complete / "web.py").write_text("import notinstalledframework\n")
        r = analyze([vuln("acme-orphan")], complete, proof_standard="balanced").results[0]
        assert r.verdict == Verdict.INCONCLUSIVE
        assert "notinstalledframework" in r.reason
        assert r.evidence.dependency_graph_unresolved == ("notinstalledframework",)

    def test_vulnerable_api_call_without_matched_import_is_inconclusive(self):
        from ca9.engine import derive_verdict
        from ca9.models import ApiUsageHit, Evidence

        evidence = Evidence(
            package_imported=False,
            declared_direct_dependency=True,
            import_name_source="metadata",
            api_usage_seen=True,
            api_usage_hits=(ApiUsageHit("app.py", 3, matched_target="acme.load"),),
        )
        component = AffectedComponent("acme")
        result = derive_verdict(vuln("acme"), evidence, "acme", component, None, False)
        assert result.verdict == Verdict.INCONCLUSIVE
        assert "vulnerable API call" in result.reason


class TestSubmoduleSoundness:
    TEMPLATE_PACKAGE = {
        "acmetpl/__init__.py": "from .environment import Environment\n",
        "acmetpl/environment.py": "from . import defaults\nclass Environment: pass\n",
        "acmetpl/defaults.py": "from .filters import FILTERS\n",
        "acmetpl/filters.py": "FILTERS = {}\n",
        "acmetpl/sandbox.py": "from .environment import Environment\n",
        "acmetpl/unused.py": "VALUE = 1\n",
    }

    def _analyze(
        self, tmp_path, site, monkeypatch, targets, *, standard, version="1.0.0", package=None
    ):
        install_dist(site, "acme-tpl", package or self.TEMPLATE_PACKAGE)
        repo = make_repo(
            tmp_path,
            {
                "requirements.txt": "acme-tpl==1.0.0\n",
                "app.py": "from acmetpl.sandbox import SandboxedEnvironment\n",
            },
        )
        component = AffectedComponent("acmetpl", targets, confidence="high")
        monkeypatch.setattr("ca9.engine.extract_affected_component", lambda _v: component)
        return analyze([vuln("acme-tpl", version)], repo, proof_standard=standard).results[0]

    @pytest.mark.parametrize("standard", ["strict", "balanced"])
    def test_library_internal_import_reaches_affected_submodule(
        self, tmp_path, site, monkeypatch, standard
    ):
        r = self._analyze(tmp_path, site, monkeypatch, ("acmetpl.filters",), standard=standard)
        assert r.verdict == Verdict.INCONCLUSIVE
        assert r.evidence.submodule_imported is True
        assert "internal imports" in r.reason

    def test_unloaded_submodule_is_unreachable_only_in_balanced(self, tmp_path, site, monkeypatch):
        r = self._analyze(tmp_path, site, monkeypatch, ("acmetpl.unused",), standard="balanced")
        assert r.verdict == Verdict.UNREACHABLE_STATIC
        assert r.evidence.submodule_imported is False
        assert "installed 'acmetpl' source" in r.reason
        report = Report([r], ".")
        statement = json.loads(write_openvex(report))["statements"][0]
        assert statement["justification"] == "vulnerable_code_not_in_execute_path"

    def test_unloaded_submodule_is_inconclusive_in_strict(self, tmp_path, site, monkeypatch):
        r = self._analyze(tmp_path, site, monkeypatch, ("acmetpl.unused",), standard="strict")
        assert r.verdict == Verdict.INCONCLUSIVE
        assert r.original_verdict == Verdict.UNREACHABLE_STATIC

    def test_lazy_module_getattr_is_inconclusive(self, tmp_path, site, monkeypatch):
        package = dict(self.TEMPLATE_PACKAGE)
        package["acmetpl/__init__.py"] = (
            "import importlib\n"
            "def __getattr__(name):\n"
            '    return importlib.import_module("." + name, __name__)\n'
        )
        r = self._analyze(
            tmp_path, site, monkeypatch, ("acmetpl.unused",), standard="balanced", package=package
        )
        assert r.verdict == Verdict.INCONCLUSIVE
        assert r.evidence.submodule_imported is None
        assert "__getattr__" in r.reason

    def test_installed_version_mismatch_is_inconclusive(self, tmp_path, site, monkeypatch):
        r = self._analyze(
            tmp_path, site, monkeypatch, ("acmetpl.unused",), standard="balanced", version="2.0.0"
        )
        assert r.verdict == Verdict.INCONCLUSIVE
        assert r.evidence.submodule_imported is None
        assert "not the reported 2.0.0" in r.reason

    @pytest.mark.parametrize("standard", ["strict", "balanced"])
    def test_django_settings_strings_count_as_submodule_imports(self, tmp_path, standard):
        repo = make_repo(
            tmp_path,
            {
                "requirements.txt": "django==4.2.0\n",
                "mysite/settings.py": (
                    'INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions"]\n'
                    'MIDDLEWARE = ["django.contrib.sessions.middleware.SessionMiddleware"]\n'
                    'SESSION_ENGINE = "django.contrib.sessions.backends.db"\n'
                ),
                "mysite/views.py": (
                    "from django.http import HttpResponse\n"
                    "def index(request):\n"
                    '    request.session["x"] = 1\n'
                    '    return HttpResponse("ok")\n'
                ),
            },
        )
        vulns = [
            vuln("django", "4.2.0", vuln_id="SESS", title="Session fixation in sessions"),
            vuln("django", "4.2.0", vuln_id="AUTH", title="Password reset authentication bypass"),
        ]
        with no_installed_dists():
            results = analyze(vulns, repo, proof_standard=standard).results
        for r in results:
            assert r.verdict == Verdict.INCONCLUSIVE
            assert r.evidence.submodule_imported is True
            assert "mysite/settings.py" in r.reason


def _narrowed_component():
    return AffectedComponent(
        "acme",
        submodule_paths=("acme.constructor",),
        confidence="high",
        extraction_source="commit_analysis",
    )


def _api_call_evidence(**overrides):
    from ca9.models import ApiUsageHit, Evidence

    fields = {
        "package_imported": True,
        "dependency_kind": "direct",
        "api_usage_seen": True,
        "api_usage_hits": (ApiUsageHit("app.py", 3, matched_target="acme.load"),),
    }
    fields.update(overrides)
    return Evidence(**fields)


class TestLocatedCallOutweighsSubmoduleGuess:
    """A fix commit narrows the affected file; a located call is direct evidence.
    Whether GitHub answered must not decide the verdict for the same code."""

    @pytest.mark.parametrize("submodule_imported", [None, False, True])
    def test_call_is_reachable_whatever_the_submodule_check_says(self, submodule_imported):
        from ca9.engine import derive_verdict

        evidence = _api_call_evidence(submodule_imported=submodule_imported)
        result = derive_verdict(vuln("acme"), evidence, "acme", _narrowed_component(), None, False)
        assert result.verdict == Verdict.REACHABLE
        assert "vulnerable API call" in result.reason

    def test_verdict_is_the_same_with_and_without_commit_analysis(self):
        from ca9.engine import derive_verdict

        narrowed = derive_verdict(
            vuln("acme"),
            _api_call_evidence(submodule_imported=False),
            "acme",
            _narrowed_component(),
            None,
            False,
        )
        unnarrowed = derive_verdict(
            vuln("acme"), _api_call_evidence(), "acme", AffectedComponent("acme"), None, False
        )
        assert narrowed.verdict == unnarrowed.verdict == Verdict.REACHABLE

    def test_unexecuted_call_site_stays_inconclusive_not_unreachable(self):
        from ca9.engine import derive_verdict

        evidence = _api_call_evidence(
            submodule_imported=False, coverage_seen=False, api_call_sites_covered=False
        )
        result = derive_verdict(vuln("acme"), evidence, "acme", _narrowed_component(), None, True)
        assert result.verdict == Verdict.INCONCLUSIVE
        assert "call sites not executed" in result.reason

    def test_version_outside_the_range_still_beats_a_call(self):
        from ca9.engine import derive_verdict

        evidence = _api_call_evidence(version_in_range=False)
        result = derive_verdict(vuln("acme"), evidence, "acme", _narrowed_component(), None, False)
        assert result.verdict == Verdict.UNREACHABLE_STATIC

    def test_unloaded_submodule_without_a_call_is_still_unreachable(self):
        from ca9.engine import derive_verdict

        evidence = _api_call_evidence(
            submodule_imported=False, api_usage_seen=False, api_usage_hits=()
        )
        result = derive_verdict(vuln("acme"), evidence, "acme", _narrowed_component(), None, False)
        assert result.verdict == Verdict.UNREACHABLE_STATIC

    def test_import_without_a_call_or_coverage_is_still_inconclusive(self):
        from ca9.engine import derive_verdict

        evidence = _api_call_evidence(
            submodule_imported=None, api_usage_seen=False, api_usage_hits=()
        )
        result = derive_verdict(vuln("acme"), evidence, "acme", _narrowed_component(), None, False)
        assert result.verdict == Verdict.INCONCLUSIVE
