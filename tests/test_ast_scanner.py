from __future__ import annotations

import sys

from ca9.analysis.ast_scanner import (
    collect_imports_from_repo,
    collect_imports_from_source,
    discover_declared_dependencies,
    discover_declared_dependency_inventory,
    is_package_imported,
    is_submodule_imported,
    pypi_to_import_name,
)


class TestPypiToImportName:
    def test_simple_name(self):
        assert pypi_to_import_name("requests") == "requests"

    def test_hyphenated_name(self):
        assert pypi_to_import_name("my-package") == "my_package"

    def test_pillow(self):
        assert pypi_to_import_name("Pillow") == "PIL"

    def test_pyyaml(self):
        assert pypi_to_import_name("PyYAML") == "yaml"

    def test_scikit_learn(self):
        assert pypi_to_import_name("scikit-learn") == "sklearn"

    def test_python_dateutil(self):
        assert pypi_to_import_name("python-dateutil") == "dateutil"


class TestCollectImports:
    def test_import_statement(self):
        source = "import os\nimport json\n"
        imports = collect_imports_from_source(source)
        assert "os" in imports
        assert "json" in imports

    def test_from_import(self):
        source = "from pathlib import Path\nfrom os.path import join\n"
        imports = collect_imports_from_source(source)
        assert "pathlib" in imports
        assert "pathlib.Path" in imports
        assert "os.path" in imports
        assert "os.path.join" in imports

    def test_mixed_imports(self):
        source = "import requests\nfrom yaml import safe_load\nfrom PIL import Image\n"
        imports = collect_imports_from_source(source)
        assert "requests" in imports
        assert "yaml" in imports
        assert "yaml.safe_load" in imports
        assert "PIL" in imports
        assert "PIL.Image" in imports

    def test_from_import_records_dotted_names(self):
        source = "from jinja2 import sandbox, Environment\n"
        imports = collect_imports_from_source(source)
        assert "jinja2" in imports
        assert "jinja2.sandbox" in imports
        assert "jinja2.Environment" in imports

    def test_star_import_does_not_record_star(self):
        source = "from jinja2 import *\n"
        imports = collect_imports_from_source(source)
        assert "jinja2" in imports
        assert "jinja2.*" not in imports

    def test_syntax_error_returns_empty(self):
        source = "def foo(:\n  pass"
        imports = collect_imports_from_source(source)
        assert imports == set()

    def test_collect_from_repo(self, sample_repo):
        imports = collect_imports_from_repo(sample_repo)
        assert "requests" in imports
        assert "yaml" in imports
        assert "PIL" in imports

    def test_collect_from_repo_skips_non_runtime_paths(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("import requests\n")
        (repo / "tests").mkdir()
        (repo / "tests" / "test_app.py").write_text("import django\n")
        (repo / "demo").mkdir()
        (repo / "demo" / "script.py").write_text("import flask\n")

        imports = collect_imports_from_repo(repo)

        assert "requests" in imports
        assert "django" not in imports
        assert "flask" not in imports


class TestDeclaredDependencies:
    def test_discovers_dependencies_from_requirements_and_pyproject(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("requests==2.31.0\n-r extras.txt\n")
        (repo / "extras.txt").write_text("PyYAML>=6.0\n")
        (repo / "pyproject.toml").write_text(
            '[project]\ndependencies = ["Pillow>=10"]\n\n[tool.poetry.dependencies]\npython = "^3.12"\ndjango = "^5.0"\n'
        )

        deps = discover_declared_dependencies(repo)

        assert "requests" in deps
        assert "pyyaml" in deps
        assert "pillow" in deps
        assert "django" in deps

    def test_discovers_dependency_inventory_with_exact_pins(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "requirements.txt").write_text("requests==2.31.0\n-r extras.txt\n")
        (repo / "extras.txt").write_text("PyYAML>=6.0\n")
        (repo / "pyproject.toml").write_text(
            '[project]\ndependencies = ["Pillow==10.4.0"]\n\n[tool.poetry.dependencies]\npython = "^3.12"\ndjango = "^5.0"\nflask = "3.0.2"\n'
        )

        deps = discover_declared_dependency_inventory(repo)

        assert deps["requests"] == ("requests", "2.31.0")
        assert deps["pyyaml"] == ("PyYAML", None)
        assert deps["pillow"] == ("Pillow", "10.4.0")
        assert deps["django"] == ("django", None)
        assert deps["flask"] == ("flask", "3.0.2")

    def test_discovers_dependency_inventory_from_uv_lock(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "pyproject.toml").write_text(
            '[project]\nname = "demo-app"\ndependencies = ["requests>=2.0", "networkx>=3.0"]\n'
        )
        (repo / "uv.lock").write_text(
            """
version = 1

[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "networkx"
version = "3.4.2"

[[package]]
name = "networkx"
version = "3.6.1"

[[package]]
name = "demo-app"
version = "0.1.0"
source = { editable = "." }
dependencies = [
    { name = "requests" },
    { name = "networkx", version = "3.4.2", marker = "python_full_version < '3.11'" },
    { name = "networkx", version = "3.6.1", marker = "python_full_version >= '3.11'" },
]
""".strip()
        )

        deps = discover_declared_dependency_inventory(repo)

        assert deps["requests"] == ("requests", "2.32.3")
        expected_networkx = "3.6.1" if sys.version_info >= (3, 11) else "3.4.2"
        assert deps["networkx"] == ("networkx", expected_networkx)

    def test_discovers_dependency_inventory_from_poetry_lock(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "pyproject.toml").write_text(
            '[tool.poetry]\nname = "demo-app"\nversion = "0.1.0"\n'
            '[tool.poetry.dependencies]\npython = "^3.11"\nrequests = "^2.0"\nPyYAML = "^6.0"\n'
        )
        (repo / "poetry.lock").write_text(
            """
[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "PyYAML"
version = "6.0.2"
""".strip()
        )

        deps = discover_declared_dependency_inventory(repo)

        assert deps["requests"] == ("requests", "2.32.3")
        assert deps["pyyaml"] == ("PyYAML", "6.0.2")


class TestIsPackageImported:
    def test_direct_match(self):
        imports = {"requests", "json", "os"}
        assert is_package_imported("requests", imports)

    def test_not_imported(self):
        imports = {"requests", "json"}
        assert not is_package_imported("flask", imports)

    def test_pypi_name_mapping(self):
        imports = {"yaml", "os"}
        assert is_package_imported("PyYAML", imports)

    def test_pillow_mapping(self):
        imports = {"PIL", "os"}
        assert is_package_imported("Pillow", imports)

    def test_submodule_import(self):
        imports = {"yaml.loader", "os"}
        assert is_package_imported("PyYAML", imports)

    def test_case_insensitive(self):
        imports = {"PIL"}
        assert is_package_imported("Pillow", imports)


class TestIsSubmoduleImported:
    def test_exact_match(self):
        imports = {"django.contrib.admin", "os"}
        found, matched = is_submodule_imported(("django.contrib.admin",), imports)
        assert found
        assert matched == "django.contrib.admin"

    def test_narrower_import(self):
        """Import is more specific than submodule path → still matches."""
        imports = {"django.contrib.admin.sites", "os"}
        found, matched = is_submodule_imported(("django.contrib.admin",), imports)
        assert found
        assert matched == "django.contrib.admin.sites"

    def test_broader_import(self):
        """Import is broader than submodule — conservative match."""
        imports = {"django.contrib", "os"}
        found, matched = is_submodule_imported(("django.contrib.admin",), imports)
        assert found
        assert matched == "django.contrib"

    def test_no_match(self):
        imports = {"django.db", "os"}
        found, matched = is_submodule_imported(("django.contrib.sessions",), imports)
        assert not found
        assert matched is None

    def test_multiple_submodule_paths(self):
        imports = {"django.template", "os"}
        found, matched = is_submodule_imported(("django.contrib.admin", "django.template"), imports)
        assert found
        assert matched == "django.template"

    def test_case_insensitive(self):
        imports = {"Django.Contrib.Admin"}
        found, _ = is_submodule_imported(("django.contrib.admin",), imports)
        assert found

    def test_empty_submodule_paths(self):
        imports = {"django"}
        found, matched = is_submodule_imported((), imports)
        assert not found
        assert matched is None

    def test_from_import_records_submodule_for_matching(self):
        """from jinja2 import sandbox → jinja2.sandbox is matchable."""
        source = "from jinja2 import sandbox\n"
        imports = collect_imports_from_source(source)
        found, matched = is_submodule_imported(("jinja2.sandbox",), imports)
        assert found
        assert matched == "jinja2.sandbox"

    def test_from_import_class_does_not_match_submodule(self):
        """from jinja2 import Environment does NOT match jinja2.sandbox."""
        source = "from jinja2 import Environment\n"
        imports = collect_imports_from_source(source)
        found, _ = is_submodule_imported(("jinja2.sandbox",), imports)
        assert not found

    def test_bare_top_level_import_does_not_match_submodule(self):
        """Bare 'django' should NOT match 'django.contrib.sessions'.

        With enhanced import collection (``from jinja2 import sandbox``
        now records ``jinja2.sandbox``), we no longer need the overly
        broad rule.  Bare top-level imports lack a dot, so the broader
        match is suppressed.
        """
        imports = {"django"}
        found, _ = is_submodule_imported(("django.contrib.sessions",), imports)
        assert not found
