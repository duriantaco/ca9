from __future__ import annotations

from unittest.mock import patch

from ca9.analysis.vuln_matcher import (
    CommitFetchResult,
    _file_paths_to_submodules,
    extract_affected_component,
)
from ca9.models import Vulnerability


def _vuln(
    pkg: str, title: str = "", desc: str = "", references: tuple[str, ...] = ()
) -> Vulnerability:
    return Vulnerability(
        id="TEST-001",
        package_name=pkg,
        package_version="1.0.0",
        severity="high",
        title=title,
        description=desc,
        references=references,
    )


class TestCuratedMappings:
    def test_django_sessions(self):
        v = _vuln("Django", title="Session fixation in Django")
        c = extract_affected_component(v)
        assert c.confidence == "high"
        assert "django.contrib.sessions" in c.submodule_paths
        assert c.extraction_source.startswith("curated:django")

    def test_django_admin(self):
        v = _vuln("Django", title="XSS in Django admin interface")
        c = extract_affected_component(v)
        assert c.confidence == "high"
        assert "django.contrib.admin" in c.submodule_paths

    def test_django_queryset(self):
        v = _vuln("Django", desc="SQL injection via QuerySet.extra()")
        c = extract_affected_component(v)
        assert c.confidence == "high"
        assert "django.db.models" in c.submodule_paths

    def test_django_template(self):
        v = _vuln("Django", title="Template injection vulnerability")
        c = extract_affected_component(v)
        assert "django.template" in c.submodule_paths

    def test_django_auth(self):
        v = _vuln("Django", title="Password reset token leak")
        c = extract_affected_component(v)
        assert "django.contrib.auth" in c.submodule_paths

    def test_django_multipart(self):
        v = _vuln("Django", desc="DoS via multipart boundary parsing")
        c = extract_affected_component(v)
        assert "django.http.multipartparser" in c.submodule_paths

    def test_werkzeug_debug(self):
        v = _vuln("Werkzeug", title="RCE via Werkzeug debugger")
        c = extract_affected_component(v)
        assert c.confidence == "high"
        assert "werkzeug.debug" in c.submodule_paths
        assert "debugger.py" in c.file_hints

    def test_jinja2_sandbox(self):
        v = _vuln("Jinja2", title="Sandbox escape in Jinja2")
        c = extract_affected_component(v)
        assert c.confidence == "high"
        assert "jinja2.sandbox" in c.submodule_paths

    def test_requests_falls_through_to_package_level(self):
        """requests is a flat package — no curated submodule mapping."""
        v = _vuln("requests", desc="Cookie leak on redirect to different host")
        c = extract_affected_component(v)
        assert c.confidence == "low"
        assert c.submodule_paths == ()

    def test_pyyaml_load(self):
        v = _vuln("PyYAML", desc="Arbitrary code via yaml.load()")
        c = extract_affected_component(v)
        assert c.confidence == "high"


class TestFilePathsToSubmodules:
    def test_basic_conversion(self):
        paths = ["src/jinja2/utils.py", "src/jinja2/filters.py"]
        result = _file_paths_to_submodules(paths, "jinja2")
        assert "jinja2.utils" in result
        assert "jinja2.filters" in result

    def test_skips_test_files(self):
        paths = ["src/jinja2/utils.py", "tests/test_utils.py"]
        result = _file_paths_to_submodules(paths, "jinja2")
        assert result == ["jinja2.utils"]

    def test_skips_test_directories(self):
        paths = ["jinja2/utils.py", "jinja2/tests/test_sandbox.py"]
        result = _file_paths_to_submodules(paths, "jinja2")
        assert result == ["jinja2.utils"]

    def test_skips_non_python(self):
        paths = ["jinja2/utils.py", "README.md", "setup.cfg"]
        result = _file_paths_to_submodules(paths, "jinja2")
        assert result == ["jinja2.utils"]

    def test_init_becomes_package(self):
        paths = ["src/jinja2/__init__.py"]
        result = _file_paths_to_submodules(paths, "jinja2")
        assert result == ["jinja2"]

    def test_nested_submodule(self):
        paths = ["django/contrib/admin/sites.py"]
        result = _file_paths_to_submodules(paths, "django")
        assert "django.contrib.admin.sites" in result

    def test_no_matching_package(self):
        paths = ["unrelated/module.py"]
        result = _file_paths_to_submodules(paths, "jinja2")
        assert result == []


class TestCommitAnalysis:
    @patch("ca9.analysis.vuln_matcher._fetch_commit_files")
    def test_commit_extracts_submodules(self, mock_fetch):
        mock_fetch.return_value = CommitFetchResult(
            status="ok",
            files=[
                "src/jinja2/utils.py",
                "src/jinja2/filters.py",
                "tests/test_utils.py",
            ],
        )
        v = _vuln(
            "Jinja2",
            title="XSS in jinja2",
            references=("https://github.com/pallets/jinja/commit/abc123def456",),
        )
        c = extract_affected_component(v)
        assert c.confidence == "high"
        assert c.extraction_source == "commit_analysis"
        assert "jinja2.utils" in c.submodule_paths
        assert "jinja2.filters" in c.submodule_paths

    @patch("ca9.analysis.vuln_matcher._fetch_commit_files")
    def test_commit_wins_over_curated(self, mock_fetch):
        mock_fetch.return_value = CommitFetchResult(
            status="ok", files=["src/jinja2/runtime.py"]
        )
        v = _vuln(
            "Jinja2",
            title="Sandbox escape in Jinja2",
            references=("https://github.com/pallets/jinja/commit/abc123def456",),
        )
        c = extract_affected_component(v)
        assert c.extraction_source == "commit_analysis"
        assert "jinja2.runtime" in c.submodule_paths

    @patch("ca9.analysis.vuln_matcher._fetch_commit_files")
    def test_commit_no_python_files_falls_through(self, mock_fetch):
        mock_fetch.return_value = CommitFetchResult(
            status="ok", files=["docs/changelog.md", "setup.cfg"]
        )
        v = _vuln(
            "Jinja2",
            title="Sandbox escape in Jinja2",
            references=("https://github.com/pallets/jinja/commit/abc123def456",),
        )
        c = extract_affected_component(v)
        assert c.extraction_source.startswith("curated:")

    def test_no_references_falls_through(self):
        v = _vuln("Jinja2", title="Sandbox escape in Jinja2")
        c = extract_affected_component(v)
        assert c.extraction_source.startswith("curated:")

    @patch("ca9.analysis.vuln_matcher._fetch_commit_files")
    def test_commit_includes_file_hints(self, mock_fetch):
        mock_fetch.return_value = CommitFetchResult(
            status="ok", files=["src/jinja2/sandbox.py"]
        )
        v = _vuln(
            "Jinja2",
            references=("https://github.com/pallets/jinja/commit/abc123def456a",),
        )
        c = extract_affected_component(v)
        assert "sandbox.py" in c.file_hints

    @patch("ca9.analysis.vuln_matcher._fetch_commit_files")
    def test_fetch_failure_degrades_to_fallback(self, mock_fetch):
        mock_fetch.return_value = CommitFetchResult(
            status="rate_limited",
            warning="GitHub rate limited",
        )
        v = _vuln(
            "Jinja2",
            title="Sandbox escape in Jinja2",
            references=("https://github.com/pallets/jinja/commit/abc123def456",),
        )
        c = extract_affected_component(v)
        assert c.extraction_source.startswith("curated:")


class TestRegexExtraction:
    def test_dotted_path_in_backticks(self):
        v = _vuln(
            "Django",
            title="Bug in contrib",
            desc="The function `django.utils.http.parse_qsl` is affected.",
        )
        c = extract_affected_component(v)
        assert c.confidence == "medium"
        assert "django.utils.http.parse_qsl" in c.submodule_paths
        assert c.extraction_source == "regex:dotted_path"

    def test_ignores_unrelated_dotted_paths(self):
        v = _vuln(
            "requests",
            desc="Compare with `urllib3.util.retry`.",
        )
        c = extract_affected_component(v)
        assert c.confidence == "low"

    def test_multiple_dotted_paths(self):
        v = _vuln(
            "Django",
            desc="Affects `django.http.request` and `django.http.response`.",
        )
        c = extract_affected_component(v)
        assert c.confidence == "medium"
        assert "django.http.request" in c.submodule_paths
        assert "django.http.response" in c.submodule_paths


class TestClassNameResolution:
    @patch("ca9.analysis.vuln_matcher._find_package_source_dir")
    @patch("ca9.analysis.vuln_matcher._scan_package_for_name")
    def test_resolves_class_name_to_submodule(self, mock_scan, mock_find):
        mock_find.return_value = "/site-packages/somelib"
        mock_scan.side_effect = lambda src, name, imp: (
            "somelib.poolmanager" if name == "ProxyManager" else None
        )
        v = _vuln(
            "somelib",
            desc="ProxyManager vulnerable to resource exhaustion",
        )
        c = extract_affected_component(v)
        assert c.confidence == "medium"
        assert c.extraction_source == "class_name_resolution"
        assert "somelib.poolmanager" in c.submodule_paths

    @patch("ca9.analysis.vuln_matcher._find_package_source_dir")
    @patch("ca9.analysis.vuln_matcher._scan_package_for_name")
    def test_multiple_class_names(self, mock_scan, mock_find):
        mock_find.return_value = "/site-packages/jinja2"
        mock_scan.side_effect = lambda src, name, imp: {
            "FileSystemBytecodeCache": "jinja2.bccache",
            "MemcachedBytecodeCache": "jinja2.bccache",
        }.get(name)
        v = _vuln(
            "Jinja2",
            desc="DoS in FileSystemBytecodeCache and MemcachedBytecodeCache",
        )
        c = extract_affected_component(v)
        assert c.confidence == "medium"
        assert "jinja2.bccache" in c.submodule_paths

    @patch("ca9.analysis.vuln_matcher._find_package_source_dir")
    def test_no_class_names_falls_through(self, mock_find):
        mock_find.return_value = "/site-packages/urllib3"
        v = _vuln("urllib3", desc="a vulnerability in the library")
        c = extract_affected_component(v)
        assert c.confidence == "low"

    def test_generic_names_excluded(self):
        v = _vuln("obscure-lib", desc="TypeError in JavaScript handling")
        c = extract_affected_component(v)
        assert c.confidence == "low"

    @patch("ca9.analysis.vuln_matcher._find_package_source_dir")
    @patch("ca9.analysis.vuln_matcher._scan_package_for_name")
    def test_class_not_found_falls_through(self, mock_scan, mock_find):
        """Class name exists in text but not in package source → fallback."""
        mock_find.return_value = "/site-packages/obscure"
        mock_scan.return_value = None
        v = _vuln("obscure-lib", desc="SomeWeirdClass is vulnerable")
        c = extract_affected_component(v)
        assert c.confidence == "low"


class TestFallback:
    def test_unknown_package(self):
        v = _vuln("obscure-lib", title="Some vulnerability")
        c = extract_affected_component(v)
        assert c.confidence == "low"
        assert c.submodule_paths == ()
        assert c.extraction_source == "fallback"

    def test_no_matching_text(self):
        v = _vuln("Django", title="An unspecified vulnerability")
        c = extract_affected_component(v)
        assert c.confidence == "low"


class TestCuratedTakesPrecedence:
    def test_curated_wins_over_regex(self):
        v = _vuln(
            "Django",
            title="Session fixation",
            desc="See `django.contrib.sessions.backends.base`.",
        )
        c = extract_affected_component(v)
        assert c.confidence == "high"
        assert "django.contrib.sessions" in c.submodule_paths
