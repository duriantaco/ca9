from __future__ import annotations

import json

from ca9.analysis.api_usage import (
    _MATCH_TYPE_CONFIDENCE,
    _build_parent_map,
    build_file_index,
    find_api_usage,
    scan_file_for_api_usage,
)
from ca9.engine import analyze
from ca9.models import ApiTarget, Verdict, Vulnerability


class TestBuildFileIndex:
    def test_import_module(self):
        source = "import requests\n"
        index = build_file_index("test.py", source)
        assert index.module_aliases["requests"] == "requests"

    def test_import_module_alias(self):
        source = "import requests as req\n"
        index = build_file_index("test.py", source)
        assert index.module_aliases["req"] == "requests"
        assert "requests" not in index.module_aliases

    def test_from_import(self):
        source = "from yaml import load, safe_load\n"
        index = build_file_index("test.py", source)
        assert index.symbol_aliases["load"] == "yaml.load"
        assert index.symbol_aliases["safe_load"] == "yaml.safe_load"

    def test_from_import_alias(self):
        source = "from yaml import load as yaml_load\n"
        index = build_file_index("test.py", source)
        assert index.symbol_aliases["yaml_load"] == "yaml.load"

    def test_star_import_ignored(self):
        source = "from os import *\n"
        index = build_file_index("test.py", source)
        assert len(index.symbol_aliases) == 0

    def test_syntax_error(self):
        source = "def broken(\n"
        index = build_file_index("test.py", source)
        assert index.parse_error is not None

    def test_nested_module_import(self):
        source = "from requests.auth import HTTPBasicAuth\n"
        index = build_file_index("test.py", source)
        assert index.symbol_aliases["HTTPBasicAuth"] == "requests.auth.HTTPBasicAuth"


class TestScanFileForApiUsage:
    def _targets(self, *fqnames):
        return [ApiTarget(package="test", fqname=fq, kind="function") for fq in fqnames]

    def test_direct_module_call(self):
        source = "import requests\nresp = requests.get('http://x')\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 1
        assert hits[0].matched_target == "requests.get"
        assert hits[0].line == 2

    def test_dotted_module_import_binds_top_level_package(self):
        source = "import werkzeug.utils\nwerkzeug.utils.send_file('example.txt')\n"
        hits = scan_file_for_api_usage("app.py", source, self._targets("werkzeug.utils.send_file"))
        assert [(hit.matched_target, hit.line) for hit in hits] == [("werkzeug.utils.send_file", 2)]

    def test_from_import_call(self):
        source = "from yaml import load\ndata = load(open('f.yml'))\n"
        targets = self._targets("yaml.load")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 1
        assert hits[0].matched_target == "yaml.load"

    def test_aliased_import(self):
        source = "import requests as req\nreq.get('http://x')\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 1
        assert hits[0].matched_target == "requests.get"

    def test_callback_in_sibling_scope_is_not_the_imported_api(self):
        source = (
            "def original():\n"
            "    from requests.auth import HTTPBasicAuth as render\n"
            "    return render('user', 'password')\n"
            "def label(render):\n"
            "    return render('hello')\n"
            "def another():\n"
            "    from html import escape as render\n"
            "    return render('hello')\n"
            "label(str.upper)\n"
        )
        hits = scan_file_for_api_usage(
            "app.py", source, self._targets("requests.auth.HTTPBasicAuth")
        )
        assert [hit.line for hit in hits] == [3]

    def test_reassigned_import_only_matches_prior_calls(self):
        source = (
            "from package import transform\n"
            "transform('first')\n"
            "transform = str.upper\n"
            "transform('second')\n"
        )
        hits = scan_file_for_api_usage("app.py", source, self._targets("package.transform"))
        assert [hit.line for hit in hits] == [2]

    def test_lexical_shadowing_and_late_module_rebinding(self):
        source = (
            "from package import transform\n"
            "def called_later():\n"
            "    return transform('hello')\n"
            "def callback(*, transform):\n"
            "    return transform('hello')\n"
            "values = [transform('hello') for transform in [str.upper]]\n"
            "to_upper = lambda transform: transform('hello')\n"
            "transform = str.upper\n"
            "called_later()\n"
        )
        assert scan_file_for_api_usage("app.py", source, self._targets("package.transform")) == []

    def test_nested_function_inherits_import_and_ignores_class_namespace(self):
        source = (
            "import package as lib\n"
            "class Formatter:\n"
            "    lib = str\n"
            "    def format(self):\n"
            "        return lib.transform('hello')\n"
            "def wrapper():\n"
            "    from package import transform as apply\n"
            "    def inner():\n"
            "        return apply('hello')\n"
        )
        hits = scan_file_for_api_usage("app.py", source, self._targets("package.transform"))
        assert sorted(hit.line for hit in hits) == [5, 9]

    def test_ambiguous_conditional_rebinding_is_inconclusive(self):
        source = (
            "def run(use_custom):\n"
            "    from package import transform\n"
            "    if use_custom:\n"
            "        transform = str.upper\n"
            "    return transform('hello')\n"
        )
        assert scan_file_for_api_usage("app.py", source, self._targets("package.transform")) == []

    def test_nested_global_and_nonlocal_writes_block_only_shared_bindings(self):
        source = (
            "from package import transform as shared\n"
            "def outer():\n"
            "    from package import transform as closed\n"
            "    def change():\n"
            "        global shared\n"
            "        nonlocal closed\n"
            "        shared = closed = str.upper\n"
            "    change()\n"
            "    return shared('hello'), closed('hello')\n"
            "def isolated():\n"
            "    from package import transform as shared\n"
            "    return shared('hello')\n"
        )
        hits = scan_file_for_api_usage("app.py", source, self._targets("package.transform"))
        assert [hit.line for hit in hits] == [12]

    def test_conditional_import_can_leave_builtin_or_class_fallback_in_effect(self):
        source = (
            "if use_custom:\n"
            "    from package import transform as sorted\n"
            "sorted([])\n"
            "render = str.upper\n"
            "class Formatter:\n"
            "    if use_custom:\n"
            "        from package import transform as render\n"
            "    value = render('hello')\n"
        )
        assert scan_file_for_api_usage("app.py", source, self._targets("package.transform")) == []

    def test_references_do_not_mask_a_genuine_call_on_the_same_line(self):
        source = "from package import transform\nfunctions = (transform, transform('hello'))\n"
        hits = scan_file_for_api_usage("app.py", source, self._targets("package.transform"))
        assert [(hit.line, hit.match_type) for hit in hits] == [(2, "attribute_call")]

    def test_relative_import_cannot_identify_external_api(self):
        source = "from .package import transform\ntransform('hello')\n"
        assert scan_file_for_api_usage("app.py", source, self._targets("package.transform")) == []

    def test_class_instantiation(self):
        source = "from requests.auth import HTTPBasicAuth\nauth = HTTPBasicAuth('u', 'p')\n"
        targets = [
            ApiTarget(package="requests", fqname="requests.auth.HTTPBasicAuth", kind="class")
        ]
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 1
        assert hits[0].match_type == "class_instantiation"

    def test_no_match(self):
        source = "import requests\nresp = requests.head('http://x')\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 0

    def test_safe_load_not_matched_for_load_target(self):
        source = "from yaml import safe_load\ndata = safe_load('x')\n"
        targets = self._targets("yaml.load")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 0

    def test_symbol_reference_not_call(self):
        source = "from yaml import UnsafeLoader\ncallback = UnsafeLoader\n"
        targets = [ApiTarget(package="pyyaml", fqname="yaml.UnsafeLoader", kind="class")]
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) >= 1
        ref_hits = [h for h in hits if h.match_type == "symbol_reference"]
        assert len(ref_hits) >= 1

    def test_multiple_targets(self):
        source = (
            "import requests\n"
            "from yaml import load, unsafe_load\n"
            "requests.get('http://x')\n"
            "load('x')\n"
            "unsafe_load('x')\n"
        )
        targets = self._targets("requests.get", "yaml.load", "yaml.unsafe_load")
        hits = scan_file_for_api_usage("t.py", source, targets)
        matched = {h.matched_target for h in hits}
        assert "requests.get" in matched
        assert "yaml.load" in matched
        assert "yaml.unsafe_load" in matched

    def test_deduplicate_same_line(self):
        source = "import requests\nrequests.get('x')\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 1

    def test_syntax_error_returns_empty(self):
        source = "def broken(\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert hits == []

    def test_snippet_captured(self):
        source = "import requests\nresp = requests.get('http://example.com')\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert hits[0].code_snippet is not None
        assert "requests.get" in hits[0].code_snippet

    def test_chained_attribute(self):
        source = "import urllib3\nurllib3.PoolManager.request('GET', 'http://x')\n"
        targets = self._targets("urllib3.PoolManager.request")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 1


def test_match_requires_exact_owner_or_explicit_reexport():
    targets = [
        ApiTarget(
            package="requests",
            fqname="requests.Session.send",
            aliases=("requests.sessions.Session.send",),
        ),
        ApiTarget(package="requests", fqname="requests.get", aliases=("requests.api.get",)),
    ]
    source = (
        "from requests.adapters import BaseAdapter\n"
        "from requests.sessions import Session\n"
        "from requests.api import get\n"
        "BaseAdapter.send(None, None)\n"
        "Session.send(None, None)\n"
        "get('example')\n"
    )
    hits = scan_file_for_api_usage("app.py", source, targets)
    assert [(h.line, h.matched_target) for h in hits] == [
        (5, "requests.Session.send"),
        (6, "requests.get"),
    ]


class TestConfidenceGradation:
    def _targets(self, *fqnames, kind="function"):
        return [ApiTarget(package="test", fqname=fq, kind=kind) for fq in fqnames]

    def test_attribute_call_confidence(self):
        source = "import requests\nrequests.get('http://x')\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert hits[0].confidence == _MATCH_TYPE_CONFIDENCE["attribute_call"]

    def test_class_instantiation_confidence(self):
        source = "from requests.auth import HTTPBasicAuth\nHTTPBasicAuth('u', 'p')\n"
        targets = self._targets("requests.auth.HTTPBasicAuth", kind="class")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert hits[0].confidence == _MATCH_TYPE_CONFIDENCE["class_instantiation"]

    def test_symbol_reference_confidence(self):
        source = "from yaml import UnsafeLoader\ncallback = UnsafeLoader\n"
        targets = [ApiTarget(package="pyyaml", fqname="yaml.UnsafeLoader", kind="class")]
        hits = scan_file_for_api_usage("t.py", source, targets)
        ref_hits = [h for h in hits if h.match_type == "symbol_reference"]
        assert ref_hits[0].confidence == _MATCH_TYPE_CONFIDENCE["symbol_reference"]


class TestParentMap:
    def test_parent_map_correct_for_call(self):
        import ast

        source = "from yaml import load\nload('x')\n"
        tree = ast.parse(source)
        parent_map = _build_parent_map(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_node = node.func
                parent = parent_map.get(id(func_node))
                assert isinstance(parent, ast.Call)
                assert parent.func is func_node

    def test_symbol_ref_parent_is_not_call(self):
        import ast

        source = "from yaml import UnsafeLoader\ncallback = UnsafeLoader\n"
        tree = ast.parse(source)
        parent_map = _build_parent_map(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                value_node = node.value
                if isinstance(value_node, ast.Name) and value_node.id == "UnsafeLoader":
                    parent = parent_map.get(id(value_node))
                    assert not (isinstance(parent, ast.Call) and parent.func is value_node)


class TestFindApiUsage:
    def test_scan_repo(self, tmp_path):
        (tmp_path / "app.py").write_text("import requests\nrequests.get('http://x')\n")
        (tmp_path / "util.py").write_text("from yaml import load\nload('x')\n")
        targets = [
            ApiTarget(package="requests", fqname="requests.get"),
            ApiTarget(package="pyyaml", fqname="yaml.load"),
        ]
        hits = find_api_usage(tmp_path, targets)
        matched = {h.matched_target for h in hits}
        assert "requests.get" in matched
        assert "yaml.load" in matched

    def test_skips_hidden_dirs(self, tmp_path):
        hidden = tmp_path / ".venv"
        hidden.mkdir()
        (hidden / "dep.py").write_text("import requests\nrequests.get('x')\n")
        targets = [ApiTarget(package="requests", fqname="requests.get")]
        hits = find_api_usage(tmp_path, targets)
        assert len(hits) == 0

    def test_empty_targets_returns_empty(self, tmp_path):
        (tmp_path / "app.py").write_text("import requests\nrequests.get('x')\n")
        hits = find_api_usage(tmp_path, [])
        assert hits == []


def test_covered_callback_does_not_prove_imported_api_execution(tmp_path):
    (tmp_path / "app.py").write_text(
        "def unused():\n"
        "    from requests.auth import HTTPBasicAuth as render\n"
        "\n"
        "def label(render):\n"
        "    return render('hello')\n"
        "\n"
        "label(str.upper)\n"
    )
    coverage = tmp_path / "coverage.json"
    coverage.write_text(
        json.dumps({"files": {"app.py": {"executed_lines": [1, 4, 5, 7], "missing_lines": [2]}}})
    )
    advisory = Vulnerability(
        id="LOCAL-TEST",
        package_name="requests",
        package_version="2.30.0",
        severity="medium",
        title="authentication",
    )
    result = analyze([advisory], tmp_path, coverage_path=coverage).results[0]
    assert result.verdict == Verdict.INCONCLUSIVE
    assert "requests.auth.HTTPBasicAuth" in result.evidence.api_targets
    assert result.evidence.api_usage_hits == ()
