from __future__ import annotations

from pathlib import Path

import pytest

from ca9.analysis.api_usage import (
    FileSymbolIndex,
    build_file_index,
    find_api_usage,
    scan_file_for_api_usage,
)
from ca9.models import ApiTarget


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
        return [
            ApiTarget(package="test", fqname=fq, kind="function")
            for fq in fqnames
        ]

    def test_direct_module_call(self):
        source = "import requests\nresp = requests.get('http://x')\n"
        targets = self._targets("requests.get")
        hits = scan_file_for_api_usage("t.py", source, targets)
        assert len(hits) == 1
        assert hits[0].matched_target == "requests.get"
        assert hits[0].line == 2

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
        targets = [
            ApiTarget(package="pyyaml", fqname="yaml.UnsafeLoader", kind="class")
        ]
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
        # Same line, same target → only one hit
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
        # This depends on whether PoolManager is resolved — import is bare module
        # The chain urllib3.PoolManager.request should resolve to urllib3.PoolManager.request
        assert len(hits) == 1


class TestFindApiUsage:
    def test_scan_repo(self, tmp_path):
        (tmp_path / "app.py").write_text(
            "import requests\nrequests.get('http://x')\n"
        )
        (tmp_path / "util.py").write_text(
            "from yaml import load\nload('x')\n"
        )
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
