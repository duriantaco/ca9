"""Opt-in code for reviewers: diff excerpts around upgrade deltas (``context_lines``) and a
diff of the changed code files when only the publisher changed (``identity_diff_bytes``)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.test_upgrade_review import NPM, registry

from ca9 import api
from ca9.review import code_context

__all__ = ["registry"]

GOLDEN = Path(__file__).parent / "fixtures" / "upgrade_review_defaults.json"
TRUNCATED = "... (truncated)"
TRUSTED = {"name": "GitHub Actions", "trustedPublisher": {"id": "github"}}
ACCOUNT = {"name": "mallory", "email": "mallory@example.com"}
EXEC = "const cp = require('node:child_process');"
LINES = [f"const v{index} = {index};" for index in range(1, 29)]
HIDDEN = "\u202e\u2066\u2069\u200b\x1b\x07\r\u2028\u2029\x0c"


def _text(lines):
    return "".join(f"{line}\n" for line in lines)


def _review(pairs, **options):
    return api.review_upgrades(pairs, options=options or None)


def _upgrade(ecosystem, name, old, new, **options):
    report = _review([{"ecosystem": ecosystem, "name": name, "old": old, "new": new}], **options)
    return report["results"][0], report["receipt"]


def _with_provenance(registry, name, version):
    url = f"{NPM}/{name}/{version}"
    document = json.loads(registry.documents[url])
    document["dist"]["attestations"] = {"url": f"{NPM}/-/npm/v1/attestations/{name}@{version}"}
    registry.documents[url] = json.dumps(document).encode()


def _files(diff):
    names = []
    for line in diff.split("\n"):
        for prefix in ("--- a/", "+++ b/"):
            if line.startswith(prefix) and line[len(prefix) :] not in names:
                names.append(line[len(prefix) :])
    return names


def _defaults_fixture(registry):
    registry.npm("sample", "1.0.0", {"index.js": "module.exports = 1;\n"}, user=TRUSTED)
    registry.npm(
        "sample",
        "1.0.1",
        {"index.js": _text(["const a = 1;", EXEC, "module.exports = a;"]), "README.md": "x\n"},
        user=ACCOUNT,
    )
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "VALUE = 1\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            "demo/__init__.py": "VALUE = 2\n",
            "demo/_x.so": b"\x7fELF\x02" + b"\x00" * 64,
            "demo_boot.pth": "import os; os.system('id')\n",
        },
    )
    registry.npm(
        "fresh",
        "1.0.0",
        {"index.js": _text([EXEC, "module.exports = 1;"]), "install.js": "console.log(1);\n"},
        manifest={"scripts": {"postinstall": "node install.js"}},
    )
    return [
        {"ecosystem": "npm", "name": "sample", "old": "1.0.0", "new": "1.0.1"},
        {"ecosystem": "pypi", "name": "demo", "old": "1.0", "new": "1.1"},
        {"ecosystem": "npm", "name": "fresh", "old": None, "new": "1.0.0"},
    ]


def test_without_the_options_the_output_is_byte_identical(registry):
    pairs = _defaults_fixture(registry)

    report = _review(pairs)
    explicit = _review(pairs, context_lines=0, identity_diff_bytes=0)

    assert json.dumps(report, indent=1) + "\n" == GOLDEN.read_text()
    assert explicit["results"] == report["results"]
    assert explicit["receipt"] == {**report["receipt"], "context_lines": 0}


def test_context_is_the_diff_around_the_delta_line_within_context_lines(registry):
    registry.npm("inserted", "1.0.0", {"index.js": _text(LINES)})
    registry.npm("inserted", "1.0.1", {"index.js": _text([*LINES[:14], EXEC, *LINES[14:]])})
    registry.npm("swapped", "1.0.0", {"index.js": _text(LINES)})
    registry.npm("swapped", "1.0.1", {"index.js": _text([*LINES[:14], EXEC, *LINES[15:]])})

    inserted, receipt = _upgrade("npm", "inserted", "1.0.0", "1.0.1", context_lines=2)
    swapped, _receipt = _upgrade("npm", "swapped", "1.0.0", "1.0.1", context_lines=1)

    assert [(item["kind"], item["path"], item["line"]) for item in inserted["warn"]] == [
        ("new_import_time_exec", "index.js", 15)
    ]
    assert inserted["warn"][0]["context"] == (
        "@@ -13,4 +13,5 @@\n"
        " const v13 = 13;\n"
        " const v14 = 14;\n"
        f"+{EXEC}\n"
        " const v15 = 15;\n"
        " const v16 = 16;"
    )
    assert swapped["warn"][0]["context"] == (
        f"@@ -14,3 +14,3 @@\n const v14 = 14;\n-const v15 = 15;\n+{EXEC}\n const v16 = 16;"
    )
    assert receipt["context_lines"] == 2 and receipt["complete"] is True
    assert "identity_diff" not in inserted


def test_context_over_8_kb_is_cut_around_the_delta_line_with_a_marker(registry):
    old = [f"const before{index:03d} = '{'a' * 40}';" for index in range(300)]
    new = [f"const after{index:03d} = '{'b' * 40}';" for index in range(300)]
    new.insert(99, EXEC)
    registry.npm("bulky", "1.0.0", {"index.js": _text(old)})
    registry.npm("bulky", "1.0.1", {"index.js": _text(new)})

    result, receipt = _upgrade("npm", "bulky", "1.0.0", "1.0.1", context_lines=200)

    delta = result["warn"][0]
    lines = delta["context"].split("\n")
    rows = [line for line in lines[:-1] if not line.startswith("@@ ")]
    centre = rows.index(f"+{EXEC}")
    assert delta["line"] == 100
    assert len(delta["context"].encode()) <= 8192
    assert lines[0].startswith("@@ ") and lines[-1] == TRUNCATED
    assert all(row[:1] in {" ", "+", "-"} for row in rows)
    assert abs(centre - (len(rows) - 1 - centre)) <= 1 and len(rows) > 100
    assert receipt["context_lines"] == 200


def test_minified_line_is_shown_in_part_within_8_kb(registry):
    registry.npm("mini", "1.0.0", {"index.js": "module.exports=1;\n"})
    registry.npm("mini", "1.0.1", {"index.js": "var a=1;" * 8000 + EXEC + "\n"})

    result, _receipt = _upgrade("npm", "mini", "1.0.0", "1.0.1", context_lines=50)

    context = result["warn"][0]["context"]
    assert len(context.encode()) == 8192
    assert context.startswith("@@ -1,0 +1 @@\n+var a=1;var a=1;")
    assert context.endswith("\n" + TRUNCATED) and context.count("\n") == 2


def test_distant_edits_in_a_large_file_are_aligned(registry):
    old = [f"const o{index} = {index};" for index in range(6000)]
    new = list(old)
    new[1000] = EXEC
    new[5000] = "const changed = 1;"
    registry.npm("large", "1.0.0", {"index.js": _text(old)})
    registry.npm("large", "1.0.1", {"index.js": _text(new)})

    result, _receipt = _upgrade("npm", "large", "1.0.0", "1.0.1", context_lines=1)

    assert result["warn"][0]["line"] == 1001
    assert result["warn"][0]["context"] == (
        f"@@ -1000,3 +1000,3 @@\n const o999 = 999;\n-const o1000 = 1000;\n+{EXEC}\n"
        " const o1001 = 1001;"
    )


def test_contexts_share_64_kb_per_result_and_each_keeps_its_line(registry):
    padding = [f"# padding line {index:03d} {'.' * 60}" for index in range(150)]
    files = {
        f"demo_{index:02d}.pth": _text([f"import os; os.system('id {index}')", *padding])
        for index in range(12)
    }
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "VALUE = 1\n"})
    registry.pypi("demo", "1.1", wheel={"demo/__init__.py": "VALUE = 1\n", **files})

    result, _receipt = _upgrade("pypi", "demo", "1.0", "1.1", context_lines=200)

    assert [item["path"] for item in result["block"]] == sorted(files)
    contexts = [item["context"] for item in result["block"]]
    assert sum(len(context.encode()) for context in contexts) <= 65536
    for index, context in enumerate(contexts):
        lines = context.split("\n")
        assert len(context.encode()) <= 8192
        assert lines[0].startswith("@@ -0,0 +1,") and lines[-1] == TRUNCATED
        assert lines[1] == f"+import os; os.system('id {index}')"


def test_binary_file_deltas_get_no_context_and_new_files_are_plus_lines(registry):
    registry.pypi("demo", "1.0", wheel={"demo/__init__.py": "VALUE = 1\n"})
    registry.pypi(
        "demo",
        "1.1",
        wheel={
            "demo/__init__.py": "VALUE = 1\n",
            "demo/_x.so": b"\x7fELF\x02" + b"\x00" * 64,
            "demo_boot.pth": "import os; os.system('id')\n",
        },
    )
    registry.npm("helper", "2.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm(
        "helper",
        "2.0.1",
        {
            "index.js": "module.exports = require('./lib/x.js');\n",
            "lib/x.js": "const a = 1;\nconst cp = require('child_process');\nmodule.exports = a;\n",
        },
    )

    wheel, _receipt = _upgrade("pypi", "demo", "1.0", "1.1", context_lines=5)
    added, _receipt = _upgrade("npm", "helper", "2.0.0", "2.0.1", context_lines=5)

    native = [item for item in wheel["warn"] if item["kind"] == "new_native_binary"]
    assert len(native) == 1 and "context" not in native[0]
    assert wheel["block"][0]["context"] == "@@ -0,0 +1 @@\n+import os; os.system('id')"
    assert [(item["path"], item["line"]) for item in added["warn"]] == [("lib/x.js", 2)]
    assert added["warn"][0]["context"] == (
        "@@ -0,0 +1,3 @@\n"
        "+const a = 1;\n"
        "+const cp = require('child_process');\n"
        "+module.exports = a;"
    )


def test_first_release_context_is_the_new_file_only(registry):
    registry.npm(
        "fresh",
        "1.0.0",
        {
            "index.js": _text(["const a = 1;", EXEC, "module.exports = a;", "// end"]),
            "install.js": "console.log(1);\n",
        },
        manifest={"scripts": {"postinstall": "node install.js"}},
    )

    report = _review([{"ecosystem": "npm", "name": "fresh", "new": "1.0.0"}], context_lines=1)

    result = report["results"][0]
    assert result["first_release"] is True and report["receipt"]["context_lines"] == 1
    warn = [item for item in result["warn"] if item["path"] == "index.js"]
    assert warn[0]["context"] == (f"@@ -0,0 +1,3 @@\n+const a = 1;\n+{EXEC}\n+module.exports = a;")
    hook = [item for item in result["block"] if item["kind"] == "new_install_hook"]
    assert hook[0]["context"].startswith('@@ -0,0 +1 @@\n+{"name": "fresh"')
    assert all("context" in item for item in [*result["block"], *result["warn"]])
    assert "identity_diff" not in result


def test_identity_diff_only_when_the_publisher_changed_or_provenance_dropped(registry):
    registry.npm("quiet", "1.0.0", {"index.js": "module.exports = 1;\n"}, user=TRUSTED)
    registry.npm("quiet", "1.0.1", {"index.js": "module.exports = 2;\n"}, user=ACCOUNT)
    registry.npm("signed", "1.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm("signed", "1.0.1", {"index.js": "module.exports = 2;\n"})
    _with_provenance(registry, "signed", "1.0.0")
    registry.npm("steady", "1.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm("steady", "1.0.1", {"index.js": "module.exports = 2;\n"})

    changed, receipt = _upgrade("npm", "quiet", "1.0.0", "1.0.1", identity_diff_bytes=10000)
    dropped, _receipt = _upgrade("npm", "signed", "1.0.0", "1.0.1", identity_diff_bytes=10000)
    steady, _receipt = _upgrade("npm", "steady", "1.0.0", "1.0.1", identity_diff_bytes=10000)
    off, off_receipt = _upgrade("npm", "quiet", "1.0.0", "1.0.1")

    assert [item["kind"] for item in changed["warn"]] == ["publisher_change"]
    assert changed["identity_diff"] == (
        "--- a/index.js\n+++ b/index.js\n@@ -1 +1 @@\n"
        "-module.exports = 1;\n+module.exports = 2;\n"
        "--- a/package.json\n+++ b/package.json\n@@ -1 +1 @@\n"
        '-{"name": "quiet", "version": "1.0.0", "main": "index.js"}\n'
        '+{"name": "quiet", "version": "1.0.1", "main": "index.js"}'
    )
    assert changed["identity_diff_truncated"] is False
    assert "context" not in changed["warn"][0] and receipt["context_lines"] == 0
    assert [item["kind"] for item in dropped["warn"]] == ["provenance_dropped"]
    assert _files(dropped["identity_diff"]) == ["index.js", "package.json"]
    assert dropped["identity_diff_truncated"] is False
    assert "identity_diff" not in steady and "identity_diff_truncated" not in steady
    assert "identity_diff" not in off and "context_lines" not in off_receipt


def test_identity_diff_lists_code_files_smallest_change_first_and_is_capped(registry):
    big_old = [f"export const left{index:02d} = {index};" for index in range(40)]
    big_new = [f"export const right{index:02d} = {index * 2};" for index in range(40)]
    common = {
        "index.js": "module.exports = require('./lib/core.js');\n",
        "lib/same.js": "module.exports = 'same';\n",
    }
    registry.npm(
        "shifty",
        "1.0.0",
        {
            **common,
            "lib/core.js": "module.exports = 1;\n",
            "lib/big.js": _text(big_old),
            "lib/old.js": _text([f"const gone{index} = {index};" for index in range(10)]),
            "README.md": "old readme\n",
            "package-lock.json": '{"lockfileVersion": 2}\n',
            "data/blob.json": b"\x00\x01\x02old",
        },
        user=TRUSTED,
    )
    registry.npm(
        "shifty",
        "1.0.1",
        {
            **common,
            "lib/core.js": "module.exports = 2;\n",
            "lib/big.js": _text(big_new),
            "lib/new.ts": _text([f"export const fresh{index} = {index};" for index in range(20)]),
            "README.md": "new readme\n",
            "package-lock.json": '{"lockfileVersion": 3}\n',
            "data/blob.json": b"\x00\x01\x02new",
        },
        user=ACCOUNT,
    )

    full, _receipt = _upgrade("npm", "shifty", "1.0.0", "1.0.1", identity_diff_bytes=200000)
    text = full["identity_diff"]
    cut_at = text.index("\n--- a/lib/old.js")
    capped, _receipt = _upgrade("npm", "shifty", "1.0.0", "1.0.1", identity_diff_bytes=cut_at + 20)

    assert _files(text) == ["lib/core.js", "package.json", "lib/old.js", "lib/new.ts", "lib/big.js"]
    assert "--- a/lib/old.js\n+++ /dev/null\n@@ -1,10 +0,0 @@\n-const gone0 = 0;" in text
    assert "--- /dev/null\n+++ b/lib/new.ts\n@@ -0,0 +1,20 @@\n+export const fresh0 = 0;" in text
    assert full["identity_diff_truncated"] is False
    assert capped["identity_diff"] == text[:cut_at]
    assert capped["identity_diff_truncated"] is True
    assert len(capped["identity_diff"].encode()) <= cut_at + 20


def test_control_and_bidi_characters_are_stripped_and_hidden_line_breaks_shown(registry):
    tricky = f"{EXEC}\u202e // \u2066ok\u2069\u200b\x1b[2K\x07\rrun();\u2028next();\x0cdone();\r"
    registry.npm("tricky", "1.0.0", {"index.js": "const a = 1;\n\tmodule.exports = a;\n"})
    registry.npm(
        "tricky",
        "1.0.1",
        {"index.js": f"const a = 1;\n{tricky}\n\tmodule.exports = a;\n"},
        user=ACCOUNT,
    )
    _with_provenance(registry, "tricky", "1.0.0")

    result, _receipt = _upgrade(
        "npm", "tricky", "1.0.0", "1.0.1", context_lines=1, identity_diff_bytes=5000
    )

    shown = f"+{EXEC} // ok[2K\\rrun();\\u2028next(); done();"
    exec_delta = next(item for item in result["warn"] if item["path"] == "index.js")
    assert exec_delta["context"] == (
        f"@@ -1,2 +1,3 @@\n const a = 1;\n{shown}\n \tmodule.exports = a;"
    )
    assert shown in result["identity_diff"].split("\n")
    for text in (exec_delta["context"], result["identity_diff"]):
        assert not any(char in text for char in HIDDEN)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("context_lines", -1),
        ("context_lines", 201),
        ("context_lines", True),
        ("context_lines", 2.0),
        ("context_lines", "5"),
        ("identity_diff_bytes", -1),
        ("identity_diff_bytes", 200001),
        ("identity_diff_bytes", False),
    ],
)
def test_invalid_values_are_reported_like_other_options(key, value):
    report = api.review_upgrades([], options={key: value})

    assert report["receipt"]["invalid_options"] == [key]
    assert report["receipt"]["complete"] is False
    assert report["receipt"]["context_lines"] == 0


def test_boundary_values_are_accepted():
    report = api.review_upgrades([], options={"context_lines": 200, "identity_diff_bytes": 200000})

    assert report["receipt"]["invalid_options"] == []
    assert report["receipt"]["context_lines"] == 200


def test_a_failure_while_building_code_text_never_changes_the_review(registry, monkeypatch):
    registry.npm("quiet", "1.0.0", {"index.js": "module.exports = 1;\n"}, user=TRUSTED)
    registry.npm("quiet", "1.0.1", {"index.js": _text([EXEC, "module.exports = 2;"])}, user=ACCOUNT)
    plain, _receipt = _upgrade("npm", "quiet", "1.0.0", "1.0.1")

    def broken(file):
        raise RuntimeError("unreadable")

    monkeypatch.setattr(code_context, "read_lines", broken)
    result, receipt = _upgrade(
        "npm", "quiet", "1.0.0", "1.0.1", context_lines=5, identity_diff_bytes=1000
    )

    assert result["status"] == "reviewed" and receipt["complete"] is True
    assert result["warn"] == plain["warn"] and result["block"] == plain["block"]
    assert result["identity_diff"] == "" and result["identity_diff_truncated"] is True
