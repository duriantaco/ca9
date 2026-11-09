from __future__ import annotations

from packaging.tags import sys_tags
from tests.test_upgrade_review import _kinds, _one, registry
from tests.test_upgrade_review_bypasses import pypi_wheels

__all__ = ["registry"]

ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 120
HERE = str(next(iter(sys_tags())))


def _js(registry, name, code):
    registry.npm(name, "1.0.0", {"index.js": "module.exports = (a) => a;\n"})
    registry.npm(name, "1.0.1", {"index.js": code})
    return _one("npm", name, "1.0.0", "1.0.1")[0]


def test_process_binding_mentioned_in_comments_is_not_a_capability(registry):
    line_comment = _js(
        registry,
        "c1",
        "// Legacy `process.binding('util')` for very old Node versions.\nmodule.exports = 1;\n",
    )
    block_comment = _js(
        registry,
        "c2",
        "/* uses process.binding('natives') on old runtimes */\nmodule.exports = 1;\n",
    )
    real = _js(registry, "c3", "const fs = process.binding('fs');\nmodule.exports = fs;\n")
    in_string = _js(
        registry,
        "c4",
        "const note = '// not a comment';\nconst b = process.binding('fs');\nmodule.exports = b;\n",
    )

    assert line_comment["warn"] == [] and block_comment["warn"] == []
    assert _kinds(real, "warn") == ["new_import_time_exec"]
    assert _kinds(in_string, "warn") == ["new_import_time_exec"]


def test_extension_modules_keep_their_identity_across_abi_tags(registry):
    old = {"pkg/__init__.py": "X = 1\n", "pkg/_core.cpython-314-darwin.so": ELF}
    new = {"pkg/__init__.py": "X = 1\n", "pkg/_core.abi3.so": ELF + b"\x01"}
    registry.pypi("pkg", "1.0", wheel=old, wheel_tag=HERE)
    registry.pypi("pkg", "1.1", wheel=new, wheel_tag=HERE)
    added = {**new, "pkg/_extra.abi3.so": ELF + b"\x02"}
    registry.pypi("pkg", "1.2", wheel=added, wheel_tag=HERE)

    retagged, _ = _one("pypi", "pkg", "1.0", "1.1")
    extra, _ = _one("pypi", "pkg", "1.1", "1.2")

    assert retagged["warn"] == []
    assert [delta["path"] for delta in extra["warn"]] == ["pkg/_extra.abi3.so"]


def test_compiled_wheel_against_sdist_or_pure_wheel_of_a_native_project_is_not_new_native(registry):
    built = {"pkg/__init__.py": "X = 1\n", "pkg/_speed.cpython-399-x.so": ELF}
    registry.pypi(
        "srcpkg",
        "1.0",
        sdist={"pkg/__init__.py": "X = 1\n", "pkg/_speed.c": "int f(void){return 1;}\n"},
    )
    registry.pypi(
        "srcpkg", "1.1", wheel=built, sdist={"pkg/__init__.py": "X = 1\n"}, wheel_tag=HERE
    )
    pypi_wheels(
        registry,
        "mixed",
        "1.0",
        [
            ("py3-none-any", {"pkg/__init__.py": "X = 1\n"}),
            ("cp27-cp27mu-manylinux1_x86_64", built),
        ],
    )
    pypi_wheels(
        registry, "mixed", "1.1", [("py3-none-any", {"pkg/__init__.py": "X = 1\n"}), (HERE, built)]
    )

    from_sdist, _ = _one("pypi", "srcpkg", "1.0", "1.1")
    from_pure, _ = _one("pypi", "mixed", "1.0", "1.1")

    for result in (from_sdist, from_pure):
        assert "new_native_binary" not in _kinds(result, "warn")
        assert result["block"] == []


def test_a_previously_pure_project_that_starts_shipping_native_code_still_warns(registry):
    registry.pypi("purepkg", "1.0", wheel={"pkg/__init__.py": "X = 1\n"})
    pypi_wheels(
        registry,
        "purepkg",
        "1.1",
        [
            ("py3-none-any", {"pkg/__init__.py": "X = 1\n"}),
            (HERE, {"pkg/__init__.py": "X = 1\n", "pkg/_hidden.cpython-399-x.so": ELF}),
        ],
    )

    result, _ = _one("pypi", "purepkg", "1.0", "1.1")

    assert "new_native_binary" in _kinds(result, "warn")


def test_one_new_native_module_is_reported_once_across_wheels(registry):
    from tests.test_upgrade_review_bypasses import pypi_wheels

    base = {"pkg/__init__.py": "X = 1\n"}
    tags = ["cp312-cp312-win_amd64", "cp313-cp313-win_amd64", "cp312-cp312-manylinux2014_x86_64"]

    def built(tag, *names):
        abi = tag.split("-")[0]
        return {
            **base,
            **{
                f"pkg/{name}.{abi}-{tag.split('-')[-1]}.pyd": ELF + tag.encode() + name.encode()
                for name in names
            },
        }

    pypi_wheels(
        registry,
        "fanout",
        "1.0",
        [("py3-none-any", base), *((tag, built(tag, "_core")) for tag in tags)],
    )
    pypi_wheels(
        registry,
        "fanout",
        "1.1",
        [("py3-none-any", base), *((tag, built(tag, "_core", "_speed")) for tag in tags)],
    )

    result, _ = _one("pypi", "fanout", "1.0", "1.1")

    assert _kinds(result, "warn") == ["new_native_binary"]
