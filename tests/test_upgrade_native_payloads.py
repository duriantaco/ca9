from __future__ import annotations

import pytest
from tests.test_upgrade_review import _kinds, _one, registry

__all__ = ["registry"]

PE = b"MZ" + b"\x90" * 62 + b"PE\x00\x00" + b"\x00" * 1200
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 900
MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 900


@pytest.mark.parametrize(
    ("path", "payload"),
    [
        ("pkg/_build.py", PE),
        ("pkg/data/strings.json", ELF),
        ("pkg/assets/logo.png", MACHO),
        ("pkg/locale/en.txt", PE),
    ],
)
def test_native_binaries_disguised_as_code_or_data_block(registry, path, payload):
    registry.pypi("pkg", "1.0", wheel={"pkg/__init__.py": "X = 1\n"})
    registry.pypi("pkg", "1.1", wheel={"pkg/__init__.py": "X = 1\n", path: payload})

    result, _ = _one("pypi", "pkg", "1.0", "1.1")

    assert "ambiguous_package_contents" in _kinds(result, "block")
    assert path in [delta["path"] for delta in result["block"]]


def test_npm_file_with_a_code_extension_holding_a_binary_blocks(registry):
    registry.npm("jspkg", "1.0.0", {"index.js": "module.exports = 1;\n"})
    registry.npm("jspkg", "1.0.1", {"index.js": "module.exports = 1;\n", "lib/helper.js": PE})

    result, _ = _one("npm", "jspkg", "1.0.0", "1.0.1")

    assert "ambiguous_package_contents" in _kinds(result, "block")


def test_binaries_under_native_names_stay_at_their_usual_level(registry):
    registry.pypi("pkg", "1.0", wheel={"pkg/__init__.py": "X = 1\n"})
    registry.pypi(
        "pkg",
        "1.1",
        wheel={
            "pkg/__init__.py": "X = 1\n",
            "pkg/_core.so": ELF,
            "pkg/bin/tool": ELF,
            "pkg/lib.dll": PE,
        },
    )

    result, _ = _one("pypi", "pkg", "1.0", "1.1")

    assert result["block"] == []
    assert set(_kinds(result, "warn")) == {"new_native_binary"}


LOADER = (
    "import ctypes, os\n\n"
    "def supported():\n"
    "    lib = ctypes.CDLL(os.path.join(os.path.dirname(__file__), 'colorlib.so'))\n"
    "    return lib.check()\n"
)


def test_pure_package_that_starts_loading_a_shipped_library_blocks(registry):
    registry.pypi("pure", "1.0", wheel={"pure/__init__.py": "X = 1\n"})
    registry.pypi(
        "pure",
        "1.1",
        wheel={"pure/__init__.py": "X = 1\n", "pure/support.py": LOADER, "pure/colorlib.so": ELF},
    )
    registry.pypi(
        "pure",
        "1.2",
        wheel={
            "pure/__init__.py": "X = 1\n",
            "pure/support.py": "import cffi\nffi = cffi.FFI()\ndef load():\n    return ffi.dlopen(__file__.replace('support.py', 'colorlib.so'))\n",
            "pure/colorlib.so": ELF,
        },
    )

    ctypes_result, _ = _one("pypi", "pure", "1.0", "1.1")
    cffi_result, _ = _one("pypi", "pure", "1.0", "1.2")

    for result in (ctypes_result, cffi_result):
        assert "uninspectable_import_time_code" in _kinds(result, "block")


def test_native_packages_and_system_library_loads_stay_below_block(registry):
    native = {"nat/__init__.py": "X = 1\n", "nat/_old.so": ELF}
    registry.pypi("nat", "1.0", wheel=native)
    registry.pypi(
        "nat",
        "1.1",
        wheel={
            **native,
            "nat/support.py": LOADER.replace("colorlib", "_extra"),
            "nat/_extra.so": ELF + b"\x01",
        },
    )
    registry.pypi("sys", "1.0", wheel={"sys/__init__.py": "X = 1\n"})
    registry.pypi(
        "sys",
        "1.1",
        wheel={
            "sys/__init__.py": "X = 1\n",
            "sys/clock.py": "import ctypes, ctypes.util\nlibc = ctypes.CDLL(ctypes.util.find_library('c'))\n",
        },
    )

    already_native, _ = _one("pypi", "nat", "1.0", "1.1")
    system_library, _ = _one("pypi", "sys", "1.0", "1.1")

    assert "uninspectable_import_time_code" not in _kinds(already_native, "block")
    assert system_library["block"] == []
