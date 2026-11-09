from __future__ import annotations

import base64
import zlib

from tests.test_upgrade_review import _kinds, _one, registry

__all__ = ["registry"]

CODE = base64.b64encode(b"require('child_process').execSync('uname -a')").decode()
BLOB = base64.b64encode(zlib.compress(bytes(range(256)) * 60, 0)).decode()


def _js(registry, name, files):
    registry.npm(name, "1.0.0", {"index.js": "module.exports = (a) => a;\n"})
    registry.npm(name, "1.0.1", files)
    return _one("npm", name, "1.0.0", "1.0.1")[0]


def test_indirect_eval_forms_fed_by_decoded_strings_block(registry):
    sinks = [
        f"(0, eval)(Buffer.from('{CODE}', 'base64').toString());\n",
        f"const s = atob('{CODE}');\n(0,eval)(s);\n",
        f"globalThis['eval'](Buffer.from('{CODE}', 'base64').toString('utf8'));\n",
        f"window.eval(atob('{CODE}'));\n",
    ]
    for index, sink in enumerate(sinks):
        result = _js(registry, f"ind{index}", {"index.js": sink + "module.exports = 1;\n"})
        assert "new_decode_exec" in _kinds(result, "block"), sink


def test_decoded_source_compiled_as_a_module_blocks(registry):
    filler = "".join(f"const opt_{index} = {index};\n" for index in range(60))
    code = (
        "const parts = ['" + CODE[:20] + "', '" + CODE[20:] + "'];\n"
        "const src = Buffer.from(parts.join(''), 'base64').toString();\n"
        + filler
        + "setImmediate(() => {\n"
        "  const Module = require('module');\n"
        "  const m = new Module('.');\n"
        "  m._compile(src, 'x.js');\n"
        "});\nmodule.exports = 1;\n"
    )

    result = _js(registry, "compiled", {"index.js": code})

    assert "new_decode_exec" in _kinds(result, "block")


def test_string_array_lookups_that_load_sensitive_modules_block(registry):
    encoded = [base64.b64encode(item.encode()).decode() for item in ("child_process", "execSync")]
    shapes = {
        "b64array": (
            f"const _0x3f2a=['{encoded[0]}','{encoded[1]}'];\n"
            "function _0x51c0(i){return Buffer.from(_0x3f2a[i-0x1a],'base64').toString();}\n"
            "const cp=require(_0x51c0(0x1a));cp[_0x51c0(0x1b)]('id');\n"
        ),
        "plainarray": (
            "var _0x9b1d=['execSync','child_process','log'];\n"
            "var _0x2c44=function(i){i=i-0x0;return _0x9b1d[i];};\n"
            "require(_0x2c44('0x1'))[_0x2c44('0x0')]('id');\n"
        ),
    }
    for name, code in shapes.items():
        result = _js(registry, name, {"index.js": code + "module.exports = 1;\n"})
        assert "new_decode_exec" in _kinds(result, "block"), name


def test_large_encoded_blob_decoded_into_an_eval_blocks(registry):
    code = (
        "const zlib = require('zlib');\n"
        f"const _b = '{BLOB}';\n"
        "const _p = zlib.inflateSync(Buffer.from(_b, 'base64')).toString();\n"
        "(0, eval)(_p);\n"
    )

    result = _js(
        registry,
        "blobpkg",
        {"index.js": "require('./lib/engine.min.js');\n", "lib/engine.min.js": code},
    )

    assert "obfuscation_growth" in _kinds(result, "block")


def test_transpiled_calls_source_maps_wasm_and_plain_arrays_stay_quiet(registry):
    quiet = {
        "index.js": (
            "var _utils = require('./utils');\n"
            "module.exports = function (x) { return (0, _utils.default)(x); };\n"
            f"//# sourceMappingURL=data:application/json;base64,{BLOB}\n"
        ),
        "utils.js": "exports.default = (x) => x;\n",
        "wasm.js": (
            f"const bytes = Buffer.from('{BLOB}', 'base64');\n"
            "module.exports = WebAssembly.instantiate(bytes);\n"
        ),
        "lookup.js": (
            "var _0x1a2b=['lodash','map','filter'];\n"
            "var _0x3c4d=function(i){return _0x1a2b[i];};\n"
            "module.exports=require(_0x3c4d(0))[_0x3c4d(1)];\n"
        ),
        "register.js": (
            "const Module = require('module');\n"
            "const fs = require('fs');\n"
            "module.exports = (file) => { const m = new Module(file);\n"
            "  m._compile(transform(fs.readFileSync(file, 'utf8')), file); return m; };\n"
            "function transform(code) { return code; }\n"
        ),
    }

    result = _js(registry, "quietpkg", quiet)

    assert result["block"] == []
