from __future__ import annotations

import ast
import base64
import binascii
import json
import posixpath
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

from ca9.artifacts.model import ArtifactFile, ArtifactSnapshot
from ca9.core.models import Evidence, Finding, RiskSignal, SourceEvidence

MAX_TEXT_BYTES = 2 * 1024 * 1024
# Oversized files are reported as uninspected, but their first and last bytes
# are still scanned with text rules: bundled loaders often sit at either end.
OVERSIZE_SCAN_BYTES = 1024 * 1024
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
_CODE_SUFFIXES = (".py", ".pth", ".js", ".cjs", ".mjs", ".sh")
_NATIVE_SUFFIXES = (".node", ".so", ".dylib", ".dll", ".exe")
# ELF, PE, and thin Mach-O headers; fat Mach-O is omitted because Java class
# files share its magic.
_NATIVE_MAGIC = (b"\x7fELF", b"MZ", b"\xfe\xed\xfa", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe")
_MAX_NESTED_SOURCE_DEPTH = 2
_MAX_RESOLVE_DEPTH = 16
_EXFIL_LINE_WINDOW = 80

# Text fallbacks for Python sources the AST cannot parse (for example Python 2
# sdists) and for partially scanned oversized files.
_PTH_SUSPICIOUS_RE = re.compile(
    r"\b(exec|eval|compile|subprocess|os\.system|os\.popen|socket|urllib|requests|http|"
    r"base64|zlib|marshal|codecs|binascii)\b",
    re.I,
)
_SETUP_EXEC_RE = re.compile(
    r"\b(subprocess\.(?:run|call|Popen|check_call|check_output)|os\.system|"
    r"os\.popen|exec\((?!\s*(?:open|io\.open|codecs\.open)\()|eval\(|urllib\.request|"
    r"requests\.|socket\.)",
    re.I,
)
_ENCODED_EXEC_RE = re.compile(
    r"(base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode|"
    r"binascii\.unhexlify)[\s\S]{0,800}(?<![\w.])(exec|eval|compile)\s*\(|"
    r"(?<![\w.])(?:exec|eval)\s*\([^\n]{0,200}?"
    r"(?:b64decode|decompress|unhexlify|marshal\.loads|codecs\.decode)",
    re.I,
)
_STARTUP_CUSTOMIZE_RE = re.compile(
    r"(?<![\w.])(?:exec|eval|compile)\s*\(|"
    r"\b(subprocess|os\.system|socket|urllib|requests|base64)\b",
    re.I,
)
_CREDENTIAL_RE = re.compile(
    r"(?:json\.dumps?|str|repr|urlencode)\(\s*(?:dict\()?\s*os\.environ\b(?!\.get|\[)|"
    r"\.aws[/\\]credentials|\.ssh[/\\]id_(?:rsa|ed25519|ecdsa|dsa)|\.npmrc\b|\.pypirc\b|"
    r"\.git-credentials|Login Data|Local Storage[/\\]+leveldb|login\.keychain|"
    r"find-(?:generic|internet)-password",
    re.I,
)
_NETWORK_RE = re.compile(
    r"\b(requests\.(?:get|post|put|request)|urllib\.request\.urlopen|"
    r"http\.client|socket\.socket|ftplib\.FTP|smtplib\.SMTP)\b",
    re.I,
)
_SILENT_PROCESS_RE = re.compile(
    r"\b(subprocess\.(?:run|call|Popen|check_call|check_output)|os\.system|os\.popen)\b",
    re.I,
)

NPM_INSTALL_HOOKS = ("preinstall", "install", "postinstall")
NPM_PREPARE_HOOK = "prepare"
NPM_SCRIPT_EXEC_RE = re.compile(
    r"\b(?:curl|wget)(?:\.exe)?(?=\s|$)|\bnode\s+(?:-e|--eval)\b|"
    r"\beval\b|\bbase64\b|"
    r"\b(?:bash|sh)\s+-c\b|/dev/tcp|\bchmod\b|\bpowershell\b|\biex\b|"
    r"\|\s*(?:sh|bash)\b|\bpython(?:[0-9]+(?:\.[0-9]+)?)?\s+-c\b|"
    r"\$\(|`|>\s*/dev/|\b(?:nc|ncat)(?=\s|$)",
    re.I,
)
# JavaScript identifiers are case-sensitive, and patterns that open with a
# literal let the regex engine skip ahead quickly in multi-megabyte bundles.
# Process sinks are child_process calls; RegExp.prototype.exec is ".exec(".
_JS_PROCESS_SINK = (
    r"child_process|exec(?:Sync|File|FileSync)?\s*\((?<![\w$.]exec\()|"
    r"\.(?:spawn|spawnSync|execFile|execFileSync|fork)\s*\("
)
_JS_INDIRECT_EVAL = (
    r"\(\s*0\s*,\s*(?:\w+\s*\.\s*)?eval\s*\)\s*\(|"
    r"\[\s*['\"`]eval['\"`]\s*\]\s*\(|\beval\s*\?\.\s*\("
)
_JS_ENCODED_EXEC_RE = re.compile(
    r"(?:Buffer\.from\s*\([^)]*?['\"](?:base64|hex)['\"]|atob\s*\()"
    r"[\s\S]{0,400}?"
    r"(?:eval\s*\(|new\s+Function|"
    + _JS_INDIRECT_EVAL
    + r"|\._compile\s*\(|\brunIn(?:New|This)?Context\s*\(|"
    + _JS_PROCESS_SINK
    + r")"
)
# The sink wraps the decoder directly: eval(Buffer.from(x, 'base64').toString()).
_JS_SINK_WRAPS_DECODE_RE = re.compile(
    r"(?:(?:eval|Function|vm\.runIn(?:New|This)?Context|vm\.Script|\._compile)\s*\(|"
    + _JS_INDIRECT_EVAL
    + r")\s*"
    r"(?:['\"][\w$]*['\"]\s*,\s*)*(?:[\w$.]+\s*\(\s*)*"
    r"(?:Buffer\.from\s*\([^)]*?,\s*['\"](?:base64|hex)['\"]|atob\s*\(|"
    r"String\.fromCharCode\s*\()"
)
_JS_MODULE_LOAD = r"(?:\brequire|getBuiltinModule['\"`\]]*)\s*\(\s*['\"`](?:node:)?"
_JS_PROCESS_RE = re.compile(
    _JS_MODULE_LOAD + r"child_process['\"`]\s*\)|"
    r"child_process\.(?:exec|execSync|spawn|spawnSync|fork)|"
    r"execSync\s*\("
)
_JS_NETWORK_RE = re.compile(
    _JS_MODULE_LOAD + r"(?:https?|net|dgram|dns|tls)['\"`]\s*\)|"
    r"fetch\s*\(|axios\b|XMLHttpRequest|https?\.(?:request|get)\s*\("
)
# Harvesting, not mere access: dumping process.env, filtering it for secrets,
# or reading credential stores. A single process.env.API_KEY is SDK config.
_JS_CREDENTIAL_RE = re.compile(
    r"JSON\.stringify\(\s*(?:\{\s*\.\.\.\s*)?process\.env\b(?!\s*\.)|"
    r"(?:body|data|json|payload)\s*:\s*process\.env\b(?!\s*\.)|"
    r"Object\.(?:keys|entries|values)\(\s*process\.env\s*\)[\s\S]{0,400}?"
    r"['\"`/][^'\"`/\n]{0,80}?(?i:token|secret|passw|api_?key|credential)|"
    r"\.(?:npmrc|git-credentials|pypirc)\b|\.ssh[/\\]+id_(?:rsa|ed25519|ecdsa|dsa)|"
    r"\.aws[/\\]+credentials|\.config[/\\]+gcloud|Login Data|Local Storage[/\\]+leveldb|"
    r"login\.keychain|find-(?:generic|internet)-password|wallet\.dat|"
    r"readFileSync\([^)\n]{0,200}?['\"`][^'\"`\n]*[/\\]?\.env['\"`]"
)
# The same harvest rules split by a literal hint, so multi-megabyte bundles
# only pay for the regexes whose hint occurs in the file.
_JS_HARVEST_RULES = tuple(
    (hints, re.compile(pattern))
    for hints, pattern in (
        (
            ("process.env",),
            r"JSON\.stringify\(\s*(?:\{\s*\.\.\.\s*)?process\.env\b(?!\s*\.)|"
            r"(?:body|data|json|payload)\s*:\s*process\.env\b(?!\s*\.)|"
            r"Object\.(?:keys|entries|values)\(\s*process\.env\s*\)[\s\S]{0,400}?"
            r"['\"`/][^'\"`/\n]{0,80}?(?i:token|secret|passw|api_?key|credential)",
        ),
        ((".npmrc", ".git-credentials", ".pypirc"), r"\.(?:npmrc|git-credentials|pypirc)\b"),
        ((".ssh",), r"\.ssh[/\\]+id_(?:rsa|ed25519|ecdsa|dsa)"),
        ((".aws",), r"\.aws[/\\]+credentials"),
        (("gcloud",), r"\.config[/\\]+gcloud"),
        (("Local Storage",), r"Local Storage[/\\]+leveldb"),
        (
            ("Login Data", "keychain", "-password", "wallet.dat"),
            r"Login Data|login\.keychain|find-(?:generic|internet)-password|wallet\.dat",
        ),
        (("readFileSync",), r"readFileSync\([^)\n]{0,200}?['\"`][^'\"`\n]*[/\\]?\.env['\"`]"),
    )
)
_JS_REQUIRE_CALL_RE = re.compile(r"(?:require|import)\s*\(")
# Statements that can build a module name: concatenation, joined arrays,
# character codes, or escaped literals. Used for review evidence.
_JS_OBFUSCATED_REQUIRE_HINT_RE = re.compile(
    r"(?:require|import)\s*\(\s*(?:['\"`][^'\"`\n]*['\"`]\s*\+|\[|String\.fromCharCode|"
    r"['\"][^'\"\n]*\\[xu])"
)
_JS_DANGEROUS_MODULES = frozenset(
    {
        "child_process",
        "dgram",
        "dns",
        "fs",
        "http",
        "http2",
        "https",
        "module",
        "net",
        "os",
        "tls",
        "vm",
        "worker_threads",
    }
)
_JS_STRING_RE = re.compile(
    r"""\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)"|`((?:[^`\\$]|\\.|\$(?!\{))*)`)\s*""",
    re.S,
)
_JS_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|(.))", re.S
)
_NPM_HOOK_SCRIPT_RE = re.compile(
    r"(?:^|&&|\|\||;)\s*(?:node|bun|deno\s+run)\s+(?:--?[\w-]+(?:=\S*)?\s+)*"
    r"((?:\./)?[\w@][\w@./-]*)"
)
_JS_DOWNLOAD_RE = re.compile(
    r"\bhttps?\.(?:get|request)\s*\(|\bfetch\s*\(|\baxios\b|\bgot\s*\(|XMLHttpRequest|"
    r"\bcurl\b|\bwget\b|Invoke-WebRequest|\b(?:irm|iwr)\b",
    re.I,
)
_JS_EXECUTE_RE = re.compile(
    _JS_PROCESS_SINK + r"|\bchmod(?:Sync)?\b|\|\s*(?:ba)?sh\b|\bpowershell\b",
    re.I,
)
_JS_ASSIGN = r"\s*=(?![=>])"
_JS_DOTTED_ASSIGN_RE = re.compile(
    r"\.\s*(fetch|ethereum|solana|open|send|setRequestHeader|request|sendAsync|enable|"
    r"signTransaction|signAllTransactions|signAndSendTransaction|signMessage|"
    r"signTypedData(?:_v[34])?)" + _JS_ASSIGN
)
_JS_DEFINE_PROPERTY_RE = re.compile(
    r"(?:Object|Reflect)\s*\.\s*(?:defineProperty|set)\s*\(\s*([^,()\n]{1,80}?)\s*,\s*"
    r"(['\"`])([\w$]{1,40})\2"
)
_JS_COMPUTED_ASSIGN_RE = re.compile(
    r"\[\s*((?:['\"`][^\[\]\n]{0,200}?)|(?:[\w$]+\s*\([^()\[\]\n]{0,40}\)))\s*\]" + _JS_ASSIGN
)
_JS_TARGET_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_$.")
_JS_DEFINE_PROPERTY_VARIABLE_RE = re.compile(
    r"(?:Object|Reflect)\s*\.\s*(?:defineProperty|set)\s*\(\s*([A-Za-z_$][\w$.]{0,80}?)\s*,\s*"
    r"([A-Za-z_$][\w$]{0,40})\s*,"
)
_JS_BARE_FETCH_ASSIGN_RE = re.compile(r"(?<![\w$.])fetch\s*=(?![=>])")
_JS_LOCAL_FETCH_BINDING_RE = re.compile(
    r"(?:const|let|var|function|class)\s+fetch\b|import\s+fetch\b|"
    r"import\s*\{[^}]{0,400}\bfetch\b[^}]{0,400}\}"
)
_JS_STRING_TABLE_RE = re.compile(
    r"=\s*\[\s*((?:['\"][^'\"\\\n]{0,64}['\"]\s*,\s*){2,}"
    r"['\"][^'\"\\\n]{0,64}['\"])\s*,?\s*\]"
)
_JS_IDENTIFIER_BEFORE_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*$")
_JS_TABLE_STRING_RE = re.compile(r"['\"]([^'\"\\\n]{0,64})['\"]")
_JS_PROVIDER_ARGUMENT_RE = re.compile(r"(?:ethereum|solana)\s*[,)]")
_JS_PROVIDER_CALLEE_RE = re.compile(
    r"([A-Za-z_$][\w$]*)\s*\(\s*(?:(?:window|globalThis|self)\s*\.\s*)?"
    r"(?:phantom\s*\.\s*)?$"
)
_JS_ALIAS_RE = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;,\n]{1,160})")
_JS_IDENTIFIER_RE = re.compile(r"[A-Za-z_$][\w$]*")
_JS_GLOBAL_NAMES = frozenset({"window", "globalThis", "self", "global", "top", "parent", "frames"})
_JS_ALIAS_TOKENS = _JS_GLOBAL_NAMES | {"typeof", "undefined"}
_MAX_JS_ALIASES = 20
_JS_DECODER_CALL_RE = re.compile(r"[\w$]+\s*\([^()]*\)")
_JS_BASE64_LITERAL_RE = re.compile(r"(['\"])([A-Za-z0-9+/]{4,88}={0,2})\1")
_JS_ESCAPED_LITERAL_RE = re.compile(r"(['\"])((?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){3,})\1")
_HIJACK_SENSITIVE_NAMES = frozenset(
    {"fetch", "XMLHttpRequest", "ethereum", "solana", "phantom", "web3"}
)
_HIJACK_OVERRIDE_NAMES = frozenset(
    {
        "fetch",
        "ethereum",
        "solana",
        "open",
        "send",
        "setRequestHeader",
        "request",
        "sendAsync",
        "enable",
        "signTransaction",
        "signAllTransactions",
        "signAndSendTransaction",
        "signMessage",
        "signTypedData",
        "signTypedData_v3",
        "signTypedData_v4",
    }
)
_HIJACK_TEXT_HINTS = ("fetch", "XMLHttpRequest", "ethereum", "solana")
_CRYPTO_ADDRESS_RE = re.compile(
    r"(?<![0-9A-Za-z_$])0x[0-9a-fA-F]{40}(?![0-9A-Za-z_$])|"
    r"0x\[[^\]\n]{1,24}\]\{40\}|"
    r"0x\\[dw]\{40\}|"
    r"\[13\]\[a-km-zA-HJ-NP-Z1-9\]|"
    r"bc1\[|"
    r"\[1-9A-HJ-NP-Za-km-z\]\{3[2-9],\s*4[0-4]\}|"
    r"['\"`](?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34}|"
    r"T[1-9A-HJ-NP-Za-km-z]{33})['\"`]"
)
_MAX_HIJACK_MATCHES = 5000
_RUNTIME_INSTALL_RE = re.compile(
    r"bun\.sh/install|oven-sh/bun|deno\.land/(?:x/)?install|dl\.deno\.land|"
    r"(?:spawn|spawnSync|exec|execSync|execFile|execFileSync)\s*\(\s*['\"`]bun\b",
    re.I,
)

# Python sinks, resolved through import aliases and simple assignments.
_EXEC_CALLS = frozenset({"exec", "eval", "compile", "execfile"})
_PROCESS_CALLS = frozenset(
    {
        "asyncio.create_subprocess_exec",
        "asyncio.create_subprocess_shell",
        "commands.getoutput",
        "os.execl",
        "os.execle",
        "os.execlp",
        "os.execlpe",
        "os.execv",
        "os.execve",
        "os.execvp",
        "os.execvpe",
        "os.popen",
        "os.posix_spawn",
        "os.posix_spawnp",
        "os.spawnl",
        "os.spawnle",
        "os.spawnlp",
        "os.spawnv",
        "os.spawnve",
        "os.spawnvp",
        "os.startfile",
        "os.system",
        "pty.spawn",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
        "subprocess.run",
    }
)
_NETWORK_CALLS = frozenset(
    {
        *(
            f"{module}.{name}"
            for module in ("requests", "httpx")
            for name in (
                "get",
                "post",
                "put",
                "patch",
                "delete",
                "head",
                "options",
                "request",
                "stream",
                "Session",
                "session",
                "Client",
                "AsyncClient",
            )
        ),
        "aiohttp.ClientSession",
        "aiohttp.request",
        "ftplib.FTP",
        "ftplib.FTP_TLS",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "httplib.HTTPConnection",
        "httplib.HTTPSConnection",
        "pycurl.Curl",
        "smtplib.SMTP",
        "smtplib.SMTP_SSL",
        "socket.create_connection",
        "socket.socket",
        "telnetlib.Telnet",
        "urllib.request.Request",
        "urllib.request.build_opener",
        "urllib.request.urlopen",
        "urllib.request.urlretrieve",
        "urllib.urlopen",
        "urllib.urlretrieve",
        "urllib2.Request",
        "urllib2.urlopen",
        "urllib3.PoolManager",
        "urllib3.request",
    }
)
# Client constructors prepare connections without sending data; creating one
# at import time is a normal library pattern.
_NETWORK_CLIENT_CALLS = frozenset(
    {
        "aiohttp.ClientSession",
        "http.client.HTTPConnection",
        "http.client.HTTPSConnection",
        "httplib.HTTPConnection",
        "httplib.HTTPSConnection",
        "httpx.AsyncClient",
        "httpx.Client",
        "pycurl.Curl",
        "requests.Session",
        "requests.session",
        "urllib.request.Request",
        "urllib.request.build_opener",
        "urllib2.Request",
        "urllib3.PoolManager",
    }
)
_DECODE_CALLS = frozenset(
    {
        "base64.a85decode",
        "base64.b16decode",
        "base64.b32decode",
        "base64.b64decode",
        "base64.b85decode",
        "base64.decodebytes",
        "base64.decodestring",
        "base64.standard_b64decode",
        "base64.urlsafe_b64decode",
        "binascii.a2b_base64",
        "binascii.a2b_hex",
        "binascii.unhexlify",
        "bytearray.fromhex",
        "bytes.fromhex",
        "bz2.decompress",
        "codecs.decode",
        "gzip.decompress",
        "lzma.decompress",
        "marshal.loads",
        "zlib.decompress",
    }
)
_SERIALIZE_CALLS = frozenset(
    {
        "base64.b64encode",
        "base64.urlsafe_b64encode",
        "json.dump",
        "json.dumps",
        "marshal.dumps",
        "pickle.dumps",
        "repr",
        "str",
        "urllib.parse.urlencode",
        "urllib.urlencode",
    }
)
_ENVIRON_DUMP_CALLS = frozenset(
    {"os.environ.copy", "os.environ.items", "os.environ.keys", "os.environ.values"}
)
_WRAPPER_CALLS = frozenset({"dict", "list", "tuple", "sorted", "str", "repr", "set"})
_RISKY_IMPORT_ROOTS = frozenset(
    {
        "base64",
        "binascii",
        "codecs",
        "http",
        "httplib",
        "httpx",
        "marshal",
        "pty",
        "requests",
        "socket",
        "subprocess",
        "urllib",
        "urllib2",
        "zlib",
    }
)
_BUILTIN_PREFIXES = ("__builtins__.", "builtins.", "__builtin__.", "__globals__.")
_INTERESTING_NAMES = frozenset(
    {
        prefix
        for name in (
            *_EXEC_CALLS,
            *_PROCESS_CALLS,
            *_NETWORK_CALLS,
            *_DECODE_CALLS,
            *_SERIALIZE_CALLS,
            *_ENVIRON_DUMP_CALLS,
            "__import__",
            "getattr",
            "importlib.import_module",
        )
        for prefix in (
            ".".join(name.split(".")[: index + 1]) for index in range(name.count(".") + 1)
        )
    }
)
_DANGEROUS_RESOLVED = _EXEC_CALLS | _PROCESS_CALLS | _NETWORK_CALLS | {"__import__"}
_DOWNLOAD_COMMAND_RE = re.compile(r"^\s*(?:\S*/)?(?:curl|wget|nc|ncat|scp|ftp)(?:\.exe)?\b")
_SECRET_NAME_RE = re.compile(r"token|secret|passw|api[_-]?key|access[_-]?key|credential", re.I)
_CREDENTIAL_PATH_RE = re.compile(
    r"(?:^|[/\\~])\.(?:aws|ssh|gnupg)(?:[/\\]|$)|"
    r"(?:^|[/\\~])\.(?:npmrc|pypirc|git-credentials|env|vault-token)$|"
    r"\.config[/\\](?:gcloud|gh)\b|\bid_(?:rsa|ed25519|ecdsa|dsa)$|"
    r"(?:^|[/\\])(?:Login Data|logins\.json|key4\.db|cookies\.sqlite|wallet\.dat)$|"
    r"Local Storage[/\\]+leveldb|login\.keychain|"
    r"\bfind-(?:generic|internet)-password\b|\bdump-keychain\b"
)
_SPACED_CREDENTIAL_RE = re.compile(r"Login Data|Local Storage|keychain|password")
_ENCODED_BLOB_RE = re.compile(r"[A-Za-z0-9+/_-]{200,}={0,2}|(?:[0-9a-fA-F]{2}){100,}")
# Startup (.pth) lines from common packaging tools: setuptools' distutils
# shim, editable-install finders, virtualenv, pywin32, and namespace packages.
_BENIGN_PTH_MODULE_RE = re.compile(
    r"(?:os|sys|types|site|importlib(?:\.util|\.machinery)?|_virtualenv|_distutils_hack|"
    r"pywin32_bootstrap|__editable__[\w.]*|__editable___\w+|_editable_impl_\w+)"
)
_BENIGN_PTH_CALLS = frozenset(
    {
        "__import__",
        "getattr",
        "hasattr",
        "importlib.machinery.PathFinder.find_spec",
        "importlib.util.module_from_spec",
        "len",
        "os.environ.get",
        "os.path.dirname",
        "os.path.exists",
        "os.path.join",
        "sys._getframe",
        "sys.modules.setdefault",
        "types.ModuleType",
    }
)
_BENIGN_PTH_METHODS = frozenset({"add_shim", "append", "insert", "install", "setdefault"})
_PTH_CRITICAL_KINDS = frozenset(
    {
        "blob",
        "credential_path",
        "decode",
        "encoded_exec",
        "exec_dynamic",
        "exec_risky",
        "harvest",
        "network",
        "network_client",
        "process",
        "risky_import",
    }
)
_RISKY_NESTED_KINDS = frozenset(
    {"encoded_exec", "exec_risky", "network", "network_client", "process"}
)


@dataclass(frozen=True)
class PackageCodeRule:
    id: str
    title: str
    severity: str
    action: str
    confidence: str
    description: str


_PTH_RULE = PackageCodeRule(
    id="python-startup-pth-exec",
    title="Python startup file executes suspicious code",
    severity="critical",
    action="block",
    confidence="high",
    description=".pth files run during interpreter startup; suspicious code here is high risk",
)
_PTH_IMPORT_RULE = PackageCodeRule(
    id="python-startup-pth-import",
    title="Python startup file runs import-time code",
    severity="medium",
    action="investigate",
    confidence="medium",
    description=(
        ".pth import lines run on every interpreter start; this one is not a recognized "
        "packaging-tool shape"
    ),
)
_SETUP_RULE = PackageCodeRule(
    id="setup-install-exec",
    title="Install script executes process or network code",
    severity="high",
    action="block",
    confidence="medium",
    description="setup/build code can run during installation",
)
_ENCODED_RULE = PackageCodeRule(
    id="encoded-execution",
    title="Encoded payload is decoded and executed",
    severity="high",
    action="block",
    confidence="medium",
    description="encoded payload execution is common in malicious package loaders",
)
_STARTUP_CUSTOMIZE_RULE = PackageCodeRule(
    id="python-startup-customize-exec",
    title="Python startup customization file contains suspicious behavior",
    severity="critical",
    action="block",
    confidence="high",
    description="sitecustomize.py and usercustomize.py execute automatically during interpreter startup",
)
_CREDENTIAL_EXFIL_RULE = PackageCodeRule(
    id="credential-network-exfiltration",
    title="Package code harvests credentials near network APIs",
    severity="high",
    action="block",
    confidence="medium",
    description=(
        "dumping environment secrets or reading credential stores near outbound network "
        "code is a common exfiltration pattern"
    ),
)
_SILENT_PROCESS_RULE = PackageCodeRule(
    id="silent-process-execution",
    title="Package code can launch external processes",
    severity="medium",
    action="investigate",
    confidence="medium",
    description="unexpected process execution in package code can hide payload download or execution",
)
_IMPORT_TIME_RULE = PackageCodeRule(
    id="import-time-risky-behavior",
    title="Package executes risky behavior at import time",
    severity="high",
    action="block",
    confidence="medium",
    description="module-level package code runs as soon as the module is imported",
)
_UNINSPECTED_FILE_RULE = PackageCodeRule(
    id="package-file-uninspected",
    title="Package code file exceeds the inspection size limit",
    severity="medium",
    action="investigate",
    confidence="high",
    description=(
        "code larger than the text inspection limit was only partially scanned; large "
        "bundles can hide payloads"
    ),
)
_NPM_INSTALL_HOOK_RULE = PackageCodeRule(
    id="npm-install-script",
    title="npm package defines an install lifecycle script",
    severity="medium",
    action="investigate",
    confidence="high",
    description="preinstall/install/postinstall scripts run automatically during npm install",
)
_NPM_INSTALL_EXEC_RULE = PackageCodeRule(
    id="npm-install-script-exec",
    title="npm install script runs shell, network, or eval code",
    severity="critical",
    action="block",
    confidence="medium",
    description="install-time scripts that fetch or execute code are a primary supply-chain attack vector",
)
_NPM_INSTALL_DOWNLOADER_RULE = PackageCodeRule(
    id="npm-install-script-downloader",
    title="npm install script runs a bundled downloader",
    severity="high",
    action="investigate",
    confidence="medium",
    description=(
        "an install lifecycle script runs bundled code that downloads and executes programs "
        "or installs another runtime"
    ),
)
_NPM_ENCODED_RULE = PackageCodeRule(
    id="npm-encoded-execution",
    title="npm package decodes and executes an encoded payload",
    severity="high",
    action="block",
    confidence="medium",
    description="decoding base64/hex into eval, Function, or child_process is a common loader pattern",
)
_NPM_OBFUSCATED_REQUIRE_RULE = PackageCodeRule(
    id="npm-obfuscated-require",
    title="npm package hides a sensitive module load",
    severity="high",
    action="block",
    confidence="medium",
    description="building a module name such as child_process at runtime hides process or network access",
)
_NPM_CREDENTIAL_EXFIL_RULE = PackageCodeRule(
    id="npm-credential-exfiltration",
    title="npm package code harvests credentials with process or network APIs",
    severity="high",
    action="block",
    confidence="medium",
    description=(
        "dumping process.env or reading credential stores near outbound network or process "
        "execution is a common exfiltration pattern"
    ),
)
_NPM_WALLET_HIJACK_RULE = PackageCodeRule(
    id="npm-wallet-network-hijack",
    title="npm package hijacks wallet providers or network APIs",
    severity="high",
    action="block",
    confidence="medium",
    description=(
        "replacing browser wallet methods or the global fetch/XMLHttpRequest from obfuscated "
        "code, or next to crypto-address patterns, is how wallet drainers swap payment "
        "addresses"
    ),
)
_NPM_NATIVE_BINARY_RULE = PackageCodeRule(
    id="npm-native-binary",
    title="npm package ships native executable code",
    severity="medium",
    action="investigate",
    confidence="high",
    description="native binaries cannot be inspected by static source rules",
)


def analyze_package_snapshots(snapshots: tuple[ArtifactSnapshot, ...]) -> list[Finding]:
    findings: list[Finding] = []
    for snapshot in snapshots:
        npm = _is_npm_snapshot(snapshot)
        native_files: list[ArtifactFile] = []
        for file in snapshot.files:
            if npm and file.relative_path.lower().endswith(_NATIVE_SUFFIXES):
                native_files.append(file)
                continue
            raw = _read_bytes(file, OVERSIZE_SCAN_BYTES if file.size > MAX_TEXT_BYTES else None)
            if raw is None:
                continue
            if npm and _is_native_binary(raw):
                native_files.append(file)
                continue
            if file.size > MAX_TEXT_BYTES:
                findings.extend(_analyze_oversized_file(snapshot, file))
                continue
            text = _decode_text(raw)
            if text is None:
                continue
            findings.extend(_analyze_file(snapshot, file, text))
        if native_files:
            findings.append(
                _finding(
                    snapshot,
                    native_files[0],
                    "",
                    _NPM_NATIVE_BINARY_RULE,
                    0,
                    {
                        "binary_count": len(native_files),
                        "binary_paths": [file.relative_path for file in native_files[:10]],
                    },
                )
            )
    return _dedupe_findings(findings)


def _analyze_file(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
) -> list[Finding]:
    findings: list[Finding] = []
    lower_path = file.relative_path.lower()

    if lower_path.endswith(".pth"):
        findings.extend(_analyze_pth(snapshot, file, text))

    if lower_path.endswith(".py"):
        findings.extend(_analyze_python(snapshot, file, text, PurePosixPath(lower_path).name))

    if _is_npm_snapshot(snapshot) and lower_path.endswith("package.json"):
        findings.extend(_analyze_npm_manifest(snapshot, file, text))

    if _is_npm_snapshot(snapshot) and lower_path.endswith((".js", ".cjs", ".mjs")):
        findings.extend(_analyze_npm_script(snapshot, file, text))

    return findings


def _is_npm_snapshot(snapshot: ArtifactSnapshot) -> bool:
    return snapshot.artifact.kind == "npm-tarball" or snapshot.package.ecosystem.lower() == "npm"


def _finding(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
    rule: PackageCodeRule,
    offset: int,
    extra: dict[str, Any] | None = None,
) -> Finding:
    line_no, snippet = _line_snippet(text, offset)
    source = SourceEvidence(
        source="package artifact",
        path=f"{snapshot.archive_path}!{file.relative_path}",
        reader="ca9 package-code analyzer",
        detail=rule.id,
    )
    evidence = Evidence(
        kind="package_code",
        description=rule.description,
        source=source,
        metadata={
            "rule_id": rule.id,
            "artifact_kind": snapshot.artifact.kind,
            "artifact_url": snapshot.artifact.url,
            "artifact_hash": snapshot.artifact.hash,
            "file_path": file.relative_path,
            "line": line_no,
            "snippet": snippet,
            **(extra or {}),
        },
    )
    signal = RiskSignal(
        signal_type=rule.id,
        package_key=snapshot.package.key,
        severity=rule.severity,
        confidence=rule.confidence,
        evidence=(evidence,),
        metadata={
            "package": snapshot.package.name,
            "version": snapshot.package.version,
            "file_path": file.relative_path,
            "line": line_no,
        },
    )
    return Finding(
        title=f"{rule.title} in {snapshot.package.name}",
        signal_type=rule.id,
        package_key=snapshot.package.key,
        severity=rule.severity,
        signals=(signal,),
        evidence=(evidence,),
        metadata={
            "action": rule.action,
            "reason": rule.description,
            "package": snapshot.package.name,
            "version": snapshot.package.version,
            "dependency_kind": snapshot.package.dependency_kind,
            "policy_id": f"ca9.{rule.id}",
            "file_path": file.relative_path,
            "line": line_no,
            **(extra or {}),
        },
    )


def _read_text_file(file: ArtifactFile) -> str | None:
    if file.size > MAX_TEXT_BYTES:
        return None
    raw = _read_bytes(file)
    return _decode_text(raw) if raw is not None else None


def _read_bytes(file: ArtifactFile, limit: int | None = None) -> bytes | None:
    try:
        with file.path.open("rb") as stream:
            return stream.read(limit if limit is not None else -1)
    except OSError:
        return None


def _decode_text(raw: bytes) -> str | None:
    if b"\x00" in raw[:4096]:
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="ignore")


def _is_native_binary(raw: bytes) -> bool:
    return raw.startswith(_NATIVE_MAGIC) and b"\x00" in raw[:4096]


def _analyze_oversized_file(snapshot: ArtifactSnapshot, file: ArtifactFile) -> list[Finding]:
    lower_path = file.relative_path.lower()
    if not lower_path.endswith(_CODE_SUFFIXES):
        return []
    findings = [
        _finding(
            snapshot,
            file,
            "",
            _UNINSPECTED_FILE_RULE,
            0,
            {"file_size": file.size, "scanned_bytes": 2 * OVERSIZE_SCAN_BYTES},
        )
    ]
    try:
        with file.path.open("rb") as stream:
            head = stream.read(OVERSIZE_SCAN_BYTES)
            stream.seek(max(file.size - OVERSIZE_SCAN_BYTES, OVERSIZE_SCAN_BYTES))
            tail = stream.read(OVERSIZE_SCAN_BYTES)
    except OSError:
        return findings
    for window, raw in (("prefix", head), ("suffix", tail)):
        text = _decode_text(raw)
        if not text:
            continue
        partial = {"partial_scan": window}
        if _is_npm_snapshot(snapshot) and lower_path.endswith((".js", ".cjs", ".mjs")):
            findings.extend(_analyze_npm_script(snapshot, file, text, partial))
        elif lower_path.endswith((".py", ".pth")):
            findings.extend(_analyze_python_text(snapshot, file, text, "", partial))
    return findings


def _line_snippet(text: str, offset: int) -> tuple[int, str]:
    line_no = text.count("\n", 0, offset) + 1
    end = text.find("\n", offset)
    snippet = text[text.rfind("\n", 0, offset) + 1 : end if end >= 0 else len(text)].strip()
    if len(snippet) > 240:
        snippet = snippet[:237] + "..."
    return line_no, snippet


# --- Python -----------------------------------------------------------------


@dataclass(frozen=True)
class _PyEvent:
    kind: str
    line: int
    import_time: bool


class _PyContext:
    """Name resolution for one module: import aliases, constants, data flow."""

    def __init__(self, tree: ast.Module) -> None:
        self.constants: dict[str, tuple[str, bool]] = {}
        self.aliases: dict[str, str] = {}
        self.obfuscated: set[str] = set()
        self.tainted: dict[str, set[str]] = {}
        # Earliest line where decoded or fetched data entered a name.
        self.taint_origin: dict[str, int] = {}
        self.imports_socket = False
        self._collect(tree)

    def resolve(self, node: ast.AST) -> tuple[str | None, bool]:
        return _resolve(node, self, 0)

    def _collect(self, tree: ast.Module) -> None:
        assignments: list[tuple[list[str], ast.AST]] = []
        # Loop variables hold single items, never a whole-environment dump.
        loop_values: set[int] = set()
        counts: dict[str, int] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == "socket":
                        self.imports_socket = True
                    if alias.asname:
                        self.aliases[alias.asname] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                if node.module.split(".")[0] == "socket":
                    self.imports_socket = True
                for alias in node.names:
                    if alias.name != "*":
                        self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Assign):
                assignments.append((_target_names(node.targets), node.value))
            elif (
                isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr))
                and node.value is not None
            ):
                assignments.append((_target_names([node.target]), node.value))
            elif isinstance(node, (ast.With, ast.AsyncWith)):
                for item in node.items:
                    if item.optional_vars is not None:
                        assignments.append((_target_names([item.optional_vars]), item.context_expr))
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                assignments.append((_target_names([node.target]), node.iter))
                loop_values.add(id(node.iter))
        for names, _value in assignments:
            for name in names:
                counts[name] = counts.get(name, 0) + 1
        single = [
            (names[0], value)
            for names, value in assignments
            if len(names) == 1 and counts[names[0]] == 1
        ]
        # A few passes resolve short alias chains such as `e = exec; f = e`.
        for _ in range(3):
            changed = False
            for name, value in single:
                if name not in self.constants:
                    folded, built = _fold(value, self, 0)
                    if folded is not None:
                        self.constants[name] = (folded, built)
                        changed = True
                resolved, obfuscated = _resolve(value, self, 0)
                if (
                    resolved
                    and resolved != name
                    and self.aliases.get(name) != resolved
                    and _is_interesting(resolved)
                ):
                    self.aliases[name] = resolved
                    if obfuscated:
                        self.obfuscated.add(name)
                    changed = True
            if not changed:
                break
        for _ in range(4):
            changed = False
            for names, value in assignments:
                kinds = _data_kinds(value, self)
                origin = _taint_origin(value, self) if kinds else None
                if id(value) not in loop_values and _environ_dump(value, self):
                    kinds.add("environ")
                for name in names:
                    current = self.tainted.setdefault(name, set())
                    if not kinds <= current:
                        current |= kinds
                        changed = True
                    if origin is not None and origin < self.taint_origin.get(name, origin + 1):
                        self.taint_origin[name] = origin
                        changed = True
            if not changed:
                break


def _target_names(targets: list[ast.expr]) -> list[str]:
    names: list[str] = []
    stack: list[ast.expr] = list(targets)
    while stack:
        target = stack.pop()
        if isinstance(target, ast.Name):
            names.append(target.id)
        elif isinstance(target, (ast.Tuple, ast.List)):
            stack.extend(target.elts)
        elif isinstance(target, ast.Starred):
            stack.append(target.value)
    return names


def _is_interesting(name: str) -> bool:
    return name in _INTERESTING_NAMES or name.split(".")[0] in _RISKY_IMPORT_ROOTS


def _normalize_builtin(name: str) -> str:
    for prefix in _BUILTIN_PREFIXES:
        if name.startswith(prefix):
            return name[len(prefix) :]
    if ".builtins." in name:
        tail = name.rsplit(".builtins.", 1)[1]
        if tail in _EXEC_CALLS or tail in {"__import__", "getattr"}:
            return tail
    return name


def _resolve(node: ast.AST, ctx: _PyContext, depth: int) -> tuple[str | None, bool]:
    """Resolve an expression to a dotted name; the flag marks obfuscated access."""
    if depth > _MAX_RESOLVE_DEPTH:
        return None, False
    if isinstance(node, ast.Name):
        target = ctx.aliases.get(node.id)
        if target is not None:
            return _normalize_builtin(target), node.id in ctx.obfuscated
        return node.id, False
    if isinstance(node, ast.Attribute):
        base, obfuscated = _resolve(node.value, ctx, depth + 1)
        if base is None:
            return None, False
        return _normalize_builtin(f"{base}.{node.attr}"), obfuscated
    if isinstance(node, ast.Call):
        func, obfuscated = _resolve(node.func, ctx, depth + 1)
        if func in {"__import__", "importlib.import_module"} and node.args:
            module, folded = _fold(node.args[0], ctx, depth + 1)
            if module:
                if func == "__import__" and len(node.args) < 4 and not node.keywords:
                    module = module.split(".")[0]
                return module, obfuscated or folded
        if func == "getattr" and len(node.args) >= 2:
            base, base_obfuscated = _resolve(node.args[0], ctx, depth + 1)
            attr, folded = _fold(node.args[1], ctx, depth + 1)
            if base and attr:
                return _normalize_builtin(f"{base}.{attr}"), obfuscated or base_obfuscated or folded
        if func in {"globals", "locals", "vars"} and not node.args:
            return "__globals__", obfuscated
        if func == "vars" and len(node.args) == 1:
            return _resolve(node.args[0], ctx, depth + 1)
        return None, False
    if isinstance(node, ast.Subscript):
        base, obfuscated = _resolve(node.value, ctx, depth + 1)
        key, folded = _fold(node.slice, ctx, depth + 1)
        if base and key:
            if base == "sys.modules":
                return key, obfuscated or folded
            # Namespace dictionary lookups are not how code normally calls a
            # builtin, so they count as obfuscated access.
            if base == "__globals__":
                return _normalize_builtin(key), True
            if base in {"__builtins__", "builtins", "__builtin__"} or base.endswith(".__dict__"):
                owner = base.removesuffix(".__dict__")
                return _normalize_builtin(f"{owner}.{key}"), True
        return None, False
    return None, False


def _fold(node: ast.AST, ctx: _PyContext, depth: int) -> tuple[str | None, bool]:
    """Constant-fold simple string expressions; the flag marks non-literal folding."""
    if depth > _MAX_RESOLVE_DEPTH:
        return None, False
    if isinstance(node, ast.Constant):
        return (node.value, False) if isinstance(node.value, str) else (None, False)
    if isinstance(node, ast.Name):
        return ctx.constants.get(node.id, (None, False))
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left, _left = _fold(node.left, ctx, depth + 1)
        right, _right = _fold(node.right, ctx, depth + 1)
        if left is not None and right is not None:
            return left + right, True
        return None, False
    if isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        for value in node.values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                parts.append(value.value)
            elif isinstance(value, ast.FormattedValue):
                inner, _inner = _fold(value.value, ctx, depth + 1)
                if inner is None:
                    return None, False
                parts.append(inner)
            else:
                return None, False
        return "".join(parts), True
    if (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Slice)
        and node.slice.lower is None
        and node.slice.upper is None
        and isinstance(node.slice.step, ast.UnaryOp)
        and isinstance(node.slice.step.op, ast.USub)
        and isinstance(node.slice.step.operand, ast.Constant)
        and node.slice.step.operand.value == 1
    ):
        inner, _inner = _fold(node.value, ctx, depth + 1)
        return (inner[::-1], True) if inner is not None else (None, False)
    if isinstance(node, ast.Call):
        return _fold_call(node, ctx, depth)
    return None, False


def _fold_call(node: ast.Call, ctx: _PyContext, depth: int) -> tuple[str | None, bool]:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "join" and len(node.args) == 1:
        separator, _separator = _fold(func.value, ctx, depth + 1)
        items = node.args[0]
        if separator is not None and isinstance(items, (ast.List, ast.Tuple)):
            parts = [_fold(item, ctx, depth + 1)[0] for item in items.elts]
            if all(part is not None for part in parts):
                return separator.join(part for part in parts if part is not None), True
        return None, False
    if (
        isinstance(func, ast.Attribute)
        and func.attr == "decode"
        and isinstance(func.value, ast.Call)
    ):
        inner = func.value
        inner_name, _inner = _resolve(inner.func, ctx, depth + 1)
        if inner.args and inner_name in {"base64.b64decode", "bytes.fromhex", "binascii.unhexlify"}:
            raw, _raw = _fold(inner.args[0], ctx, depth + 1)
            if raw is not None:
                try:
                    if inner_name == "base64.b64decode":
                        decoded = base64.b64decode(raw, validate=False)
                    else:
                        decoded = binascii.unhexlify(raw)
                    return decoded.decode("utf-8"), True
                except (ValueError, UnicodeDecodeError):
                    return None, False
        return None, False
    name, _name = _resolve(func, ctx, depth + 1)
    if name == "chr" and len(node.args) == 1:
        argument = node.args[0]
        if (
            isinstance(argument, ast.Constant)
            and isinstance(argument.value, int)
            and 0 <= argument.value < 0x110000
        ):
            return chr(argument.value), True
    return None, False


def _data_kinds(node: ast.AST, ctx: _PyContext) -> set[str]:
    kinds: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name, _obfuscated = ctx.resolve(child.func)
            if name in _DECODE_CALLS or name == "chr":
                kinds.add("decoded")
            elif name in _NETWORK_CALLS and name not in _NETWORK_CLIENT_CALLS:
                kinds.add("fetched")
        elif isinstance(child, ast.Name):
            kinds |= ctx.tainted.get(child.id, set()) & {"decoded", "fetched"}
    return kinds


def _taint_origin(node: ast.AST, ctx: _PyContext) -> int | None:
    lines: list[int] = []
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name, _obfuscated = ctx.resolve(child.func)
            if name in _DECODE_CALLS or name == "chr" or name in _NETWORK_CALLS:
                if name not in _NETWORK_CLIENT_CALLS:
                    lines.append(child.lineno)
        elif isinstance(child, ast.Name) and child.id in ctx.taint_origin:
            lines.append(ctx.taint_origin[child.id])
    return min(lines) if lines else None


def _environ_dump(node: ast.AST, ctx: _PyContext) -> bool:
    """True for whole-environment forms: os.environ, copies, items, or a tainted name."""
    if isinstance(node, ast.Name) and "environ" in ctx.tainted.get(node.id, set()):
        return True
    name, _obfuscated = ctx.resolve(node)
    if name == "os.environ":
        return True
    if isinstance(node, ast.Call):
        func, _obfuscated = ctx.resolve(node.func)
        if func in _ENVIRON_DUMP_CALLS:
            return True
        if func in _WRAPPER_CALLS | _SERIALIZE_CALLS and node.args:
            return _environ_dump(node.args[0], ctx)
    if isinstance(node, ast.Dict):
        return any(
            key is None and _environ_dump(value, ctx)
            for key, value in zip(node.keys, node.values, strict=False)
        )
    return False


def _import_time_nodes(tree: ast.Module) -> set[int]:
    """Ids of nodes evaluated on import: module and class bodies, not functions."""
    found: set[int] = set()
    stack: list[ast.AST] = [tree]
    while stack:
        node = stack.pop()
        found.add(id(node))
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            stack.extend(node.decorator_list)
            stack.extend(node.args.defaults)
            stack.extend(default for default in node.args.kw_defaults if default is not None)
            continue
        if isinstance(node, ast.Lambda):
            continue
        if isinstance(node, ast.If) and _is_main_guard(node.test):
            stack.extend(node.orelse)
            continue
        stack.extend(ast.iter_child_nodes(node))
    return found


def _is_main_guard(test: ast.expr) -> bool:
    if isinstance(test, ast.BoolOp) and isinstance(test.op, ast.And):
        return any(_is_main_guard(value) for value in test.values)
    if not isinstance(test, ast.Compare) or len(test.ops) != 1:
        return False
    if not isinstance(test.ops[0], ast.Eq):
        return False
    operands = [test.left, test.comparators[0]]
    names = [item.id for item in operands if isinstance(item, ast.Name)]
    values = [item.value for item in operands if isinstance(item, ast.Constant)]
    return names == ["__name__"] and values == ["__main__"]


def _docstring_ids(tree: ast.Module) -> set[int]:
    ids: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
            ids.add(id(node.value))
    return ids


def _parse_python(text: str) -> ast.Module | None:
    try:
        return ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def _python_events(text: str, depth: int = 0) -> list[_PyEvent] | None:
    tree = _parse_python(text)
    if tree is None:
        return None
    try:
        return _tree_events(tree, depth)
    except RecursionError:
        return None


def _tree_events(tree: ast.Module, depth: int) -> list[_PyEvent]:
    ctx = _PyContext(tree)
    import_time = _import_time_nodes(tree)
    docstrings = _docstring_ids(tree)
    events: list[_PyEvent] = []

    def add(kind: str, node: ast.AST, line: int | None = None) -> None:
        line = line if line is not None else getattr(node, "lineno", 1)
        events.append(_PyEvent(kind, line, id(node) in import_time))

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            _call_events(node, ctx, depth, add)
        elif isinstance(node, ast.Assign) and _is_obfuscated_sink(node.value, ctx):
            add("encoded_exec", node)
        elif _harvests_environment(node, ctx):
            add("harvest", node)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            if id(node) in docstrings:
                continue
            if _is_credential_path(node.value):
                add("credential_path", node)
            if len(node.value) >= 200 and _ENCODED_BLOB_RE.fullmatch(
                re.sub(r"\s+", "", node.value)
            ):
                add("blob", node)
        elif isinstance(node, ast.Import):
            if any(alias.name.split(".")[0] in _RISKY_IMPORT_ROOTS for alias in node.names):
                add("risky_import", node)
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.split(".")[0] in _RISKY_IMPORT_ROOTS:
                add("risky_import", node)
    return events


def _is_obfuscated_sink(node: ast.AST, ctx: _PyContext) -> bool:
    name, obfuscated = ctx.resolve(node)
    return obfuscated and name in _DANGEROUS_RESOLVED


def _call_events(node: ast.Call, ctx: _PyContext, depth: int, add: Any) -> None:
    name, _obfuscated = ctx.resolve(node.func)
    if _is_obfuscated_sink(node.func, ctx):
        add("encoded_exec", node)
    if name in _EXEC_CALLS:
        _exec_events(node, ctx, depth, add)
    elif name in _PROCESS_CALLS:
        add("process", node)
        if node.args and _is_download_command(node.args[0], ctx):
            add("network", node)
    elif name in _NETWORK_CLIENT_CALLS:
        add("network_client", node)
    elif name in _NETWORK_CALLS:
        add("network", node)
    elif name in _DECODE_CALLS:
        add("decode", node)
    func = node.func
    if (
        ctx.imports_socket
        and isinstance(func, ast.Attribute)
        and func.attr in {"send", "sendall", "sendto"}
    ):
        add("network", node)
    if (
        name in _SERIALIZE_CALLS
        or name in _NETWORK_CALLS
        or (isinstance(func, ast.Attribute) and func.attr in {"write", "send", "sendall"})
    ):
        arguments = [*node.args, *(item.value for item in node.keywords if item.arg != "env")]
        if any(_environ_dump(argument, ctx) for argument in arguments):
            add("harvest", node)


def _exec_events(node: ast.Call, ctx: _PyContext, depth: int, add: Any) -> None:
    if not node.args:
        return
    argument = node.args[0]
    if _data_kinds(argument, ctx) & {"decoded", "fetched"}:
        # Point at the decoder when it precedes the exec call.
        origin = _taint_origin(argument, ctx)
        add("encoded_exec", node, min(origin or node.lineno, node.lineno))
        return
    source, _folded = _fold(argument, ctx, 0)
    if source is None:
        add("exec_dynamic", node)
        return
    if depth >= _MAX_NESTED_SOURCE_DEPTH:
        return
    # exec("...") of a literal: analyze the literal as code at this call site.
    nested = _python_events(source, depth + 1) or []
    for event in nested:
        add(event.kind, node)
    if any(event.kind in _RISKY_NESTED_KINDS for event in nested):
        add("exec_risky", node)


def _harvests_environment(node: ast.AST, ctx: _PyContext) -> bool:
    if isinstance(node, ast.FormattedValue):
        return _environ_dump(node.value, ctx)
    if isinstance(node, (ast.For, ast.AsyncFor)):
        return _iterates_secrets(node.iter, node, ctx)
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
        return any(_iterates_secrets(item.iter, node, ctx) for item in node.generators)
    return False


def _is_download_command(node: ast.AST, ctx: _PyContext) -> bool:
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        node = node.elts[0]
    command, _folded = _fold(node, ctx, 0)
    return bool(command and _DOWNLOAD_COMMAND_RE.match(command))


def _iterates_secrets(iterable: ast.AST, scope: ast.AST, ctx: _PyContext) -> bool:
    if not _environ_dump(iterable, ctx):
        return False
    return any(
        isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and _SECRET_NAME_RE.search(child.value)
        for child in ast.walk(scope)
    )


def _is_credential_path(value: str) -> bool:
    if len(value) > 300 or not _CREDENTIAL_PATH_RE.search(value):
        return False
    # Paths, not prose: messages that mention a credential file contain spaces.
    return not re.search(r"\s", value) or bool(_SPACED_CREDENTIAL_RE.search(value))


def _analyze_python(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
    file_name: str,
) -> list[Finding]:
    events = _python_events(text)
    if events is None:
        return _analyze_python_text(snapshot, file, text, file_name)

    findings: list[Finding] = []

    def emit(rule: PackageCodeRule, kinds: set[str], import_time: bool | None = None) -> bool:
        event = next(
            (
                item
                for item in sorted(events, key=lambda item: item.line)
                if item.kind in kinds and (import_time is None or item.import_time == import_time)
            ),
            None,
        )
        if event is None:
            return False
        findings.append(_finding(snapshot, file, text, rule, _offset_for_line(text, event.line)))
        return True

    emit(_ENCODED_RULE, {"encoded_exec"})
    if file_name == "setup.py":
        emit(_SETUP_RULE, {"process", "network", "network_client", "exec_risky"})
    elif file_name in {"sitecustomize.py", "usercustomize.py"}:
        emit(_STARTUP_CUSTOMIZE_RULE, set(_PTH_CRITICAL_KINDS))
    exfil_offset = _python_exfil_offset(text, events)
    if exfil_offset is not None:
        findings.append(_finding(snapshot, file, text, _CREDENTIAL_EXFIL_RULE, exfil_offset))
    if file_name != "setup.py" and not emit(
        _IMPORT_TIME_RULE, {"process", "network", "exec_risky"}, import_time=True
    ):
        emit(_SILENT_PROCESS_RULE, {"process"})
    return findings


def _python_exfil_offset(text: str, events: list[_PyEvent]) -> int | None:
    harvest = [event.line for event in events if event.kind in {"harvest", "credential_path"}]
    network = [event.line for event in events if event.kind in {"network", "network_client"}]
    for harvest_line in sorted(harvest):
        if any(abs(harvest_line - line) <= _EXFIL_LINE_WINDOW for line in network):
            return _offset_for_line(text, harvest_line)
    return None


def _analyze_python_text(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
    file_name: str,
    extra: dict[str, Any] | None = None,
) -> list[Finding]:
    """Regex fallback for sources the AST cannot parse (for example Python 2)."""
    findings: list[Finding] = []
    if file_name == "setup.py":
        match = _SETUP_EXEC_RE.search(text)
        if match:
            findings.append(_finding(snapshot, file, text, _SETUP_RULE, match.start(), extra))
    match = _ENCODED_EXEC_RE.search(text)
    if match:
        findings.append(_finding(snapshot, file, text, _ENCODED_RULE, match.start(), extra))
    if file_name in {"sitecustomize.py", "usercustomize.py"}:
        match = _STARTUP_CUSTOMIZE_RE.search(text)
        if match:
            findings.append(
                _finding(snapshot, file, text, _STARTUP_CUSTOMIZE_RULE, match.start(), extra)
            )
    exfil_offset = _text_exfil_offset(text, _CREDENTIAL_RE.search(text), (_NETWORK_RE,))
    if exfil_offset is not None:
        findings.append(_finding(snapshot, file, text, _CREDENTIAL_EXFIL_RULE, exfil_offset, extra))
    if file_name != "setup.py":
        match = _SILENT_PROCESS_RE.search(text)
        if match:
            findings.append(
                _finding(snapshot, file, text, _SILENT_PROCESS_RULE, match.start(), extra)
            )
    return findings


_NEWLINE_RE = re.compile(r"\r\n|\r|\n")


def pth_lines(text: str) -> list[tuple[int, str]]:
    """(offset, line) for every line site.py may execute, each once.

    Python 3.12 and older read a .pth file by newline only, so a form feed, vertical tab,
    \\x1c-\\x1e, NEL or line separator stays inside one physical line, and that whole line
    is executed when it starts with "import". Python 3.13 and newer use str.splitlines,
    which also splits on those characters. Both readings are returned.
    """
    found: dict[tuple[int, str], None] = {}
    start = 0
    for match in _NEWLINE_RE.finditer(text):
        found[(start, text[start : match.start()])] = None
        start = match.end()
    if start < len(text):
        found[(start, text[start:])] = None
    offset = 0
    for line in text.splitlines(keepends=True):
        found[(offset, line.rstrip("\r\n\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"))] = None
        offset += len(line)
    return sorted(found)


def pth_line_number(text: str, offset: int) -> int:
    return len(_NEWLINE_RE.findall(text, 0, offset)) + 1


def _analyze_pth(snapshot: ArtifactSnapshot, file: ArtifactFile, text: str) -> list[Finding]:
    """site.py executes .pth lines starting with "import"; other lines are paths."""
    critical: int | None = None
    investigate: int | None = None
    for offset, line in pth_lines(text):
        if line.startswith(("import ", "import\t")):
            verdict = _pth_line_verdict(line.strip())
            if verdict == "critical" and (critical is None or offset < critical):
                critical = offset
            elif verdict == "investigate" and (investigate is None or offset < investigate):
                investigate = offset
    if critical is not None:
        return [_finding(snapshot, file, text, _PTH_RULE, critical)]
    if investigate is not None:
        return [_finding(snapshot, file, text, _PTH_IMPORT_RULE, investigate)]
    return []


def _pth_line_verdict(line: str) -> str | None:
    tree = _parse_python(line)
    if tree is None:
        return "critical" if _PTH_SUSPICIOUS_RE.search(line) else "investigate"
    try:
        events = _tree_events(tree, 0)
    except RecursionError:
        return "critical"
    if any(event.kind in _PTH_CRITICAL_KINDS for event in events):
        return "critical"
    if _is_benign_pth(tree):
        return None
    return "investigate"


def _is_benign_pth(tree: ast.Module) -> bool:
    ctx = _PyContext(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if not all(_BENIGN_PTH_MODULE_RE.fullmatch(alias.name) for alias in node.names):
                return False
        elif isinstance(node, ast.ImportFrom):
            return False
        elif isinstance(node, ast.Call):
            name, _obfuscated = ctx.resolve(node.func)
            if name == "__import__":
                module, _folded = _fold(node.args[0], ctx, 0) if node.args else (None, False)
                if module is None or not _BENIGN_PTH_MODULE_RE.fullmatch(module):
                    return False
            elif name in _BENIGN_PTH_CALLS:
                continue
            elif not (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _BENIGN_PTH_METHODS
                and (name or "").split(".")[0] not in _RISKY_IMPORT_ROOTS
            ):
                return False
    return True


def _offset_for_line(text: str, line_no: int) -> int:
    offset = 0
    for _index in range(line_no - 1):
        offset = text.find("\n", offset) + 1
        if not offset:
            return max(0, len(text) - 1)
    return offset


def _text_exfil_offset(
    text: str,
    harvest: re.Match[str] | None,
    sink_res: tuple[re.Pattern[str], ...],
) -> int | None:
    if harvest is None:
        return None
    sinks = [match for pattern in sink_res if (match := pattern.search(text))]
    if not sinks:
        return None
    sink = min(sinks, key=lambda match: match.start())
    harvest_line, _snippet = _line_snippet(text, harvest.start())
    sink_line, _snippet = _line_snippet(text, sink.start())
    if abs(harvest_line - sink_line) > _EXFIL_LINE_WINDOW:
        return None
    return min(harvest.start(), sink.start())


# --- npm --------------------------------------------------------------------


def _analyze_npm_manifest(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
) -> list[Finding]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    scripts = data.get("scripts")
    if not isinstance(scripts, dict):
        return []
    findings: list[Finding] = []
    for hook in NPM_INSTALL_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        offset = max(text.find(f'"{hook}"'), 0)
        if NPM_SCRIPT_EXEC_RE.search(command):
            findings.append(_finding(snapshot, file, text, _NPM_INSTALL_EXEC_RULE, offset))
            continue
        findings.append(_finding(snapshot, file, text, _NPM_INSTALL_HOOK_RULE, offset))
        downloader = _install_hook_downloader(snapshot, file, hook, command)
        if downloader is not None:
            findings.append(downloader)
    return findings


def _install_hook_downloader(
    snapshot: ArtifactSnapshot,
    manifest: ArtifactFile,
    hook: str,
    command: str,
) -> Finding | None:
    files = {item.relative_path: item for item in snapshot.files}
    root = PurePosixPath(manifest.relative_path).parent
    for match in _NPM_HOOK_SCRIPT_RE.finditer(command):
        target = posixpath.normpath(str(root / match.group(1)))
        script = next(
            (
                files[candidate]
                for candidate in (target, f"{target}.js", f"{target}/index.js")
                if candidate in files
            ),
            None,
        )
        if script is None:
            continue
        text = _read_text_file(script)
        if text is None:
            continue
        runtime = _RUNTIME_INSTALL_RE.search(text)
        download = _JS_DOWNLOAD_RE.search(text)
        execute = _JS_EXECUTE_RE.search(text)
        if runtime is not None:
            offset = runtime.start()
        elif download is not None and execute is not None:
            offset = min(download.start(), execute.start())
        else:
            continue
        return _finding(
            snapshot,
            script,
            text,
            _NPM_INSTALL_DOWNLOADER_RULE,
            offset,
            {"hook": hook, "hook_command": command[:240], "runtime_install": runtime is not None},
        )
    return None


def _analyze_npm_script(
    snapshot: ArtifactSnapshot,
    file: ArtifactFile,
    text: str,
    extra: dict[str, Any] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    encoded = _JS_ENCODED_EXEC_RE.search(text) or _JS_SINK_WRAPS_DECODE_RE.search(text)
    if encoded:
        findings.append(_finding(snapshot, file, text, _NPM_ENCODED_RULE, encoded.start(), extra))
    obfuscated = _js_obfuscated_require_offset(text)
    if obfuscated is not None:
        findings.append(
            _finding(snapshot, file, text, _NPM_OBFUSCATED_REQUIRE_RULE, obfuscated, extra)
        )
    exfil_offset = _npm_credential_exfil_offset(text)
    if exfil_offset is not None:
        findings.append(
            _finding(snapshot, file, text, _NPM_CREDENTIAL_EXFIL_RULE, exfil_offset, extra)
        )
    hijack = _wallet_network_hijack(text)
    if hijack is not None:
        offset, details = hijack
        findings.append(
            _finding(
                snapshot,
                file,
                text,
                _NPM_WALLET_HIJACK_RULE,
                offset,
                {**(extra or {}), **details},
            )
        )
    return findings


def _wallet_network_hijack(text: str) -> tuple[int, dict[str, Any]] | None:
    """Find a wallet-provider or global network override that looks like a drainer.

    An override (assigning ethereum/solana request or sign methods, the global
    fetch, XMLHttpRequest.prototype.open/send, or defineProperty on them) reports
    only when its target name is obfuscated (concatenated, escaped, or decoded from
    an encoded string table) or the file carries crypto-address literals or
    address regexes. Polyfills that assign a plain fetch stay quiet.
    """
    hinted = any(hint in text for hint in _HIJACK_TEXT_HINTS)
    computed = _JS_COMPUTED_ASSIGN_RE.search(text) is not None
    if not hinted and not computed:
        return None
    encoded_names = _encoded_sensitive_names(text)
    table_names = _string_table_names(text)
    decoded_names = encoded_names | table_names
    global_aliases: set[str] = set()
    wallet_aliases: set[str] = set()
    if hinted:
        global_aliases, wallet_aliases = _js_aliases(text, decoded_names)
    read_counts: dict[str, int] = {}
    overrides: list[tuple[int, bool, str]] = []
    if "fetch" in text and not _JS_LOCAL_FETCH_BINDING_RE.search(text):
        for count, match in enumerate(_JS_BARE_FETCH_ASSIGN_RE.finditer(text)):
            if count >= _MAX_HIJACK_MATCHES:
                break
            if _starts_statement(text, match.start()):
                overrides.append((match.start(), False, "global_fetch"))
    if hinted:
        for count, match in enumerate(_JS_DOTTED_ASSIGN_RE.finditer(text)):
            if count >= _MAX_HIJACK_MATCHES:
                break
            kind = _dotted_override_kind(
                _assignment_target(text, match.start()),
                match.group(1),
                global_aliases,
                wallet_aliases,
            )
            if kind is not None:
                overrides.append((match.start(), False, kind))
    if hinted:
        for count, match in enumerate(_JS_DEFINE_PROPERTY_RE.finditer(text)):
            if count >= _MAX_HIJACK_MATCHES:
                break
            kind = _define_property_kind(
                match.group(1), match.group(3), global_aliases, wallet_aliases
            )
            if kind is not None:
                overrides.append((match.start(), False, kind))
        for count, match in enumerate(_JS_DEFINE_PROPERTY_VARIABLE_RE.finditer(text)):
            if count >= _MAX_HIJACK_MATCHES:
                break
            target = re.sub(r"\s+", "", match.group(1))
            if target in wallet_aliases or target.rsplit(".", 1)[-1] in {"ethereum", "solana"}:
                overrides.append((match.start(), False, "wallet_method_dynamic"))
    if computed:
        for count, match in enumerate(_JS_COMPUTED_ASSIGN_RE.finditer(text)):
            if count >= _MAX_HIJACK_MATCHES:
                break
            override = _computed_override(
                text,
                _assignment_target(text, match.start()),
                match.group(1),
                decoded_names,
                global_aliases,
                wallet_aliases,
                read_counts,
            )
            if override is not None:
                overrides.append((match.start(), *override))
    if not overrides:
        return None
    address = _CRYPTO_ADDRESS_RE.search(text)
    for offset, obfuscated, kind in sorted(overrides):
        if obfuscated or encoded_names or (address is not None and kind != "wallet_provider"):
            details: dict[str, Any] = {
                "override_kind": kind,
                "obfuscated_name": obfuscated,
                "crypto_address_pattern": address is not None,
            }
            if encoded_names:
                details["encoded_names"] = sorted(encoded_names)
            return offset, details
    return None


def _dotted_override_kind(
    target: str,
    prop: str,
    global_aliases: set[str],
    wallet_aliases: set[str],
) -> str | None:
    on_global = target in _JS_GLOBAL_NAMES or target in global_aliases
    owner = target.rsplit(".", 1)[-1]
    if prop == "fetch":
        if on_global:
            return "global_fetch"
        return None
    if prop in {"ethereum", "solana"}:
        if on_global:
            return "wallet_provider"
        return None
    if prop in {"open", "send", "setRequestHeader"} and target.endswith("XMLHttpRequest.prototype"):
        return "xhr_prototype"
    if prop in _HIJACK_OVERRIDE_NAMES and (
        owner in {"ethereum", "solana"} or target in wallet_aliases
    ):
        return "wallet_method"
    return None


def _assignment_target(text: str, bracket: int, limit: int = 200) -> str:
    """The member expression just before ``[`` (dots and bracket chains), read backwards."""
    end = bracket
    while end > 0 and text[end - 1] in " \t":
        end -= 1
    start = end
    while start > 0 and end - start < limit:
        char = text[start - 1]
        if char in _JS_TARGET_CHARS:
            start -= 1
            continue
        if char != "]":
            break
        depth = 0
        index = start - 1
        while index >= 0 and end - index < limit:
            if text[index] == "]":
                depth += 1
            elif text[index] == "[":
                depth -= 1
                if depth == 0:
                    break
            index -= 1
        if index < 0 or depth != 0:
            break
        start = index
    return text[start:end]


def _starts_statement(text: str, offset: int) -> bool:
    """True when ``fetch = ...`` begins a statement rather than a parameter or pattern."""
    index = offset - 1
    newline = False
    while index >= 0 and text[index] in " \t\r\n":
        if text[index] == "\n":
            newline = True
        index -= 1
    if index < 0:
        return True
    previous = text[index]
    if previous in ";})":
        return True
    if previous == "{":
        before = index - 1
        while before >= 0 and text[before] in " \t\r\n":
            before -= 1
        return before >= 0 and text[before] in ")>"
    return newline and previous not in ",({[:?=&|+-*/%!<>."


def _string_table_names(text: str) -> set[str]:
    """Wallet and network API names held in an obfuscator-style string table.

    A table counts only when it is read through a computed index (``return
    T[i]``, ``=> T[i]``, ``= T[i - 0x1a2]``), the shape of a string decoder.
    """
    names: set[str] = set()
    if not any(f"'{name}'" in text or f'"{name}"' in text for name in _HIJACK_SENSITIVE_NAMES):
        return names
    for count, match in enumerate(_JS_STRING_TABLE_RE.finditer(text)):
        if count >= _MAX_HIJACK_MATCHES:
            break
        strings = set(_JS_TABLE_STRING_RE.findall(match.group(1)))
        sensitive = strings & _HIJACK_SENSITIVE_NAMES
        if not sensitive:
            continue
        table = _JS_IDENTIFIER_BEFORE_RE.search(text, max(0, match.start() - 120), match.start())
        if table is None:
            continue
        accessor = re.compile(
            r"(?:return|=>|=)\s*" + re.escape(table.group(1)) + r"\s*\[\s*[A-Za-z_$(]"
        )
        if accessor.search(text, match.end()) or accessor.search(text, 0, match.start()):
            names |= sensitive
    return names


def _js_aliases(text: str, decoded_names: set[str]) -> tuple[set[str], set[str]]:
    """Local names bound to the global object or to an injected wallet provider.

    Parameters of functions called with ``window.ethereum`` count as providers, and
    so does ``global[decoder(i)]`` when the file decodes a wallet name.
    """
    global_aliases: set[str] = set()
    wallet_aliases: set[str] = set()
    for count, argument in enumerate(_JS_PROVIDER_ARGUMENT_RE.finditer(text)):
        if count >= _MAX_HIJACK_MATCHES or len(wallet_aliases) >= _MAX_JS_ALIASES:
            break
        call = _JS_PROVIDER_CALLEE_RE.search(text, max(0, argument.start() - 120), argument.start())
        if call is None:
            continue
        function = re.escape(call.group(1))
        definition = re.search(
            r"function\s+"
            + function
            + r"\s*\(\s*([A-Za-z_$][\w$]*)|"
            + function
            + r"\s*=\s*(?:async\s+)?(?:function\s*)?\(?\s*([A-Za-z_$][\w$]*)",
            text,
        )
        if definition is not None:
            wallet_aliases.add(definition.group(1) or definition.group(2))
    for count, match in enumerate(_JS_ALIAS_RE.finditer(text)):
        if (
            count >= _MAX_HIJACK_MATCHES
            or len(global_aliases) + len(wallet_aliases) >= _MAX_JS_ALIASES
        ):
            break
        name, value = match.group(1), match.group(2).strip()
        tokens = _JS_IDENTIFIER_RE.findall(value)
        if tokens and set(tokens) <= _JS_ALIAS_TOKENS and set(tokens) & _JS_GLOBAL_NAMES:
            global_aliases.add(name)
            continue
        compact = re.sub(r"\s+|\?", "", value)
        computed = re.fullmatch(r"([\w$]+)\[[\w$]+\([^()]*\)\]", compact)
        if (
            computed is not None
            and (computed.group(1) in _JS_GLOBAL_NAMES or computed.group(1) in global_aliases)
            and decoded_names & {"ethereum", "solana"}
        ):
            wallet_aliases.add(name)
            continue
        head, _dot, tail = compact.rpartition(".")
        if tail in {"ethereum", "solana"} and (
            not head
            or head in _JS_GLOBAL_NAMES
            or head in global_aliases
            or head.endswith("phantom")
        ):
            wallet_aliases.add(name)
    return global_aliases, wallet_aliases


def _define_property_kind(
    target: str,
    prop: str,
    global_aliases: set[str],
    wallet_aliases: set[str],
) -> str | None:
    compact = re.sub(r"\s+", "", target)
    if prop in {"ethereum", "solana"}:
        return "wallet_provider_property"
    if prop == "fetch" and (compact in _JS_GLOBAL_NAMES or compact in global_aliases):
        return "global_fetch"
    if prop in {"open", "send", "setRequestHeader"} and "XMLHttpRequest" in compact:
        return "xhr_prototype"
    if prop in _HIJACK_OVERRIDE_NAMES and (
        "ethereum" in compact or "solana" in compact or compact in wallet_aliases
    ):
        return "wallet_method"
    return None


def _computed_override(
    text: str,
    target: str,
    key: str,
    encoded_names: set[str],
    global_aliases: set[str],
    wallet_aliases: set[str],
    read_counts: dict[str, int],
) -> tuple[bool, str] | None:
    """Classify target[key] = ... assignments.

    A key built from pieces or escapes is obfuscated. A decoder-call key counts when
    the file decodes wallet or network API names and the original member is read
    before it is replaced. A plainly written key counts only on the global object
    or a wallet provider.
    """
    stripped = key.strip()
    owner = target.rsplit(".", 1)[-1]
    sensitive_owner = (
        "XMLHttpRequest" in target
        or owner in {"ethereum", "solana"}
        or owner in wallet_aliases
        or target in wallet_aliases
    )
    if stripped[:1] in {"'", '"', "`"} or "+" in stripped:
        folded, obfuscated = _fold_js_string(stripped)
        if folded is None or folded not in _HIJACK_OVERRIDE_NAMES:
            return None
        if obfuscated:
            return True, f"computed_{folded}"
        on_global = target in _JS_GLOBAL_NAMES or target in global_aliases
        if folded in {"fetch", "ethereum", "solana"} and on_global:
            return False, f"computed_{folded}"
        if sensitive_owner:
            return False, f"computed_{folded}"
        return None
    if not _JS_DECODER_CALL_RE.fullmatch(stripped):
        return None
    if sensitive_owner:
        return True, "decoded_name"
    if not encoded_names & _HIJACK_SENSITIVE_NAMES:
        return None
    if target in _JS_GLOBAL_NAMES or target in global_aliases:
        return True, "decoded_name"
    member = f"[{stripped}]"
    if member not in read_counts:
        read_counts[member] = text.count(member)
    if read_counts[member] < 2:
        return None
    return True, "decoded_name"


def _encoded_sensitive_names(text: str) -> set[str]:
    """Wallet and network API names that appear only base64- or escape-encoded."""
    names: set[str] = set()
    for count, match in enumerate(_JS_BASE64_LITERAL_RE.finditer(text)):
        if count >= _MAX_HIJACK_MATCHES:
            break
        literal = match.group(2)
        if len(literal) % 4:
            continue
        try:
            decoded = base64.b64decode(literal, validate=True).decode("ascii")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded in _HIJACK_SENSITIVE_NAMES and decoded != literal:
            names.add(decoded)
    for count, match in enumerate(_JS_ESCAPED_LITERAL_RE.finditer(text)):
        if count >= _MAX_HIJACK_MATCHES:
            break
        decoded = _decode_js_escapes(match.group(2))
        if decoded in _HIJACK_SENSITIVE_NAMES:
            names.add(decoded)
    return names


def _npm_credential_exfil_offset(text: str) -> int | None:
    harvest = min(
        (
            match
            for hints, pattern in _JS_HARVEST_RULES
            if any(hint in text for hint in hints) and (match := pattern.search(text))
        ),
        key=lambda match: match.start(),
        default=None,
    )
    return _text_exfil_offset(text, harvest, (_JS_NETWORK_RE, _JS_PROCESS_RE))


def _js_obfuscated_require_offset(text: str) -> int | None:
    for count, match in enumerate(_JS_REQUIRE_CALL_RE.finditer(text)):
        if count >= 5000:
            break
        if match.start() and (
            text[match.start() - 1].isalnum() or text[match.start() - 1] in "_$."
        ):
            continue
        argument = _js_call_argument(text, match.end() - 1)
        if argument is None:
            continue
        module, obfuscated = _fold_js_string(argument)
        if not obfuscated or module is None:
            continue
        if module.removeprefix("node:") in _JS_DANGEROUS_MODULES:
            return match.start()
    return None


def _js_call_argument(text: str, open_index: int, limit: int = 4096) -> str | None:
    """Return the text between a call's parentheses, skipping string literals."""
    depth = 0
    quote: str | None = None
    index = open_index
    end = min(len(text), open_index + limit)
    while index < end:
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_index + 1 : index]
        index += 1
    return None


def _fold_js_string(expression: str) -> tuple[str | None, bool]:
    """Fold string literal concatenation; the flag marks non-literal construction."""
    pieces = _split_js_concatenation(expression)
    obfuscated = len(pieces) > 1
    parts: list[str] = []
    for piece in pieces:
        literal = _JS_STRING_RE.fullmatch(piece)
        if literal:
            raw = next(group for group in literal.groups() if group is not None)
            decoded = _decode_js_escapes(raw)
            obfuscated = obfuscated or decoded != raw
            parts.append(decoded)
            continue
        joined = re.fullmatch(r"\s*\[(.*)\]\s*\.join\(\s*(['\"])(.*?)\2\s*\)\s*", piece, re.S)
        if joined:
            items = [
                _JS_STRING_RE.fullmatch(item) for item in _split_js_top_level(joined.group(1), ",")
            ]
            if not items or any(item is None for item in items):
                return None, False
            values = [
                _decode_js_escapes(next(group for group in item.groups() if group is not None))
                for item in items
                if item is not None
            ]
            parts.append(joined.group(3).join(values))
            obfuscated = True
            continue
        char_codes = re.fullmatch(r"\s*String\.fromCharCode\(([\d\s,]+)\)\s*", piece)
        if char_codes:
            try:
                parts.append(
                    "".join(
                        chr(int(code)) for code in char_codes.group(1).split(",") if code.strip()
                    )
                )
            except ValueError:
                return None, False
            obfuscated = True
            continue
        return None, False
    return "".join(parts), obfuscated


def _split_js_concatenation(expression: str) -> list[str]:
    return _split_js_top_level(expression, "+")


def _split_js_top_level(expression: str, separator: str) -> list[str]:
    pieces: list[str] = []
    depth = 0
    quote: str | None = None
    start = 0
    index = 0
    while index < len(expression):
        char = expression[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char == separator and depth == 0:
            pieces.append(expression[start:index])
            start = index + 1
        index += 1
    pieces.append(expression[start:])
    return pieces


def _decode_js_escapes(raw: str) -> str:
    def replace(match: re.Match[str]) -> str:
        hex_byte, code_point, code_unit, other = match.groups()
        value = hex_byte or code_point or code_unit
        if value is not None:
            try:
                return chr(int(value, 16))
            except (ValueError, OverflowError):
                return match.group(0)
        return {"n": "\n", "t": "\t", "r": "\r", "0": "\0"}.get(other, other)

    return _JS_ESCAPE_RE.sub(replace, raw)


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        deduped[finding.fingerprint] = finding
    return sorted(
        deduped.values(),
        key=lambda finding: (
            _SEVERITY_RANK.get(finding.severity, 5),
            finding.signal_type,
            finding.package_key,
            str(finding.metadata.get("file_path") or ""),
        ),
    )
