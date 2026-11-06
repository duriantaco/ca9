"""Behaviour checks on the command strings agents and editors run.

Everything here looks at what a command does (fetch remote code, decode and
run a payload, run a file disguised as a font or image, hide behind padding,
launch from a hidden home or temporary directory), never at who it claims to be.
"""

from __future__ import annotations

import re
import shlex
from typing import Any

MAX_COMMAND_CHARS = 4096
MAX_DISPLAY_CHARS = 300
PADDING_RUN = 40
LINE_PADDING_RUN = 100

_FETCH = (
    r"(?:curl|wget|aria2c|iwr|irm|invoke-webrequest|invoke-restmethod|"
    r"start-bitstransfer)(?:\.exe)?"
)
_PREFIX = r"(?:sudo\s+(?:-\S+\s+)*)?(?:(?:/usr)?(?:/local)?/bin/)?"
_SHELLS = (
    r"(?:(?:ba|z|da|k|c|tc|fi|a)?sh|iex|invoke-expression|pwsh|powershell(?:\.exe)?|"
    r"source|osascript)"
)
_SCRIPT_RUNNERS = r"(?:node(?:js)?|python[0-9.]*|py|perl|ruby|php|bun|deno)"
_STDIN_RUNNER = (
    rf"{_PREFIX}(?:{_SHELLS}\b|{_SCRIPT_RUNNERS}\b"
    r"(?!\s+(?:-[cemp]\b|--eval\b|--print\b|-m\b|[^\s-])))"
)
_RUNNER = rf"{_PREFIX}(?:{_SHELLS}|{_SCRIPT_RUNNERS})"
_DOWNLOADERS = re.compile(
    rf"\b{_FETCH}\b[^|;&\n]*\|\s*{_STDIN_RUNNER}"
    rf"|(?:\$\(|`|<\()\s*{_FETCH}\b"
    rf"|\b{_FETCH}\b[^;&|\n]*(?:\s-o\b|\s-O\b|--output|-outfile)[^;&|\n]*"
    rf"(?:&&|;|\|\|)\s*(?:chmod\b|{_RUNNER}\b|\./|\.\\)"
    r"|downloadstring|downloadfile|net\.webclient"
    r"|\b(?:npx|bunx|pnpx|pnpm\s+dlx|yarn\s+dlx|npm\s+(?:exec|x|install|i)|bun\s+x|uvx|"
    r"uv\s+tool\s+run|pipx\s+run|pip[0-9.]*\s+install|deno\s+run|bun\s+run)\b[^;&|\n]*?"
    r"(?:\b(?:github|gitlab|bitbucket|gist):|git\+|git://|https?://)"
    r"|\b(?:node(?:js)?|bun|deno)\b[^;&|\n]*\s-(?:e|p|-eval|-print)\b[^\n]*"
    r"(?:fetch\s*\(|https?\.(?:get|request)|require\(\s*['\"]https?['\"]\s*\)|"
    r"import\(\s*['\"]https?://)"
    r"|\bpython[0-9.]*\b[^;&|\n]*\s-c\b[^\n]*(?:urllib|urlopen|requests\.|httpx\.|http\.client)",
    re.IGNORECASE,
)
_DECODERS = re.compile(
    rf"\b(?:base64|openssl\s+(?:base64|enc))\b[^|;&\n]*\s(?:-d|-D|--decode)\b[^|;&\n]*"
    rf"(?:\|\s*{_STDIN_RUNNER}|(?:&&|;)\s*(?:chmod\b|{_RUNNER}\b))"
    rf"|\bxxd\s+-r\b[^|;&\n]*\|\s*{_STDIN_RUNNER}"
    r"|(?:\$\(|`)\s*(?:echo|printf)\b[^)`]*\|\s*(?:base64|openssl\s+base64)\s[^)`]*"
    r"(?:-d|-D|--decode)"
    r"|\b(?:pwsh|powershell)(?:\.exe)?\b[^\n]*\s-(?:e|ec|en|enc|enco|encod|encode|encoded|"
    r"encodedcommand)\s+[A-Za-z0-9+/=]{16,}"
    r"|\b(?:eval|exec|Function|execSync|runInThisContext|runInNewContext|compile)\s*\("
    r"[^)]{0,120}?(?:atob\s*\(|Buffer\.from\s*\(|b64decode|base64\.|fromhex|codecs\.decode|"
    r"zlib\.decompress|marshal\.loads|fromCharCode|unescape\s*\()",
    re.IGNORECASE,
)
_INTERPRETERS = frozenset(
    {
        "node",
        "nodejs",
        "bun",
        "deno",
        "python",
        "python3",
        "py",
        "sh",
        "bash",
        "zsh",
        "dash",
        "ksh",
        "fish",
        "perl",
        "ruby",
        "php",
        "osascript",
        "wscript",
        "cscript",
        "pwsh",
        "powershell",
        "tsx",
        "ts-node",
    }
)
_DISGUISE_EXTENSIONS = re.compile(
    r"\.(?:woff2?|ttf|otf|eot|png|jpe?g|gif|bmp|ico|svg|webp|avif|mp3|mp4|wav|ogg|pdf|txt|md|"
    r"log|lock|map|css|scss|csv|dat|bin|db|sqlite)$",
    re.IGNORECASE,
)
_ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAPPERS = frozenset({"env", "sudo", "nohup", "exec", "command", "time", "nice"})
_HOME_PREFIX = re.compile(
    r"^(?:~|\$HOME|\$\{HOME\}|\$\{userHome\}|\$\{env:HOME\}|\$\{env:USERPROFILE\}|"
    r"%USERPROFILE%|%HOMEPATH%|\$env:USERPROFILE|\$env:HOME|/Users/[^/\\]+|/home/[^/\\]+|"
    r"/root|/var/root|[A-Za-z]:[\\/]+Users[\\/]+[^\\/]+)(?:[\\/]+(?P<rest>.*))?$",
    re.IGNORECASE,
)
_APPDATA_PREFIX = re.compile(
    r"^(?:%APPDATA%|%LOCALAPPDATA%|\$env:APPDATA|\$env:LOCALAPPDATA|\$\{env:APPDATA\}|"
    r"\$\{env:LOCALAPPDATA\})(?:[\\/]|$)",
    re.IGNORECASE,
)
_TEMP_PREFIX = re.compile(
    r"^(?:/tmp|/private/tmp|/var/tmp|/dev/shm|/private/var/folders|/var/folders|\$TMPDIR|"
    r"\$\{TMPDIR\}|\$\{env:TMPDIR\}|\$\{env:TEMP\}|%TEMP%|%TMP%|\$env:TEMP|\$env:TMP|"
    r"[A-Za-z]:[\\/]+Windows[\\/]+Temp)(?:[\\/]|$)",
    re.IGNORECASE,
)
_WINDOWS_TEMP = re.compile(r"[\\/]AppData[\\/]Local[\\/]Temp(?:[\\/]|$)", re.IGNORECASE)
_TOOLCHAIN_DIRS = frozenset(
    {
        ".nvm",
        ".volta",
        ".fnm",
        ".nodenv",
        ".local",
        ".cargo",
        ".bun",
        ".deno",
        ".pyenv",
        ".asdf",
        ".npm-global",
        ".yarn",
        ".rbenv",
        ".linuxbrew",
        ".rye",
        ".pixi",
        ".proto",
    }
)
_LAUNCHERS = frozenset(
    {
        "npx",
        "npm",
        "pnpm",
        "pnpx",
        "yarn",
        "bunx",
        "bun",
        "uvx",
        "uv",
        "pipx",
        "node",
        "nodejs",
        "deno",
        "python",
        "python3",
        "py",
        "docker",
        "podman",
    }
)


def split_command(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def basename(token: str) -> str:
    name = re.split(r"[\\/]", token)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def interpreter_name(token: str) -> str:
    name = basename(token)
    match = re.match(r"^(python)[0-9.]*$", name)
    if match:
        return "python"
    return name


def display(command: str) -> str:
    collapsed = " ".join(command.split())
    if len(collapsed) > MAX_DISPLAY_CHARS:
        return collapsed[: MAX_DISPLAY_CHARS - 3] + "..."
    return collapsed


def bounded(command: str) -> str:
    return command[:MAX_COMMAND_CHARS]


def executable_and_args(tokens: list[str]) -> tuple[str | None, list[str]]:
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if _ENV_ASSIGNMENT.match(token) or basename(token) in _WRAPPERS or token.startswith("-"):
            index += 1
            continue
        return token, tokens[index + 1 :]
    return None, []


def script_argument(tokens: list[str]) -> str | None:
    executable, rest = executable_and_args(tokens)
    if executable is None:
        return None
    if interpreter_name(executable) not in _INTERPRETERS:
        if _looks_like_path(executable):
            return executable
        return None
    skip_next = False
    for token in rest:
        if skip_next:
            skip_next = False
            continue
        if token in {"-e", "-c", "-p", "--eval", "--print", "-m"}:
            return None
        if token in {"-r", "--require", "--import", "--loader", "-I", "--input-type"}:
            skip_next = True
            continue
        if token.startswith("-"):
            continue
        if token == "run" and interpreter_name(executable) in {"deno", "bun"}:
            continue
        return token
    return None


def _looks_like_path(token: str) -> bool:
    return "/" in token or "\\" in token or token.startswith(".")


def classify(command: str) -> dict[str, Any]:
    tokens = split_command(command)
    executable, _ = executable_and_args(tokens)
    script = script_argument(tokens)
    disguised = None
    if script and executable and interpreter_name(executable) in _INTERPRETERS:
        if _DISGUISE_EXTENSIONS.search(script):
            disguised = script
    return {
        "fetches_remote": bool(_DOWNLOADERS.search(command)),
        "decodes_and_executes": bool(_DECODERS.search(command)),
        "disguised_script": disguised,
        "padded": bool(re.search(rf"\s{{{PADDING_RUN},}}", command.strip())),
        "script": script,
        "executable": executable,
    }


def line_padded(text: str, line_start: int, offset: int) -> bool:
    return bool(re.search(rf"[ \t]{{{LINE_PADDING_RUN},}}", text[line_start:offset]))


def hidden_location(token: str) -> str | None:
    value = token.strip().strip("'\"")
    if not value:
        return None
    if _TEMP_PREFIX.match(value) or _WINDOWS_TEMP.search(value):
        return "temporary directory"
    if _APPDATA_PREFIX.match(value):
        return "hidden home directory"
    match = _HOME_PREFIX.match(value)
    if not match:
        return None
    rest = match.group("rest") or ""
    first = re.split(r"[\\/]+", rest)[0]
    if first.startswith(".") and first not in {".", ".."}:
        return "hidden home directory"
    if first.lower() == "appdata":
        return "hidden home directory"
    return None


def toolchain_launcher(token: str) -> bool:
    value = token.strip().strip("'\"")
    match = _HOME_PREFIX.match(value)
    if not match or basename(value) not in _LAUNCHERS:
        return False
    parts = re.split(r"[\\/]+", match.group("rest") or "")
    if not parts or parts[0] not in _TOOLCHAIN_DIRS:
        return False
    return "bin" in parts[1:-1] or parts[0] in {".nvm", ".volta", ".fnm", ".nodenv", ".pyenv"}


def path_tokens(tokens: list[str]) -> list[str]:
    values: list[str] = []
    for token in tokens:
        if token.startswith("-") and "=" in token:
            values.append(token.split("=", 1)[1])
        else:
            values.append(token)
    return values
