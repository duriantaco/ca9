"""Work out which package an MCP server launch fetches and whether it is pinned.

``parse_launch(command, args)`` understands npx / npm exec / pnpm dlx / yarn dlx /
bunx / uvx / uv tool run / pipx run / python -m / node and other interpreters /
deno / docker and podman run, including ``cmd /c`` and ``sh -c`` wrappers. With
``version=`` it also returns the same argv with that exact version inserted.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Callable
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from ca9.agent_config.commands import basename, interpreter_name, split_command

_NPM_EXACT = re.compile(r"^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_PREFIXES = ("github:", "gitlab:", "bitbucket:", "gist:", "git+", "git://", "git@")
_URL_PREFIXES = ("http://", "https://")
_LOCAL_PREFIXES = ("file:", "./", "../", "/", "~", ".\\", "..\\")
_NPX_VALUE_FLAGS = frozenset(
    {
        "-c",
        "--call",
        "--registry",
        "--cache",
        "--userconfig",
        "--prefix",
        "-w",
        "--workspace",
        "--node-options",
        "--script-shell",
        "--loglevel",
    }
)
_UV_VALUE_FLAGS = frozenset(
    {
        "--with",
        "--with-editable",
        "--with-requirements",
        "-p",
        "--python",
        "--index",
        "--index-url",
        "--extra-index-url",
        "--default-index",
        "-i",
        "--find-links",
        "-f",
        "-c",
        "--constraints",
        "--constraint",
        "--override",
        "--overrides",
        "-b",
        "--build-constraints",
        "--refresh-package",
        "--reinstall-package",
        "--upgrade-package",
        "-P",
        "--exclude-newer",
        "--exclude-newer-package",
        "--resolution",
        "--prerelease",
        "--index-strategy",
        "--keyring-provider",
        "-C",
        "--config-setting",
        "--link-mode",
        "--cache-dir",
        "--directory",
        "--project",
        "--config-file",
        "--color",
        "--env-file",
        "--python-platform",
        "--torch-backend",
        "--allow-insecure-host",
        "--fork-strategy",
    }
)
_PIPX_VALUE_FLAGS = frozenset(
    {"--python", "--index-url", "-i", "--pip-args", "--backend", "--preinstall"}
)
_PYTHON_VALUE_FLAGS = frozenset({"-X", "-W", "-Q"})
_NODE_VALUE_FLAGS = frozenset(
    {
        "-r",
        "--require",
        "--import",
        "--loader",
        "--experimental-loader",
        "--env-file",
        "--input-type",
        "-C",
        "--conditions",
        "--title",
    }
)
_DOCKER_VALUE_FLAGS = frozenset(
    {
        "-e",
        "--env",
        "--env-file",
        "-v",
        "--volume",
        "--mount",
        "--network",
        "--net",
        "--name",
        "-p",
        "--publish",
        "-u",
        "--user",
        "-w",
        "--workdir",
        "--entrypoint",
        "--platform",
        "--pull",
        "--label",
        "-l",
        "--label-file",
        "--add-host",
        "-m",
        "--memory",
        "--memory-swap",
        "--cpus",
        "-c",
        "--cpu-shares",
        "--cpuset-cpus",
        "--hostname",
        "-h",
        "--ipc",
        "--pid",
        "--device",
        "--gpus",
        "--log-driver",
        "--log-opt",
        "--tmpfs",
        "--ulimit",
        "--dns",
        "--cap-add",
        "--cap-drop",
        "--security-opt",
        "--restart",
        "--runtime",
        "--shm-size",
        "--stop-signal",
        "--stop-timeout",
        "--userns",
        "--uts",
        "--volumes-from",
        "--cidfile",
        "--cgroupns",
        "--cgroup-parent",
        "--expose",
        "--link",
        "--ip",
        "--ip6",
        "--isolation",
        "--group-add",
        "--sysctl",
        "--storage-opt",
        "--annotation",
        "-a",
        "--attach",
        "--network-alias",
        "--pids-limit",
        "--health-cmd",
        "--health-interval",
        "--health-retries",
        "--health-timeout",
        "--health-start-period",
        "--detach-keys",
        "--domainname",
        "--oom-score-adj",
        "--mac-address",
    }
)
DOCKER_RUN_VALUE_FLAGS = _DOCKER_VALUE_FLAGS
_SHELL_WRAPPERS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
_NPM_PACKAGE_FLAGS = frozenset({"-p", "--package"})
_NPM_INDEX_FLAGS = frozenset({"--registry"})
_UV_EXTRA_FLAGS = frozenset({"--with"})
_UV_LOCAL_EXTRA_FLAGS = frozenset({"--with-editable", "--with-requirements"})
_UV_INDEX_FLAGS = frozenset(
    {"--index", "--index-url", "-i", "--extra-index-url", "--default-index", "--find-links", "-f"}
)
_PIPX_INDEX_FLAGS = frozenset({"--index-url", "-i"})
_PIP_INDEX_FLAGS = frozenset({"--index-url", "-i", "--extra-index-url", "--find-links", "-f"})
_PUBLIC_INDEXES = frozenset(
    {
        "https://registry.npmjs.org",
        "https://registry.yarnpkg.com",
        "https://pypi.org",
        "https://pypi.org/simple",
        "https://pypi.python.org/simple",
    }
)
_NPM_PARSES_EVERYWHERE = frozenset({"npm exec"})

Rebuild = Callable[[list[str]], list[str]]


def parse_launch(command: object, args: object = None, *, version: object = None) -> dict | None:
    if not isinstance(command, str) or not command.strip():
        return None
    if args is None:
        args = []
    if not isinstance(args, (list, tuple)) or not all(isinstance(item, str) for item in args):
        return None
    argv = [command, *args]
    if not args and re.search(r"\s", command.strip()):
        tokens = split_command(command)
        if tokens and _known_launcher(tokens[0]):
            argv = tokens
    wanted = None
    if isinstance(version, str) and version.strip():
        wanted = version.strip()
    return _dispatch(argv, wanted, lambda inner: inner)


def _known_launcher(token: str) -> bool:
    return basename(token) in {
        "npx",
        "pnpx",
        "npm",
        "pnpm",
        "yarn",
        "bunx",
        "bun",
        "uvx",
        "uv",
        "pipx",
        "docker",
        "podman",
        "cmd",
        "env",
        "deno",
        *_SHELL_WRAPPERS,
    } or interpreter_name(token) in {"python", "node", "nodejs"}


def _dispatch(argv: list[str], version: str | None, rebuild: Rebuild) -> dict | None:
    if not argv:
        return None
    name = basename(argv[0])
    rest = argv[1:]
    if name == "cmd":
        index = 0
        while index < len(rest) and rest[index].lower() in {"/s", "/q", "/d"}:
            index += 1
        if index < len(rest) and rest[index].lower() in {"/c", "/k"}:
            prefix = argv[: index + 2]
            inner = rest[index + 1 :]
            if len(inner) == 1:
                inner = split_command(inner[0])
            return _dispatch(inner, version, lambda new: rebuild(prefix + new))
    if name in _SHELL_WRAPPERS and len(rest) >= 2 and re.fullmatch(r"-[a-z]*c", rest[0]):
        prefix = argv[:2]
        tail = rest[2:]
        return _dispatch(
            split_command(rest[1]),
            version,
            lambda new: rebuild([*prefix, shlex.join(new), *tail]),
        )
    if name == "env":
        index = 0
        while index < len(rest) and (
            rest[index].startswith("-") or re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", rest[index])
        ):
            index += 1
        prefix = argv[: index + 1]
        return _dispatch(rest[index:], version, lambda new: rebuild(prefix + new))
    if name in {"npx", "pnpx", "bunx"}:
        return _npm_exec(argv, 1, name, version, rebuild)
    if name == "npm" and rest and rest[0] in {"exec", "x"}:
        return _npm_exec(argv, 2, "npm exec", version, rebuild)
    if name in {"pnpm", "yarn"} and rest and rest[0] == "dlx":
        return _npm_exec(argv, 2, f"{name} dlx", version, rebuild)
    if name == "bun" and rest and rest[0] == "x":
        return _npm_exec(argv, 2, "bun x", version, rebuild)
    if name == "uvx":
        return _uvx(argv, 1, "uvx", version, rebuild)
    if name == "uv" and rest[:2] == ["tool", "run"]:
        return _uvx(argv, 3, "uv tool run", version, rebuild)
    if name == "pipx" and rest and rest[0] == "run":
        return _pipx(argv, 2, version, rebuild)
    if name in {"docker", "podman"}:
        if rest[:1] == ["run"]:
            return _docker(argv, 2, name, version, rebuild)
        if rest[:2] == ["container", "run"]:
            return _docker(argv, 3, name, version, rebuild)
    if name == "deno":
        return _deno(argv, version, rebuild)
    interpreter = interpreter_name(argv[0])
    if interpreter == "python":
        return _python(argv)
    if interpreter in {"node", "nodejs", "bun", "tsx", "ts-node"}:
        return _script(argv, interpreter, _NODE_VALUE_FLAGS)
    return _result("local", argv[0], None, False, None, "local", False, argv[0], "local")


def _result(
    ecosystem: str,
    package: str,
    version: str | None,
    pinned: bool,
    pinned_command: list[str] | None,
    launcher: str,
    fetches: bool,
    spec: str,
    source: str,
) -> dict[str, Any]:
    return {
        "ecosystem": ecosystem,
        "package": package,
        "version": version,
        "pinned": pinned,
        "pinned_command": pinned_command,
        "launcher": launcher,
        "fetches": fetches,
        "spec": spec,
        "source": source,
    }


def _first_positional(
    argv: list[str], start: int, value_flags: frozenset[str], spec_flags: frozenset[str]
) -> tuple[int | None, int | None, bool]:
    spec_index = None
    inline = False
    positional = None
    index = start
    while index < len(argv):
        token = argv[index]
        if token == "--":
            if index + 1 < len(argv):
                positional = index + 1
            break
        flag, eq, _ = token.partition("=")
        if flag in spec_flags:
            if spec_index is None:
                if eq:
                    spec_index, inline = index, True
                elif index + 1 < len(argv):
                    spec_index = index + 1
            index += 2
            if eq:
                index -= 1
            continue
        if token in value_flags:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        positional = index
        break
    return spec_index, positional, inline


def _replace(argv: list[str], index: int, inline: bool, value: str) -> list[str]:
    updated = list(argv)
    if inline:
        updated[index] = f"{updated[index].split('=', 1)[0]}={value}"
    else:
        updated[index] = value
    return updated


def _token_value(argv: list[str], index: int, inline: bool) -> str:
    if inline:
        return argv[index].split("=", 1)[1]
    return argv[index]


def _npm_exec(
    argv: list[str], start: int, launcher: str, version: str | None, rebuild: Rebuild
) -> dict | None:
    spec_index, positional, inline = _first_positional(
        argv, start, _NPX_VALUE_FLAGS, _NPM_PACKAGE_FLAGS
    )
    index = spec_index
    if index is None:
        index, inline = positional, False
    if index is None:
        return None
    spec = _token_value(argv, index, inline)
    package, found, source = _npm_spec(spec)
    pinned = _npm_pinned(found, source)
    pinned_command = None
    if version and source == "registry" and _NPM_EXACT.match(version):
        pinned_command = rebuild(_replace(argv, index, inline, f"{package}@{version}"))
    result = _result(
        "npm", package, found, pinned, pinned_command, launcher, source != "local", spec, source
    )
    everywhere = launcher in _NPM_PARSES_EVERYWHERE
    extras = []
    for value in _option_values(argv, start, _NPM_PACKAGE_FLAGS, _NPX_VALUE_FLAGS, everywhere)[1:]:
        extra, extra_version, extra_source = _npm_spec(value)
        extras.append(
            _extra(extra, extra_version, _npm_pinned(extra_version, extra_source), extra_source)
        )
    indexes = _option_values(argv, start, _NPM_INDEX_FLAGS, _NPX_VALUE_FLAGS, everywhere)
    return _with_fetch_sources(result, extras, indexes)


def _option_values(
    argv: list[str],
    start: int,
    names: frozenset[str],
    value_flags: frozenset[str],
    everywhere: bool = False,
) -> list[str]:
    """Values of the launcher's own ``names`` options, in order. They stop at ``--`` and,
    unless the launcher parses options ``everywhere`` (npm exec), at the first positional:
    npx, dlx, uvx and pipx pass what follows the package to the server."""
    values: list[str] = []
    index = start
    while index < len(argv):
        token = argv[index]
        if token == "--":
            break
        flag, eq, inline = token.partition("=")
        if flag in names:
            if eq:
                values.append(inline)
            elif index + 1 < len(argv):
                values.append(argv[index + 1])
                index += 1
            index += 1
            continue
        if token in value_flags:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        if not everywhere:
            break
        index += 1
    return values


def _extra(package: str, version: str | None, pinned: bool, source: str) -> dict[str, Any]:
    return {"package": package, "version": version, "pinned": pinned, "source": source}


def _index_url(value: str) -> str:
    text = value.strip()
    name, eq, rest = text.partition("=")
    if eq and "://" not in name:
        text = rest.strip()
    return text


def non_public_indexes(values: list[str]) -> list[str]:
    """Registry or index URLs other than the public npm registry and PyPI."""
    found: list[str] = []
    for value in values:
        url = _index_url(value)
        if url and url.rstrip("/").lower() not in _PUBLIC_INDEXES and url not in found:
            found.append(url)
    return found


def _with_fetch_sources(
    result: dict[str, Any], extras: list[dict[str, Any]], indexes: list[str]
) -> dict[str, Any]:
    """A launch is pinned only when every package it fetches is pinned and it fetches from
    the public registry; otherwise no single version makes it pinned."""
    other = non_public_indexes(indexes)
    if extras:
        result["extra_packages"] = extras
    if other:
        result["indexes"] = other
    if other or any(not item["pinned"] for item in extras):
        result["pinned"] = False
        result["pinned_command"] = None
    return result


def _npm_spec(spec: str) -> tuple[str, str | None, str]:
    value = spec.strip()
    if value.startswith("npm:"):
        value = value[4:]
    if value.lower().startswith(_GIT_PREFIXES):
        base, _, ref = value.partition("#")
        return base, ref or None, "git"
    if value.lower().startswith(_URL_PREFIXES):
        return value, None, "url"
    if value.startswith(_LOCAL_PREFIXES) or value.endswith((".tgz", ".tar.gz")):
        return value, None, "local"
    if not value.startswith("@") and "/" in value:
        base, _, ref = value.partition("#")
        return base, ref or None, "git"
    at = value.rfind("@")
    if at > 0:
        return value[:at], value[at + 1 :] or None, "registry"
    return value, None, "registry"


def _npm_pinned(found: str | None, source: str) -> bool:
    if found is None:
        return False
    if source == "git":
        return bool(_FULL_SHA.match(found.lower()))
    if source == "registry":
        return bool(_NPM_EXACT.match(found))
    return False


def _uvx(
    argv: list[str], start: int, launcher: str, version: str | None, rebuild: Rebuild
) -> dict | None:
    spec_index, positional, inline = _first_positional(
        argv, start, _UV_VALUE_FLAGS, frozenset({"--from"})
    )
    if spec_index is not None:
        result = _pypi(argv, spec_index, inline, launcher, version, rebuild, "from")
    elif positional is None:
        return None
    else:
        result = _pypi(argv, positional, False, launcher, version, rebuild, "uvx")
    extras = []
    for value in _option_values(argv, start, _UV_EXTRA_FLAGS, _UV_VALUE_FLAGS):
        for requirement in value.split(","):
            if requirement.strip():
                name, _extras, found, exact, source = _pypi_spec(requirement)
                extras.append(_extra(name, found, exact, source))
    for value in _option_values(argv, start, _UV_LOCAL_EXTRA_FLAGS, _UV_VALUE_FLAGS):
        extras.append(_extra(value, None, False, "local"))
    indexes = _option_values(argv, start, _UV_INDEX_FLAGS, _UV_VALUE_FLAGS)
    return _with_fetch_sources(result, extras, indexes)


def _pipx(argv: list[str], start: int, version: str | None, rebuild: Rebuild) -> dict | None:
    spec_index, positional, inline = _first_positional(
        argv, start, _PIPX_VALUE_FLAGS, frozenset({"--spec"})
    )
    if spec_index is not None:
        result = _pypi(argv, spec_index, inline, "pipx run", version, rebuild, "from")
    elif positional is None:
        return None
    else:
        result = _pypi(argv, positional, False, "pipx run", version, rebuild, "pipx")
    extras = []
    for value in _option_values(argv, start, frozenset({"--preinstall"}), _PIPX_VALUE_FLAGS):
        name, _extras, found, exact, source = _pypi_spec(value)
        extras.append(_extra(name, found, exact, source))
    indexes = _option_values(argv, start, _PIPX_INDEX_FLAGS, _PIPX_VALUE_FLAGS)
    for value in _option_values(argv, start, frozenset({"--pip-args"}), _PIPX_VALUE_FLAGS):
        words = split_command(value)
        indexes.extend(_option_values(words, 0, _PIP_INDEX_FLAGS, frozenset(), True))
    return _with_fetch_sources(result, extras, indexes)


def _pypi(
    argv: list[str],
    index: int,
    inline: bool,
    launcher: str,
    version: str | None,
    rebuild: Rebuild,
    form: str,
) -> dict[str, Any]:
    spec = _token_value(argv, index, inline)
    name, extras, found, exact, source = _pypi_spec(spec)
    pinned_command = None
    if version and source == "registry" and _pep440_exact(version):
        requirement = f"{name}{extras}=={version}"
        if form == "from":
            pinned_command = rebuild(_replace(argv, index, inline, requirement))
        elif form == "uvx" and not extras:
            pinned_command = rebuild(_replace(argv, index, False, f"{name}@{version}"))
        else:
            flag = "--from"
            if form == "pipx":
                flag = "--spec"
            pinned_command = rebuild(argv[:index] + [flag, requirement, name] + argv[index + 1 :])
    return _result(
        "pypi", name, found, exact, pinned_command, launcher, source != "local", spec, source
    )


def _pypi_spec(spec: str) -> tuple[str, str, str | None, bool, str]:
    value = spec.strip()
    lowered = value.lower()
    if lowered.startswith(("git+", "git://")):
        base, _, ref = value.rpartition("@")
        if not base or "/" in ref:
            return value, "", None, False, "git"
        return base, "", ref, bool(_FULL_SHA.match(ref.lower())), "git"
    if lowered.startswith(_URL_PREFIXES):
        return value, "", None, False, "url"
    if value.startswith(_LOCAL_PREFIXES) or lowered.endswith((".whl", ".tar.gz", ".zip")):
        return value, "", None, False, "local"
    head, at, tail = value.partition("@")
    if at and tail and not re.search(r"[<>=!~ ]", head):
        found = tail.strip()
        extras = _extras(head)
        name = head[: len(head) - len(extras)]
        if tail.strip().lower().startswith(_URL_PREFIXES):
            return name, extras, None, False, "url"
        if found.lower() == "latest":
            return name, extras, None, False, "registry"
        return name, extras, found, _pep440_exact(found), "registry"
    try:
        requirement = Requirement(value)
    except InvalidRequirement:
        return value, "", None, False, "registry"
    extras = ""
    if requirement.extras:
        extras = f"[{','.join(sorted(requirement.extras))}]"
    if requirement.url:
        return requirement.name, extras, None, False, "url"
    specifiers = list(requirement.specifier)
    if len(specifiers) == 1 and specifiers[0].operator in {"==", "==="}:
        found = specifiers[0].version
        return requirement.name, extras, found, _pep440_exact(found), "registry"
    found = str(requirement.specifier) or None
    return requirement.name, extras, found, False, "registry"


def _extras(head: str) -> str:
    match = re.search(r"\[[^\]]*\]$", head)
    if match:
        return match.group()
    return ""


def _pep440_exact(value: str) -> bool:
    if "*" in value or not value.strip():
        return False
    try:
        Version(value)
    except InvalidVersion:
        return False
    return True


def _python(argv: list[str]) -> dict[str, Any]:
    index = 1
    while index < len(argv):
        token = argv[index]
        if token == "-m" and index + 1 < len(argv):
            module = argv[index + 1].split(".")[0]
            return _result(
                "pypi", module, None, False, None, "python -m", False, module, "installed"
            )
        if token == "-c":
            return _result("local", argv[0], None, False, None, "python -c", False, "-c", "local")
        if token in _PYTHON_VALUE_FLAGS:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return _result("local", token, None, False, None, "python", False, token, "local")
    return _result("local", argv[0], None, False, None, "python", False, argv[0], "local")


def _script(argv: list[str], interpreter: str, value_flags: frozenset[str]) -> dict[str, Any]:
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in {"-e", "--eval", "-p", "--print"}:
            return _result("local", argv[0], None, False, None, interpreter, False, token, "local")
        if token in value_flags:
            index += 2
            continue
        if token.startswith("-") or (token == "run" and interpreter == "bun"):
            index += 1
            continue
        return _result("local", token, None, False, None, interpreter, False, token, "local")
    return _result("local", argv[0], None, False, None, interpreter, False, argv[0], "local")


def _deno(argv: list[str], version: str | None, rebuild: Rebuild) -> dict[str, Any]:
    index = 1
    while index < len(argv):
        token = argv[index]
        if token in {"run", "x"} or token.startswith("-"):
            index += 1
            continue
        if token.startswith("npm:"):
            package, found, _ = _npm_spec(token)
            pinned_command = None
            if version and _NPM_EXACT.match(version):
                pinned_command = rebuild(_replace(argv, index, False, f"npm:{package}@{version}"))
            pinned = _npm_pinned(found, "registry")
            return _result(
                "npm", package, found, pinned, pinned_command, "deno", True, token, "registry"
            )
        if token.lower().startswith(_URL_PREFIXES):
            return _result("url", token, None, False, None, "deno", True, token, "url")
        return _result("local", token, None, False, None, "deno", False, token, "local")
    return _result("local", argv[0], None, False, None, "deno", False, argv[0], "local")


def _docker(
    argv: list[str], start: int, launcher: str, version: str | None, rebuild: Rebuild
) -> dict | None:
    _, positional, _ = _first_positional(argv, start, _DOCKER_VALUE_FLAGS, frozenset())
    if positional is None:
        return None
    image = argv[positional]
    repo, tag, digest = _image_parts(image)
    found = digest or tag
    pinned = bool(digest and _DIGEST.match(digest))
    pinned_command = None
    if version and _DIGEST.match(version):
        tagged = repo
        if tag:
            tagged = f"{repo}:{tag}"
        pinned_command = rebuild(_replace(argv, positional, False, f"{tagged}@{version}"))
    return _result("docker", repo, found, pinned, pinned_command, launcher, True, image, "image")


def _image_parts(image: str) -> tuple[str, str | None, str | None]:
    name, _, digest = image.partition("@")
    slash = name.rfind("/")
    colon = name.rfind(":")
    tag = None
    if colon > slash:
        name, tag = name[:colon], name[colon + 1 :]
    return name, tag or None, digest or None
