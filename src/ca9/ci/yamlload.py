"""Line-aware YAML loading for CI files.

Mappings load as :class:`LineMap` and sequences as :class:`LineList`, which
remember the 1-based line of each key, value and item. ``on``/``off``/``yes``/``no``
stay strings (GitHub reads ``on:`` as a key, not as ``True``). Unknown tags such as
GitLab's ``!reference`` load as plain data instead of failing the file.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 1_000_000

_BOOL_TAG = "tag:yaml.org,2002:bool"
_BOOL_RE = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")


class YamlUnavailable(RuntimeError):
    """PyYAML is not importable in this installation."""


class YamlError(ValueError):
    """The file is not usable YAML (syntax, size, or structure)."""


class LineMap(dict):
    """A mapping that records where each key and value starts."""

    __slots__ = ("line", "key_lines", "value_lines", "value_styles")

    def key_line(self, key: str) -> int:
        return self.key_lines.get(key, self.line)

    def value_line(self, key: str) -> int:
        return self.value_lines.get(key, self.key_line(key))

    def value_style(self, key: str) -> str | None:
        return self.value_styles.get(key)


class LineList(list):
    """A sequence that records where each item starts."""

    __slots__ = ("line", "item_lines")

    def item_line(self, index: int) -> int:
        if 0 <= index < len(self.item_lines):
            return self.item_lines[index]
        return self.line


_LOADER: Any = None


def _loader() -> Any:
    global _LOADER
    if _LOADER is not None:
        return _LOADER
    try:
        import yaml
    except ImportError as exc:
        raise YamlUnavailable("PyYAML is not installed") from exc

    class Loader(yaml.SafeLoader):
        pass

    Loader.yaml_implicit_resolvers = {
        first: [(tag, regexp) for tag, regexp in resolvers if tag != _BOOL_TAG]
        for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    Loader.add_implicit_resolver(_BOOL_TAG, _BOOL_RE, list("tTfF"))
    Loader.add_constructor("tag:yaml.org,2002:map", _construct_map)
    Loader.add_constructor("tag:yaml.org,2002:seq", _construct_seq)
    Loader.add_multi_constructor("!", _construct_unknown)
    _LOADER = Loader
    return Loader


def load_file(path: Path, root: Path) -> Any:
    """Load a YAML file that must live inside ``root`` and stay under the size limit."""
    try:
        resolved = path.resolve()
        resolved.relative_to(root.resolve())
        size = resolved.stat().st_size
    except (OSError, ValueError) as exc:
        raise YamlError("file is outside the repository or unreadable") from exc
    if size > MAX_FILE_BYTES:
        raise YamlError("file is larger than the CI file size limit")
    return load(resolved.read_text(encoding="utf-8", errors="replace"))


def yaml_available() -> bool:
    try:
        _loader()
    except YamlUnavailable:
        return False
    return True


def load(text: str) -> Any:
    """Parse one YAML document; raise YamlError for anything unusable."""
    loader_class = _loader()
    import yaml

    if len(text.encode("utf-8", errors="ignore")) > MAX_FILE_BYTES:
        raise YamlError("file is larger than the CI file size limit")
    try:
        return yaml.load(text, Loader=loader_class)
    except (yaml.YAMLError, RecursionError, TypeError, ValueError) as exc:
        raise YamlError(type(exc).__name__) from exc


def _key_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    return str(value)


def _construct_map(loader: Any, node: Any) -> Any:
    data = LineMap()
    data.line = node.start_mark.line + 1
    data.key_lines = {}
    data.value_lines = {}
    data.value_styles = {}
    yield data
    loader.flatten_mapping(node)
    for key_node, value_node in node.value:
        key = _key_text(loader.construct_object(key_node, deep=True))
        value = loader.construct_object(value_node, deep=True)
        data[key] = value
        data.key_lines[key] = key_node.start_mark.line + 1
        data.value_lines[key] = value_node.start_mark.line + 1
        style = getattr(value_node, "style", None)
        if style:
            data.value_styles[key] = style


def _construct_seq(loader: Any, node: Any) -> Any:
    data = LineList()
    data.line = node.start_mark.line + 1
    data.item_lines = [item.start_mark.line + 1 for item in node.value]
    yield data
    data.extend(loader.construct_object(item, deep=True) for item in node.value)


def _construct_unknown(loader: Any, _suffix: str, node: Any) -> Any:
    import yaml

    if isinstance(node, yaml.MappingNode):
        return loader.construct_object(
            yaml.MappingNode("tag:yaml.org,2002:map", node.value, node.start_mark, node.end_mark),
            deep=True,
        )
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_object(
            yaml.SequenceNode("tag:yaml.org,2002:seq", node.value, node.start_mark, node.end_mark),
            deep=True,
        )
    return loader.construct_scalar(node)


def empty_map() -> LineMap:
    """A LineMap with no keys, usable wherever a parsed mapping is expected."""
    data = LineMap()
    data.line = 1
    data.key_lines = {}
    data.value_lines = {}
    data.value_styles = {}
    return data


def as_strings(value: Any) -> list[str]:
    """A scalar or a list of scalars as strings; anything else as an empty list."""
    scalar = (str, int, float)
    if isinstance(value, scalar) and not isinstance(value, bool):
        return [str(value)]
    if isinstance(value, list):
        return [
            str(item) for item in value if isinstance(item, scalar) and not isinstance(item, bool)
        ]
    return []


def script_start_line(mapping: LineMap, key: str) -> int:
    """First line of a scalar's text: the line after ``key: |`` for block scalars."""
    line = mapping.value_line(key)
    if mapping.value_style(key) in {"|", ">"}:
        return line + 1
    return line
