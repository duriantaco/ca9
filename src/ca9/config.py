from __future__ import annotations

from pathlib import Path


def _load_toml(path: Path) -> dict:
    try:
        import tomllib
    except ModuleNotFoundError:
        try:
            import tomli as tomllib
        except ModuleNotFoundError:
            return {}

    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except OSError:
        return {}


def find_config(start: Path | None = None) -> Path | None:
    current = (start or Path.cwd()).resolve()
    for directory in (current, *current.parents):
        candidate = directory / ".ca9.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path) -> dict:
    data = _load_toml(path)
    section = data.get("ca9")
    if isinstance(section, dict):
        merged = {k: v for k, v in data.items() if k != "ca9"}
        merged.update(section)
        return merged
    return data
