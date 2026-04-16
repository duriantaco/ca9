from __future__ import annotations

from typing import Any, Protocol

from packaging.utils import canonicalize_name

from ca9.models import Vulnerability


class SCAParser(Protocol):
    def can_parse(self, data: Any) -> bool: ...

    def parse(self, data: Any) -> list[Vulnerability]: ...


def parse_package_ref(value: Any) -> str | None:
    if isinstance(value, dict):
        package = value.get("package")
        if isinstance(package, dict):
            name = package.get("name")
            if isinstance(name, str) and name:
                return name
        name = value.get("name")
        if isinstance(name, str) and name:
            return name
        return None

    if not isinstance(value, str):
        return None

    ref = value.strip()
    if not ref:
        return None

    if "@" in ref and not ref.startswith("@"):
        return ref.rsplit("@", 1)[0]

    return ref


def normalize_dependency_chain(
    chain: list[str],
    package_name: str,
    project_name: str | None = None,
) -> tuple[str, ...]:
    cleaned = [name for name in chain if name]
    if not cleaned:
        return ()

    if project_name:
        normalized_project = project_name.strip()
        if normalized_project and cleaned[0] == normalized_project:
            cleaned = cleaned[1:]

    if not cleaned:
        return ()

    pkg_key = canonicalize_name(package_name)
    if canonicalize_name(cleaned[-1]) != pkg_key:
        return ()

    return tuple(cleaned)
