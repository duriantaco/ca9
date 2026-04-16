from __future__ import annotations

from pathlib import PurePosixPath

from ca9.capabilities.models import Capability


def normalize_path(path: str) -> str:
    return str(PurePosixPath(path))


def normalize_scope(scope: str) -> str:
    scope = normalize_path(scope)

    if scope.startswith("./"):
        scope = scope[2:]

    if scope and not scope.endswith("/**") and not scope.endswith("/*") and scope != "/**":
        if "/" in scope and not scope.endswith((".", ".txt", ".json", ".py", ".js")):
            if not scope.endswith("/**"):
                scope = scope.rstrip("/") + "/**"

    return scope


def deduplicate_capabilities(capabilities: list[Capability]) -> list[Capability]:
    grouped: dict[tuple[str, str, str], Capability] = {}
    for cap in capabilities:
        key = (cap.name, cap.scope, cap.asset)
        if key not in grouped:
            grouped[key] = cap
        else:
            existing = grouped[key]
            for evidence in cap.evidence:
                if evidence not in existing.evidence:
                    existing.evidence.append(evidence)

    result = []
    for cap in grouped.values():
        cap.evidence = sorted(set(cap.evidence))[:5]
        result.append(cap)

    return result


def is_scope_wider(old_scope: str, new_scope: str) -> bool:
    old = normalize_scope(old_scope)
    new = normalize_scope(new_scope)

    if old == new:
        return False

    if new == "/**":
        return True

    old_base = old.rstrip("*").rstrip("/")
    new_base = new.rstrip("*").rstrip("/")

    if old_base.startswith(new_base) and old_base != new_base:
        return True

    old_depth = old.count("/")
    new_depth = new.count("/")

    if new_depth < old_depth:
        old_prefix = "/".join(old.split("/")[: new_depth + 1])
        new_prefix = "/".join(new.split("/")[: new_depth + 1])
        if old_prefix == new_prefix:
            return True

    return False
