"""Internal records for the CI job reach model and their ``ca9.ci_inventory.v1`` form."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCHEMA = "ca9.ci_inventory.v1"
MAX_ITEMS_PER_LIST = 100
MAX_NAME_LENGTH = 120


@dataclass
class Origin:
    """Where a record really lives when it came from a local composite action."""

    file: str
    line: int

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line}


@dataclass
class Install:
    ecosystem: str
    manager: str
    kind: str
    ignore_scripts: bool
    line: int
    origin: Origin | None = None
    order: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "ecosystem": self.ecosystem,
            "manager": self.manager,
            "kind": self.kind,
            "ignore_scripts": self.ignore_scripts,
            "line": self.line,
        }
        _add_origin(data, self.origin)
        return data


@dataclass
class Tool:
    name: str
    route: str
    pinned: bool
    line: int
    manager: str | None = None
    self_update: bool = False
    origin: Origin | None = None
    order: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "route": self.route,
            "pinned": self.pinned,
            "line": self.line,
        }
        if self.self_update:
            data["self_update"] = True
        _add_origin(data, self.origin)
        return data

    def other_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "name": self.name,
            "manager": self.manager or self.route,
            "pinned": self.pinned,
            "line": self.line,
        }
        _add_origin(data, self.origin)
        return data


@dataclass
class Indirect:
    """A command whose installs are hidden in another file or image: make, docker build,
    tox, a repository script. It may install packages; the inventory cannot tell."""

    command: str
    line: int
    origin: Origin | None = None
    order: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"command": self.command, "line": self.line}


@dataclass
class Download:
    host: str
    line: int
    target: str | None = None
    verified: bool = False
    reaches_publish: bool = False
    archive: bool = False
    executed: bool = False
    lands_in: str | None = None
    replaces: bool = False
    used_by_publish: bool = False
    step: int = 0
    origin: Origin | None = None
    order: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "host": self.host,
            "verified": self.verified,
            "reaches_publish": self.reaches_publish,
            "line": self.line,
        }
        if self.archive:
            data["archive"] = True
        if self.executed:
            data["executed"] = True
        if self.lands_in:
            data["lands_in"] = self.lands_in
        _add_origin(data, self.origin)
        return data


@dataclass
class Publish:
    registry: str
    line: int
    method: str = "unknown"
    command: str = ""
    via: str = "command"
    provenance: bool = False
    context: str = ""
    step: int = 0
    origin: Origin | None = None
    order: tuple[int, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "registry": self.registry,
            "method": self.method,
            "line": self.line,
            "command": self.command,
            "via": self.via,
        }
        if self.provenance:
            data["provenance"] = True
        _add_origin(data, self.origin)
        return data


@dataclass
class ActionRef:
    uses: str
    ref: str
    pinned: bool
    line: int
    third_party: bool
    kind: str = "action"
    origin: Origin | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "uses": self.uses,
            "ref": self.ref,
            "pinned": self.pinned,
            "line": self.line,
            "third_party": self.third_party,
            "kind": self.kind,
        }
        _add_origin(data, self.origin)
        return data


@dataclass
class Job:
    id: str
    line: int
    labels: list[str] = field(default_factory=list)
    self_hosted: bool = False
    runner_inferred: bool = False
    environment: str | None = None
    environment_dynamic: bool = False
    write: list[str] = field(default_factory=list)
    id_token: bool = False
    permissions_source: str = "default"
    secret_names: set[str] = field(default_factory=set)
    inherit: bool = False
    all_via_tojson: bool = False
    installs: list[Install] = field(default_factory=list)
    actions: list[ActionRef] = field(default_factory=list)
    tools: list[Tool] = field(default_factory=list)
    other_tools: list[Tool] = field(default_factory=list)
    downloads: list[Download] = field(default_factory=list)
    publishes: list[Publish] = field(default_factory=list)
    indirect: list[Indirect] = field(default_factory=list)
    uses_cache: bool = False
    calls: str | None = None
    local_actions: list[str] = field(default_factory=list)
    publish_credentials: dict[str, str] = field(default_factory=dict)
    credential_lines: dict[str, int] = field(default_factory=dict)
    remote_reusable: bool = False
    publish_guards: list[frozenset[tuple[str, ...]]] = field(default_factory=list)
    truncated: bool = False

    @property
    def credentialed(self) -> bool:
        return bool(
            self.id_token
            or self.publish_credentials
            or self.publishes
            or self.inherit
            or self.all_via_tojson
        )

    def to_dict(self) -> dict[str, Any]:
        lists = {
            "installs": [item.to_dict() for item in self.installs],
            "actions": [item.to_dict() for item in self.actions],
            "tools": [item.to_dict() for item in self.tools],
            "downloads": [item.to_dict() for item in self.downloads],
            "publishes": [item.to_dict() for item in self.publishes],
            "other_tools": [item.other_dict() for item in self.other_tools],
            "indirect": [item.to_dict() for item in self.indirect],
        }
        for key, items in lists.items():
            if len(items) > MAX_ITEMS_PER_LIST:
                lists[key] = items[:MAX_ITEMS_PER_LIST]
                self.truncated = True
        data: dict[str, Any] = {
            "id": self.id,
            "line": self.line,
            "runner": {
                "self_hosted": self.self_hosted,
                "labels": list(self.labels)[:MAX_ITEMS_PER_LIST],
                "inferred": self.runner_inferred,
            },
            "environment": self.environment,
            "permissions": {
                "write": sorted(self.write),
                "id_token": self.id_token,
                "source": self.permissions_source,
            },
            "secrets": {
                "names": sorted(self.secret_names)[:MAX_ITEMS_PER_LIST],
                "inherit": self.inherit,
                "all_via_tojson": self.all_via_tojson,
            },
            "installs": lists["installs"],
            "actions": lists["actions"],
            "tools": lists["tools"],
            "downloads": lists["downloads"],
            "publishes": lists["publishes"],
            "uses_cache": self.uses_cache,
            "other_tools": lists["other_tools"],
            "publish_credentials": sorted(self.publish_credentials),
            "remote_reusable": self.remote_reusable,
            "indirect": lists["indirect"],
        }
        if self.environment_dynamic:
            data["environment_dynamic"] = True
        if self.calls:
            data["calls"] = self.calls
        if self.local_actions:
            data["local_actions"] = sorted(set(self.local_actions))
        return data


@dataclass
class Workflow:
    file: str
    provider: str
    triggers: list[str] = field(default_factory=list)
    trigger_lines: dict[str, int] = field(default_factory=dict)
    dispatch: bool = False
    branch_filters: list[str] | None = None
    any_branch: bool = False
    jobs: list[Job] = field(default_factory=list)
    called_by: list[str] = field(default_factory=list)
    caller_triggers: list[str] = field(default_factory=list)
    includes: list[ActionRef] = field(default_factory=list)
    on_line: int = 1

    def to_dict(self) -> dict[str, Any]:
        filters = None
        if self.branch_filters is not None:
            filters = list(self.branch_filters)
        data: dict[str, Any] = {
            "file": self.file,
            "provider": self.provider,
            "triggers": list(self.triggers),
            "dispatch": self.dispatch,
            "branch_filters": filters,
            "any_branch": self.any_branch,
            "jobs": [job.to_dict() for job in self.jobs],
        }
        if self.called_by:
            data["called_by"] = sorted(set(self.called_by))
            data["caller_triggers"] = sorted(set(self.caller_triggers))
        if self.includes:
            data["includes"] = [item.to_dict() for item in self.includes[:MAX_ITEMS_PER_LIST]]
        return data


def _add_origin(data: dict[str, Any], origin: Origin | None) -> None:
    if origin is not None:
        data["via_action"] = origin.to_dict()
