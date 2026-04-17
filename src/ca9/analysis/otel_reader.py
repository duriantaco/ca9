from __future__ import annotations

import json
from pathlib import Path


def load_otel_traces(traces_path: Path) -> dict[str, int]:
    data = json.loads(traces_path.read_text())

    if isinstance(data, list):
        return _parse_simple_format(data)
    elif isinstance(data, dict):
        if "resourceSpans" in data:
            return _parse_otlp_format(data)
        if "resource_spans" in data:
            return _parse_otlp_format(data)
        if "traces" in data and isinstance(data["traces"], list):
            return _parse_simple_format(data["traces"])

    raise ValueError(
        "Unrecognized trace format. Expected OTLP JSON (resourceSpans) "
        "or simple format ([{module, function, count}])"
    )


def _parse_simple_format(entries: list) -> dict[str, int]:
    modules: dict[str, int] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        module = entry.get("module", "")
        count = entry.get("count", 1)

        if not module:
            continue

        if not isinstance(count, int):
            try:
                count = int(count)
            except (ValueError, TypeError):
                count = 1

        modules[module] = modules.get(module, 0) + count

    return modules


def _parse_otlp_format(data: dict) -> dict[str, int]:
    modules: dict[str, int] = {}

    resource_spans = data.get("resourceSpans") or data.get("resource_spans", [])

    for rs in resource_spans:
        scope_spans = rs.get("scopeSpans") or rs.get("scope_spans", [])

        for ss in scope_spans:
            spans = ss.get("spans", [])

            for span in spans:
                attrs = span.get("attributes", [])
                code_ns = _get_attr(attrs, "code.namespace")
                code_func = _get_attr(attrs, "code.function")
                code_filepath = _get_attr(attrs, "code.filepath")

                module = ""
                if code_ns:
                    module = code_ns
                elif code_filepath:
                    module = _filepath_to_module(code_filepath)

                if module:
                    modules[module] = modules.get(module, 0) + 1

                if module and code_func:
                    full_ref = f"{module}.{code_func}"
                    modules[full_ref] = modules.get(full_ref, 0) + 1

    return modules


def _get_attr(attrs: list, key: str) -> str:
    for attr in attrs:
        if attr.get("key") == key:
            value = attr.get("value", {})
            if isinstance(value, dict):
                return value.get("stringValue", "") or value.get("string_value", "")
            if isinstance(value, str):
                return value
    return ""


def _filepath_to_module(filepath: str) -> str:
    path = filepath.replace("\\", "/")
    if path.endswith(".py"):
        path = path[:-3]
    if path.startswith("./"):
        path = path[2:]
    return path.replace("/", ".")
