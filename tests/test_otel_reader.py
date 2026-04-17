from __future__ import annotations

import json
from pathlib import Path

from ca9.analysis.otel_reader import (
    _filepath_to_module,
    _get_attr,
    _parse_otlp_format,
    _parse_simple_format,
    load_otel_traces,
)

FIXTURES = Path(__file__).parent / "fixtures"


class TestSimpleFormat:
    def test_basic(self):
        entries = [
            {"module": "requests.api", "function": "get", "count": 100},
            {"module": "requests.api", "function": "post", "count": 50},
            {"module": "flask.app", "function": "dispatch", "count": 200},
        ]
        result = _parse_simple_format(entries)
        assert result["requests.api"] == 150
        assert result["flask.app"] == 200

    def test_missing_module(self):
        entries = [{"function": "get", "count": 10}]
        result = _parse_simple_format(entries)
        assert result == {}

    def test_default_count(self):
        entries = [{"module": "requests"}]
        result = _parse_simple_format(entries)
        assert result["requests"] == 1

    def test_string_count(self):
        entries = [{"module": "requests", "count": "42"}]
        result = _parse_simple_format(entries)
        assert result["requests"] == 42

    def test_invalid_count(self):
        entries = [{"module": "requests", "count": "abc"}]
        result = _parse_simple_format(entries)
        assert result["requests"] == 1

    def test_empty_input(self):
        assert _parse_simple_format([]) == {}

    def test_non_dict_entries(self):
        entries = ["not a dict", 42, None]
        assert _parse_simple_format(entries) == {}


class TestOtlpFormat:
    def test_parses_fixture(self):
        data = json.loads((FIXTURES / "sample_otel_traces.json").read_text())
        result = _parse_otlp_format(data)

        assert "requests.api" in result
        assert result["requests.api"] >= 2
        assert "requests.api.get" in result
        assert "requests.api.post" in result

    def test_code_filepath_fallback(self):
        data = {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": "handler",
                                    "attributes": [
                                        {
                                            "key": "code.filepath",
                                            "value": {"stringValue": "app/services/fetch.py"},
                                        }
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        result = _parse_otlp_format(data)
        assert "app.services.fetch" in result

    def test_empty_spans(self):
        data = {"resourceSpans": [{"scopeSpans": [{"spans": []}]}]}
        result = _parse_otlp_format(data)
        assert result == {}

    def test_snake_case_keys(self):
        data = {
            "resource_spans": [
                {
                    "scope_spans": [
                        {
                            "spans": [
                                {
                                    "name": "test",
                                    "attributes": [
                                        {
                                            "key": "code.namespace",
                                            "value": {"string_value": "mymod"},
                                        }
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        result = _parse_otlp_format(data)
        assert "mymod" in result


class TestGetAttr:
    def test_found(self):
        attrs = [{"key": "code.function", "value": {"stringValue": "get"}}]
        assert _get_attr(attrs, "code.function") == "get"

    def test_not_found(self):
        attrs = [{"key": "other", "value": {"stringValue": "x"}}]
        assert _get_attr(attrs, "code.function") == ""

    def test_string_value_key(self):
        attrs = [{"key": "code.namespace", "value": {"string_value": "mod"}}]
        assert _get_attr(attrs, "code.namespace") == "mod"

    def test_plain_string_value(self):
        attrs = [{"key": "code.function", "value": "get"}]
        assert _get_attr(attrs, "code.function") == "get"


class TestFilepathToModule:
    def test_basic(self):
        assert _filepath_to_module("app/services/fetch.py") == "app.services.fetch"

    def test_leading_dot_slash(self):
        assert _filepath_to_module("./app/main.py") == "app.main"

    def test_no_extension(self):
        assert _filepath_to_module("app/config") == "app.config"

    def test_backslash(self):
        assert _filepath_to_module("app\\services\\fetch.py") == "app.services.fetch"


class TestLoadOtelTraces:
    def test_otlp_fixture(self):
        result = load_otel_traces(FIXTURES / "sample_otel_traces.json")
        assert "requests.api" in result
        assert result["requests.api"] >= 2

    def test_simple_format(self, tmp_path):
        f = tmp_path / "traces.json"
        f.write_text(
            json.dumps(
                [
                    {"module": "requests", "function": "get", "count": 42},
                ]
            )
        )
        result = load_otel_traces(f)
        assert result["requests"] == 42

    def test_wrapped_simple_format(self, tmp_path):
        f = tmp_path / "traces.json"
        f.write_text(
            json.dumps(
                {
                    "traces": [
                        {"module": "requests", "function": "get", "count": 10},
                    ]
                }
            )
        )
        result = load_otel_traces(f)
        assert result["requests"] == 10

    def test_unknown_format(self, tmp_path):
        import pytest

        f = tmp_path / "traces.json"
        f.write_text(json.dumps({"unknown": "format"}))
        with pytest.raises(ValueError, match="Unrecognized trace format"):
            load_otel_traces(f)
