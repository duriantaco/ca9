"""Record ordinary file-serving paths with the pinned Flask source and locked wheels."""

import hashlib
import json
import sys
import tempfile
from collections import defaultdict
from importlib.metadata import version
from pathlib import Path

import flask
from werkzeug.security import safe_join


def capture(app, directory, use_directory):
    lines = defaultdict(set)
    observed_call = False

    def trace(frame, event, arg):
        nonlocal observed_call
        module = frame.f_globals.get("__name__")
        if module not in {"werkzeug.utils", "werkzeug.security"}:
            return None
        if event == "call" and frame.f_code is safe_join.__code__:
            observed_call = True
        if event == "line":
            lines[module].add(frame.f_lineno)
        return trace

    with app.test_request_context("/"):
        sys.settrace(trace)
        try:
            if use_directory:
                response = flask.send_from_directory(directory, "hello.txt")
            else:
                response = flask.send_file(directory / "hello.txt")
            response.direct_passthrough = False
            try:
                assert response.get_data() == b"hello"
            finally:
                response.close()
        finally:
            sys.settrace(None)
    assert observed_call == use_directory
    return {
        "called_safe_join": observed_call,
        "files": {
            f"site-packages/{module.replace('.', '/')}.py": {"executed_lines": sorted(numbers)}
            for module, numbers in sorted(lines.items())
        },
    }


if __name__ == "__main__":
    flask_path = Path(flask.__file__).resolve().parent
    helpers_hash = hashlib.sha256((flask_path / "helpers.py").read_bytes()).hexdigest()
    expected_hash = "ac96607bbfc9dbcf09d5442fe7e90d7f8a046b0df7d8f3fc3535b44112016d71"
    if version("werkzeug") != "3.1.5" or helpers_hash != expected_hash:
        raise SystemExit("Expected Flask 3.1.3 source and its locked Werkzeug 3.1.5")
    with tempfile.TemporaryDirectory() as tmp:
        directory = Path(tmp)
        (directory / "hello.txt").write_bytes(b"hello")
        app = flask.Flask(__name__, root_path=str(directory))
        observations = {
            "send_file": capture(app, directory, False),
            "send_from_directory": capture(app, directory, True),
        }
    print(json.dumps(observations, indent=2))
