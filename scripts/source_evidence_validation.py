"""Check static API attribution and scan completeness on hash-pinned public source."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from ca9.analysis.api_usage import scan_file_for_api_usage
from ca9.analysis.ast_scanner import collect_imports_from_repo
from ca9.engine import analyze
from ca9.models import ApiTarget, Vulnerability
from ca9.vex import write_openvex


@dataclass(frozen=True)
class Source:
    repo: str
    commit: str
    path: str
    sha256: str

    @property
    def url(self) -> str:
        return f"https://raw.githubusercontent.com/{self.repo}/{self.commit}/{self.path}"

    def read(self, local: Path | None) -> bytes:
        if local is None:
            with urllib.request.urlopen(self.url, timeout=30) as response:
                data = response.read(1024 * 1024)
        else:
            data = local.read_bytes()
        if hashlib.sha256(data).hexdigest() != self.sha256:
            raise ValueError(f"Source checksum mismatch for {local or self.url}")
        return data


FLASK = Source(
    "pallets/flask",
    "954f5684e4841aad84a8eec7ace7b81a0d3f6831",
    "src/flask/helpers.py",
    "b2a8f7abae90fbb0c586f59e0a4bc1614741c3373565ff96325d5e8167d9fbce",
)
PACKAGING = Source(
    "pypa/packaging",
    "929fd4b1410ac7ef61ef3f45b2f5d7e87711a9b5",
    "src/packaging/version.py",
    "558b2fb50fd198c660a4c082f96b8919c565911b6b4b6e07f34b6b60c074be97",
)
CPYTHON_STRING = (
    Source(
        "python/cpython",
        "b703b2c5e704341d61e367b9b940b77ed11dded0",
        "Lib/string/__init__.py",
        "8c9751e6ae9776b4e94c1c9850b53c0d24e8407196901aeaebffbb1a11a64e05",
    ),
    Source(
        "python/cpython",
        "b703b2c5e704341d61e367b9b940b77ed11dded0",
        "Lib/string/templatelib.py",
        "cafa8b20e15ffc8839a93aacd64f9e28b6596055a04e0ece4d789575ab36b057",
    ),
)


def call_sites(
    source: Source, data: bytes, target: str, expected: list[int], absent: list[int]
) -> dict:
    api = ApiTarget(package=target.partition(".")[0], fqname=target)
    hits = scan_file_for_api_usage(source.path, data.decode("utf-8"), [api])
    actual = sorted({h.line for h in hits if h.match_type != "symbol_reference"})
    return {
        "source": source.url,
        "sha256": source.sha256,
        "target": target,
        "expected_calls": expected,
        "labelled_noncalls": absent,
        "actual_calls": actual,
        "missed_calls": sorted(set(expected) - set(actual)),
        "false_calls": sorted(set(actual) - set(expected)),
        "pass": actual == expected,
    }


def parser_control(local_dir: Path | None) -> dict:
    with tempfile.TemporaryDirectory(prefix="ca9-parser-control-") as tmp:
        repo = Path(tmp)
        for source in CPYTHON_STRING:
            filename = Path(source.path).name
            data = source.read(local_dir / filename if local_dir else None)
            (repo / filename).write_bytes(data)

        # This synthetic dependency chain tests absence-based decisions only.
        probe = Vulnerability(
            "CA9-CONTROL",
            "urllib3",
            "1.0",
            "low",
            "Control",
            report_dependency_chain=("requests", "urllib3"),
        )
        report = analyze([probe], repo)
        verdict = report.results[0].verdict.value
        vex = json.loads(write_openvex(report))["statements"][0]["status"]
        seen = "itertools" in collect_imports_from_repo(repo)

    # templatelib.py contains a real Python 3.14 template string. Earlier
    # parsers skip the file containing the package's itertools import.
    compatible = sys.version_info >= (3, 14)
    expected = {
        "imports_itertools": compatible,
        "warns_skipped_templatelib": not compatible,
        "verdict": "unreachable_static" if compatible else "inconclusive",
        "vex": "not_affected" if compatible else "under_investigation",
    }
    actual = {
        "imports_itertools": seen,
        "warns_skipped_templatelib": any("templatelib.py" in w for w in report.warnings),
        "verdict": verdict,
        "vex": vex,
    }
    return {
        "source_files": {s.url: s.sha256 for s in CPYTHON_STRING},
        "control": "Synthetic advisory with a supplied requests -> urllib3 dependency chain",
        "expected": expected,
        "actual": actual,
        "pass": actual == expected,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--flask-file", type=Path, help="Use a local copy of Flask's helpers.py.")
    parser.add_argument(
        "--packaging-file", type=Path, help="Use a local copy of packaging's version.py."
    )
    parser.add_argument(
        "--cpython-string-dir", type=Path, help="Use a local CPython 3.14.10 Lib/string directory."
    )
    args = parser.parse_args()
    try:
        flask, packaging = FLASK.read(args.flask_file), PACKAGING.read(args.packaging_file)
        cases = [
            # Flask imports werkzeug.utils on line 12 and calls it at line 528.
            call_sites(FLASK, flask, "werkzeug.utils.send_file", [528], []),
            call_sites(PACKAGING, packaging, "re.compile", [258, 396, 1149], []),
            # Lines 28–36 select a stdlib or local decorator at runtime. The
            # typing_extensions import is only in an elif TYPE_CHECKING block.
            call_sites(PACKAGING, packaging, "typing_extensions.deprecated", [], [836, 843]),
        ]
        completeness = parser_control(args.cpython_string_dir)
    except (OSError, ValueError) as exc:
        print(json.dumps({"pass": False, "input_error": str(exc)}, indent=2))
        return 2
    passed = all(case["pass"] for case in cases) and completeness["pass"]
    print(
        json.dumps(
            {
                "python": sys.version.split()[0],
                "call_sites": cases,
                "parser_control": completeness,
                "pass": passed,
            },
            indent=2,
        )
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
