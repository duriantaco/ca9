"""Publish the current GitHub Action report and record its findings exit code."""

import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import click

from ca9.cli import main


def run(args: list[str]) -> int:
    output = Path(os.environ["CA9_OUTPUT"])
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as step_outputs:
        output.parent.mkdir(parents=True, exist_ok=True)
        with TemporaryDirectory(dir=output.parent) as staging:
            report = Path(staging) / "report"
            try:
                # In standalone mode Click turns usage errors into exit 2,
                # which is also ca9's exit code for an inconclusive report.
                status = main.main(
                    [*args, "-o", str(report)], prog_name="ca9", standalone_mode=False
                )
            except click.ClickException as exc:
                exc.show()
                print(f"exit-code={exc.exit_code}", file=step_outputs)
                return exc.exit_code
            except SystemExit as exc:
                status = exc.code
            status = 0 if status is None else status
            print(f"exit-code={status}", file=step_outputs)
            if status not in (0, 1, 2):
                return status
            if not report.is_file() or not report.stat().st_size:
                print("ca9 did not produce a report.", file=sys.stderr)
                return 1
            report.replace(output)
            print("report-written=true", file=step_outputs)
    return 0


if __name__ == "__main__":
    sys.exit(run(sys.argv[1:]))
