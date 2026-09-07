"""Click entry point for dependency update reviews."""

from __future__ import annotations

from pathlib import Path

import click

from ca9.review.render import write_json, write_markdown


@click.command(name="review")
@click.option(
    "--base",
    "base_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Base npm v2/v3 package-lock.json file.",
)
@click.option(
    "--head",
    "head_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Updated npm v2/v3 package-lock.json file.",
)
@click.option(
    "-f",
    "--format",
    "output_format",
    type=click.Choice(["json", "markdown"]),
    default="markdown",
    show_default=True,
)
@click.option(
    "-o",
    "--output",
    "output_path",
    type=click.Path(dir_okay=False, path_type=Path),
    help="Write the report to a file instead of stdout.",
)
@click.option(
    "--cache-dir",
    type=click.Path(file_okay=False, path_type=Path),
    help="Directory for downloaded and verified package artifacts.",
)
@click.option(
    "--trusted-registry",
    "trusted_registries",
    multiple=True,
    metavar="HTTPS_ORIGIN",
    help="Add a trusted HTTPS artifact origin; registry.npmjs.org is trusted by default.",
)
@click.option(
    "--no-scan-artifacts",
    is_flag=True,
    help="Compare lock metadata only; changed artifact behavior remains incomplete.",
)
def review_cmd(
    base_path: Path,
    head_path: Path,
    output_format: str,
    output_path: Path | None,
    cache_dir: Path | None,
    trusted_registries: tuple[str, ...],
    no_scan_artifacts: bool,
) -> None:
    """Review npm dependency changes using hash-verified package artifacts.

    Compares declarations and static observations without executing package code.
    Exits 0 for a complete pass, 1 for review/block, or 2 for incomplete evidence
    (unless a blocking observation takes precedence) or invalid input.
    """
    from ca9.review.service import review_lockfiles

    try:
        report = review_lockfiles(
            base_path,
            head_path,
            cache_dir=cache_dir,
            trusted_registries=tuple(
                dict.fromkeys(("https://registry.npmjs.org", *trusted_registries))
            ),
            scan_artifacts=not no_scan_artifacts,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from None
    except OSError as exc:
        raise click.UsageError(f"Cannot read dependency review inputs: {exc}") from None

    text = write_json(report) if output_format == "json" else write_markdown(report)
    if output_path is not None:
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise click.ClickException(f"Cannot write dependency review report: {exc}") from None
    else:
        click.echo(text, nl=not text.endswith("\n"))
    raise SystemExit(report.exit_code)
