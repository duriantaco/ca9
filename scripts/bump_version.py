from __future__ import annotations

import argparse
import re
from pathlib import Path

SEMVER_RE = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT_FILE = ROOT / "src" / "ca9" / "__init__.py"
STRUCTURED_DATA = ROOT / "docs" / "assets" / "structured-data.js"
CHANGELOG = ROOT / "CHANGELOG.md"


def validate_version(version: str) -> str:
    if not SEMVER_RE.fullmatch(version):
        raise ValueError(
            f"{version!r} is not a valid SemVer version. Use a value like 0.2.0 or 1.0.0-rc.1."
        )
    return version


def _replace_once(text: str, pattern: str, replacement: str, label: str) -> str:
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise RuntimeError(f"Could not update {label}")
    return updated


def _write_updated(path: Path, text: str, dry_run: bool) -> bool:
    old = path.read_text()
    if old == text:
        return False
    if not dry_run:
        path.write_text(text)
    return True


def bump_version(version: str, dry_run: bool = False) -> list[Path]:
    validate_version(version)
    changed: list[Path] = []

    pyproject_text = _replace_once(
        PYPROJECT.read_text(),
        r'^version = "[^"]+"',
        f'version = "{version}"',
        "pyproject.toml [project].version",
    )
    if _write_updated(PYPROJECT, pyproject_text, dry_run):
        changed.append(PYPROJECT)

    init_text = _replace_once(
        INIT_FILE.read_text(),
        r'^__version__ = "[^"]+"',
        f'__version__ = "{version}"',
        "src/ca9/__init__.py __version__",
    )
    if _write_updated(INIT_FILE, init_text, dry_run):
        changed.append(INIT_FILE)

    if STRUCTURED_DATA.exists():
        structured_text = _replace_once(
            STRUCTURED_DATA.read_text(),
            r'"softwareVersion": "[^"]+"',
            f'"softwareVersion": "{version}"',
            "docs structured-data softwareVersion",
        )
        if _write_updated(STRUCTURED_DATA, structured_text, dry_run):
            changed.append(STRUCTURED_DATA)

    return changed


def extract_changelog_section(version: str, changelog_text: str) -> str:
    validate_version(version)
    pattern = re.compile(
        rf"^## \[{re.escape(version)}\](?: - \d{{4}}-\d{{2}}-\d{{2}})?\n(?P<body>.*?)(?=^## \[|\Z)",
        re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(changelog_text)
    if not match:
        raise ValueError(f"CHANGELOG.md does not contain a section for [{version}]")

    body = match.group("body").strip()
    if not body:
        raise ValueError(f"CHANGELOG.md section for [{version}] is empty")

    return body + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Update ca9 release version files.")
    parser.add_argument("version", help="SemVer release version, for example 0.2.0")
    parser.add_argument(
        "--check-changelog",
        action="store_true",
        help="Require CHANGELOG.md to contain a non-empty section for the version.",
    )
    parser.add_argument(
        "--notes-output",
        type=Path,
        default=None,
        help="Write the CHANGELOG.md section for this version to a release notes file.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Validate without writing files.")
    args = parser.parse_args()

    version = validate_version(args.version)

    if args.check_changelog or args.notes_output:
        notes = extract_changelog_section(version, CHANGELOG.read_text())
        if args.notes_output and not args.dry_run:
            args.notes_output.write_text(notes)

    changed = bump_version(version, dry_run=args.dry_run)
    for path in changed:
        print(path.relative_to(ROOT))
    if not changed:
        print("Version files already match.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
