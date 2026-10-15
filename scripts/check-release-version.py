#!/usr/bin/env python3
"""Fail closed when a release tag does not match the documented project version."""
from __future__ import annotations

import re
import sys
from pathlib import Path

VERSION_RE = r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
TAG_RE = re.compile(rf"v(?P<version>{VERSION_RE})\Z")
EN_RE = re.compile(r"^\*\*Version:\*\*\s+([0-9A-Za-z.+-]+)", re.MULTILINE)
FA_RE = re.compile(r"^\*\*نسخه:\s*([0-9A-Za-z.+-]+)", re.MULTILINE)
CHANGELOG_RE = re.compile(r"^## ([0-9A-Za-z.+-]+)\s*$", re.MULTILINE)


def read_documented_version(root: Path) -> tuple[str | None, list[str]]:
    """Return the changelog's first release version and all documentation errors."""
    patterns = (
        ("README.md", EN_RE, "English README"),
        ("README.fa.md", FA_RE, "Persian README"),
        ("CHANGELOG.md", CHANGELOG_RE, "top changelog entry"),
    )
    found: list[tuple[str, str]] = []
    errors: list[str] = []
    for filename, pattern, label in patterns:
        try:
            content = (root / filename).read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"cannot read {filename}: {exc}")
            continue
        match = pattern.search(content)
        if not match:
            errors.append(f"cannot determine the version from {filename}")
            continue
        found.append((label, match.group(1)))

    if not found:
        return None, errors
    changelog_version = next(
        (version for label, version in found if label == "top changelog entry"),
        found[0][1],
    )
    for label, version in found:
        if version != changelog_version:
            errors.append(
                f"{label} version {version!r} does not match changelog version "
                f"{changelog_version!r}"
            )
    return changelog_version, errors


def validate_tag(tag: str, root: Path) -> list[str]:
    """Validate tag syntax and ensure all release documentation matches it."""
    match = TAG_RE.fullmatch(tag)
    if not match:
        return [
            f"invalid release tag {tag!r}; expected vMAJOR.MINOR.PATCH with an optional prerelease suffix"
        ]
    expected = match.group("version")
    documented, errors = read_documented_version(root)
    if documented is not None and documented != expected:
        errors.append(
            f"release tag version {expected!r} does not match documented version {documented!r}"
        )
    return errors


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parents[1]
    if len(argv) == 2 and argv[1] == "--check-docs":
        version, errors = read_documented_version(root)
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        print(f"Release documentation version is consistent: {version}")
        return 0
    if len(argv) != 2:
        print(f"Usage: {Path(argv[0]).name} vMAJOR.MINOR.PATCH[-prerelease] | --check-docs", file=sys.stderr)
        return 2
    errors = validate_tag(argv[1], root)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Release tag {argv[1]} matches README.md, README.fa.md and CHANGELOG.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
