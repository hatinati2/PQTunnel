#!/usr/bin/env python3
"""Unit tests for the release tag/version guard."""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("check-release-version.py")
SPEC = importlib.util.spec_from_file_location("check_release_version", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


def write_docs(root: Path, version: str, *, fa_version: str | None = None) -> None:
    (root / "README.md").write_text(
        f"**Version:** {version} · experimental\n", encoding="utf-8"
    )
    (root / "README.fa.md").write_text(
        f"**نسخه: {fa_version or version} · آزمایشی**\n", encoding="utf-8"
    )
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## {version}\n\n- test notes\n", encoding="utf-8"
    )


class ReleaseVersionGuardTests(unittest.TestCase):
    def test_matching_release_candidate_tag_is_accepted(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_docs(root, "0.3.0-rc2")
            self.assertEqual(CHECKER.validate_tag("v0.3.0-rc2", root), [])

    def test_mismatched_tag_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_docs(root, "0.3.0-rc2")
            errors = CHECKER.validate_tag("v0.3.0-rc1", root)
            self.assertTrue(any("does not match documented version" in item for item in errors))

    def test_invalid_tag_syntax_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_docs(root, "0.3.0-rc2")
            self.assertTrue(CHECKER.validate_tag("release-candidate", root))

    def test_mismatched_readme_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_docs(root, "0.3.0-rc2", fa_version="0.3.0-rc1")
            errors = CHECKER.validate_tag("v0.3.0-rc2", root)
            self.assertTrue(any("Persian README version" in item for item in errors))

    def test_documented_version_consistency_check(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_docs(root, "1.2.3")
            version, errors = CHECKER.read_documented_version(root)
            self.assertEqual(version, "1.2.3")
            self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
