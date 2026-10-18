#!/usr/bin/env python3
"""Regression checks for release packaging, integration, and supported targets."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
BUNDLE_BUILDER = ROOT / "scripts" / "build-release-bundles.sh"


class ReleaseProxyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")
        cls.ci_workflow = CI_WORKFLOW.read_text(encoding="utf-8")
        cls.bundle_builder = BUNDLE_BUILDER.read_text(encoding="utf-8")

    def test_proxy_is_built_for_release_integration(self) -> None:
        self.assertIn(
            'go build -o "$RUNNER_TEMP/pqtunnel-bin/pqtunnel-proxy" ./cmd/pqtunnel-proxy',
            self.workflow,
        )

    def test_release_gate_runs_isolated_proxy_netns_lab(self) -> None:
        self.assertIn(
            'sudo env PQTUNNEL_PROXY_BIN="$RUNNER_TEMP/pqtunnel-bin/pqtunnel-proxy" '
            'bash scripts/test-proxy-netns.sh',
            self.workflow,
        )

    def test_proxy_binary_is_packaged_for_each_supported_release_architecture(self) -> None:
        self.assertIn(
            "for cmd in pqtunneld pqtunnel-client pqtunnel-pki pqtunnel-proxy; do",
            self.bundle_builder,
        )
        self.assertIn("pqtunnel-manager", self.bundle_builder)

    def test_release_assets_are_limited_to_supported_linux_targets(self) -> None:
        self.assertIn("for goarch in amd64 arm64; do", self.bundle_builder)
        self.assertNotIn("GOOS=windows", self.bundle_builder)
        self.assertIn('[[ ! -e "$DIST_DIR/PQTunnel-${VERSION}-windows-amd64.tar.gz" ]]',
                      self.bundle_builder)

    def test_release_publish_requires_manual_dispatch_and_separates_prerelease_from_final_gates(self) -> None:
        self.assertIn("workflow_dispatch:", self.workflow)
        self.assertIn("release_tag:", self.workflow)
        self.assertIn("linux_mvp_gates_passed:", self.workflow)
        self.assertIn("experimental_prerelease:", self.workflow)
        self.assertNotIn("    tags: ['v*']", self.workflow)
        release_start = self.workflow.index("  release:")
        release_job = self.workflow[release_start:]
        release_condition = "if: github.ref == 'refs/heads/main' && (inputs.linux_mvp_gates_passed == true || (inputs.experimental_prerelease == true && contains(inputs.release_tag, '-')))"
        self.assertIn(release_condition, release_job)
        self.assertIn("needs: integration-test", release_job)
        self.assertIn("ref: ${{ github.sha }}", self.workflow)
        self.assertNotIn("ref: ${{ inputs.release_tag }}", self.workflow)
        self.assertIn('if [[ "$existing_sha" != "$TARGET_SHA" ]]; then', self.workflow)
        self.assertIn("tag_name: ${{ inputs.release_tag }}", release_job)
        self.assertIn("target_commitish: ${{ github.sha }}", release_job)
        self.assertIn("name: ${{ contains(inputs.release_tag, '-') && format('PQTunnel {0} — Experimental VPS Test', inputs.release_tag) || format('PQTunnel {0}', inputs.release_tag) }}", release_job)
        self.assertIn("contents: write", release_job)
        self.assertIn("prerelease: ${{ contains(inputs.release_tag, '-') }}", release_job)
        self.assertLess(
            release_job.index(release_condition),
            release_job.index("- name: Publish release"),
        )

    def test_rc9_release_version_is_consistent_across_installer_and_docs(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        readme_fa = (ROOT / "README.fa.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        setup_script = (ROOT / "scripts" / "pqtunnel-site-to-site-setup.sh").read_text(encoding="utf-8")
        self.assertIn("**Version:** 0.3.0-rc9", readme)
        self.assertIn("**نسخه: 0.3.0-rc9", readme_fa)
        self.assertEqual(changelog.splitlines()[:3], ["# Changelog", "", "## 0.3.0-rc9"])
        self.assertIn('VERSION="v0.3.0-rc9"', installer)
        self.assertIn('VERSION="${PQTUNNEL_SETUP_VERSION:-v0.3.0-rc9}"', setup_script)

    def test_release_workflow_uses_the_verified_bundle_builder(self) -> None:
        build_step = 'bash scripts/build-release-bundles.sh "$RELEASE_TAG" dist'
        self.assertIn(build_step, self.workflow)
        self.assertLess(self.workflow.index(build_step), self.workflow.index("Publish release"))

    def test_ci_smoke_tests_the_same_release_bundle_builder(self) -> None:
        self.assertIn(
            'bash scripts/build-release-bundles.sh ci-smoke "$RUNNER_TEMP/pqtunnel-release-dist"',
            self.ci_workflow,
        )


if __name__ == "__main__":
    unittest.main()
