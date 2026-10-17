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

    def test_release_workflow_uses_the_verified_bundle_builder(self) -> None:
        build_step = 'bash scripts/build-release-bundles.sh "$GITHUB_REF_NAME" dist'
        self.assertIn(build_step, self.workflow)
        self.assertLess(self.workflow.index(build_step), self.workflow.index("Publish release"))

    def test_ci_smoke_tests_the_same_release_bundle_builder(self) -> None:
        self.assertIn(
            'bash scripts/build-release-bundles.sh ci-smoke "$RUNNER_TEMP/pqtunnel-release-dist"',
            self.ci_workflow,
        )


if __name__ == "__main__":
    unittest.main()
