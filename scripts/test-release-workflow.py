#!/usr/bin/env python3
"""Regression checks for release packaging, integration, and supported targets."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "release.yml"


class ReleaseProxyWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

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

    def test_proxy_binary_is_packaged_for_each_release_target(self) -> None:
        self.assertIn(
            "for cmd in pqtunneld pqtunnel-client pqtunnel-pki pqtunnel-proxy; do",
            self.workflow,
        )

    def test_release_assets_are_limited_to_supported_linux_targets(self) -> None:
        self.assertIn("for target in 'linux amd64' 'linux arm64'; do", self.workflow)
        self.assertNotIn("'windows amd64'", self.workflow)
        self.assertNotIn("windows amd64.tar.gz", self.workflow)


if __name__ == "__main__":
    unittest.main()
