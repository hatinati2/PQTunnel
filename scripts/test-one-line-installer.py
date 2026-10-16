#!/usr/bin/env python3
"""Regression checks for the one-line installer version and manager-token handoff."""
from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


class OneLineInstallerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.script = INSTALLER.read_text(encoding="utf-8")
        cls.readme_en = (ROOT / "README.md").read_text(encoding="utf-8")
        cls.readme_fa = (ROOT / "README.fa.md").read_text(encoding="utf-8")

    def test_installer_tracks_current_rc4_release(self) -> None:
        self.assertIn('VERSION="v0.3.0-rc4"', self.script)
        self.assertNotIn("v0.3.0-rc3", self.script)
        self.assertIn('"$RELEASE_BASE/SHA256SUMS"', self.script)
        self.assertIn('sha256sum --check -', self.script)

    def test_new_token_is_saved_root_only_and_shown_once(self) -> None:
        self.assertIn("TOKEN_GENERATED=0", self.script)
        self.assertIn("TOKEN_GENERATED=1", self.script)
        self.assertIn('chmod 0600 "$CONFIG"', self.script)
        self.assertIn("PQTUNNEL_MANAGER_TOKEN=%s", self.script)
        self.assertIn("it is shown only once", self.script)
        self.assertNotIn("The token was not printed", self.script)

    def test_existing_token_is_not_regenerated_or_printed(self) -> None:
        self.assertIn("if ! grep -q '^PQTUNNEL_MANAGER_TOKEN=.' \"$CONFIG\"; then", self.script)
        self.assertIn('if (( TOKEN_GENERATED )); then', self.script)
        self.assertIn('unset TOKEN', self.script)

    def test_manager_install_does_not_claim_to_configure_the_tunnel(self) -> None:
        self.assertIn("does NOT install/configure/start the tunnel endpoint", self.script)
        self.assertIn("does not change routes, firewall, NAT, or forwarding", self.script)
        self.assertIn("this command installs the **web manager only**" if False else "web manager only", self.readme_en)
        self.assertIn("فقط پنل مدیریت وب", self.readme_fa)

    def test_manager_starts_only_after_unit_validation(self) -> None:
        validate = self.script.index("systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service")
        start = self.script.index("systemctl enable --now pqtunnel-manager")
        self.assertLess(validate, start)
        self.assertIn("Default access", self.script) if "Default access" in self.script else self.assertIn("127.0.0.1:9091", self.script)


if __name__ == "__main__":
    unittest.main()
