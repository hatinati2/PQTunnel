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
        cls.setup = (ROOT / "scripts/pqtunnel-site-to-site-setup.sh").read_text(encoding="utf-8")
        cls.remote_setup = (ROOT / "scripts/pqtunnel-site-to-site-remote.sh").read_text(encoding="utf-8")

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
        self.assertIn("web manager only", self.readme_en)
        self.assertIn("فقط پنل مدیریت وب", self.readme_fa)

    def test_manager_starts_only_after_unit_validation(self) -> None:
        validate = self.script.index("systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service")
        start = self.script.index("systemctl enable --now pqtunnel-manager")
        self.assertLess(validate, start)
        self.assertIn("127.0.0.1:9091", self.script)

    def test_full_two_vps_setup_is_reachable_from_one_line_entrypoint(self) -> None:
        self.assertIn("--site-to-site", self.script)
        self.assertIn('MODE=site-to-site', self.script)
        self.assertIn('scripts/pqtunnel-site-to-site-setup.sh', self.script)
        self.assertIn('PQTUNNEL_SETUP_VERSION="$VERSION"', self.script)
        self.assertIn('curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --site-to-site', self.script)

    def test_guided_setup_requires_explicit_confirmation_and_is_selective(self) -> None:
        self.assertIn("Type exactly INSTALL to continue", self.setup)
        self.assertIn("selected destination ports only, not all device traffic", self.setup)
        self.assertIn("PQTUNNEL_TCP_EGRESS_PORTS=$TCP", self.setup)
        self.assertIn("PQTUNNEL_UDP_EGRESS_PORTS=$UDP", self.setup)
        self.assertIn("PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091", self.setup)
        self.assertIn("PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091", self.remote_setup)

    def test_existing_public_dialer_manager_is_restricted_before_long_setup(self) -> None:
        rotate = self.setup.index("Existing Dialer manager is now restricted to loopback")
        package_install = self.setup.index("apt-get update")
        self.assertLess(rotate, package_install)
        self.assertIn("PQTUNNEL_MANAGER_ALLOW_INSECURE_PUBLIC_HTTP", self.setup)
        self.assertIn("systemctl restart pqtunnel-manager", self.setup)

    def test_full_setup_fails_closed_and_does_not_send_ca_private_key(self) -> None:
        for fragment in ("active UFW", "already has nftables rules", "already has iptables rules",
                         "route table 518/519 in use", "already has pqtun0"):
            self.assertIn(fragment, self.setup)
        self.assertIn("CA private key must stay offline", self.remote_setup)
        self.assertIn("PQTUNNEL_MANAGER_ROLE=gateway", self.remote_setup)
        self.assertIn("PQTUNNEL_MANAGER_ROLE=dialer", self.setup)
        self.assertIn("chmod 0600", self.remote_setup)


    def test_existing_gateway_manager_is_restricted_before_endpoint_install(self) -> None:
        install_branch = self.remote_setup.index("  install)")
        manager_config = self.remote_setup.index("    configure_manager", install_branch)
        endpoint_install = self.remote_setup.index('bash "$BUNDLE/scripts/install-server.sh"', install_branch)
        self.assertLess(manager_config, endpoint_install)
        self.assertIn("systemctl restart pqtunnel-manager", self.remote_setup)



if __name__ == "__main__":
    unittest.main()
