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
        cls.manager_installer = (ROOT / "scripts/install-manager.sh").read_text(encoding="utf-8")
        cls.pki_installer = (ROOT / "scripts/prepare-site-to-site-pki.sh").read_text(encoding="utf-8")

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
        self.assertIn("--manager installs only the local web manager", self.script)
        self.assertIn("Provider firewalls/security groups are not modified", self.script)
        self.assertIn("web manager only", self.readme_en)
        self.assertIn("فقط پنل مدیریت وب", self.readme_fa)

    def test_manager_starts_only_after_unit_validation(self) -> None:
        validate = self.script.index("systemd-analyze verify /etc/systemd/system/pqtunnel-manager.service")
        start = self.script.index("systemctl enable --now pqtunnel-manager")
        self.assertLess(validate, start)
        self.assertIn("127.0.0.1:9091", self.manager_installer)

    def test_pair_mode_downloads_verified_bundle_and_invokes_orchestrator(self) -> None:
        self.assertIn("--pair", self.script)
        self.assertIn("SOURCE_RAW_BASE/scripts/pqtunnel-oneclick-pair.sh", self.script)
        verify = self.script.index('sha256sum --check -)')
        extract = self.script.index('tar -xzf "$TMP_DIR/$ASSET" -C "$TMP_DIR"')
        self.assertLess(verify, extract)
        self.assertIn('bash "$SOURCE_DIR/scripts/pqtunnel-oneclick-pair.sh"', self.script)

    def test_pair_installer_keeps_panels_private_and_requires_network_confirmation(self) -> None:
        pair = (ROOT / "scripts/pqtunnel-oneclick-pair.sh").read_text(encoding="utf-8")
        self.assertIn('PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091', pair)
        self.assertIn('type APPLY-NETWORK', pair)
        confirm = pair.index('[[ "$APPLY_CONFIRM" != APPLY-NETWORK ]]')
        gateway_apply = pair.index('gateway-up')
        dialer_start = pair.index('systemctl enable --now pqtunnel-client')
        self.assertLess(confirm, gateway_apply)
        self.assertLess(confirm, dialer_start)
        self.assertIn('speed_listen=10.66.0.2:9109', pair)
        self.assertIn('PQTUNNEL_MANAGER_SPEEDTEST_LISTEN=10.66.0.1:9109', pair)
        self.assertIn('PQTUNNEL_MANAGER_SPEEDTEST_TOKEN', pair)
        self.assertIn('127.0.0.1:9091', pair)

    def test_pki_helper_accepts_trusted_release_binary_without_go(self) -> None:
        self.assertIn('PQTUNNEL_PKI_BIN', self.pki_installer)
        self.assertIn('run this script from the PQTunnel repository root, or set PQTUNNEL_PKI_BIN', self.pki_installer)

    def test_pair_installer_secures_existing_local_manager_before_ssh(self) -> None:
        pair = (ROOT / "scripts/pqtunnel-oneclick-pair.sh").read_text(encoding="utf-8")
        prepare_confirm = pair.index('[[ "$CONFIRM" == PREPARE ]]')
        secure = pair.index("install_or_check_manager dialer", prepare_confirm)
        ssh_auth = pair.index("if ! REMOTE_UID=$(ssh")
        self.assertLess(prepare_confirm, secure)
        self.assertLess(secure, ssh_auth)
        self.assertIn("PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091", pair)

    def test_pair_installer_transfers_gateway_credentials_only(self) -> None:
        pair = (ROOT / "scripts/pqtunnel-oneclick-pair.sh").read_text(encoding="utf-8")
        scp_start = pair.index('scp -P "$SSH_PORT"')
        scp_end = pair.index('"$REMOTE_TARGET:$REMOTE_STAGE/"', scp_start)
        payload = pair[scp_start:scp_end]
        self.assertIn('"$WORK_DIR/pki-bundle/gateway-pki"', payload)
        self.assertNotIn('"$WORK_DIR/pki-bundle/dialer-pki"', payload)
        self.assertNotIn('ca-offline', payload)

    def test_pair_docs_call_out_selected_port_scope_and_provider_firewall(self) -> None:
        self.assertIn('--pair', self.readme_en)
        self.assertIn('full-tunnel/default-route VPN', self.readme_en)
        self.assertIn('--pair', self.readme_fa)
        self.assertIn('فایروال ابری را تغییر نمی‌دهد', self.readme_fa)



if __name__ == "__main__":
    unittest.main()
