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
        cls.node_panel_installer = (ROOT / "scripts/install-node-panel.sh").read_text(encoding="utf-8")
        cls.pki_installer = (ROOT / "scripts/prepare-site-to-site-pki.sh").read_text(encoding="utf-8")
        cls.setup = (ROOT / "scripts/pqtunnel-site-to-site-setup.sh").read_text(encoding="utf-8")
        cls.remote_setup = (ROOT / "scripts/pqtunnel-site-to-site-remote.sh").read_text(encoding="utf-8")

    def test_installer_tracks_current_rc6_release(self) -> None:
        self.assertIn('VERSION="v0.3.0-rc6"', self.script)
        self.assertNotIn('VERSION="v0.3.0-rc5"', self.script)
        self.assertIn('"$RELEASE_BASE/SHA256SUMS"', self.script)
        self.assertIn('sha256sum --check -', self.script)

    def test_independent_panel_mode_installs_one_role_and_leaves_endpoint_stopped(self) -> None:
        self.assertIn("--panel gateway", self.script)
        self.assertIn("--panel dialer", self.script)
        self.assertIn("--public-http-host", self.script)
        self.assertIn('scripts/install-node-panel.sh', self.script)
        self.assertIn("systemctl enable --now pqtunnel-manager", self.node_panel_installer)
        self.assertIn('Endpoint unit: %s (not enabled or started)', self.node_panel_installer)
        self.assertIn("No routes, firewall rules, TUN interfaces, or forwarding settings were changed.", self.node_panel_installer)
        self.assertIn("gateway-preflight", (ROOT / "scripts/site-to-site-selective.sh").read_text(encoding="utf-8"))

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

    def test_pair_installer_defers_network_dependencies_until_after_manager_security(self) -> None:
        pair = (ROOT / "scripts/pqtunnel-oneclick-pair.sh").read_text(encoding="utf-8")
        secure = pair.index("install_or_check_manager dialer")
        network_need = pair.index("for cmd in curl tar sha256sum ssh scp ip nft sysctl pgrep ss sort timeout python3; do need")
        self.assertLess(secure, network_need)
        self.assertNotIn("need python3; need ssh; need scp", self.script)

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
        self.assertIn('ALLOW="$(allowlist "$TCP" "$UDP")"', self.setup)
        self.assertNotIn('TCP="$(add_port "$TCP" 9109)"', self.setup)
        self.assertIn("PQTUNNEL_UDP_EGRESS_PORTS=$UDP", self.setup)
        self.assertIn("PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091", self.setup)
        self.assertIn("PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091", self.remote_setup)
        self.assertIn("USER@IRAN_PUBLIC_IP", self.setup)
        self.assertIn("Replace USER@IRAN_PUBLIC_IP", self.setup)

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


    def test_helper_scripts_follow_the_immutable_release_bundle(self) -> None:
        self.assertIn('SOURCE_RAW_BASE="$RAW_BASE"', self.script)
        self.assertIn('RAW="https://raw.githubusercontent.com/$REPO/$VERSION"', self.setup)
        self.assertNotIn('SOURCE_RAW_BASE="https://raw.githubusercontent.com/${REPO}/main"', self.script)
        self.assertNotIn('RAW="https://raw.githubusercontent.com/$REPO/main"', self.setup)
    def test_manager_upgrade_installs_wizard_and_preserves_loopback_tokens(self) -> None:
        self.assertIn("--manager-upgrade", self.script)
        self.assertIn("--upgrade", self.manager_installer)
        self.assertIn("Protected backup:", self.manager_installer)
        self.assertIn("PQTUNNEL_SETUP_VERSION=", self.manager_installer)
        self.assertIn("PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091", self.manager_installer)
        self.assertIn("PQTUNNEL_SETUP_PRESERVE_DIALER_MANAGER_TOKEN=1", (ROOT / "scripts/pqtunnel-setup-worker.sh").read_text(encoding="utf-8"))

    def test_graphical_setup_has_separate_preflight_and_approval_gates(self) -> None:
        setup_ui = (ROOT / "internal/adminui/setup_ui.go").read_text(encoding="utf-8")
        setup_manager = (ROOT / "internal/manager/setup.go").read_text(encoding="utf-8")
        self.assertIn('Confirm: "CHECK"', setup_ui)
        self.assertIn("awaiting-confirmation", self.setup)
        self.assertIn("ApproveSiteToSiteSetup", setup_manager)
        self.assertIn('[]byte("INSTALL\\n")', setup_manager)
        self.assertIn("requireLoopbackSetupAccess", setup_ui)
        self.assertIn("if h.allowedPublicHost !=", setup_ui)

    def test_graphical_wizard_worker_is_fixed_and_token_logs_are_redacted(self) -> None:
        worker = (ROOT / "scripts/pqtunnel-setup-worker.sh").read_text(encoding="utf-8")
        unit = (ROOT / "deploy/systemd/pqtunnel-setup.service").read_text(encoding="utf-8")
        self.assertIn("ExecStart=/usr/local/lib/pqtunnel/pqtunnel-setup-worker.sh", unit)
        self.assertIn('bash "$SCRIPT"', worker)
        self.assertIn("PQTUNNEL_SETUP_INPUT_B64", worker)
        self.assertIn("sanitize_log", worker)
        self.assertIn('rm -f "$RAW_LOG"', worker)
        self.assertNotIn("bash -c", worker)

    def test_existing_gateway_manager_is_restricted_before_endpoint_install(self) -> None:
        install_branch = self.remote_setup.index("  install)")
        manager_config = self.remote_setup.index("    configure_manager", install_branch)
        endpoint_install = self.remote_setup.index('bash "$BUNDLE/scripts/install-server.sh"', install_branch)
        self.assertLess(manager_config, endpoint_install)
        self.assertIn("systemctl restart pqtunnel-manager", self.remote_setup)
        self.assertIn('"$REMOTE:$STAGE/gateway-manager-token"', self.setup)
        self.assertIn('"$REMOTE:$STAGE/speedtest-token"', self.setup)

    def test_full_setup_hardens_existing_public_manager_before_network_checks(self) -> None:
        secure = self.setup.rindex("secure_existing_local_manager")
        network_dependencies = self.setup.index("for c in curl sha256sum tar ssh scp python3 getent")
        self.assertLess(secure, network_dependencies)
        self.assertIn('PQTUNNEL_MANAGER_LISTEN=127.0.0.1:9091', self.setup)
        self.assertIn("PQTUNNEL_MANAGER_TOKEN=%s", self.setup)
        self.assertIn("warning: setup stopped part-way", self.setup.lower())


if __name__ == "__main__":
    unittest.main()
