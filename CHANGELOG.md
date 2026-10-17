# Changelog

## 0.3.0-rc6

- Added an independent per-VPS installer mode: `--node gateway|dialer --public-ip IPv4` installs and starts only the local management panel, while installing role-specific endpoint assets without enabling or starting the tunnel.
- Added a per-node setup page that generates Gateway PKI locally and exchanges only public CA/profile bundles between separately administered panels; private endpoint keys are generated and retained on their own VPS.
- Added transport-only Gateway/Dialer systemd units that provision only the PQTunnel-owned TUN interface and peer IPs; they do not modify existing firewall rules, NAT, forwarding, policy routing, or default routes.
- Preserved the existing manager token and role during a same-role upgrade, and added guardrails to refuse overwriting an existing tunnel endpoint or an overlapping route/TUN interface.
- Added independent-node request validation and installer regression tests. This release candidate remains experimental; public HTTP is plaintext and the profile transfer workflow requires a trusted management network.

## 0.3.0-rc5

- Added an authenticated, Persian/English graphical two-VPS setup wizard to the standalone Dialer manager, with constrained inputs and a separate final approval gate after both hosts pass preflight.
- Added a fixed systemd setup worker, protected state/log handling, one-time token handoff, output redaction, and release-pinned helper scripts; management panels remain loopback-only and the wizard is disabled on public manager listener configurations.
- Added safe manager upgrade support with protected backups, role/config preservation, and hardening/token rotation when upgrading an existing public or insecure HTTP listener.
- Added regression tests for wizard input validation, public-listener denial, CSRF-protected install approval, one-time token handoff, and shell installer invariants.
- This release candidate remains experimental and has not undergone an independent security audit or validated a production two-VPS deployment.

## 0.3.0-rc4

- Added an experimental user-space Direct/Reverse TCP proxy (`pqtunnel-proxy`) with bounded flow control and regression coverage for rejecting WINDOW_UPDATE credits for DATA that has not been sent.
- Added isolated network-namespace proxy integration tests and made them release gates on Ubuntu 24.04 and 26.04.
- Included `pqtunnel-proxy` in Linux amd64/arm64 and Windows amd64 release bundles; Linux bundles also include `pqtunnel-manager`.
- This remains an experimental release candidate, not production-ready. The proxy and tunnel have not undergone an independent security audit or real two-physical-VPS end-to-end validation.

## 0.3.0-rc3

- Added the standalone Linux server manager with role-scoped systemd lifecycle controls, a validated editor for selected non-secret tunnel settings, protected configuration backups and attempted rollback after failed restarts.
- Added authenticated, bounded recent-journal viewing with secret redaction and a peer-to-peer tunnel-path speed test reporting median RTT plus upload/download throughput. Speed-test targets are constrained to private tunnel peer addresses and transfers are bounded.
- Included the manager binary in Linux amd64/arm64 release bundles and documented opt-in installation; the manager is not automatically enabled or started.
- Enforced listener-side local source-prefix checks to reject spoofed packet sources and added regression coverage for dialer reconnect and peer disconnect/re-registration behavior.
- Corrected the manager installer's Go-version guard to match the module's Go 1.26 requirement.
- This remains an experimental release candidate, not production-ready. No independent security audit or real two-physical-VPS end-to-end validation has been completed.

## 0.3.0-rc2



- Added an optional Persian-language web admin panel inside `pqtunneld`, disabled by default and restricted to literal loopback addresses.
- Added token authentication requiring at least 32 bytes, expiring in-memory sessions, HttpOnly/SameSite cookies, Origin and CSRF checks, security headers, bounded request bodies, and login rate limiting.
- Restricted the panel to operational status and authenticated peer disconnection; it does not control systemd, routes, firewall rules, NAT, sysctls, certificates, or keys.
- Added regression tests for rate limiting, DNS-rebinding Host checks, session expiry, security headers, CSRF failures, and oversized forms.
- Updated English/Persian setup documentation and clarified that the installer preserves an existing `/etc/default/pqtunneld` file rather than modifying it.
- Hardened the read-only firewall coexistence audit: parse real iptables options/targets, ignore action-like and selector-like text inside comments, and conservatively classify unrecognized options as `other`; added regression coverage and clarified the report limits.
- This remains an experimental release candidate. It has not undergone an independent security audit; Android provisioning and Windows route/DNS/kill-switch management remain incomplete.

## 0.3.0-dev

- Added normal IPv6 packet framing/parsing alongside IPv4 (IPv6 jumbograms remain unsupported).
- Added experimental single-peer server-to-server route profiles with separate peer-source/return-route and listener-destination CIDR allowlists, plus explicit peer certificate identity pinning.
- Added DNS/IPv4/IPv6 endpoint selection for the dialer (`tcp`, `tcp4`, `tcp6`).
- Added PKI commands for additional server certificates and named peer client certificates.

- Changed the Go module path to the public GitHub repository path.
- Bounded concurrent TLS handshakes as well as authenticated tunnel sessions.
- Added Ubuntu systemd packaging and a server installer that does not change NAT/firewall rules unless the separate network script is explicitly invoked.
- Added isolated server IPv4 forwarding/NAT apply/status/rollback helper.
- Added a Linux client routing helper for endpoint-route pinning, IPv4 full-tunnel routing, systemd-resolved DNS routing, and IPv6 default-route blackholing, with an explicit `down` path.
- Added Go test/static analysis/cross-build workflows and release packaging workflows.
- Updated documentation to describe known limitations and the lack of a security audit.

This is still a development build, not a production VPN release. Windows routing, a persistent cross-platform kill-switch, and verified Android build/provisioning remain incomplete.

## Unreleased — standalone server manager

- Added an optional standalone, loopback-only web manager that remains available when the tunnel daemon is stopped; it can start/stop/restart only the role's fixed systemd unit.
- Added a restricted editor for site-to-site endpoint, CIDR, peer identity and TCP/UDP destination-port settings, with validation, protected backups and attempted rollback if a restart fails. Default routes, credentials, PKI files and firewall/NAT changes remain outside the web editor.
- Added an authenticated, bounded recent-journal view for the fixed tunnel service.
- Added a private-TUN-IP speed-test agent and UI results for median RTT and upload/download throughput. Targets must belong to configured peer prefixes, speed tests need a separate shared token and allowed TCP port, and transfers are capped at 32 MiB per direction.
- The manager installer is opt-in and does not enable/start the manager or change live tunnel/network state. These features still require review and integration tests before any production VPS use.

## Unreleased — selective site-to-site prototype

- Hardened listener TUN-to-peer forwarding: packets must have a source inside configured local prefixes as well as a unique matching peer destination route; added IPv4/IPv6 regression coverage.
- Added optional TCP/UDP destination-port allowlists in the client and listener.
- Added Linux socket-mark support so the PQTunnel transport can be exempted from mark-based egress policy routing.
- Added an experimental selective site-to-site network helper and config example. It is guarded against existing firewall/forwarding state and must only be validated on an isolated lab host.
- Added IPv4/IPv6 port-policy parser tests; fragmented packets are rejected while a port allowlist is active.
- This does not complete true reverse-initiated operation or replace real two-host integration testing.
