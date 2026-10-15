# Changelog

## 0.3.0-rc2

- Added an optional Persian-language web admin panel inside `pqtunneld`, disabled by default and restricted to literal loopback addresses.
- Added token authentication requiring at least 32 bytes, expiring in-memory sessions, HttpOnly/SameSite cookies, Origin and CSRF checks, security headers, bounded request bodies, and login rate limiting.
- Restricted the panel to operational status and authenticated peer disconnection; it does not control systemd, routes, firewall rules, NAT, sysctls, certificates, or keys.
- Added regression tests for rate limiting, DNS-rebinding Host checks, session expiry, security headers, CSRF failures, and oversized forms.
- Updated English/Persian setup documentation and clarified that the installer preserves an existing `/etc/default/pqtunneld` file rather than modifying it.
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

## Unreleased — selective site-to-site prototype

- Added optional TCP/UDP destination-port allowlists in the client and listener.
- Added Linux socket-mark support so the PQTunnel transport can be exempted from mark-based egress policy routing.
- Added an experimental selective site-to-site network helper and config example. It is guarded against existing firewall/forwarding state and must only be validated on an isolated lab host.
- Added IPv4/IPv6 port-policy parser tests; fragmented packets are rejected while a port allowlist is active.
- This does not complete true reverse-initiated operation or replace real two-host integration testing.
