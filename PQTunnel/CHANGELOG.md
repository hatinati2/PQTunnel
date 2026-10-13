# Changelog

## 0.2.0-dev

- Changed the Go module path to the public GitHub repository path.
- Bounded concurrent TLS handshakes as well as authenticated tunnel sessions.
- Added Ubuntu systemd packaging and a server installer that does not change NAT/firewall rules unless the separate network script is explicitly invoked.
- Added isolated server IPv4 forwarding/NAT apply/status/rollback helper.
- Added a Linux client routing helper for endpoint-route pinning, IPv4 full-tunnel routing, systemd-resolved DNS routing, and IPv6 default-route blackholing, with an explicit `down` path.
- Added Go test/static analysis/cross-build workflows and release packaging workflows.
- Updated documentation to describe known limitations and the lack of a security audit.

This is still a development build, not a production VPN release. Windows routing, a persistent cross-platform kill-switch, and verified Android build/provisioning remain incomplete.
