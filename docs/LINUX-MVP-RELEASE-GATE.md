# Linux MVP Release Gate

**Purpose:** Define the minimum evidence required before calling the Linux server-to-server MVP ready for a public beta. This checklist is a plan, not proof that the items have passed. PQTunnel remains experimental until the evidence is recorded.

## 1. Supported scope

### In scope for the Linux MVP

- Linux Gateway/Listener and Dialer on Ubuntu 24.04 and 26.04, on amd64 and arm64 where the required packages are available.
- TLS 1.3 mutual authentication with the configured hybrid key-exchange group, certificate and peer identity validation, and explicit fail-closed behavior.
- IPv4/IPv6 packet transport and narrowly configured peer-prefix allowlists.
- The standalone manager for first-time setup, validated configuration, service lifecycle controls, bounded/redacted logs, and recovery-aware upgrades.
- Explicit, reviewed network changes only. Provider firewalls are not changed by the installer. A successful install or manager health check does not prove that routed traffic works.

### Out of scope and unsupported

- **Windows:** unsupported until Wintun provisioning and address, route, DNS, firewall/kill-switch, crash cleanup, and reboot lifecycle are implemented and tested.
- **Android:** unsupported until certificate onboarding, lifecycle/error handling, build verification, and physical-device tests are complete.
- A persistent, audited client kill-switch; automatic production firewall/NAT management; multiple peer-route profiles per listener; and production readiness claims without a security review.

Cross-compilation, a scaffold, or a green CI run must not be described as platform support.

## 2. Release gates

### Gate A — source and CI integrity

- [ ] Confirm the exact candidate commit and verify that CI, security scanning, shell checks, and package tests completed successfully on that commit.
- [ ] Run `go test -race ./...` and `go vet ./...` with the supported Go toolchain.
- [ ] Confirm Linux amd64 and arm64 builds from a clean checkout and from the candidate release bundle.
- [ ] Run dependency and vulnerability checks; review every actionable result rather than treating a successful scanner exit as a security audit.
- [ ] Verify that all tests use the repository root as their source of truth. The nested legacy `PQTunnel/` tree must not be packaged or deployed.

### Gate B — disposable Linux network lab

- [ ] Pass `scripts/test-site-to-site-netns.sh` and `scripts/test-selective-forward-netns.sh` on Ubuntu 24.04 and 26.04.
- [ ] Pass `scripts/test-selective-egress-netns.sh` and `scripts/test-site-to-site-selective-fail-closed.sh` on both Ubuntu versions.
- [ ] Test reconnects, peer disconnect/re-registration, wrong identity, source-prefix spoofing, overlapping prefixes, duplicate/invalid port rules, and unlisted TCP/UDP ports.
- [ ] Inject failures at each network-apply stage and verify rollback only touches resources created by PQTunnel.
- [ ] Save redacted logs and the exact commit/toolchain/OS matrix with the release evidence.

Namespace tests exercise Linux networking in an isolated runner. They do not replace tests between separate hosts or validate provider firewalls and existing host firewall policy.

### Gate C — TLS, identity, and PKI

- [ ] Verify with a real handshake or instrumented test that the intended `X25519MLKEM768` group is negotiated.
- [ ] Verify incompatible peers fail rather than silently falling back to a classical key exchange.
- [ ] Test wrong CA, wrong server name, wrong peer identity, expired certificates, wrong EKU, missing certificates, and mismatched private key/certificate pairs.
- [ ] Verify key and configuration file ownership/permissions, including setup bundles and manager backups.
- [ ] Keep the CA signing private key off both VPSes and verify no private key, token, or unredacted configuration appears in logs or release archives.

### Gate D — manager and installer safety

- [ ] Test first-time installation and same-role upgrade from a clean Ubuntu host; record every file, unit, user, directory, and network resource created.
- [ ] Verify an upgrade preserves the existing role and manager token, creates protected backups, and does not overwrite unrelated endpoint/configuration artifacts.
- [ ] Test invalid configuration, invalid upload/profile archives, repeated setup, partial failure, and rollback paths.
- [ ] Verify authentication, session expiry, CSRF/Origin checks, rate limiting, request limits, output redaction, and role-scoped controls.
- [ ] Confirm the manager binds to loopback by default, public plaintext HTTP is not enabled by default, and remote access documentation uses an encrypted management channel.
- [ ] Confirm installer defaults do not silently alter provider firewall rules, unrelated routes, existing firewall rules, DNS, or forwarding sysctls.

### Gate E — two independent Linux hosts

- [ ] Run controlled end-to-end tests between two distinct Linux hosts, with console/out-of-band recovery available on both.
- [ ] Complete the four Ubuntu pairings: 24.04↔24.04, 24.04↔26.04, 26.04↔24.04, and 26.04↔26.04.
- [ ] Test both listener/dialer directions where supported, and test transport endpoints by DNS name, IPv4, and IPv6.
- [ ] Verify intended IPv4/IPv6 prefixes, return routes, allowed and denied ports, DNS behavior, reconnect after process/service restart, and long-running transfer.
- [ ] Test alongside representative pre-existing firewall state, including documented handling of nftables, iptables, UFW, packet marks, and NOTRACK rules.
- [ ] Inject a controlled failure and rehearse console-based restoration. Do not use a live production host as the first integration test.
- [ ] Record test topology, software commit, exact commands, expected/actual results, redacted logs, and a signed go/no-go decision.

### Gate F — release bundle and documentation

- [ ] Build bundles from the exact candidate commit on a clean runner for Linux amd64 and arm64.
- [ ] Install and smoke-test from each built bundle, not only from a source checkout.
- [ ] Verify `SHA256SUMS` against every published archive and inspect the archive contents for private identifiers, secrets, and stale nested-project files.
- [ ] Ensure installation/upgrade/recovery documentation matches the actual scripts and tested behavior.
- [ ] Ensure English and Persian documentation label Windows and Android as unsupported until their gates pass.
- [ ] Keep the release marked experimental/beta until the full evidence above has been reviewed.

## 3. Decision rules

- A failed, skipped, unknown, or unrecorded critical gate is **not passed**.
- A CI pass does not prove two-host networking works.
- A successful installer does not prove the tunnel, route policy, provider firewall, or application traffic works.
- Do not call the project production-ready or fully post-quantum. Certificate signatures currently use classical Ed25519, and an independent security review has not been completed.
- Do not use sensitive production traffic for acceptance testing. Use lab hosts and test-only credentials first.

## 4. Evidence record

Fill this in for each candidate rather than relying on memory.

| Field | Evidence |
| --- | --- |
| Candidate commit | Not recorded |
| Go version | Not recorded |
| Ubuntu test matrix | Not recorded |
| CI / security run URLs | Not recorded |
| Network-lab results | Not recorded |
| Two-host test record | Not recorded |
| Bundle hashes | Not recorded |
| Reviewer / go-no-go | Not recorded |
