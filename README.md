# PQTunnel

**Version:** 0.3.0-rc3 · **Status:** experimental release candidate, not production-ready.

PQTunnel is an experimental layer-3 tunnel for normal IPv4 and IPv6 packets using TCP with TLS 1.3 and a strict `X25519MLKEM768` hybrid key exchange. It uses mutual TLS with a private CA, length-prefixed IP frames, a Linux TUN device, a Windows Wintun adapter, and an Android `VpnService` scaffold.

> **Security notice:** This repository has not undergone an independent security audit. Do not use it to protect sensitive activity or deploy it on a production server. The key exchange is post-quantum hybrid; certificate signatures are currently Ed25519 (classical), so the entire authentication system is not post-quantum. No cryptographic construction is unbreakable by definition.

## Repository layout notice

The active project source tree and CI source of truth are at the **repository root**. The nested `PQTunnel/` directory is a stale legacy copy retained pending a separate cleanup decision; it is not the active development or release source, and the root CI workflow does not test that nested copy. Do not build, package, or deploy from `PQTunnel/`.

## Current scope

- TLS 1.3 only, with `X25519MLKEM768` explicitly selected and no classical key-exchange fallback.
- Mutual TLS for client authentication.
- Legacy single-host mode maps an IP address in the client certificate Common Name to a host prefix.
- Experimental single-peer server-to-server mode with IPv4/IPv6 CIDR allowlists (`--peer-prefixes`, `--peer-name`, `--local-prefixes`, `--remote-prefixes`) and overlapping-prefix rejection.
- Length-prefixed IPv4/IPv6 packets, source-prefix anti-spoofing, bounded active/handshaking connections, bounded packet queue, and reconnect backoff.
- Client transport can connect using a DNS name, IPv4 or bracketed IPv6 endpoint; `--network tcp4` and `--network tcp6` force the underlay address family.
- Server systemd unit and separate, explicit Ubuntu IPv4 forwarding/NAT script.
- Linux client network helper for endpoint routing, IPv4 full-tunnel routing, systemd-resolved DNS routing, and blocking IPv6 default traffic while configured.
- Privacy-preserving, read-only inventory of existing nftables/iptables firewall state. Unknown iptables options are treated conservatively as additional selectors; output excludes raw rules and selector values. See [firewall coexistence notes](docs/EXISTING-FIREWALL-COEXISTENCE.md).
- Optional standalone Linux server-to-server web manager (`pqtunnel-manager`) with fixed-role Start/Stop/Restart controls, validated non-secret tunnel configuration editing, redacted service logs, peer disconnect and in-tunnel peer speed tests. It is disabled by default, loopback-only, and intended for SSH forwarding; see [the manager guide](docs/WEB-ADMIN-PANEL.md). The older in-process panel remains a separate, more limited feature.
- GitHub Actions tests/cross-builds, a loopback TLS integration test, and Linux network-namespace tests using real TUN interfaces, including inbound TCP/UDP port-forward round trips and selective-vs-direct egress checks over IPv4 and IPv6.
- Android `VpnService` scaffold and Linux/Windows TUN adapters.

## Local web admin panel (experimental)

The panel runs inside `pqtunneld` and is disabled unless explicitly configured in the daemon environment:

```ini
PQTUNNEL_ADMIN_LISTEN=127.0.0.1:9090
PQTUNNEL_ADMIN_TOKEN=REPLACE_WITH_RANDOM_SECRET_AT_LEAST_32_BYTES
```

Replace the example token with a strong random secret of at least 32 bytes. Do not commit the real token or place it in command-line arguments. The listener accepts only a literal loopback IP (for example, `127.0.0.1:9090` or `[::1]:9090`); wildcard and public addresses are rejected. The panel uses plain HTTP because it is loopback-only. Open it in the browser using a numeric loopback URL such as `http://127.0.0.1:9090/`, not `localhost` or a domain name; Origin validation rejects hostnames to reduce DNS-rebinding risk. For access from another machine, use an encrypted SSH tunnel and never expose the panel port directly to the internet.

When using the repository's systemd unit, put these variables in `/etc/default/pqtunneld`, which the unit reads as its `EnvironmentFile`. If `/etc/default/pqtunneld` does not exist, the installer writes both settings as commented examples when creating it. If the file already exists, the installer preserves it and does not append these lines; add them manually in that case. To enable the panel, uncomment `PQTUNNEL_ADMIN_LISTEN` and set a strong random value for `PQTUNNEL_ADMIN_TOKEN`. Generate a random token in a secure terminal with `openssl rand -hex 32`, then place the output in the environment file (do not commit it or copy it into logs). Keep the file root-only readable with `sudo chmod 0600 /etc/default/pqtunneld`. Restarting the service is required after editing and will disconnect active tunnel peers, so plan a maintenance window. For remote access, keep the admin listener on loopback and create an SSH tunnel from your workstation:

```sh
ssh -N -L 9090:127.0.0.1:9090 USER@SERVER
```

Then open `http://127.0.0.1:9090/` locally. Replace `USER@SERVER` with your SSH account and host. Full setup notes are in [the panel guide](docs/WEB-ADMIN-PANEL.md).

After login, it shows limited daemon and connected-peer status and allows disconnecting a selected peer. It does not start or stop systemd, or modify routes, sysctls, firewall, NAT, certificates, or keys. Sessions are in-memory and expire after 12 hours; state-changing requests have CSRF protection, and five failed logins from an IP trigger a 60-second lockout. This is an experimental admin surface, not a complete audit or user-management system.

## Important limitations

1. The server network script does not alter UFW or other existing firewall policies. Forwarding may still be blocked when UFW or another firewall is active; read the script and configure the host firewall deliberately.
2. The Linux client route helper is not a persistent, audited firewall kill-switch. Its IPv4 route remains directed at TUN while the helper state is active, and it blackholes an IPv6 default route while connected, but the route configuration does not automatically survive reboot. Custom processes that bind directly to a physical interface require a firewall policy as well.
3. Windows TUN uses Wintun, which must be provisioned from the official distribution; automatic Windows route/DNS/kill-switch management is not included in this release.
4. Android is a scaffold; the AAR must be built locally with `gomobile`, certificate import is not implemented in the UI, and the app has not been tested on physical devices.
5. The server and Linux-client scripts affect networking when explicitly run. Review them first and keep console/out-of-band access available. They have not been tested on your host.
6. The single TCP transport can suffer TCP-over-TCP head-of-line blocking.
7. There is no online certificate revocation service, secure device provisioning flow, or PQ signature/certificate chain yet.

## Quick install entry point (experimental)

A one-line entry point is available for the optional standalone manager and read-only preflight:

```sh
curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash
```

The menu offers read-only host checks or installation of the standalone manager from the matching Linux release bundle. To install only the manager directly on the Iran/Dialer host:

```sh
curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --manager dialer
```

The installer verifies the selected release archive against `SHA256SUMS`, supports Linux amd64 and arm64, and does not require Go for manager installation. The manager is installed but **not started**; set a random `PQTUNNEL_MANAGER_TOKEN` of at least 32 bytes in `/etc/default/pqtunnel-manager`, review the file, then start the service deliberately. Keep its listener on loopback and use SSH forwarding.

This is not a one-command tunnel configuration: Gateway/Dialer setup still requires reviewed certificates and role-specific environment files. The tunnel install/start commands are separate because they can change services or network state. The current release remains experimental and is not independently security-audited.

## Requirements

- Go 1.26 or later to build this source tree (`go.mod` declares Go 1.26.0); CI uses Go 1.27.x. The standardized TLS `X25519MLKEM768` hybrid key exchange was introduced in Go 1.24. See the [Go 1.24 release notes](https://go.dev/doc/go1.24).
- Ubuntu/Linux server with systemd, `iproute2`, `nftables`, and `/dev/net/tun` for the supplied deployment scripts.
- Linux client with `iproute2` and `systemd-resolved` (`resolvectl`) for the supplied client route helper.
- Windows: official Wintun DLL/driver and a provisioned adapter named `pqtun0`; this project does not distribute the driver.
- Android build: Android Studio/SDK and NDK plus `gomobile`.

## Build and test

```sh
go test ./...
go vet ./...
go build ./cmd/pqtunneld ./cmd/pqtunnel-client ./cmd/pqtunnel-pki ./cmd/pqtunnel-manager
```

CI runs unit tests, vet and Linux builds on both Ubuntu 24.04 and 26.04, cross-compiles Linux amd64/arm64 and Windows amd64, and exercises real Linux TUN devices plus IPv4/IPv6 routes between disposable network namespaces. These namespace tests cover the tunnel packet path, inbound TCP/UDP port-forward round trips, and multi-port selective egress: TCP/443 and TCP/8443 plus UDP/53 and UDP/5354 use the tunnel, while TCP/8080, TCP/9443, UDP/5353, UDP/5355 and protocol-mismatched TCP/53 or UDP/443 remain direct, over IPv4 and IPv6. They do not validate public VPS routing, provider firewalls or production NAT/firewall integration, arbitrary egress policies beyond these test cases, DNS leaks, the four cross-version pairings, Windows route management, or Android physical devices.

## PKI workflow

Create the CA and server certificate in a trusted development environment, not on the public server:

```sh
go run ./cmd/pqtunnel-pki init --out ./pki --server-name vpn.example.com
go run ./cmd/pqtunnel-pki issue-client --out ./pki --ip 10.66.0.2
# For named site-to-site peer certificates:
go run ./cmd/pqtunnel-pki issue-peer --out ./pki --name iran
# To create a second server certificate under the same CA:
go run ./cmd/pqtunnel-pki issue-server --out ./pki --server-name iran.example.com --prefix iran
```

Issue a separate client certificate for each device with a unique IP address. Never copy `ca.key` to the server or any client. The server needs only `server.crt`, `server.key`, and `ca.crt`; each client needs `ca.crt` plus its own client certificate and private key. Transfer private keys over a separate trusted channel.

The current certificate signatures use Ed25519. The `X25519MLKEM768` KEM does not make these signatures post-quantum. For site-to-site mode, configure both `PQTUNNEL_PEER_PREFIXES` (allowed peer source/return-route CIDRs) and `PQTUNNEL_LOCAL_PREFIXES` (allowed listener-side destination CIDRs) in `/etc/default/pqtunneld`, set `PQTUNNEL_PEER_NAME`, and set `PQTUNNEL_MAX_CLIENTS=1`. The peer name must exactly match the issued client/peer certificate Common Name. Listener certificate paths can be selected using `PQTUNNEL_TLS_CERT` and `PQTUNNEL_TLS_KEY` when reversing the roles.

## VPS preflight and one-line bootstrap

Before preparing either VPS, run the **read-only** preflight from a source checkout:

```sh
bash scripts/site-to-site-preflight.sh --role gateway
bash scripts/site-to-site-preflight.sh --role dialer
```

A one-line remote preflight is also available; it defaults to checks only and does not need root:

```sh
curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/scripts/pqtunnel-bootstrap.sh | bash
```

The same bootstrap also has guarded `install-server` and `install-client` modes. Both require certificates and reviewed role-specific environment files to be staged first; the client build requires Go 1.24+ already installed. `install-server` stages the listener and network-helper configuration; `--start` starts the daemon, and the additional `--apply-network` flag is required to explicitly apply gateway routes/NAT. `install-client` stages the dialer service; its `--start` option activates the systemd unit, which applies the dialer network helper and invokes rollback after the service stops. Both modes refuse existing artifacts and do not install operating-system packages. Example settings use documentation-only IP prefixes and must be replaced. These helpers are not a substitute for a reviewed recovery plan and have not been run on your VPS. CI exercises them only in the disposable GitHub runner.

### One-line install and launch (explicit, network-changing mode)

These commands are intentionally separate from the default read-only bootstrap. Before using them, stage the named PKI/config files on the destination host, replace the example paths, review every setting, and complete a disposable-lab test. They are **not approved for your live VPS yet**. The gateway command starts the service and applies its network helper; the dialer command starts a service that changes route state. Keep out-of-band console access available. The installer does not install OS packages, open provider firewall ports, or overwrite detected existing artifacts.

Germany gateway (requires server.crt, server.key, ca.crt, a reviewed server env file, and a reviewed gateway network env file):

```sh
REF=REPLACE_WITH_REVIEWED_40_CHAR_SHA; curl -fsSL "https://raw.githubusercontent.com/hatinati2/PQTunnel/${REF}/scripts/pqtunnel-bootstrap.sh" | sudo env PQTUNNEL_REF="$REF" bash -s -- install-server --pki-dir /root/pqtunnel-input/germany-pki --server-env-file /root/pqtunnel-input/germany-app.env --network-env-file /root/pqtunnel-input/germany-network.env --start --apply-network
```

Iran dialer (requires client.crt, client.key, ca.crt, a reviewed client env file, and a reviewed dialer network env file):

```sh
REF=REPLACE_WITH_REVIEWED_40_CHAR_SHA; curl -fsSL "https://raw.githubusercontent.com/hatinati2/PQTunnel/${REF}/scripts/pqtunnel-bootstrap.sh" | sudo env PQTUNNEL_REF="$REF" bash -s -- install-client --pki-dir /root/pqtunnel-input/iran-pki --client-env-file /root/pqtunnel-input/iran-app.env --network-env-file /root/pqtunnel-input/iran-network.env --start
```

The paths above are examples, not files created by the command. These operations are not transactional across the full host configuration and are not an upgrade path. Replace the SHA placeholder in each command with a reviewed, lowercase 40-character commit SHA. The bootstrap and downloaded source then use the same immutable commit; installer modes reject mutable refs such as main. For the current project stage, run only the read-only preflight command above; do not run these install/launch lines on the live servers.

## Ubuntu server packaging

The deployment assets are intentionally split into installation and network setup so that installing the service does not silently modify firewall/NAT policy.

1. Ensure the server PKI directory contains `server.crt`, `server.key`, and `ca.crt`; do not place `ca.key` on the server. The installer validates that the server certificate chains to the supplied CA and matches its private key.
2. Review `scripts/install-server.sh` and `deploy/systemd/pqtunneld.service`. The installer accepts either a source checkout (requires Go 1.24+) or a matching Linux release bundle containing a prebuilt `pqtunneld`. It refuses to overwrite a detected existing installation. By default it does not start/enable the service; `--enable` starts and enables it. This is not an upgrade tool.
3. `scripts/server-network.sh` is deliberately restricted to a dedicated test host. It refuses to apply if IPv4 forwarding is already enabled, UFW is active, or existing nftables/iptables rules are detected. Its forward chain uses `policy drop`, allowing only traffic between `pqtun0` and the selected WAN interface for the client subnet; other forwarded IPv4 traffic will be blocked. Do not use it on an existing router, multi-tunnel host, or production VPS without a specific firewall review.
4. The network helper does not open TCP port 8443 in the provider firewall. Firewall integration (including UFW) must be separately reviewed.

Do not run server installation or network scripts on a remote host without console/out-of-band recovery access. These scripts have not been tested against your existing server, active tunnels, provider firewall, or routing rules. Do not deploy on your current VPS until this review and a separate lab test are complete.

## Linux client route helper

Copy `scripts/client.env.example` to `/etc/pqtunnel/client.env`, set `PQTUNNEL_SERVER_IP` to the server's **literal IPv4 address**, and select a unique client address. Review `scripts/linux-client-network.sh` first.

- `up` installs a physical route for the server endpoint before directing the IPv4 default route through TUN. It directs systemd-resolved's catch-all DNS domain to the TUN DNS server and blackholes an IPv6 default route if one is present.
- Start `pqtunnel-client` with matching endpoint, certificate, key, server name and local IP values.
- Stop the client process before using `down`. `down` deliberately restores ordinary networking.

This helper is a prototype, not a guarantee against every possible DNS/IPv6 leak or against traffic before configuration is applied at boot. Test with a non-sensitive client first.

## Windows and Android

The Windows adapter expects a Wintun adapter named `pqtun0` to exist and be available; manual route/DNS/kill-switch management is not yet bundled. See the upstream [Wintun project](https://git.zx2c4.com/wintun).

For Android, the initial AAR command is available through `make android-aar`, but first install/configure `gomobile` and Android SDK/NDK. Place `ca.crt`, `client.crt`, and `client.key` in the app's private `files/pki` directory using a secure development workflow. Do not commit those files. The UI does not yet provide an import flow.

## Release assets

Pushing a version tag (`v*`) triggers `.github/workflows/release.yml` to build Linux amd64/arm64 and Windows amd64 command-line artifacts. This workflow does not imply that the complete VPN client is production-ready.

## Documentation

- [فارسی](README.fa.md)
- [Security notes](SECURITY.md)
- [Web management panel](docs/WEB-ADMIN-PANEL.md) (opt-in and loopback-only)
- [Two-VPS deployment readiness and recovery runbook](docs/TWO-VPS-DEPLOYMENT.md)
- [Protocol notes](docs/PROTOCOL.md)
- [Experimental server-to-server guide (Persian)](docs/SITE-TO-SITE.fa.md)
- [Pre-release checklist](docs/RELEASE-CHECKLIST.md)

## License

MIT. See [LICENSE](LICENSE).
