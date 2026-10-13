# PQTunnel

**Version:** 0.2.0-dev · **Status:** experimental prototype, not production-ready.

PQTunnel is an experimental IPv4 layer-3 tunnel using TCP with TLS 1.3 and a strict `X25519MLKEM768` hybrid key exchange. It uses mutual TLS with a private CA, length-prefixed IP frames, a Linux TUN device, a Windows Wintun adapter, and an Android `VpnService` scaffold.

> **Security notice:** This repository has not undergone an independent security audit. Do not use it to protect sensitive activity or deploy it on a production server. The key exchange is post-quantum hybrid; certificate signatures are currently Ed25519 (classical), so the entire authentication system is not post-quantum. No cryptographic construction is unbreakable by definition.

## Current scope

- TLS 1.3 only, with `X25519MLKEM768` explicitly selected and no classical key-exchange fallback.
- Mutual TLS for client authentication.
- Per-client IPv4 identity taken from the signed client certificate's Common Name; clients must receive unique addresses in `10.66.0.0/24`.
- Length-prefixed IPv4 packets, source-address anti-spoofing, bounded active/handshaking connections, bounded packet queue, and reconnect backoff.
- Server systemd unit and separate, explicit Ubuntu IPv4 forwarding/NAT script.
- Linux client network helper for endpoint routing, IPv4 full-tunnel routing, systemd-resolved DNS routing, and blocking IPv6 default traffic while configured.
- GitHub Actions tests/cross-builds and release packaging.
- Android `VpnService` scaffold and Linux/Windows TUN adapters.

## Important limitations

1. The server network script does not alter UFW or other existing firewall policies. Forwarding may still be blocked when UFW or another firewall is active; read the script and configure the host firewall deliberately.
2. The Linux client route helper is not a persistent, audited firewall kill-switch. Its IPv4 route remains directed at TUN while the helper state is active, and it blackholes an IPv6 default route while connected, but the route configuration does not automatically survive reboot. Custom processes that bind directly to a physical interface require a firewall policy as well.
3. Windows TUN uses Wintun, which must be provisioned from the official distribution; automatic Windows route/DNS/kill-switch management is not included in this release.
4. Android is a scaffold; the AAR must be built locally with `gomobile`, certificate import is not implemented in the UI, and the app has not been tested on physical devices.
5. The server and Linux-client scripts affect networking when explicitly run. Review them first and keep console/out-of-band access available. They have not been tested on your host.
6. The single TCP transport can suffer TCP-over-TCP head-of-line blocking.
7. There is no online certificate revocation service, secure device provisioning flow, or PQ signature/certificate chain yet.

## Requirements

- Go 1.24 or later; CI uses Go 1.27.x. Go 1.24 introduced the standardized TLS `X25519MLKEM768` hybrid key exchange. See the [Go 1.24 release notes](https://go.dev/doc/go1.24).
- Ubuntu/Linux server with systemd, `iproute2`, `nftables`, and `/dev/net/tun` for the supplied deployment scripts.
- Linux client with `iproute2` and `systemd-resolved` (`resolvectl`) for the supplied client route helper.
- Windows: official Wintun DLL/driver and a provisioned adapter named `pqtun0`; this project does not distribute the driver.
- Android build: Android Studio/SDK and NDK plus `gomobile`.

## Build and test

```sh
go test ./...
go vet ./...
go build ./cmd/pqtunneld ./cmd/pqtunnel-client ./cmd/pqtunnel-pki
```

CI performs tests and cross-compiles Linux amd64/arm64 and Windows amd64. The Android application is not part of the verified CI build.

## PKI workflow

Create the CA and server certificate in a trusted development environment, not on the public server:

```sh
go run ./cmd/pqtunnel-pki init --out ./pki --server-name vpn.example.com
go run ./cmd/pqtunnel-pki issue-client --out ./pki --ip 10.66.0.2
```

Issue a separate client certificate for each device with a unique IP address. Never copy `ca.key` to the server or any client. The server needs only `server.crt`, `server.key`, and `ca.crt`; each client needs `ca.crt` plus its own client certificate and private key. Transfer private keys over a separate trusted channel.

The current certificate signatures use Ed25519. The `X25519MLKEM768` KEM does not make these signatures post-quantum.

## Ubuntu server packaging

The deployment assets are intentionally split into installation and network setup so that installing the service does not silently modify firewall/NAT policy.

1. Ensure the server PKI directory contains `server.crt`, `server.key`, and `ca.crt` only. Do not place `ca.key` on the server.
2. Review `scripts/install-server.sh` and `deploy/systemd/pqtunneld.service` before use. The installer builds the daemon with Go 1.24+ and installs the binary, certificates, and systemd unit. By default it does not start/enable the service. The optional `--enable` flag starts it.
3. `scripts/server-network.sh` supports `status`, `apply --wan-if <actual-uplink-interface>`, and `rollback`. It manages only the dedicated `ip pqtunnel` nftables table and a dedicated sysctl file. It does not update UFW, open TCP port 8443, or change unrelated firewall rules. Review the script and take a backup before applying network changes.
4. Open the TCP listening port using the host provider firewall and host firewall policy appropriate for your environment. Do not assume the network helper does this.

Do not run server network scripts on a remote host without console/out-of-band recovery access. The project maintainer has not tested these scripts against your existing firewall, provider firewall, or routing rules.

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
- [Protocol notes](docs/PROTOCOL.md)
- [Pre-release checklist](docs/RELEASE-CHECKLIST.md)

## License

MIT. See [LICENSE](LICENSE).
