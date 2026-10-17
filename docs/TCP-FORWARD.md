# Optional TCP front-door forwarding over the TUN

The independent Node Setup mode intentionally brings up only the authenticated transport and the `pqtun0` interface. It does not rewrite host routing, NAT, forwarding, or firewall rules. A working TLS transport alone does not make a public VLESS/Xray configuration available on the Dialer IP.

For a service already listening on the Gateway TUN address, this optional helper creates a persistent **user-space TCP relay** on the Dialer. It uses `socat` and a systemd unit, and deliberately does not alter nftables/iptables, sysctls, routes, NAT, or the Gateway Xray service.

## Preconditions

- The Dialer tunnel service is configured and active, and the Gateway is reachable through the tunnel.
- `PQTUNNEL_REMOTE_PREFIXES` in `/etc/default/pqtunnel-client` contains the target address (for example, `10.66.0.1/32`).
- The target TCP port is allowed by `PQTUNNEL_ALLOWED_DST_PORTS` on both endpoints (for example, `tcp:10488`).
- `socat` is installed on the Dialer, and the requested listen address is assigned to a local interface.
- The requested public TCP port is intentionally exposed in the provider/host firewall. The helper does not open firewall ports.
- The Gateway service is already listening at the TUN target address/port. This helper does not install or reconfigure Xray.

## Preview and install

Run on the Dialer from a checked-out copy of the repository or the matching release bundle. Replace example addresses and ports with your own.

Preview the generated systemd unit first. This is read-only and does not start the service:

```sh
sudo bash scripts/pqtunnel-tcp-forward.sh install --name xray --listen-address 213.176.7.211 --listen-port 10488 --target-address 10.66.0.1 --target-port 10488 --dry-run
```

If the preview is correct and TCP/10488 is intentionally exposed on the Dialer, install and start the service explicitly:

```sh
sudo bash scripts/pqtunnel-tcp-forward.sh install --name xray --listen-address 213.176.7.211 --listen-port 10488 --target-address 10.66.0.1 --target-port 10488 --start
```

The script requires an installed PQTunnel client systemd unit (`pqtunnel-client-transport.service` or the legacy `pqtunnel-client.service`), validates that the target is in the configured remote prefixes, validates the TCP destination-port allowlist, refuses a port that already has a listener, and creates `pqtunnel-tcp-forward-xray.service`. `--start` requires that the tunnel service is already active; it does not silently start or reconfigure a tunnel. The forward is tied to that client unit, so it is stopped/restarted with it. Without `--start`, the generated unit is created but left stopped.

The helper supports IPv4/TCP only. It relays the stream without terminating TLS/Reality or modifying VLESS/Xray payloads. It does not preserve the original public client IP: the Gateway sees the Dialer's TUN address as the TCP source. It does not provide a general Internet route or forward UDP.

## Point the client configuration at the Dialer

For an Xray/VLESS configuration using the Gateway's existing TCP/10488 inbound, set the client-facing server address to the Dialer's reachable public IP and the relay port:

- Address: `213.176.7.211`
- Port: `10488`

Keep the UUID, transport, TLS/Reality parameters, SNI/server name, public key and short ID unchanged unless the Gateway configuration itself requires a change. Do not use `10.66.0.1` as the address on a phone or external client; that is the TUN-side target used by the Dialer relay. Do not point the client at PQTunnel's outer port (`11784`); that port carries the PQTunnel TLS transport, not VLESS.

## Verify and remove

```sh
sudo systemctl --no-pager --full status pqtunnel-tcp-forward-xray.service
sudo ss -lntp '( sport = :10488 )'
sudo journalctl -u pqtunnel-tcp-forward-xray.service -f
```

Test from an actual external client. A successful TCP connection to the relay is not, by itself, proof that a VLESS/Reality handshake succeeded. A log such as `Connection reset by peer` means a TCP leg was closed/reset; it must be interpreted together with client logs and the Gateway Xray logs.

To remove only the unit created by the helper:

```sh
sudo bash scripts/pqtunnel-tcp-forward.sh remove --name xray
```

Removing this unit does not remove any other unit, stop Xray, or change the tunnel's routes or firewall. Keep console/out-of-band access available. PQTunnel is experimental and has not been independently security-audited.
