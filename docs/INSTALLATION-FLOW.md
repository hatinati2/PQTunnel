# First-time site-to-site installation flow

PQTunnel has separate tunnel endpoints and an optional management UI. Installing
only `pqtunnel-manager` does not install either tunnel endpoint.

## 1. Use two hosts

Install one Gateway/Listener endpoint on the host that accepts the TCP connection,
and one Dialer endpoint on the host that initiates it. Do not treat the optional
manager service as a replacement for either endpoint.

The Gateway requires `pqtunneld.service` and `/etc/default/pqtunneld`.
The Dialer requires `pqtunnel-client.service` and `/etc/default/pqtunnel-client`.
Both roles also require their role-specific certificate and configuration files.

## 2. Prepare a role-specific PKI bundle

Run this on a trusted workstation or other secure staging machine, from the
repository root. Use the real DNS name or IP that the Dialer will use for the
Gateway certificate, and the unique IPv4 address assigned to the Dialer peer
inside the tunnel.

```bash
bash scripts/prepare-site-to-site-pki.sh \
  --server-name gateway.example.net \
  --client-ip 10.66.0.2 \
  --out /root/pqtunnel-pki-bundle
```

This generates certificates and validates the resulting bundle. It does not
install any service or change routes, sysctls, forwarding, or firewall rules.
The output contains:

- `gateway-pki/`: `server.crt`, `server.key`, and `ca.crt`.
- `dialer-pki/`: `client.crt`, `client.key`, and `ca.crt`.
- `ca-offline/`: the CA private key. Keep this directory offline and never copy it to either endpoint.

Transfer only the appropriate role directory to each host through a trusted
channel. The Gateway `PQTUNNEL_PEER_NAME` must match the Common Name in the client
certificate; the Dialer `PQTUNNEL_SERVER_NAME` must match the server certificate SAN.

## 3. Prepare the endpoint configuration files

Start from the repository examples and replace all documentation-only values
with your real endpoint, prefixes, and port policy:

- Gateway application environment: `scripts/pqtunneld.site-to-site.env.example`.
- Gateway network-helper environment: `scripts/site-to-site-gateway.env.example`.
- Dialer application environment: `scripts/pqtunnel-client.env.example`.
- Dialer network-helper environment: `scripts/site-to-site.env.example`.

Validate both pairs before installing:

```bash
bash scripts/pqtunnel-bootstrap.sh check-config \
  --kind gateway \
  --app-env /secure/path/gateway.env \
  --network-env /secure/path/gateway-network.env

bash scripts/pqtunnel-bootstrap.sh check-config \
  --kind dialer \
  --app-env /secure/path/dialer.env \
  --network-env /secure/path/dialer-network.env
```

These examples are not production defaults. The actual LAN CIDRs, Gateway endpoint,
WAN interface, TLS name, peer identity, and allowed destination ports must be known
before installing or starting a tunnel.

## 4. Install files without starting the tunnel

Use the `install-server` and `install-client` modes of
`scripts/pqtunnel-bootstrap.sh` with a reviewed, immutable 40-character commit SHA.
Stage the correct PKI directory and configuration files on each respective host.
Omit `--start` during the initial install. The scripts install the endpoint
binary, systemd unit, helper scripts, role-specific certificates, and environment files;
they do not install operating-system packages.

The client systemd unit references
`/usr/local/lib/pqtunnel/stop-client-network.sh`. The client installer stages this
helper along with the run and network helpers. `scripts/test-installer-completeness.sh`
guards this relationship in CI.

## 5. Treat network setup as a separate operation

Do not start the Dialer service until its network behavior has been reviewed:
the Dialer unit runs `site-to-site-selective.sh dialer-up` as `ExecStartPre`.
That helper may alter routes, policy routing, sysctls, and its own nftables rules.
The Gateway's separate network apply action can also alter network state.

If preflight reports existing nftables/iptables rules, enabled forwarding, or
unmanaged TUN interfaces, do not bypass the safety checks and do not use `--start`.
This project does not automatically integrate its policy rules with an existing
production firewall. Use a separately reviewed integration plan if network changes
are not permitted. This installation flow never enables UFW or modifies the host
firewall merely to install files.

## 7. Optional paired one-line installer

For a first-time two-VPS setup, the interactive paired entry point can run from the
Iran/Dialer VPS, provided SSH key authentication and non-interactive sudo already
work for the overseas Gateway:

```sh
curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/main/install.sh | sudo bash -s -- --pair
```

It downloads the architecture-matching Linux release and verifies its archive
against the release `SHA256SUMS`, then fetches the current orchestration and PKI
scripts. It prompts for the Gateway SSH target, certificate DNS name/IP, TCP
listener port, both WAN interfaces and selected TCP/UDP egress ports. It builds
mutual-TLS role credentials, transfers only Gateway credentials to the Gateway
and keeps the Dialer private key on Iran. The CA signing key is kept only in
the temporary root-owned work directory and removed on exit; this is convenient
for a disposable setup but not a replacement for an offline, backed-up CA if
certificates must later be renewed.

Both standalone managers are configured to listen on `127.0.0.1:9091` with
new, separate manager login tokens. A third, separate speed-test token is
configured for the private tunnel addresses `10.66.0.1:9109` and
`10.66.0.2:9109`. The manager tokens are printed once when the installer exits;
save them securely. The panels are accessed remotely through SSH forwarding
(`9091` for the Iran panel and local `9092` forwarded to remote `9091` for
the Gateway panel).

The default profile is **selected-port egress, not a full tunnel**: TCP 80/443
and UDP 53/123/443 from the Iran VPS are selected for routing through the
Gateway. TCP/9109 is allowed only for the private speed-test agent, not added
to the WAN egress port list. The external provider firewall/security group is
not edited by the script; the Gateway listener port (default TCP/8443) must
already be reachable from Iran.

The installer checks for existing endpoint artifacts and refuses to overwrite
them. It installs both endpoints and managers with tunnel services stopped,
validates the generated configs, and asks the operator to type exactly
`APPLY-NETWORK` before it starts services and applies the selective policy
routing/nftables/forwarding rules. Do not confirm without independent console
or recovery access on both VPSes. Existing UFW, existing firewall tables, or
pre-existing forwarding/policy-routing state may cause the network helper to
refuse activation; do not bypass these guards. The script does not modify
provider firewalls and does not automatically test general internet reachability
or prove production readiness.

This mode still changes live Linux network state after explicit confirmation and
has not been validated on the specific customer VPS pair. Treat PQTunnel as
experimental; use in a disposable/lab environment first.

## 6. Attach the manager after the endpoint exists

The optional `pqtunnel-manager` is a control panel, not a tunnel installer. Set
`PQTUNNEL_MANAGER_ROLE=gateway` on the Gateway manager or
`PQTUNNEL_MANAGER_ROLE=dialer` on the Dialer manager. The matching endpoint unit
and its protected environment file must exist before service controls or configuration
editing can work. The panel now hides those controls when the endpoint state/configuration
is unavailable instead of presenting a blank form as if setup were complete.
