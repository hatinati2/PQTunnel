# Two-VPS deployment readiness and recovery runbook

**Status: planning and read-only checks only. This guide does not authorize deployment to production.** PQTunnel remains experimental and has not been validated on the actual Iran/Germany VPS pair, their provider firewalls, or their current routing state.

## Intended topology

- **Germany — Gateway/Listener:** accepts the TLS connection and routes allowed site traffic.
- **Iran — Dialer:** initiates the outbound TLS connection to Germany.
- Selective egress tunnels only configured TCP/UDP destination ports. Inbound forwarding is separate and requires a specific mapping plus matching tunnel-side destination-port allowlists.
- Example files use documentation-only networks. Never copy them unchanged to a live host.

## Stage 0 — prerequisites before any change

Do not begin operational rollout until all of these are true:

- Console/serial access or an independently tested out-of-band recovery path is available for **both** hosts. SSH over the route being modified is not a recovery plan.
- Provider firewall/security-group rules and host firewall state are documented. Listener TCP port(s), including the selected TLS port, are reviewed separately; the installer does not open provider firewall ports.
- Current default routes, routing rules, forwarding sysctls, nftables/iptables/UFW state and active tunnels are recorded by the operator.
- Actual site prefixes are known and do not overlap. Default-route/full-tunnel routing requires an explicit design and separate recovery path.
- TLS server name matches the server certificate SAN; the peer common name matches `PQTUNNEL_PEER_NAME`; port allowlists include every selected egress port and forwarded target port.
- The CA private key remains offline. Only the required role-specific certificate, matching private key and CA certificate are staged on the relevant host over a trusted channel.
- Config and key files are reviewed. Bootstrap configuration validation intentionally rejects shell expansions and unsupported characters; do not put secrets in command-line arguments.

## Stage 1 — read-only preflight on each host

Run the correct role-specific command separately on each VPS. These commands fetch the preflight script directly from an immutable commit, perform read-only inspection, do not install packages or write reports, do not change routes/sysctls/firewall rules, and do not start or stop services.

Germany:

```sh
curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/558ba23bb947051f349e5ad76631d2d118881a62/scripts/site-to-site-preflight.sh | bash -s -- --role gateway
```

Iran:

```sh
curl -fsSL https://raw.githubusercontent.com/hatinati2/PQTunnel/558ba23bb947051f349e5ad76631d2d118881a62/scripts/site-to-site-preflight.sh | bash -s -- --role dialer
```

Or run from a reviewed checkout:

```sh
bash scripts/site-to-site-preflight.sh --role gateway
bash scripts/site-to-site-preflight.sh --role dialer
```

The optional `--endpoint HOST_OR_IP` checks the current route to the endpoint; hostname checks can perform a DNS lookup. Do not post unredacted output publicly.

### Interpreting results

- **FAIL:** stop and resolve the finding before proceeding; the script exits non-zero.
- **WARN:** investigate and record why it is acceptable. A warning is not permission to apply network rules.
- **PASS:** that individual read-only check passed; it does not prove two-host connectivity.

Preflight checks OS/tool availability, routes and policy-rule collisions, routing tables 518/519, forwarding and reverse-path-filter sysctls, firewall query success/failure, service/binary/config presence, private-key permissions, and—when files exist—certificate expiry, CA verification and certificate/private-key match. Firewall query failures are reported as **unknown/WARN**, not incorrectly assumed to mean an empty firewall. Certificate and private-key contents are never printed.

When available, preflight also reports TUN/TAP interfaces other than `pqtun0`. This only identifies device presence, not ownership; review each interface before changing network state.

Linux `rp_filter` values are `0=disabled`, `1=strict`, and `2=loose`. The effective value per interface is `max(net.ipv4.conf.all.rp_filter, net.ipv4.conf.<interface>.rp_filter)`; `conf.default` is a template for newly created interfaces, not a substitute for inspecting existing interfaces. Strict reverse-path filtering may drop asymmetric or policy-routed traffic. Do not change these values merely to pass preflight: doing so can affect unrelated tunnels and routes.

The current preflight also inspects nftables/iptables/ip6tables output for `NOTRACK` and packet-marking rules. `NOTRACK` means matching flows may bypass conntrack and conflict with SNAT/DNAT; existing packet marks may interact with PQTunnel policy routing. These warnings do not identify rule ownership or establish coexistence safety. See the [existing-firewall coexistence design note](EXISTING-FIREWALL-COEXISTENCE.md) for requirements and lab validation gates.

When sharing results, send only the role, Ubuntu version, PASS/WARN/FAIL counts, warning text, and whether required files exist with safe permissions. Redact hostnames, addresses and provider identifiers where appropriate. Never share private keys, unredacted config, or raw systemd environment output.

## Stage 2 — prepare and review config without activating services

Use these files as templates only:

- Gateway app environment: `scripts/pqtunneld.site-to-site.env.example`
- Dialer app environment: `scripts/pqtunnel-client.env.example`
- Gateway network helper: `scripts/site-to-site-gateway.env.example`
- Dialer network helper: `scripts/site-to-site.env.example`

Replace every documentation-only IP/CIDR, interface name, server endpoint/name, peer Common Name and port allowlist. Validate each pair of environment files on a trusted workstation with the bootstrap's `check-config` mode before staging it. Do not copy `ca.key` to either VPS.

In site-to-site mode, the listener checks both the destination peer route and the packet source against `PQTUNNEL_LOCAL_PREFIXES` before forwarding a packet from its TUN into the tunnel. The dialer applies corresponding local-source and remote-destination checks. Keep these CIDRs as narrow as the actual routed sites require; widening them to silence drops weakens isolation.

For now, the safe action is only to prepare the files and collect the two preflight reports. Do **not** run `install-server --start --apply-network` or `install-client --start` on the live hosts. The one-line installer/start entry points are documented in the main README, but installation is not approved for these VPSes yet.

## Stage 3 — rollout gates still unmet

A production rollout remains blocked until these items are completed and reviewed in a disposable lab:

1. End-to-end testing between distinct Linux hosts with all four Ubuntu pairings: 24.04↔24.04, 24.04↔26.04, 26.04↔24.04, 26.04↔26.04.
2. Endpoint reachability and provider-firewall review for the selected TLS port, with recovery independent of the tunnel.
3. Inbound TCP/UDP forwarding tests using intended address families and application targets.
4. Selective TCP/UDP egress, unlisted ports, wrong-protocol/same-port cases, DNS and IPv6 tests.
5. Service crash, peer reconnect, reboot, partial-apply failure and full console-based recovery tests.
6. Verification that existing artifacts are not overwritten and a complete inventory of files/services/network resources the installer creates.
7. A rollback rehearsal and written go/no-go decision. Current CI tests disposable Linux namespaces, not your providers or real VPSs.

## Recovery planning — operator checklist, not commands

Before any future change window, record the prior service state, routes/rules, forwarding values, firewall tables/chains, files and hashes, and resource ownership (PQTunnel versus another service). Keep reviewed config copies and the exact source commit.

If rollout fails, stop further rollout, use out-of-band console access, preserve failure logs and current state, and identify which PQTunnel unit, TUN interface, route/rule, nftables table, forwarding sysctl or file was created. Restore **only the recorded pre-change state** using a reviewed host-specific recovery plan. Do not flush the global firewall, delete unrelated routes, or blindly run a generic network-reset command. Validate ordinary management connectivity before relying on SSH again.

The helper's rollback tests inject nftables apply failure in a disposable namespace. They do **not** make the full bootstrap installation transactional or prove recovery on your host.

## Current decision

**Read-only preflight and offline config review only. No live installation, service start, route/NAT apply, firewall change or other state-changing VPS command is authorized by this runbook.** The next decision depends on the two redacted preflight summaries and more isolated two-host testing.


## Stage 1b — detailed read-only firewall coexistence inventory

After the initial preflight, run this inventory from a reviewed checkout. It summarizes nftables chain hooks/policies and counts of NOTRACK, packet-mark, NAT and verdict rules in nftables/iptables, without printing raw rules, addresses, ports or counters:

```sh
python3 scripts/site-to-site-coexistence-audit.py --role gateway
```

Use `--role dialer` on the Iran host. This is read-only, but table and chain names may still reveal service names; review its output before sharing. It helps choose a disposable-lab backend and does not authorize a live firewall change.
