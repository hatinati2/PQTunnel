# Security policy

PQTunnel is an experimental prototype and has not undergone an independent security audit. Do not use it to protect sensitive activity or on production infrastructure.

## Reporting a vulnerability

Do not open public issues containing private keys, certificates, connection tokens, server IPs you consider sensitive, or unredacted logs. Contact the maintainer privately through a trusted channel and include a minimal reproducible description. Do not expect a response-time SLA for this prototype.

## Current cryptographic design

- TLS 1.3 only.
- Explicit hybrid key-exchange group `X25519MLKEM768`; no classical key-exchange fallback is configured.
- Mutual TLS using a private CA.
- Certificate signatures are currently Ed25519 (classical). Authentication is therefore not post-quantum even though key exchange is hybrid post-quantum.
- No custom cipher, KDF or cryptographic primitive is implemented by this project.

## Known gaps

- No independent security review or fuzzing campaign.
- No online revocation/distribution or safe automated enrollment workflow.
- Windows routes/DNS/kill-switch and Android certificate import/build verification remain incomplete.
- The site-to-site link mode currently supports one configured peer-route profile per listener. The experimental `scripts/site-to-site-selective.sh` helper can apply narrowly scoped IPv4/IPv6 policy routing, forwarding and NAT for selected-port egress and explicit TCP/UDP port mappings on clean dedicated hosts; it refuses detected pre-existing firewall/forwarding state.
- CI exercises the helper in disposable Linux network namespaces, including injected failures and rollback checks. This does not validate two independent VPSs, provider firewalls, or arbitrary existing host firewall/routing policy; real-host recovery rehearsals remain required before stable release.
- The separate `scripts/server-network.sh` helper handles IPv4 forwarding/NAT only. Packet encapsulation itself does not configure general host routes or firewall policy, and IPv6 behavior must be reviewed for the specific network design.
- Linux networking helpers are prototypes and are not a persistent, audited kill-switch.
- Traffic may be exposed if endpoints, client keys, CA signing key, host firewall rules, or device permissions are compromised.

Please avoid claiming that the tunnel is "unbreakable", "fully post-quantum", "leak-proof", or ready for production.
