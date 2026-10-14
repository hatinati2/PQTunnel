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
- The site-to-site link mode currently supports one configured peer-route profile per listener; host route installation, dual-stack forwarding and NAT are not automated or integration-tested.
- IPv6 packet encapsulation is implemented, but IPv6 host routing/firewall policy must be separately configured and tested.
- Linux networking helpers are prototypes and are not a persistent, audited kill-switch.
- Traffic may be exposed if endpoints, client keys, CA signing key, host firewall rules, or device permissions are compromised.

Please avoid claiming that the tunnel is "unbreakable", "fully post-quantum", "leak-proof", or ready for production.
