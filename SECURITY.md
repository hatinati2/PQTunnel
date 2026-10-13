# Security status

This repository is an experimental prototype, not a security-audited VPN product.

- Require Go 1.24+ and TLS 1.3 only.
- Enable only `tls.X25519MLKEM768`; failure to negotiate must fail closed.
- Client and server authenticate with X.509 certificates issued by a private CA.
- Certificate signatures are Ed25519 (classical); only the key exchange is post-quantum hybrid in this prototype.
- No custom cryptographic algorithms are implemented.
- IPv6 packets are intentionally discarded, not tunneled.
- Route management, DNS control, kill-switch, certificate revocation, device enrollment, robust MTU/PMTUD, anti-replay beyond TLS stream semantics, resource quotas, and production observability are incomplete.
- Protect CA and client private keys. `ca.key` must not be copied to the server or any client.
- A compromised endpoint or host can observe plaintext packets before/after the TLS tunnel.
- A single TCP stream may perform poorly under loss due to TCP-over-TCP head-of-line blocking.

Do not expose a daemon to the public Internet until the missing routing policy, rate limits, resource controls, certificate lifecycle, platform behavior, and security review are addressed.
