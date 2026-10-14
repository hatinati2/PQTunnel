# PQTunnel wire protocol (v0)

After a successful mutually authenticated TLS 1.3 handshake, each direction carries an uncompressed sequence of frames:

1. `uint32` unsigned network-byte-order packet length.
2. Exactly that many bytes of one layer-3 IPv4 or IPv6 packet.

Accepted packet lengths are 1..65575 bytes. IPv4 total lengths and the standard IPv6 payload length are validated. IPv6 jumbograms are not supported. No user-defined encryption is layered over TLS.

TLS is restricted to TLS 1.3 and the standardized hybrid key-exchange group `X25519MLKEM768`. The implementation requires a recent Go toolchain that supports this group and does not intentionally fall back to classical key exchange. Certificate signatures currently use Ed25519, so certificate authentication is not fully post-quantum.

## Host mode (compatibility)

When the server is started without `--peer-prefixes`, each client certificate Common Name must be a literal IP address. That address becomes the peer's `/32` or `/128` route and the server checks that packets sent by the peer use that source address.

## Server-to-server routed link mode

For a single authenticated site peer, configure `pqtunneld --peer-prefixes` with a comma-separated list of CIDRs reachable on the dialer's side and `--local-prefixes` with the listener-side destinations permitted from that peer. Both are required in site-to-site mode. Peer prefixes act as source allowlist and return-route set; local prefixes constrain destinations injected into the listener-side TUN. This mode requires `--max-clients=1` and `--peer-name` matching the client certificate Common Name. The explicit identity pin prevents another certificate issued by the same CA from claiming the route profile. The peer identity may be a named client certificate generated with `pqtunnel-pki issue-peer`.

The dialer configures both `--local-prefixes` and `--remote-prefixes`:

- `--local-prefixes` must include the source/destination ranges belonging to the dialer-side network, including its TUN address or routed LANs.
- `--remote-prefixes` must include the ranges reachable beyond the listening side. For a full egress tunnel, this may include `0.0.0.0/0` and `::/0`; use only what the network routing policy is intended to send through the tunnel.

On the listener, packets are accepted only when their source address belongs to the configured peer prefixes. Packets read from the listener TUN are sent to the authenticated peer only when the destination matches exactly one peer's allowed prefix. Overlapping routes are rejected when peers connect.

The side that runs `pqtunneld` listens; the side that runs `pqtunnel-client` initiates the TCP connection. To use the reverse connection direction, move the listener role to the other server, use a server certificate for that server's DNS name/IP, and issue the matching peer certificate/configuration. This does not itself choose host routes or turn on forwarding/NAT.

`pqtunneld --listen` accepts one address or a comma-separated list such as `0.0.0.0:8443,[::]:8443` to bind explicit IPv4 and IPv6 listeners. `--server` accepts `hostname:port`, `IPv4:port`, or `[IPv6]:port`; `--server-name` is separately used for TLS certificate verification. `--network tcp` uses system DNS/address selection, while `tcp4` and `tcp6` force the transport IP family. If a hostname is used, the underlay must be able to resolve it before traffic is redirected to the TUN.

Protocol version negotiation, explicit keepalive frames, certificate revocation, route-helper integration, congestion control and multi-peer per-identity route profiles remain outside the current prototype. IPv6 packet encapsulation is implemented, but IPv6 forwarding and firewall/NAT behavior must be configured and tested separately on the hosts.
