# PQTunnel wire protocol (v0)

After a successful mutually authenticated TLS 1.3 handshake, each direction carries an uncompressed sequence of frames:

1. `uint32` unsigned network-byte-order packet length.
2. Exactly that many bytes of one layer-3 IPv4 packet.

Accepted lengths are 1..65535 bytes. Lengths outside that range terminate the stream. Packets with invalid IPv4 headers are dropped. IPv6 is intentionally unsupported and dropped. No user-defined encryption is layered over TLS.

The client certificate's Subject Common Name is required to be a valid IPv4 address. The server checks that a client's outbound IPv4 source address matches that assigned address and routes return packets by their destination address. One active session per address is allowed.

Protocol versioning, negotiated features, datagram congestion control, multiple independent transport streams, explicit keepalives, per-client rate limits and certificate revocation are not yet implemented.
