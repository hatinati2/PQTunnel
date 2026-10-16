# PQTunnel user-space proxy wire protocol

This protocol is separate from the Layer-3 packet framing documented in [PROTOCOL.md](PROTOCOL.md). It is used only by the experimental Direct/Reverse TCP proxy.

Both endpoints first establish mutually authenticated TLS 1.3. A byte stream then carries versioned frames with a 12-byte header: protocol version (1 byte), frame type (1 byte), reserved bits (2 bytes, must be zero), stream ID (4 bytes, network byte order), and payload length (4 bytes, network byte order). Each payload length is validated before allocation. Version 2 adds explicit per-stream send credits; version 1 peers are not wire-compatible.

## Bounded stream flow control

A stream starts with eight DATA-frame credits. A sender must acquire one credit before placing each DATA frame on the transport. The receiver returns one credit only after its local `Stream.Read` has consumed an entire received frame. `WINDOW_UPDATE` is a stream-scoped frame with a four-byte, unsigned network-byte-order credit count. Its value must be between 1 and 8, and a peer cannot increase the sender's available window above eight frames. Unknown or duplicate credits are rejected (or ignored for a recently closed stream, like late stream-control frames).

The receive queue remains bounded to eight frames per stream, with DATA payloads capped at 16 KiB. A conforming sender therefore cannot overflow that queue during ordinary sustained transfers. A peer that sends DATA beyond the granted window may still cause the affected stream to be reset; the shared transport remains isolated from a single stream's local overrun where protocol handling allows it. Writers blocked waiting for credit honor write deadlines, session shutdown, and stream resets.

## Frame types

| Type | Stream ID | Payload |
|---|---:|---|
| `OPEN_DIRECT` | nonzero | Fixed Direct TCP target encoded by the implementation |
| `OPEN_REVERSE` | nonzero | Configured Reverse mapping name |
| `OPEN_OK` | nonzero | Empty |
| `OPEN_ERROR` | nonzero | Bounded error text |
| `DATA` | nonzero | 1..16384 bytes |
| `CLOSE` | nonzero | One-byte half-close or reset flag |
| `PING`, `PONG` | zero | Eight-byte keepalive token |
| `WINDOW_UPDATE` | nonzero | Four-byte credit count, 1..8 |

`WINDOW_UPDATE` credits DATA frames, not bytes. The sender has at most 128 KiB of DATA payload per stream outstanding under the initial eight-frame window. The window is intentionally bounded; throughput tuning for high-RTT links must preserve the per-stream and aggregate memory bounds.

## Scope

The protocol carries TCP application streams, not UDP datagrams or arbitrary IP packets. The Direct listener is loopback-only SOCKS5 TCP CONNECT. Reverse listeners map to fixed configured target names. TLS/mTLS authenticates and encrypts the transport but does not guarantee that traffic is invisible to deep-packet inspection.
