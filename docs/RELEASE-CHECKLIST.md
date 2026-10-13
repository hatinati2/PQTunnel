# Pre-release validation checklist

Do not mark PQTunnel stable until these items have been performed and their results are documented.

## Build and CI

- [ ] Run `go test -race ./...` with a supported, patched Go toolchain (CI uses 1.27.x).
- [ ] Run `go vet ./...` and dependency vulnerability scanning.
- [ ] Confirm Linux amd64/arm64 and Windows amd64 artifacts build from the tagged commit.
- [ ] Build the Android AAR with the documented `gomobile` version, SDK and NDK; install it on physical devices.

## TLS and identity

- [ ] Test a real client/server handshake and capture the negotiated group using a suitable TLS diagnostic or instrumented test build. Verify that `X25519MLKEM768` is selected.
- [ ] Force an incompatible peer and verify connection failure; no classical key exchange may be silently negotiated.
- [ ] Test expired, wrong-CA, wrong-server-name, wrong-client-EKU and revoked/disabled client credentials.
- [ ] Review private-key file permissions and provisioning for CA, server, desktop clients and Android.

## Packet and network tests

- [ ] Run protocol tests and fuzzing for malformed/truncated/oversized frames and IP packets.
- [ ] Test two clients with unique addresses and reject duplicate identities/source spoofing.
- [ ] Test reconnects, packet loss, long RTT, server restart, sleep/resume and TCP-over-TCP degradation.
- [ ] Verify IPv4 forwarding/NAT with and without UFW or another host firewall. Verify rollback from console access.
- [ ] Check DNS and IPv6 on all desktop OSs using independent leak tests; test before tunnel, while connected, after transport loss, during sleep/resume and after reboot.
- [ ] Confirm the Linux client route helper refuses ambiguous existing routes and that its explicit `down` path restores the original connectivity.
- [ ] Test that loss of the client process does not silently restore physical default routing while the VPN is expected to remain connected.

## Platform completeness

- [ ] Windows: provision Wintun from the official source; implement and test address, route, DNS and firewall/kill-switch management; confirm cleanup on crash and reboot.
- [ ] Android: implement certificate import/provisioning, proper status/error reporting, duplicate-start protection, foreground-service lifecycle and physical-device tests on supported Android versions.
- [ ] Verify no system firewall, SSH route, DNS setting or unrelated route is modified by default.

## Release documentation

- [ ] State clearly that certificate signatures currently use classical Ed25519.
- [ ] Publish a threat model and independently review the implementation.
- [ ] Do not use claims such as "unbreakable", "fully post-quantum", "leak-proof" or "production-ready" without evidence.
