# User-space Direct and Reverse Proxy Mode — Design Proposal

**Status: design only. No endpoint implementation or live deployment is approved by this document.**

## Why a separate mode is needed

The current PQTunnel site-to-site mode is a Layer-3 TUN tunnel. Its Linux helper installs policy routes, packet marks, nftables rules, NAT/forwarding rules, and may change forwarding sysctls. It deliberately refuses hosts with existing firewall rules, pre-enabled forwarding, or unmanaged TUN interfaces. Keep that fail-closed behavior.

The reviewed Iran and Germany hosts already have active tunnel interfaces, firewall rules, packet-marking/NOTRACK behavior, and forwarding enabled. A port number that appears unused by `ss` does not prove that an outbound or inbound flow is compatible with those policies. Do not try more ports on a production host as a substitute for a compatibility design.

Because the operator's requirement is to preserve existing routes and firewall state, a separate application-layer proxy mode is the candidate to evaluate. It must not reuse the Layer-3 network helper.

## Proposed goal

Provide both functions at the same time over one authenticated encrypted transport, without creating a TUN device or changing host routes, sysctls, firewall rules, NAT, or existing services:

1. **Direct (application proxy):** applications on the Dialer host explicitly configured to use a loopback SOCKS5 or HTTP CONNECT proxy can open outbound TCP streams through the Germany Gateway.
2. **Reverse (TCP forward):** a specifically configured TCP listener on the Germany Gateway forwards accepted connections back through the established tunnel to a specifically configured target reachable from the Dialer host.

The Dialer initiates the outer connection to the Gateway. The Gateway must not attempt to initiate a new inbound control connection to Iran.

This is deliberately *not* transparent system-wide IP routing. Without route/policy/firewall changes, arbitrary applications cannot be transparently redirected. UDP and SOCKS5 UDP ASSOCIATE are a later, separate phase; the first implementation must not claim UDP proxy support.

## Transport and authentication

- Use one persistent TLS 1.3 connection with mutual certificate authentication.
- Reuse the project's strict TLS configuration and hybrid X25519MLKEM768 key exchange. Do not add a classical key-exchange fallback.
- Validate the Gateway's configured DNS name or IP against its certificate SAN, and validate the peer certificate and exact configured client identity.
- Multiplex logical TCP streams with explicit stream IDs and message types for OPEN, OPEN_RESULT, DATA, CLOSE, and bounded keepalive/control messages.
- Use a documented, versioned binary frame format with maximum frame size, maximum open streams, per-stream and total buffering limits, open/connect deadlines, idle timeouts, and clean cancellation.
- Reject unknown message types, malformed lengths, duplicate stream IDs, data for unopened/closed streams, and resource-limit violations.
- Apply explicit allowlists for local proxy listeners, reverse public listener ports, reverse target addresses/ports, and outbound destinations. Do not accept an arbitrary target supplied by a remote peer.
- Do not expose a SOCKS or admin listener to non-loopback addresses by default. Reverse listeners must bind only to explicitly configured addresses and ports.

## Direct and Reverse semantics

### Direct

- Bind the proxy endpoint to loopback by default (for example, `127.0.0.1`).
- Support TCP CONNECT only in the first phase.
- DNS requests should be resolved on the intended side according to an explicit configuration; the implementation must not silently promise DNS-leak prevention.
- Application traffic uses the tunnel only when the application is configured to use the proxy. Other host traffic follows its existing network path unchanged.

### Reverse

- Bind only explicitly configured listener addresses and ports on the Gateway.
- Each reverse listener maps to one fixed Dialer-side target address and port.
- An inbound connection is accepted only when the listener is configured, the authenticated Dialer is present, and capacity limits allow it.
- The existing provider firewall and host firewall must already permit the listener. This feature must not add firewall rules or reload the current firewall/service to create reachability.
- If no unused and already reachable listener port exists, reverse mode cannot be deployed under a strict no-firewall-change requirement until an existing approved ingress path is made available.

## DPI and traffic visibility

TLS protects the tunneled application payload in transit, but it does **not** make the connection invisible to DPI. A network observer may still identify endpoint IP addresses, the destination port, connection timing and size patterns, and characteristics of the TLS handshake. A standard TLS connection may be classified or blocked. Do not advertise this mode as undetectable or guarantee bypass of any DPI system.

The first implementation should prioritize strong authentication, confidentiality, bounded resource use, and predictable traffic behavior. Any later transport camouflage would need separate threat modeling and review; it must not weaken TLS authentication or disguise the security properties of the connection.

## Non-goals and safety boundaries

- Do not change or flush nftables/iptables rules, UFW, NAT, routes, policy rules, packet marks, forwarding, reverse-path filtering, or DNS configuration.
- Do not create, configure, or delete TUN/TAP devices.
- Do not stop, restart, reload, or replace any existing service.
- Do not use the existing Layer-3 `dialer-up` or `gateway-up` actions for this mode.
- Do not make the listener public by default.
- Do not claim full system-wide Direct routing, UDP forwarding, or DPI invisibility in the initial version.
- Keep the current Layer-3 mode and its fail-closed network helper unchanged.

## Required implementation and test phases

### Phase A — protocol and unit tests

- Specify the wire framing and protocol version before implementation.
- Test partial reads/writes, truncated and oversized frames, invalid stream IDs, open failure, simultaneous streams, connection cancellation, backpressure, and resource-limit enforcement.
- Test certificate identity/SAN mismatches and failure to authenticate the peer.
- Ensure a malformed peer cannot cause an unbounded allocation or goroutine/stream leak.

### Phase B — isolated TCP integration tests

Run only in disposable CI network namespaces or isolated VMs. Do not run these tests on either production VPS.

The automated lab is `scripts/test-proxy-netns.sh`, wired into CI on Ubuntu 24.04 and 26.04. It creates two temporary network namespaces connected only by a veth pair, generates a disposable CA and role certificates, and gives the Gateway a synthetic public test address that is routed to loopback inside that namespace. Neither namespace has a default route to the Internet.

The current lab verifies:

- The actual proxy binary completes TLS 1.3 mutual authentication using the strict `X25519MLKEM768` group.
- Twelve Direct SOCKS5 TCP streams and twelve Reverse TCP streams can transfer data concurrently over one authenticated transport.
- Unlisted Direct destination ports and reserved/private destination addresses are rejected.
- Active Direct and Reverse flows close when the isolated Gateway transport is stopped; the still-running Dialer reconnects when the Gateway comes back.
- Interface/address, route, policy-rule, selected sysctl, nftables, iptables and ip6tables snapshots are unchanged inside both namespaces. Host routes, rules, selected sysctls and firewall configuration are captured before setup and compared after cleanup. Transient DAD flags, packet counters and save-file timestamps are normalized so the check tests configuration rather than unrelated runtime counters.

Separate generated-certificate Go tests also assert rejection of a wrong client identity and a wrong Gateway DNS SAN. The lab does not use provider networking, does not prove reachability through a production firewall, and must not be run on the two production VPSs. It intentionally does not claim HTTP CONNECT or UDP support.

### Phase C — review gates

No live deployment until all tests pass in CI and an operator confirms that the selected Gateway listener is already reachable without changing host/provider firewall state. Record the configured listener, reverse targets, direct proxy binding, certificate identities, resource limits, and a rollback plan.

The first live test, if ever approved, should be a manually started foreground process with a loopback-only Direct proxy and one deliberately selected reverse target. It must not use systemd auto-start or change existing networking. Approval to do that test is separate from this design proposal.

## Current implementation status

The draft branch now contains an initial implementation of the user-space TCP proxy path:

- `internal/proxymux/frame.go`: versioned and bounded frame codec.
- `internal/proxymux/session.go`: multiplexed logical streams with odd/even stream IDs, bounded queue sizes, keepalive, deadlines, close/half-close handling, and stream cleanup.
- `internal/proxymux/broker.go`: a reconnect-aware broker that lets listener handlers wait for an authenticated session.
- `internal/proxymux/proxy.go`: loopback-only SOCKS5 TCP CONNECT for Direct, explicit Reverse TCP listeners with named fixed targets, target-port allowlisting, and rejection of private/reserved IP ranges for Direct outbound targets.
- `cmd/pqtunnel-proxy/main.go`: explicit `gateway` and `dialer` roles using PQTunnel's strict TLS 1.3/mTLS configuration.

CI tests cover the frame codec, TLS 1.3/mTLS integration with generated certificates, exact peer identity/SAN rejection, simultaneous Direct and Reverse traffic, stream limits and bad configuration. The additional `scripts/test-proxy-netns.sh` lab runs the actual proxy binaries in separate Gateway/Dialer network namespaces, stresses 12 streams per direction, rejects disallowed destinations, drops active flows during a Gateway restart, checks Dialer reconnection, and snapshots routes/rules/selected sysctls/firewall rules before and after. Passing this lab is evidence about the proxy in a disposable namespace, not proof of reachability through either production host's firewall or a provider firewall.

### Configuration model (illustrative only)

Gateway:

```text
PQTUNNEL_PROXY_ROLE=gateway
PQTUNNEL_PROXY_LISTEN=EXPLICIT_BIND_IP:PORT
PQTUNNEL_PROXY_CA=/secure/path/ca.crt
PQTUNNEL_PROXY_CERT=/secure/path/server.crt
PQTUNNEL_PROXY_KEY=/secure/path/server.key
PQTUNNEL_PROXY_PEER_NAME=EXPECTED_CLIENT_CERT_CN
PQTUNNEL_PROXY_DIRECT_ALLOWED_PORTS=80,443
PQTUNNEL_PROXY_REVERSE_LISTENERS=web=127.0.0.1:14443
PQTUNNEL_PROXY_MAX_STREAMS=128
```

Dialer:

```text
PQTUNNEL_PROXY_ROLE=dialer
PQTUNNEL_PROXY_SERVER=GATEWAY_HOST:PORT
PQTUNNEL_PROXY_SERVER_NAME=GATEWAY_CERTIFICATE_SAN_NAME
PQTUNNEL_PROXY_CA=/secure/path/ca.crt
PQTUNNEL_PROXY_CERT=/secure/path/client.crt
PQTUNNEL_PROXY_KEY=/secure/path/client.key
PQTUNNEL_PROXY_DIRECT_LISTEN=127.0.0.1:1080
PQTUNNEL_PROXY_REVERSE_TARGETS=web=127.0.0.1:8080
PQTUNNEL_PROXY_MAX_STREAMS=128
```

The Gateway listener name and Dialer target name must match exactly. Replace every placeholder with reviewed, real values; these examples are not ready-to-run config files. Keep private keys owner-readable only (mode `0600`). A public Reverse listener must only be configured on a port that is already permitted by the host/provider's existing policy; this program does not alter the firewall to open it. The Direct allowlist is an explicit destination TCP port allowlist.

### Remaining release gates

- Extend adversarial stream tests for half-close edge cases, queue saturation, open cancellation, repeated session replacement and cleanup under `go test -race`.
- Add failure injection for target DNS changes, dial failures, malformed authenticated frames and peer shutdown at each stage of stream open/relay.
- Decide and document whether HTTP CONNECT support is needed; the first implementation supports SOCKS5 TCP CONNECT only.
- UDP forwarding, SOCKS5 UDP ASSOCIATE and transparent system-wide L3 routing are not implemented by this proxy mode.
- Do not introduce an installer/systemd unit until protocol/security tests are complete and a separate operator-approved deployment plan identifies a listener already reachable under existing firewall/provider policy.

## Current decision

The user-space proxy is now partially implemented on the draft branch, but it is **not ready for installation or production use**. In particular, the currently reviewed hosts have active tunnels, pre-enabled forwarding and existing netfilter rules. No command from this branch has been run on either production VPS; no services, routes, TUN devices, sysctls, NAT or firewall state has been changed. Do not bypass the existing Layer-3 helper's fail-closed checks.

This design avoids host route and firewall modifications for Direct/Reverse TCP proxying, but it does not make arbitrary host traffic transparently flow through the tunnel. TLS protects payload confidentiality and peer authentication; it does not guarantee DPI invisibility.
