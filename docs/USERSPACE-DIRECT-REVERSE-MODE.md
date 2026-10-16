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

- Start a fake Gateway and Dialer-side TCP target inside namespaces.
- Verify a SOCKS5/HTTP CONNECT Direct connection traverses the TLS transport and returns the expected payload.
- Verify a Gateway reverse listener reaches only its configured Dialer target.
- Run Direct and Reverse concurrently over the same transport.
- Verify disallowed targets/ports, unauthenticated peers, and non-loopback proxy binds are rejected.
- Seed namespaces with representative unrelated host-firewall chains, mangle rules, and raw/NOTRACK rules. Confirm the proxy mode never changes the seeded rules or routing state.
- Compare snapshots before/after tests for routes, sysctls, and firewall rules; ignore only packet counters.
- Inject failures during connect, stream open, data transfer, and shutdown; assert deterministic cleanup without touching unrelated resources.

### Phase C — review gates

No live deployment until all tests pass in CI and an operator confirms that the selected Gateway listener is already reachable without changing host/provider firewall state. Record the configured listener, reverse targets, direct proxy binding, certificate identities, resource limits, and a rollback plan.

The first live test, if ever approved, should be a manually started foreground process with a loopback-only Direct proxy and one deliberately selected reverse target. It must not use systemd auto-start or change existing networking. Approval to do that test is separate from this design proposal.

## Current decision

This proposal is an alternative to transparent Layer-3 routing when firewall and route changes are prohibited. It is not implemented yet and must not be treated as an install guide. The production hosts remain untouched.
