# Routing and Tunnel Reference Review for PQTunnel

**Scope:** targeted review of the default-branch repository trees and network-relevant code paths (configuration, routing/firewall helpers, transport/mux/reverse behavior, installer scripts, tests, and license files) in the twelve requested projects. This is design research, not a line-by-line security audit of every file in each large repository.


**Upstream-first rule:** when a supplied fork is behind or has diverged, use the upstream default branch for current design and behavior. The fork is useful only to establish what differs in the supplied copy. This snapshot pins the upstream default-branch commits observed on 2026-10-16; the project descriptions below are based on upstream source links, not stale fork snapshots.

| Project | Upstream default-branch snapshot | Review note |
|---|---|---|
| XRayMesh | [102b05f](https://github.com/Erfan-XRay/XRayMesh/commit/102b05f7bb271bcc734ee50eb9247293948908d4) | Main branch release commit dated 2026-10-03 |
| WatTunnel | [d571886](https://github.com/JohnWatsoon/WatTunnel/commit/d57188673a9a3a99d2116172118adf0141c1718a) | v2.4.17 stream cleanup fix dated 2026-10-13 |
| Tunnel-Panel | [2b5b719](https://github.com/DrSaeedHub/Tunnel-Panel/commit/2b5b7190ec0ea30b390e5abddc7073e162277958) | Main branch commit dated 2026-10-02 |
| BackPack | [132467b](https://github.com/AminMGMT/BackPack/commit/132467bfdfb2698d74ada2992413e75bfccbfbd3) | Main branch commit dated 2026-10-11 |
| Kariz | [1a2d636](https://github.com/Erfan-XRay/Kariz/commit/1a2d63643bdb3dbe3345713c0c9ad5d9d875d134) | Kariz 2.6.1 commit dated 2026-10-16 |
| Golden-GRE | [cf88a2b](https://github.com/LivingG0D/Golden-GRE/commit/cf88a2b064d0e583c7f02eab1e5e2eac614d87f8) | Main branch commit dated 2026-10-14 |
| VortexL2 | [78f2a48](https://github.com/iliya-Developer/VortexL2/commit/78f2a4878b87e86e8e64f4f4c132d457cadf1142) | Main branch v4.0.0 commit dated 2026-02-09 |
| UDP2RAW | [cf255c0](https://github.com/amirmbn/UDP2RAW/commit/cf255c0f3904395d6c3d755b33822f4727e5a60b) | Main branch commit dated 2026-07-06 |
| 6TO4-GRE-IPIP-SIT | [3167bf6](https://github.com/Azumi67/6TO4-GRE-IPIP-SIT/commit/3167bf61e00f1d54cfb24f333e8b80e95a388992) | Main branch commit dated 2025-07-31 |
| Backhaul_script | [e130615](https://github.com/Azumi67/Backhaul_script/commit/e1306154a93f83baeeda8631c4259ec007dede73) | Main branch commit dated 2024-12-01 |
| WaterWall | [5c1487a](https://github.com/radkesvat/WaterWall/commit/5c1487a2be615b7724e9223e78c6687004fa11e7) | Active upstream main; commit dated 2026-10-16. Do not use the much-staler supplied fork as the current implementation reference |
| IPTABLE-Tunnel-multi-port | [73fe935](https://github.com/azavaxhuman/IPTABLE-Tunnel-multi-port/commit/73fe935e86b8ae74fb83901c2624204fdf6e664d) | Main branch commit dated 2024-01-04 |


**Production safety decision:** neither `example-host-1` nor `example-ubuntu-host` is to be changed by this work. Both have existing TUN/tunnel services, netfilter rules and forwarding state. PQTunnel's existing Layer-3 helper intentionally fails closed on these hosts; do not bypass it or import scripts that mutate global routes/firewall state.

## Findings by project

### 1. XRayMesh
- Sources: [user fork](https://github.com/hatinati2/XRayMesh), [upstream](https://github.com/Erfan-XRay/XRayMesh), [upstream license](https://github.com/Erfan-XRay/XRayMesh/blob/main/LICENSE).
- Architecture: EasyTier-based encrypted mesh, separate engines for port forwarding (HAProxy, iptables, GOST and Realm), and BackPack-backed ICMP/PCK links. Its own tests cover port parsing and selected iptables tunnel invariants.
- Fork state: the default branch is 4 commits behind upstream with no fork-only commits in the compared mainline history.
- Reuse decision: concept study only. Its source-available license explicitly prohibits republishing, derivatives and using any part as the basis of another project without prior written permission. Do not copy XRayMesh code into PQTunnel. The matching XRayMesh/BackPack-related services are already active on the user's hosts; do not run its installer or update scripts on those hosts.

### 2. WatTunnel
- Sources: [user fork](https://github.com/hatinati2/WatTunnel), [upstream](https://github.com/JohnWatsoon/WatTunnel), [configuration](https://github.com/JohnWatsoon/WatTunnel/blob/main/cmd/wattun/config.go), [reverse carrier adapter](https://github.com/JohnWatsoon/WatTunnel/blob/main/wat/carrier_reverse.go).
- Architecture: one process handles many TCP/UDP port mappings; it distinguishes a client-side listen port from the server-side target port and separately validates the server's target-port allowlist. It has multiple carriers and a reverse direction built from a listener pool plus a reconnecting dialer pool. Session limits, idle timeout, bounded queues and diagnostics are useful design references.
- Upstream-first finding from v2.4.17 ([commit](https://github.com/JohnWatsoon/WatTunnel/commit/d57188673a9a3a99d2116172118adf0141c1718a), 2026-10-13): it fixed a lingering-stream leak when a local connection closes with buffered unread data or while the peer is still sending. Its regression tests specifically assert that both peer sessions release the stream. PQTunnel now has an independent target-disconnect stream-reaping regression test; its race/backpressure lifecycle still needs continued testing.
- Fork state: 50 commits behind upstream and no fork-only commits in the compared mainline history. The upstream license is MIT.
- Reuse decision: use behavior and test ideas as reference; do not add alternate carriers before the standard TLS/mTLS stream mode is complete. The ICMP carrier and the project's custom AEAD/session protocol are separate designs, not a drop-in PQTunnel transport.

### 3. Tunnel-Panel
- Sources: [user fork](https://github.com/hatinati2/Tunnel-Panel), [upstream route planner](https://github.com/DrSaeedHub/Tunnel-Panel/blob/main/internal/route/plan.go), [safety guard](https://github.com/DrSaeedHub/Tunnel-Panel/blob/main/internal/safety/route.go), [route reconciliation](https://github.com/DrSaeedHub/Tunnel-Panel/blob/main/internal/reconcile/routes.go), [namespace regression](https://github.com/DrSaeedHub/Tunnel-Panel/blob/main/internal/route/lab_integration_test.go).
- Architecture: deterministic preview/plans; guardrails against forwarding SSH/panel ports; per-subsystem ownership; explicit foreign-rule reporting; read-only reconciliation; and reversible apply plans. These are the strongest operational-safety ideas in the reviewed set.
- Fork state: the default branch is identical to upstream. No LICENSE file was present in the fork's root tree, so code reuse rights are not established.
- Reuse decision: follow the design principles, not source code. In the current project the appropriate action is still no host firewall/routing writes. A separate coexistence backend would need its own license review and lab tests.

### 4. BackPack
- Sources: [user fork](https://github.com/hatinati2/BackPack), [upstream](https://github.com/AminMGMT/BackPack), [direct-stream session](https://github.com/AminMGMT/BackPack/blob/main/internal/tunnel/direct/session.go), [target validation](https://github.com/AminMGMT/BackPack/blob/main/internal/tunnel/direct/target.go), [mux server session](https://github.com/AminMGMT/BackPack/blob/main/internal/server/transport/muxsession.go), [direct docs](https://github.com/AminMGMT/BackPack/blob/main/docs/direct-tunnel.md).
- Architecture: direct versus reverse connection direction; multiplexed logical streams; per-session/per-stream bounds; explicit deadlines; reconnect/backoff; stream cleanup and slot release; UDP as an explicit opt-in; and target validation to reject dangerous metadata IPs. The current upstream wizard's Direct mode is Layer-3, while its legacy stream Direct implementation still exists; do not confuse those modes.
- Fork state: 45 commits behind upstream and no fork-only commits in the compared mainline history. Upstream is AGPL-3.0 with additional attribution/trademark conditions.
- Reuse decision: these are good engineering patterns, but no BackPack source will be copied into PQTunnel without an explicit licensing decision. Keep PQTunnel's strict mutual TLS identity and hybrid TLS configuration rather than replacing them with a shared-token-only handshake.

### 5. Kariz
- Sources: [user fork](https://github.com/hatinati2/Kariz), [upstream](https://github.com/Erfan-XRay/Kariz), [network/GRE docs](https://github.com/Erfan-XRay/Kariz/blob/main/docs/networks.md), [Direct config](https://github.com/Erfan-XRay/Kariz/blob/main/configs/entry-direct.toml), [Reverse config](https://github.com/Erfan-XRay/Kariz/blob/main/configs/exit-reverse.toml), [GRE namespace test](https://github.com/Erfan-XRay/Kariz/blob/main/tests/gre_ns.sh).
- Architecture: a clear role/mode distinction; fixed `listen -> target` mappings; reverse mode keeps an outbound pool; UDP forwarding is an explicit setting; and its private-GRE-network feature checks for overlapping CIDRs, reserves unique link keys, and tests filtered GRE behavior in disposable namespaces.
- Fork state: the fork's current mainline has no common ancestor with upstream, so a reliable standard compare could not establish fork-only changes. The checked-in Kariz license is source-available and explicitly forbids use of the Core/protocol/config in other projects.
- Reuse decision: concept study only; do not copy Kariz code, wire format or configuration schema. GRE is protocol 47, can be filtered, and requires interface/route changes; it is not suitable as the no-network-change fallback here.

### 6. Golden-GRE
- Sources: [user fork](https://github.com/hatinati2/Golden-GRE), [upstream](https://github.com/LivingG0D/Golden-GRE), [bring-up script](https://github.com/hatinati2/Golden-GRE/blob/main/scripts/golden-gre-up.sh), [preflight script](https://github.com/hatinati2/Golden-GRE/blob/main/scripts/preflight.sh).
- Architecture: Linux FOU wraps GRE in UDP; per-tunnel devices/configs, explicit routes, conservative MTU defaults and TCP MSS clamping are relevant concepts for a future Layer-3 lab.
- Fork state: 46 commits behind upstream; Apache-2.0.
- Compatibility risks in the reviewed fork: bring-up uses `ip link del "$DEV"` before recreating the interface, inserts global FORWARD mangle rules, may add MASQUERADE, and relies on kernel modules/sysctl. The preflight's `modprobe` calls can change kernel module state. None of this is acceptable as an experiment on the current sensitive VPSs.

### 7. VortexL2
- Sources: [user fork](https://github.com/hatinati2/VortexL2), [upstream](https://github.com/iliya-Developer/VortexL2), [tunnel implementation](https://github.com/hatinati2/VortexL2/blob/main/vortexl2/tunnel.py), [forwarding documentation](https://github.com/hatinati2/VortexL2/blob/main/README.md).
- Architecture: L2TPv3 with IP or UDP encapsulation, with port forwarding handled separately through HAProxy or socat. Its helper adjusts MTU, reverse-path filtering, forwarding, and in UDP mode inserts iptables rules.
- Fork state: 25 commits behind upstream; MIT.
- Compatibility: `l2tpeth0` and the VortexL2 services are already present on both reviewed servers. Do not reinstall, reconfigure or restart this system as part of PQTunnel work.

### 8. UDP2RAW
- Sources: [user fork](https://github.com/hatinati2/UDP2RAW), [upstream](https://github.com/amirmbn/UDP2RAW), [user fork setup script](https://github.com/hatinati2/UDP2RAW/blob/main/udp2raw.sh).
- Architecture: raw-socket encapsulation options such as fake-TCP can carry a separate transport, but this is not the same thing as end-to-end TLS authentication and does not guarantee invisibility to traffic classification.
- Fork state: 33 commits behind upstream; Apache-2.0.
- Compatibility risks: the script installs downloadable binaries, writes persistent forwarding settings, runs `sysctl -p`, creates/restarts systemd services, and asks for firewall changes. Do not run it or integrate these host-level actions into the no-network-change PQTunnel mode.

### 9. 6TO4-GRE-IPIP-SIT
- Sources: [user fork](https://github.com/hatinati2/6TO4-GRE-IPIP-SIT), [upstream](https://github.com/Azumi67/6TO4-GRE-IPIP-SIT), [wrapper](https://github.com/hatinati2/6TO4-GRE-IPIP-SIT/blob/main/lightweight.sh).
- Architecture: a broad catalogue of kernel encapsulation mechanisms and manual MTU/default-route options.
- Fork state: identical to upstream on the default branch; GPL-3.0.
- Compatibility risks: the visible launcher installs packages, downloads and runs another script; other tunnel types require route, sysctl, interface or systemd changes. It is not a safe way to add another tunnel to the current multi-tunnel hosts and no code is copied.

### 10. Backhaul_script
- Sources: [user fork](https://github.com/hatinati2/Backhaul_script), [upstream](https://github.com/Azumi67/Backhaul_script), [launcher](https://github.com/hatinati2/Backhaul_script/blob/main/backhaul.sh).
- Architecture documented in the repository includes reverse forwarding over TCP, TCP mux, WebSocket/WSS, and UDP, with a token and configurable listener/target port mappings.
- Fork state: 5 commits behind upstream; MIT.
- Audit limitation: the checked-in shell files are launchers that download a separate `backhaul.py` from a release URL; the actual implementation is not committed in this repository. The download is not pinned to a verified immutable SHA in the launcher. Treat the README as a feature inventory, not as a complete security audit.

### 11. WaterWall
- Sources: [user fork](https://github.com/hatinati2/WaterWall), [upstream](https://github.com/radkesvat/WaterWall), [reverse client](https://github.com/radkesvat/WaterWall/blob/main/tunnels/client/reverse/reverse_client.c), [mux client](https://github.com/radkesvat/WaterWall/blob/main/tunnels/client/mux/mux_client.c), [TCP connector](https://github.com/radkesvat/WaterWall/blob/main/tunnels/adapters/connector/tcp/tcp_connector.c).
- Architecture: a modular node pipeline with listener/connector adapters, reverse connection pools, multiplexing, explicit queue/backpressure management and per-connection state cleanup.
- Fork state: 2,793 commits behind upstream; MPL-2.0.
- Reuse decision: only the broad modular design is considered. The fork is too stale to be a safe source of current implementation details; any source copying would need MPL-2.0 review and file-level compliance.

### 12. IPTABLE-Tunnel-multi-port
- Sources: [user fork](https://github.com/hatinati2/IPTABLE-Tunnel-multi-port), [upstream](https://github.com/azavaxhuman/IPTABLE-Tunnel-multi-port), [tunnel script](https://github.com/hatinati2/IPTABLE-Tunnel-multi-port/blob/main/tunnel.sh).
- Architecture: direct DNAT/SNAT for selected TCP/UDP ports.
- Fork state: identical to upstream on the default branch; GPL-3.0.
- Critical incompatibility: the script changes forwarding, appends broad NAT rules, persists the entire `iptables-save` output, and exposes a menu option to flush all iptables rules. Never run this on either current server and do not port this style into PQTunnel.

## Cross-project decisions for PQTunnel

### Use the good design ideas

1. Model Direct and Reverse as explicit roles sharing one long-lived Dialer-initiated authenticated transport. Direct is a per-application local TCP proxy; Reverse is a fixed Gateway listener mapped to a fixed Dialer-side destination. Both can multiplex logical streams across the same transport.
2. Define per-listener and per-target allowlists in configuration; never let an authenticated remote peer request arbitrary host/port targets. Reject local metadata endpoints and protected listeners.
3. Bound maximum frame size, total streams, stream buffers, connection attempts and connect/handshake deadlines. Release stream/connection capacity on every failure path. Use keepalives, reconnect backoff, and actionable, rate-limited diagnostics.
4. Keep TCP and UDP mappings distinct; UDP should remain off unless a datagram-flow implementation, idle expiry, response routing, and resource limits are tested. Start with TCP.
5. Treat route/firewall changes as a separate optional subsystem. If that is ever expanded, require a deterministic preview, ownership tracking, an explicit state journal, pre/post snapshots, fail-closed conflict detection, and rollback tests in isolated namespaces.

### Do not bring over

- No raw `iptables -F`, `iptables-restore` of a global snapshot, broad FORWARD accept, unscoped MASQUERADE, global routing/default-route changes, or automatic sysctl writes.
- No deleting an interface just because its configured name is occupied.
- No reuse of XRayMesh or Kariz source/code/protocol under their current source-available licenses; no Tunnel-Panel source reuse without licensing permission; no BackPack source reuse without an explicit AGPL-3.0 compliance decision.
- No promise that TCP, TLS, fake-TCP, ICMP, GRE-in-UDP or another carrier is undetectable by DPI. TLS protects payload confidentiality and authenticates the peer, but transport metadata and traffic patterns may remain observable.

## Recommended work sequence

1. Finish and test PQTunnel's independent frame protocol and stream lifecycle in CI.
2. Implement the TCP Direct local proxy and Reverse fixed-target listener over the same mTLS session, with target protections and concurrent-stream limits.
3. Test both directions concurrently in disposable network namespaces; compare routes, sysctls and firewall rule snapshots before/after and assert exact equality except counters.
4. Leave current production VPSs untouched until tests pass and an already-reachable Gateway listener can be used without firewall changes. The existing Layer-3 network helper must remain fail-closed.
