# Existing firewall and tunnel coexistence — design note

**Status: proposal only; not an installation guide and not approval for live deployment.**

PQTunnel's current network helper intentionally rejects hosts with existing firewall rules or pre-enabled forwarding. Keep that fail-closed behavior. This note defines what must be designed and tested before a separate coexistence mode can be implemented.

No production host has been changed by this proposal. Any future network integration must first be tested in disposable network namespaces and isolated Linux VMs.

## Why the current guard must remain

`scripts/site-to-site-selective.sh` currently checks for existing UFW, nftables, and iptables state before applying routes or firewall rules. It also checks the selected policy-routing priorities and route tables. Its current mode is intended for a dedicated lab host, not for a general-purpose VPS with an existing tunnel or firewall manager.

Simply deleting `check_no_existing_firewall`, adding an `--allow-existing-firewall` switch, or changing a base chain's policy to `accept` is not a safe compatibility feature:

- An nftables `accept` verdict in one base chain does not guarantee that a later base chain will not drop the same packet.
- A base chain with policy `drop` can block unrelated forwarded traffic if its rules are too broad.
- The common `iptables-nft` backend represents iptables-managed tables inside nftables. Those tables must not be edited independently with native nft commands.
- Existing mangle rules may set marks or alter MSS; overwriting packet marks can change another service's policy routing.
- Existing raw-table `NOTRACK` rules can bypass conntrack, which can break NAT/DNAT assumptions for overlapping traffic.
- Globally changing forwarding or reverse-path filtering can affect unrelated VPNs, tunnels, containers, or routes.
- Removing rules by table name or flushing a ruleset could destroy rules owned by another service.

## Required design principles

1. **Keep modes separate.** The present dedicated-host mode remains fail-closed. Any coexistence backend must be an explicitly designed and separately tested implementation, not a bypass around the existing checks.
2. **Never own global firewall state.** Do not flush, replace, or rewrite existing `inet/ip/ip6 filter`, `mangle`, `raw`, NAT tables, UFW files, or persistent iptables rules. Do not disable a firewall manager.
3. **Scope every new rule.** Filter and NAT rules must match the dedicated PQTunnel interface, expected overlay source/destination prefixes, and specifically configured protocols/ports. Rules must not alter unrelated forwarded packets. The exact chain-hook priorities and interaction with other base chains must be proven in tests.
4. **Detect the backend and refuse unsupported combinations.** UFW-active, firewalld-managed, native nftables, and iptables-nft systems do not have identical integration semantics. A backend must declare which combinations it supports; unknown ownership or an unrecognized ruleset means stop without changes.
5. **Reserve marks and policy routing.** Check both IPv4 and IPv6 rule priorities, tables, fwmarks/mark masks, output-routing rules, and endpoint-route behavior. Do not overwrite unrelated mark bits or assume an empty route table proves a mark is unused.
6. **Preserve sysctls.** A coexistence mode must never turn off a pre-enabled forwarding setting during rollback. Prefer requiring the necessary forwarding state to be explicitly prepared and reviewed; if a future mode changes a value, it must record the prior value and restore it only if the value still equals the one PQTunnel set. Do not auto-adjust `rp_filter` or `src_valid_mark` without a documented, tested requirement.
7. **Avoid conntrack conflicts.** Check new listener and forwarding ports against existing raw/NOTRACK rules. Do not silently change or delete NOTRACK behavior. A conflict must produce a clear preflight failure.
8. **Track ownership before applying.** Write a root-owned, restrictive state journal before the first network mutation. Track every resource created by PQTunnel. Rollback may remove only resources whose existence and ownership are proven by that journal; it must preserve all unrelated firewall rules, routes, links, and sysctls.
9. **Persistence is a separate concern.** Do not overwrite `/etc/iptables/rules.v4`, `rules.v6`, UFW files, or native nftables configuration. The persistence mechanism must be reviewed for the selected backend and must not race the existing firewall service during boot or shutdown.
10. **Document unsupported use plainly.** Coexistence is not supported merely because preflight exits zero or because rules can be inserted successfully. The relevant traffic and rollback tests must pass first.

## Required validation before implementation is considered ready

Tests must run only inside disposable network namespaces or isolated VMs:

- Seed the lab with a representative pre-existing `iptables-nft` ruleset: INPUT/FORWARD/OUTPUT chains, mangle rules, raw/NOTRACK examples, and unrelated accepted traffic.
- Capture baseline connectivity for unrelated TCP, UDP, DNS, ICMP, and IPv4/IPv6 routes; verify the same traffic still works during and after PQTunnel tests.
- Test selective egress and inbound TCP/UDP forwarding with allowed ports, blocked ports, wrong-protocol ports, and disjoint IPv4/IPv6 prefixes.
- Verify that a firewall-owned drop still blocks traffic unless the selected firewall-manager integration explicitly allows it. Never claim that a separate nftables accept rule overrides UFW or another base chain.
- Inject failures after each mutation step: TUN creation/addressing, route/rule installation, nft apply, forwarding preparation, service startup, and rollback. Compare the prior and resulting rules/routes/sysctls, ignoring packet counters that legitimately increase.
- Test pre-existing policy priority, route-table, mark, interface-name, NAT, and NOTRACK conflicts. Each conflict must stop before taking ownership of another resource.
- Test service stop/start, daemon crash, boot ordering, and reboot on isolated hosts, including the four Ubuntu 24.04/26.04 pairings.
- Keep a reproducible test log and explicit go/no-go checklist. Passing current CI or a namespace test does not establish compatibility with a VPS provider's firewall.

## Deployment gates

Before any live rollout, an operator must identify the current firewall manager and rule owners, decide whether PQTunnel replaces or runs alongside each existing tunnel, document current routes/marks/sysctls and provider-side firewall rules, verify independent out-of-band recovery, and rehearse rollback on equivalent disposable hosts.

A generic coexistence mode must not be added until at least one clearly specified backend has passed the tests above. If the environment uses an unsupported or mixed manager setup, the correct result is a clear refusal and a backend-specific integration plan—not a forced install.

## Current decision

**No live installation, service start, route change, forwarding change, NAT edit, or firewall edit is authorized by this document.** Continue using read-only preflight on the real hosts. Develop and test the coexistence design separately.


## Disposable lab regression

CI runs `scripts/test-firewall-coexistence-netns.sh` in three disposable network namespaces. It models an existing forward chain with a default-drop policy and a separate later PQTunnel-like allow chain. The test asserts that the independent allow chain cannot override the earlier drop verdict, then demonstrates a narrow allow in the owning host-firewall chain that explicitly permits new and established packets. The test topology, routes, forwarding setting and firewall rules are confined to temporary namespaces and removed by cleanup.

This is a rule-ordering contract test, not a general production coexistence implementation. A real backend still has to integrate with the firewall manager that owns the active ruleset (including UFW or an iptables-nft-managed configuration), preserve packet-mark and conntrack assumptions, and be tested against a sanitized existing ruleset in a disposable VM before any live rollout.


## Read-only host inventory before backend design

The optional `scripts/site-to-site-coexistence-audit.py` inventory summarizes nftables hook priorities and policies plus per-chain counts for NOTRACK, packet marks, NAT and verdicts. It deliberately omits raw rule text, IP addresses, ports and counters. It helps design a backend against the owning firewall manager; it is not permission to apply changes.


### Interpreting compatibility-backend counts and NOTRACK scope

When `iptables -V` reports `nf_tables`, the `iptables-save` output is another view of the nftables-backed ruleset. Its rule totals overlap with the `nft -j list ruleset` total; do not add them together. Some compatibility expressions may be classified differently by the nft JSON summary, so review both views.

The audit prints per-rule NOTRACK selector *types* (interface, protocol, address, port, connection, mark, or other) without their values. `selectors=none-detected` means no selector from the audit's recognized set was identified; it is not proof that a rule matches all traffic. The output is a privacy-preserving clue for lab design, not enough by itself to prove whether a specific PQTunnel flow overlaps a NOTRACK rule.


### Opaque xtables-compat fallback in nft JSON

Some libnftables versions serialize an xtables-compatibility statement as `{"xt": null}`. In that case, nft JSON confirms an opaque compatibility extension exists but does not expose its target name. The audit reports `xt_fallback` for any such extension and `xt_opaque` when the extension name is not available. A rule counted as `xt_opaque` must not be guessed to be NOTRACK, NAT, MARK, or a verdict. Use the sanitized `iptables-save` category output to identify known target types and keep the native nft JSON view marked as opaque. If `xt_opaque` is nonzero, the native summary alone is insufficient to assert that its target categories agree with the compatibility view.


### Distinguishing XT matches from XT targets

The privacy-preserving audit counts xtables-compat entries by their declared type (`match`, `target`, or `watcher`). It only classifies names such as NOTRACK, MARK, NAT targets, DROP/REJECT, and ACCEPT as actions when the XT entry type is `target`. A match extension with a similar name must not be mistaken for an action. `xt_fallback` by itself only means that a rule includes an xtables-compat entry; it does not identify which action the rule performs. The audit reports only aggregate categories, never the extension's raw name or the rule's selector values.


### Distinguishing NOTRACK mechanisms without exposing rules

The audit separately labels the iptables-save form as `direct_target` (the NOTRACK target) or `ct_target_option` (the CT target with the `--notrack` option). It reports only these fixed labels, table/chain names, and selector categories; it does not print ports, addresses, or raw expressions. In nft JSON, a named CT target is reported as `xt_ct_target` but is not automatically counted as NOTRACK, because the XT fallback may not expose the target options. Compare the two views at the same raw chain; matching counts are useful evidence but do not reveal the packet values matched by the rules.
