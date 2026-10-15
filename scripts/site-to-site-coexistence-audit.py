#!/usr/bin/env python3
"""Read-only firewall inventory. Never print raw rules, addresses, ports or counters."""
from __future__ import annotations
import argparse
import json
import re
import subprocess
import shlex
from collections import defaultdict
from pathlib import Path
from typing import Any

CATEGORIES = ("notrack", "packet_mark", "nat", "drop_reject", "accept", "xt_fallback", "xt_opaque", "xt_match", "xt_target", "xt_watcher", "xt_type_unknown", "xt_ct_target", "xt_target_other")

def walk_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key.lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)

def walk_xt_entries(value: Any):
    """Yield (type, name, opaque) for xtables-compat fallback objects."""
    if isinstance(value, dict):
        if "xt" in value:
            xt_obj = value.get("xt")
            if isinstance(xt_obj, dict) and isinstance(xt_obj.get("name"), str):
                xt_type = xt_obj.get("type")
                yield (xt_type.lower() if isinstance(xt_type, str) else "",
                       xt_obj["name"].lower(), False)
            else:
                # Some libnftables versions expose only {"xt": null}, which
                # proves an xtables fallback exists but hides its extension name.
                yield "", "", True
        for child in value.values():
            yield from walk_xt_entries(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_xt_entries(child)

def expr_categories(expr: Any) -> set[str]:
    keys = set(walk_keys(expr))
    # XT extension names are meaningful only together with their type.
    # A match named "mark" is not the same as a MARK target.
    xt_entries = list(walk_xt_entries(expr))
    xt_targets = {name for xt_type, name, opaque in xt_entries
                  if not opaque and xt_type == "target" and name}
    out: set[str] = set()
    valid_types = {"match", "target", "watcher"}
    if xt_entries:
        out.add("xt_fallback")
    if any(opaque for _, _, opaque in xt_entries):
        out.add("xt_opaque")
    if any(not opaque and xt_type == "match" for xt_type, _, opaque in xt_entries):
        out.add("xt_match")
    if any(not opaque and xt_type == "target" for xt_type, _, opaque in xt_entries):
        out.add("xt_target")
    if any(not opaque and xt_type == "watcher" for xt_type, _, opaque in xt_entries):
        out.add("xt_watcher")
    if any(not opaque and xt_type not in valid_types
           for xt_type, _, opaque in xt_entries):
        out.add("xt_type_unknown")
    if any(not opaque and xt_type == "target" and name == "ct"
           for xt_type, name, opaque in xt_entries):
        out.add("xt_ct_target")
    recognized_targets = {
        "notrack", "ct", "mark", "connmark", "dnat", "snat", "masquerade",
        "redirect", "drop", "reject", "accept",
    }
    if any(name not in recognized_targets for name in xt_targets):
        out.add("xt_target_other")
    if "notrack" in keys or "notrack" in xt_targets:
        out.add("notrack")
    if "mark" in keys or "mangle" in keys or {"mark", "connmark"} & xt_targets:
        out.add("packet_mark")
    if {"dnat", "snat", "masquerade", "redirect"} & (keys | xt_targets):
        out.add("nat")
    if {"drop", "reject"} & (keys | xt_targets):
        out.add("drop_reject")
    if "accept" in keys or "accept" in xt_targets:
        out.add("accept")
    return out

def parse_nft_json(data: dict[str, Any]) -> dict[str, Any]:
    tables: set[tuple[str, str]] = set()
    chains: dict[tuple[str, str, str], dict[str, Any]] = {}
    rules: dict[tuple[str, str, str], dict[str, int]] = defaultdict(
        lambda: {"rules": 0, **{cat: 0 for cat in CATEGORIES}}
    )
    for item in data.get("nftables", []):
        if not isinstance(item, dict):
            continue
        table_obj = item.get("table")
        if isinstance(table_obj, dict):
            tables.add((str(table_obj.get("family", "?")), str(table_obj.get("name", "?"))))
            continue
        chain_obj = item.get("chain")
        if isinstance(chain_obj, dict):
            key = (str(chain_obj.get("family", "?")), str(chain_obj.get("table", "?")), str(chain_obj.get("name", "?")))
            chains[key] = {field: chain_obj.get(src) for field, src in (
                ("hook", "hook"), ("type", "type"), ("priority", "prio"), ("policy", "policy")
            )}
            tables.add((key[0], key[1]))
            continue
        rule_obj = item.get("rule")
        if isinstance(rule_obj, dict):
            key = (str(rule_obj.get("family", "?")), str(rule_obj.get("table", "?")), str(rule_obj.get("chain", "?")))
            counts = rules[key]
            counts["rules"] += 1
            for cat in expr_categories(rule_obj.get("expr", [])):
                counts[cat] += 1
            tables.add((key[0], key[1]))
    return {"tables": sorted(tables), "chains": chains, "rules": dict(rules)}

def notrack_mechanism(line: str) -> str:
    """Classify NOTRACK mechanics using parsed rule options, never comment text."""
    features = iptables_rule_features(line)
    if features is None:
        return "other_notrack_match"
    return features["notrack_mechanism"]


def iptables_jump_target(line: str) -> str | None:
    """Return the actual -j/--jump target, ignoring option values and comments."""
    parsed = iptables_rule_options(line)
    if parsed is None:
        return None
    for option, args in parsed:
        if option in ("-j", "--jump") and args:
            return args[0].upper()
    return None

SELECTOR_OPTION_CATEGORIES = {
    "-i": "interface", "--in-interface": "interface",
    "-o": "interface", "--out-interface": "interface",
    "-p": "protocol", "--protocol": "protocol",
    "-s": "address", "--source": "address",
    "-d": "address", "--destination": "address",
    "--src": "address", "--dst": "address",
    "--sport": "port", "--source-port": "port", "--sports": "port",
    "--dport": "port", "--destination-port": "port", "--dports": "port",
    "--ports": "port",
    "--ctstate": "connection", "--state": "connection",
    "--ctstatus": "connection", "--ctdir": "connection", "--ctexpire": "connection",
    "--mark": "mark", "--ctmark": "mark", "--nfmark": "mark",
    "--nfmask": "mark", "--ctmask": "mark",
    "--tcp-flags": "tcp_flags", "--syn": "tcp_flags",
}
OTHER_SELECTOR_ARITY = {
    "-f": 0, "--fragment": 0, "--icmp-type": 1, "--icmpv6-type": 1,
    "--uid-owner": 1, "--gid-owner": 1, "--socket-exists": 0,
    "--limit": 1, "--limit-burst": 1, "--hashlimit": 1, "--string": 1,
    "--mac-source": 1, "--length": 1, "--frag": 1, "--probability": 1,
    "--src-type": 1, "--dst-type": 1, "--physdev-in": 1, "--physdev-out": 1,
}
IGNORABLE_MATCH_MODULES = {
    "comment", "tcp", "udp", "icmp", "icmp6", "ipv6-icmp", "multiport",
    "conntrack", "state", "mark", "connmark",
}

# Consume argument-bearing options so a quoted value is never reinterpreted
# as another selector (for example --comment "--ctstate NEW").
OPTION_ARITY = {
    "-A": 1, "--append": 1, "-m": 1, "--match": 1, "-p": 1, "--protocol": 1,
    "-i": 1, "--in-interface": 1, "-o": 1, "--out-interface": 1,
    "-s": 1, "--source": 1, "-d": 1, "--destination": 1, "--src": 1, "--dst": 1,
    "--sport": 1, "--source-port": 1, "--sports": 1,
    "--dport": 1, "--destination-port": 1, "--dports": 1, "--ports": 1,
    "--ctstate": 1, "--state": 1, "--ctstatus": 1, "--ctdir": 1, "--ctexpire": 1,
    "--mark": 1, "--ctmark": 1, "--nfmark": 1, "--nfmask": 1, "--ctmask": 1,
    "--tcp-flags": 2, "--syn": 0,
    "--comment": 1, "--set-mark": 1, "--set-xmark": 1, "--set-nfmark": 1,
    "--restore-mark": 0, "--save-mark": 0,
    "-j": 1, "--jump": 1, "-g": 1, "--goto": 1,
    "--to-source": 1, "--to-destination": 1, "--to-ports": 1,
    "--limit": 1, "--limit-burst": 1, "--hashlimit": 1, "--string": 1,
    "--mac-source": 1, "--length": 1, "--frag": 1, "--probability": 1,
    "--src-type": 1, "--dst-type": 1, "--physdev-in": 1, "--physdev-out": 1,
    "-f": 0, "--fragment": 0, "--icmp-type": 1, "--icmpv6-type": 1,
    "--uid-owner": 1, "--gid-owner": 1, "--socket-exists": 0,
}

def iptables_rule_options(line: str) -> list[tuple[str, tuple[str, ...]]] | None:
    """Parse iptables options and their values, so quoted values cannot impersonate flags."""
    try:
        tokens = shlex.split(line, comments=True, posix=True)
    except ValueError:
        return None

    parsed: list[tuple[str, tuple[str, ...]]] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == "!":
            parsed.append(("!", ()))
            i += 1
            continue

        has_inline_value = token.startswith("--") and "=" in token
        if has_inline_value:
            option, inline_value = token.split("=", 1)
            arity = OPTION_ARITY.get(option)
            if arity is None:
                parsed.append((option, (inline_value,)))
                i += 1
                continue
            extra_args = max(arity - 1, 0)
            if len(tokens) - i - 1 < extra_args:
                return None
            args = (inline_value, *tokens[i + 1:i + 1 + extra_args])
            parsed.append((option, tuple(args)))
            i += 1 + extra_args
            continue

        if token in OPTION_ARITY:
            arity = OPTION_ARITY[token]
            if len(tokens) - i - 1 < arity:
                return None
            args = tuple(tokens[i + 1:i + 1 + arity])
            parsed.append((token, args))
            i += 1 + arity
            continue

        if token.startswith("-"):
            parsed.append((token, ()))
        i += 1

    return parsed


def iptables_selector_categories(line: str) -> list[str]:
    """Return selector *types*, never values, using parsed option tokens."""
    parsed = iptables_rule_options(line)
    if parsed is None:
        return ["other"]

    selectors: set[str] = set()
    for option, args in parsed:
        if option in SELECTOR_OPTION_CATEGORIES:
            selectors.add(SELECTOR_OPTION_CATEGORIES[option])
        if option in OTHER_SELECTOR_ARITY:
            selectors.add("other")
        if option in ("-m", "--match"):
            if not args:
                return sorted(selectors | {"other"})
            if args[0].lower() not in IGNORABLE_MATCH_MODULES:
                selectors.add("other")
    return sorted(selectors)


def iptables_rule_features(line: str) -> dict[str, Any] | None:
    """Classify real iptables targets/options without matching quoted text."""
    parsed = iptables_rule_options(line)
    if parsed is None:
        return None

    targets = [
        args[0].upper()
        for option, args in parsed
        if option in ("-j", "--jump") and args
    ]
    modules = {
        args[0].lower()
        for option, args in parsed
        if option in ("-m", "--match") and args
    }
    option_names = {option for option, _ in parsed}
    has_notrack_option = "--notrack" in option_names
    has_notrack_target = "NOTRACK" in targets
    notrack = has_notrack_target or has_notrack_option

    if "CT" in targets and has_notrack_option:
        mechanism = "ct_target_option"
    elif has_notrack_target:
        mechanism = "direct_target"
    elif has_notrack_option:
        mechanism = "option_other_target"
    else:
        mechanism = "other_notrack_match"

    mark_options = {
        "--set-mark", "--set-xmark", "--set-nfmark",
        "--restore-mark", "--save-mark",
    }
    packet_mark = bool(
        {"MARK", "CONNMARK"} & set(targets)
        or mark_options & option_names
        or {"mark", "connmark"} & modules
    )
    nat = bool({"DNAT", "SNAT", "MASQUERADE", "REDIRECT"} & set(targets))
    drop_reject = bool({"DROP", "REJECT"} & set(targets))
    accept = "ACCEPT" in targets
    return {
        "jump_targets": targets,
        "notrack": notrack,
        "notrack_mechanism": mechanism,
        "packet_mark": packet_mark,
        "nat": nat,
        "drop_reject": drop_reject,
        "accept": accept,
    }


PORT_OPTIONS = {
    "--sport": "source", "--source-port": "source", "--sports": "source",
    "--dport": "destination", "--destination-port": "destination", "--dports": "destination",
    "--ports": "either",
}

def parse_port_spec(value: str) -> list[tuple[int, int]] | None:
    """Parse numeric iptables ports/ranges without resolving or exposing service names."""
    ranges: list[tuple[int, int]] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            return None
        if ":" in item:
            if item.count(":") != 1:
                return None
            low_s, high_s = item.split(":", 1)
            try:
                low = int(low_s) if low_s else 0
                high = int(high_s) if high_s else 65535
            except ValueError:
                return None
        else:
            try:
                low = high = int(item)
            except ValueError:
                return None
        if not (0 <= low <= high <= 65535):
            return None
        ranges.append((low, high))
    return ranges

def port_spec_matches(value: str, candidate: int) -> bool | None:
    ranges = parse_port_spec(value)
    if ranges is None:
        return None
    return any(low <= candidate <= high for low, high in ranges)

def expected_endpoint_port_side(role: str, chain: str) -> str | None:
    """Which packet field carries the PQTunnel listener port in the outer TCP flow."""
    if role == "dialer":
        return {"OUTPUT": "destination", "PREROUTING": "source"}.get(chain)
    if role == "gateway":
        return {"OUTPUT": "source", "PREROUTING": "destination"}.get(chain)
    return None


def normalize_port_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for low, high in sorted(ranges):
        if merged and low <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], high)
        else:
            merged.append([low, high])
    return [(low, high) for low, high in merged]


def intersect_port_ranges(
    left: list[tuple[int, int]], right: list[tuple[int, int]]
) -> list[tuple[int, int]]:
    result = []
    for left_low, left_high in left:
        for right_low, right_high in right:
            low, high = max(left_low, right_low), min(left_high, right_high)
            if low <= high:
                result.append((low, high))
    return normalize_port_ranges(result)


def complement_port_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    result = []
    cursor = 0
    for low, high in normalize_port_ranges(ranges):
        if cursor < low:
            result.append((cursor, low - 1))
        cursor = max(cursor, high + 1)
    if cursor <= 65535:
        result.append((cursor, 65535))
    return result


def expected_outer_flow_sides(
    role: str, chain: str, listener_port: int, ephemeral_range: tuple[int, int]
) -> tuple[list[tuple[int, int]], list[tuple[int, int]], str, str] | None:
    """Return possible source/destination port sets and redacted labels for this chain."""
    ephemeral = [ephemeral_range]
    listener = [(listener_port, listener_port)]
    if role == "dialer":
        if chain == "OUTPUT":
            return ephemeral, listener, "client_ephemeral_range", "gateway_listener"
        if chain == "PREROUTING":
            return listener, ephemeral, "gateway_listener", "client_ephemeral_range"
    if role == "gateway":
        if chain == "PREROUTING":
            return ephemeral, listener, "client_ephemeral_range", "gateway_listener"
        if chain == "OUTPUT":
            return listener, ephemeral, "gateway_listener", "client_ephemeral_range"
    return None


def candidate_tcp_flow_overlap_detail(
    line: str, listener_port: int, ephemeral_range: tuple[int, int], role: str, chain: str
) -> tuple[str, str, str, str]:
    """Check the outer TCP tuple using a listener port and an ephemeral range without leaking rule values."""
    flow = expected_outer_flow_sides(role, chain, listener_port, ephemeral_range)
    if flow is None:
        return "unknown", "unsupported_role_or_chain", "unknown", "unknown"
    source_possible, destination_possible, source_label, destination_label = flow
    parsed = iptables_rule_options(line)
    if parsed is None:
        return "unknown", "unparseable_rule_tokens", source_label, destination_label

    protocol = None
    protocol_negated = False
    modules: list[str] = []
    conditions: list[tuple[str, str, bool]] = []
    pending_negation = False
    for option, args in parsed:
        if option == "!":
            pending_negation = True
            continue
        if option in ("-p", "--protocol") and args:
            protocol = args[0].lower()
            protocol_negated = pending_negation
            pending_negation = False
            continue
        if option in ("-m", "--match") and args:
            modules.append(args[0].lower())
            continue
        if option in PORT_OPTIONS and args:
            conditions.append((PORT_OPTIONS[option], args[0], pending_negation))
            pending_negation = False
            continue
        if pending_negation:
            return "unknown", "unsupported_negation", source_label, destination_label
    if pending_negation:
        return "unknown", "unsupported_negation", source_label, destination_label

    if protocol is not None:
        if protocol in ("tcp", "6", "all", "0"):
            protocol_matches_tcp = not protocol_negated
        else:
            protocol_matches_tcp = protocol_negated
        if not protocol_matches_tcp:
            return "no_match", "protocol_excludes_tcp", source_label, destination_label
    elif "udp" in modules:
        return "no_match", "protocol_excludes_tcp", source_label, destination_label

    selectors = set(iptables_selector_categories(line))
    if "protocol" in selectors and protocol is None:
        return "unknown", "unsupported_protocol_selector_form", source_label, destination_label
    if "port" in selectors and not conditions:
        return "unknown", "unsupported_port_selector_form", source_label, destination_label

    source_possible = normalize_port_ranges(source_possible)
    destination_possible = normalize_port_ranges(destination_possible)
    either_conditions = []
    for side, value, negated in conditions:
        parsed_ranges = parse_port_spec(value)
        if parsed_ranges is None:
            return "unknown", "unsupported_port_spec", source_label, destination_label
        allowed = complement_port_ranges(parsed_ranges) if negated else normalize_port_ranges(parsed_ranges)
        if side == "source":
            source_possible = intersect_port_ranges(source_possible, allowed)
            if not source_possible:
                return "no_match", "port_excludes_flow_tuple", source_label, destination_label
        elif side == "destination":
            destination_possible = intersect_port_ranges(destination_possible, allowed)
            if not destination_possible:
                return "no_match", "port_excludes_flow_tuple", source_label, destination_label
        else:
            either_conditions.append((parsed_ranges, negated))

    # --ports tests either field. Keep it conservative rather than combine
    # multiple existential predicates incorrectly.
    if either_conditions:
        return "unknown", "either_port_selector_needs_joint_evaluation", source_label, destination_label

    if set(selectors) - {"protocol", "port"}:
        return "unknown", "additional_selector_present", source_label, destination_label
    return "match", "known_conditions_allow_flow", source_label, destination_label

TCP_FLAG_BITS = {
    "FIN": 0x01, "SYN": 0x02, "RST": 0x04,
    "PSH": 0x08, "ACK": 0x10, "URG": 0x20,
    "ECE": 0x40, "CWR": 0x80,
}


def tcp_flag_bits(value: str) -> int | None:
    """Parse iptables TCP flag names without retaining or printing values."""
    names = [part.strip().upper() for part in value.split(",")]
    if not names or any(not name for name in names):
        return None
    if names == ["ALL"]:
        return sum(TCP_FLAG_BITS.values())
    if names == ["NONE"]:
        return 0
    if any(name not in TCP_FLAG_BITS for name in names):
        return None
    bits = 0
    for name in names:
        bits |= TCP_FLAG_BITS[name]
    return bits


def tcp_flags_allow_rst(mask: str, comp: str) -> tuple[str, str]:
    """Return whether a --tcp-flags predicate can match any TCP RST packet."""
    mask_bits = tcp_flag_bits(mask)
    comp_bits = tcp_flag_bits(comp)
    if mask_bits is None or comp_bits is None or (comp_bits & ~mask_bits):
        return "unknown", "unsupported_tcp_flags"
    rst_bit = TCP_FLAG_BITS["RST"]
    if (mask_bits & rst_bit) and not (comp_bits & rst_bit):
        return "no_match", "tcp_flags_exclude_rst"
    return "match", "known_conditions_allow_rst"


def candidate_tcp_rst_flow_overlap_detail(
    line: str, listener_port: int, ephemeral_range: tuple[int, int], role: str
) -> tuple[str, str]:
    """Classify explicit filter OUTPUT DROP/REJECT rules for possible outer-flow TCP RST packets."""
    parsed = iptables_rule_options(line)
    if parsed is None:
        return "unknown", "unparseable_rule_tokens"

    filtered: list[str] = []
    flag_checks: list[tuple[str, str, bool]] = []
    pending_negation = False
    for option, args in parsed:
        if option == "!":
            pending_negation = True
            continue
        if option == "--tcp-flags":
            if pending_negation:
                return "unknown", "negated_tcp_flags_not_modeled"
            if len(args) < 2:
                return "unknown", "incomplete_tcp_flags_selector"
            flag_checks.append((args[0], args[1], False))
            pending_negation = False
            continue
        if option == "--syn":
            flag_checks.append(("FIN,SYN,RST,ACK", "SYN", pending_negation))
            pending_negation = False
            continue

        if pending_negation:
            filtered.append("!")
            pending_negation = False
        filtered.append(option)
        filtered.extend(args)

    if pending_negation:
        filtered.append("!")
    sanitized_line = shlex.join(filtered)
    flow_status, flow_reason, _, _ = candidate_tcp_flow_overlap_detail(
        sanitized_line, listener_port, ephemeral_range, role, "OUTPUT"
    )
    if flow_status == "no_match":
        return "no_match", flow_reason

    for mask, comp, negated in flag_checks:
        flag_status, flag_reason = tcp_flags_allow_rst(mask, comp)
        if negated:
            if flag_status == "no_match":
                flag_status, flag_reason = "match", "negated_syn_allows_rst"
            else:
                return "unknown", "negated_tcp_flags_not_fully_modeled"
        if flag_status == "no_match":
            return flag_status, flag_reason
        if flag_status == "unknown":
            return flag_status, flag_reason

    if flow_status == "unknown":
        return flow_status, flow_reason
    return "match", "known_conditions_allow_rst_flow"

def candidate_tcp_overlap_detail(line: str, port: int, side: str) -> tuple[str, str]:
    """Classify one candidate port on one packet side; reasons are fixed, non-sensitive labels."""
    if side not in ("source", "destination"):
        return "unknown", "unsupported_port_side"
    parsed = iptables_rule_options(line)
    if parsed is None:
        return "unknown", "unparseable_rule_tokens"

    protocol = None
    protocol_negated = False
    modules: list[str] = []
    conditions: list[tuple[str, str, bool]] = []
    pending_negation = False
    for option, args in parsed:
        if option == "!":
            pending_negation = True
            continue
        if option in ("-p", "--protocol") and args:
            protocol = args[0].lower()
            protocol_negated = pending_negation
            pending_negation = False
            continue
        if option in ("-m", "--match") and args:
            modules.append(args[0].lower())
            continue
        if option in PORT_OPTIONS and args:
            conditions.append((PORT_OPTIONS[option], args[0], pending_negation))
            pending_negation = False
            continue
        # A negation not consumed by a selector is outside this check's model.
        if pending_negation:
            return "unknown", "unsupported_negation"
    if pending_negation:
        return "unknown", "unsupported_negation"

    # Establish whether the rule's protocol predicate can match a TCP packet.
    if protocol is not None:
        proto = protocol
        if proto in ("tcp", "6", "all", "0"):
            protocol_matches_tcp = not protocol_negated
        else:
            # A positive exact protocol other than TCP cannot match a TCP
            # packet; its negated form can.
            protocol_matches_tcp = protocol_negated
        if not protocol_matches_tcp:
            return "no_match", "protocol_excludes_tcp"
    elif "udp" in modules:
        return "no_match", "protocol_excludes_tcp"
    # No protocol means any protocol and therefore includes TCP.

    selectors = set(iptables_selector_categories(line))
    has_unmodeled_selector = bool(selectors - {"protocol", "port"})
    side_conditions = [c for c in conditions if c[0] == side]
    opposite_conditions = [c for c in conditions if c[0] not in (side, "either")]
    either_conditions = [c for c in conditions if c[0] == "either"]

    for _, value, negated in side_conditions:
        match = port_spec_matches(value, port)
        if match is None:
            return "unknown", "unsupported_port_spec"
        if negated:
            match = not match
        if not match:
            return "no_match", "port_excludes_candidate"

    if either_conditions:
        for _, value, negated in either_conditions:
            match = port_spec_matches(value, port)
            if match is None:
                return "unknown", "unsupported_port_spec"
            if negated:
                return "unknown", "negated_either_port_selector"
            if not match:
                return "unknown", "either_port_selector_needs_packet_pair"

    if opposite_conditions:
        return "unknown", "opposite_port_selector_present"
    if has_unmodeled_selector:
        return "unknown", "additional_selector_present"
    return "match", "known_conditions_allow_port"

def candidate_tcp_overlap(line: str, port: int, role: str, chain: str) -> str:
    """Return match/no_match/unknown for the outer endpoint port, with values redacted."""
    side = expected_endpoint_port_side(role, chain)
    if side is None:
        return "unknown"
    return candidate_tcp_overlap_detail(line, port, side)[0]


def parse_iptables_save(text: str, candidate_port: int | None = None, role: str = "both", inspect_tcp_port: int | None = None, flow_listener_port: int | None = None, flow_ephemeral_range: tuple[int, int] | None = None, inspect_outer_tcp_rst: tuple[int, tuple[int, int]] | None = None) -> dict[str, Any]:
    table = None
    policies: dict[tuple[str, str], str] = {}
    rules: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"rules": 0, **{cat: 0 for cat in CATEGORIES}}
    )
    notrack_rules: list[dict[str, Any]] = []
    outer_tcp_rst_rules: list[dict[str, Any]] = []
    outer_tcp_rst_policy: str | None = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("*"):
            table = line[1:]
            continue
        if line == "COMMIT":
            table = None
            continue
        if table is None:
            continue
        if line.startswith(":"):
            fields = line[1:].split()
            if fields:
                chain_policy = fields[1] if len(fields) > 1 else "-"
                policies[(table, fields[0])] = chain_policy
                if (
                    inspect_outer_tcp_rst is not None
                    and table == "filter"
                    and fields[0] == "OUTPUT"
                    and chain_policy.upper() == "DROP"
                ):
                    outer_tcp_rst_policy = "DROP"
            continue
        if not line.startswith("-A "):
            continue
        fields = line.split(None, 2)
        if len(fields) < 2:
            continue
        counts = rules[(table, fields[1])]
        counts["rules"] += 1
        if inspect_outer_tcp_rst is not None and table == "filter" and fields[1] == "OUTPUT":
            jump_target = iptables_jump_target(line)
            if jump_target in ("DROP", "REJECT"):
                listener_port, ephemeral_range = inspect_outer_tcp_rst
                overlap, reason = candidate_tcp_rst_flow_overlap_detail(
                    line, listener_port, ephemeral_range, role
                )
                outer_tcp_rst_rules.append({
                    "action": jump_target.lower(),
                    "selectors": iptables_selector_categories(line),
                    "overlap": overlap,
                    "reason": reason,
                })
        rule_features = iptables_rule_features(line)
        if rule_features is not None and rule_features["notrack"]:
            counts["notrack"] += 1
            record = {
                "table": table, "chain": fields[1],
                "selectors": iptables_selector_categories(line),
                "mechanism": rule_features["notrack_mechanism"],
            }
            if table == "raw" and fields[1] in ("OUTPUT", "PREROUTING"):
                if candidate_port is not None:
                    side = expected_endpoint_port_side(role, fields[1])
                    record["candidate_overlap"] = candidate_tcp_overlap(line, candidate_port, role, fields[1])
                    record["candidate_overlap_reason"] = (
                        candidate_tcp_overlap_detail(line, candidate_port, side)[1]
                        if side is not None else "unknown_role_or_chain"
                    )
                    record["endpoint_port_side"] = side or "unknown"
                if inspect_tcp_port is not None:
                    for port_side in ("source", "destination"):
                        status, reason = candidate_tcp_overlap_detail(line, inspect_tcp_port, port_side)
                        record[f"{port_side}_port_overlap"] = status
                        record[f"{port_side}_port_overlap_reason"] = reason
                if flow_listener_port is not None and flow_ephemeral_range is not None:
                    status, reason, source_label, destination_label = candidate_tcp_flow_overlap_detail(
                        line, flow_listener_port, flow_ephemeral_range, role, fields[1]
                    )
                    record["flow_overlap"] = status
                    record["flow_overlap_reason"] = reason
                    record["flow_source_port_role"] = source_label
                    record["flow_destination_port_role"] = destination_label
            notrack_rules.append(record)
        if rule_features is not None:
            counts["packet_mark"] += int(rule_features["packet_mark"])
            counts["nat"] += int(rule_features["nat"])
            counts["drop_reject"] += int(rule_features["drop_reject"])
            counts["accept"] += int(rule_features["accept"])
    return {
        "policies": policies,
        "rules": dict(rules),
        "notrack_rules": notrack_rules,
        "outer_tcp_rst_rules": outer_tcp_rst_rules,
        "outer_tcp_rst_policy": outer_tcp_rst_policy,
    }

def run_readonly(argv: list[str]) -> tuple[int, str]:
    try:
        result = subprocess.run(argv, check=False, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return 127, ""
    return result.returncode, result.stdout

def fmt_categories(counts: dict[str, int]) -> str:
    return " ".join(f"{cat}={counts.get(cat, 0)}" for cat in CATEGORIES)

def audit_nft() -> None:
    rc, output = run_readonly(["nft", "-j", "list", "ruleset"])
    if rc != 0:
        print("WARN nft_json=query_failed_or_unavailable; state is unknown")
        return
    try:
        parsed = parse_nft_json(json.loads(output))
    except (json.JSONDecodeError, TypeError, ValueError):
        print("WARN nft_json=unparseable; state is unknown")
        return
    total = sum(v["rules"] for v in parsed["rules"].values())
    print(f"nft_json=ok tables={len(parsed['tables'])} chains={len(parsed['chains'])} rules={total}")
    for family, table in parsed["tables"]:
        print(f"nft_table family={family} name={table}")
    keys = sorted(set(parsed["chains"]) | set(parsed["rules"]))
    for key in keys:
        family, table, chain = key
        meta = parsed["chains"].get(key, {})
        counts = parsed["rules"].get(key, {"rules": 0, **{cat: 0 for cat in CATEGORIES}})
        hook, priority, policy = meta.get("hook") or "-", meta.get("priority"), meta.get("policy") or "-"
        if hook != "-" or any(counts[cat] for cat in CATEGORIES):
            print(f"nft_chain family={family} table={table} name={chain} hook={hook} priority={priority if priority is not None else '-'} policy={policy} {fmt_categories(counts)}")

def audit_iptables(command: str, family: str, role: str, candidate_port: int | None, inspect_tcp_port: int | None, flow_listener_port: int | None, flow_ephemeral_range: tuple[int, int] | None, inspect_outer_tcp_rst: tuple[int, tuple[int, int]] | None) -> None:
    rc, output = run_readonly([command])
    if rc != 0:
        print(f"WARN {family}_iptables_save=query_failed_or_unavailable; state is unknown")
        return
    parsed = parse_iptables_save(output, candidate_port=candidate_port, role=role, inspect_tcp_port=inspect_tcp_port, flow_listener_port=flow_listener_port, flow_ephemeral_range=flow_ephemeral_range, inspect_outer_tcp_rst=inspect_outer_tcp_rst)
    table_names = {t for t, _ in parsed["policies"]} | {t for t, _ in parsed["rules"]}
    total = sum(v["rules"] for v in parsed["rules"].values())
    print(f"{family}_iptables_save=ok tables={len(table_names)} rules={total}")
    version_rc, version = run_readonly([command.replace("-save", ""), "-V"])
    backend = "unknown"
    if version_rc == 0:
        if "nf_tables" in version.lower(): backend = "nf_tables"
        elif "legacy" in version.lower(): backend = "legacy"
    print(f"{family}_iptables_backend={backend}")
    if backend == "nf_tables":
        print(f"NOTE {family}_iptables_save is an overlapping compatibility view of nft_json; do not add the rule totals.")
    for table, chain in sorted(set(parsed["policies"]) | set(parsed["rules"])):
        counts = parsed["rules"].get((table, chain), {"rules": 0, **{cat: 0 for cat in CATEGORIES}})
        policy = parsed["policies"].get((table, chain), "-")
        if policy != "-" or any(counts[k] for k in ("notrack", "packet_mark", "nat", "drop_reject")):
            print(f"{family}_iptables_chain table={table} name={chain} policy={policy} {fmt_categories(counts)}")
    chain_indices: dict[tuple[str, str], int] = defaultdict(int)
    for rule in parsed.get("notrack_rules", []):
        key = (rule["table"], rule["chain"])
        chain_indices[key] += 1
        selectors = ",".join(rule["selectors"]) or "none-detected"
        suffix = ""
        if "candidate_overlap" in rule:
            suffix += (
                f" endpoint_port_side={rule['endpoint_port_side']}"
                f" candidate_tcp_overlap={rule['candidate_overlap']}"
                f" candidate_tcp_overlap_reason={rule['candidate_overlap_reason']}"
            )
        if "source_port_overlap" in rule:
            suffix += (
                f" tcp_port_probe_source_overlap={rule['source_port_overlap']}"
                f" tcp_port_probe_source_reason={rule['source_port_overlap_reason']}"
                f" tcp_port_probe_destination_overlap={rule['destination_port_overlap']}"
                f" tcp_port_probe_destination_reason={rule['destination_port_overlap_reason']}"
            )
        if "flow_overlap" in rule:
            suffix += (
                f" tcp_flow_source_role={rule['flow_source_port_role']}"
                f" tcp_flow_destination_role={rule['flow_destination_port_role']}"
                f" tcp_flow_overlap={rule['flow_overlap']}"
                f" tcp_flow_reason={rule['flow_overlap_reason']}"
            )
        print(f"{family}_iptables_notrack_scope table={key[0]} chain={key[1]} rule={chain_indices[key]} selectors={selectors} mechanism={rule['mechanism']}{suffix}")
    for index, rule in enumerate(parsed.get("outer_tcp_rst_rules", []), 1):
        selectors = ",".join(rule["selectors"]) or "none-detected"
        print(
            f"{family}_iptables_outer_tcp_rst table=filter chain=OUTPUT rule={index} "
            f"action={rule['action']} selectors={selectors} "
            f"rst_flow_overlap={rule['overlap']} rst_flow_reason={rule['reason']}"
        )
    if parsed.get("outer_tcp_rst_policy") == "DROP":
        print(
            f"{family}_iptables_outer_tcp_rst_default_policy table=filter chain=OUTPUT "
            "policy=DROP effect=may-drop-unmatched-rst"
        )

def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only firewall inventory; raw rules are never printed.")
    parser.add_argument("--role", choices=("dialer", "gateway", "both"), default="both")
    port_checks = parser.add_mutually_exclusive_group()
    port_checks.add_argument(
        "--candidate-tcp-port", type=int, choices=range(1, 65536), default=None,
        help="check a proposed PQTunnel outer TCP listener port against NOTRACK rules; rule values remain redacted",
    )
    port_checks.add_argument(
        "--inspect-tcp-port", type=int, choices=range(1, 65536), default=None,
        help="probe this TCP port independently on source and destination sides of raw NOTRACK rules; rule values remain redacted",
    )
    port_checks.add_argument(
        "--inspect-outer-tcp-flow", nargs=2, metavar=("LISTENER_PORT", "EPHEMERAL_RANGE"),
        default=None,
        help="check a role-aware outer TCP flow using listener port and client ephemeral range (for example 8443 32768:60999); all supplied port values are redacted in output",
    )
    port_checks.add_argument(
        "--inspect-outer-tcp-rst", nargs=2, metavar=("LISTENER_PORT", "EPHEMERAL_RANGE"),
        default=None,
        help="check explicit filter OUTPUT DROP/REJECT predicates for possible outer TCP RST overlap; supplied and rule port values are redacted",
    )
    args = parser.parse_args()
    flow_listener_port = None
    flow_ephemeral_range = None
    inspect_outer_tcp_rst = None
    outer_flow_args = args.inspect_outer_tcp_flow or args.inspect_outer_tcp_rst
    if outer_flow_args is not None:
        try:
            flow_listener_port = int(outer_flow_args[0])
        except ValueError:
            parser.error("LISTENER_PORT must be a decimal TCP port")
        if not 1 <= flow_listener_port <= 65535:
            parser.error("LISTENER_PORT must be between 1 and 65535")
        parsed_range = parse_port_spec(outer_flow_args[1])
        if parsed_range is None or len(parsed_range) != 1:
            parser.error("EPHEMERAL_RANGE must be one numeric range, such as LOW:HIGH")
        flow_ephemeral_range = parsed_range[0]
        if flow_ephemeral_range[0] > flow_ephemeral_range[1]:
            parser.error("EPHEMERAL_RANGE lower bound must not exceed upper bound")
        if args.role == "both":
            parser.error("outer flow inspection requires --role dialer or --role gateway")
        if args.inspect_outer_tcp_rst is not None:
            inspect_outer_tcp_rst = (flow_listener_port, flow_ephemeral_range)
    os_release = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError:
        pass
    print("PQTunnel firewall coexistence audit — READ-ONLY")
    print(f"role={args.role} os={os_release.get('ID', 'unknown')} version={os_release.get('VERSION_ID', 'unknown')}")
    print("Privacy: raw rules, IP addresses, ports, counters and packet contents are not printed.")
    if args.candidate_tcp_port is not None:
        print("candidate_tcp_port_check=enabled port_value=redacted")
    if args.inspect_tcp_port is not None:
        print("tcp_port_probe=enabled port_value=redacted sides=source,destination mode=NOTRACK-rule-predicate")
    if flow_listener_port is not None and flow_ephemeral_range is not None and args.inspect_outer_tcp_flow is not None:
        print("outer_tcp_flow_check=enabled listener_port=redacted client_ephemeral_range=redacted tuple_values=redacted")
    if inspect_outer_tcp_rst is not None:
        print("outer_tcp_rst_check=enabled listener_port=redacted client_ephemeral_range=redacted rule_values=redacted mode=filter-OUTPUT-DROP-REJECT")
    audit_nft()
    audit_iptables("iptables-save", "ipv4", args.role, args.candidate_tcp_port, args.inspect_tcp_port, flow_listener_port, flow_ephemeral_range, inspect_outer_tcp_rst)
    audit_iptables("ip6tables-save", "ipv6", args.role, args.candidate_tcp_port, args.inspect_tcp_port, flow_listener_port, flow_ephemeral_range, inspect_outer_tcp_rst)
    print("READ-ONLY GUARANTEE: no files, routes, sysctls, firewall state or services were changed.")
    print("This inventory supports lab design; it is not approval to apply network changes.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
