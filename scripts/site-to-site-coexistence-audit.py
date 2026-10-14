#!/usr/bin/env python3
"""Read-only firewall inventory. Never print raw rules, addresses, ports or counters."""
from __future__ import annotations
import argparse
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any

CATEGORIES = ("notrack", "packet_mark", "nat", "drop_reject", "accept")

def walk_keys(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key.lower()
            yield from walk_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_keys(child)

def walk_xt_names(value: Any):
    """Yield names of xtables-compat expressions (not rule selector values)."""
    if isinstance(value, dict):
        xt_obj = value.get("xt")
        if isinstance(xt_obj, dict):
            name = xt_obj.get("name")
            if isinstance(name, str):
                yield name.lower()
        for child in value.values():
            yield from walk_xt_names(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk_xt_names(child)

def expr_categories(expr: Any) -> set[str]:
    keys = set(walk_keys(expr))
    # iptables-nft can expose targets as {"xt":{"type":"target","name":"NOTRACK"}}
    # when nftables has no native translation for that xtables extension.
    xt_names = set(walk_xt_names(expr))
    out: set[str] = set()
    if "notrack" in keys or "notrack" in xt_names:
        out.add("notrack")
    if "mark" in keys or "mangle" in keys or {"mark", "connmark"} & xt_names:
        out.add("packet_mark")
    if {"dnat", "snat", "masquerade", "redirect"} & (keys | xt_names):
        out.add("nat")
    if {"drop", "reject"} & (keys | xt_names):
        out.add("drop_reject")
    if "accept" in keys or "accept" in xt_names:
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

MARK_RE = re.compile(r"(?:--set-(?:x)?mark\b|--restore-mark\b|--save-mark\b|(?:-j|--jump)\s+(?:CONN)?MARK\b|CONNMARK)", re.I)
NOTRACK_RE = re.compile(r"(?:--notrack\b|(?:-j|--jump)\s+NOTRACK\b)", re.I)
NAT_RE = re.compile(r"(?:-j|--jump)\s+(?:DNAT|SNAT|MASQUERADE|REDIRECT)\b", re.I)
DROP_RE = re.compile(r"(?:-j|--jump)\s+(?:DROP|REJECT)\b", re.I)
ACCEPT_RE = re.compile(r"(?:-j|--jump)\s+ACCEPT\b", re.I)

SELECTOR_PATTERNS: dict[str, re.Pattern[str]] = {
    "interface": re.compile(r"(?:^|\s)(?:-i|--in-interface|-o|--out-interface)(?:\s|=)", re.I),
    "protocol": re.compile(r"(?:^|\s)(?:-p|--protocol)(?:\s|=)", re.I),
    "address": re.compile(r"(?:^|\s)(?:-s|--source|-d|--destination|--src|--dst)(?:\s|=)", re.I),
    "port": re.compile(r"(?:^|\s)(?:--(?:sport|source-port|sports|dport|destination-port|dports))(?:\s|=)", re.I),
    "connection": re.compile(r"(?:^|\s)(?:--(?:ctstate|state|ctstatus|ctdir|ctexpire))(?:\s|=)", re.I),
    "mark": re.compile(r"(?:^|\s)(?:--(?:mark|ctmark|nfmark|nfmask|ctmask))(?:\s|=)", re.I),
}
OTHER_SELECTOR_RE = re.compile(
    r"(?:^|\s)(?:--(?:tcp-flags|syn|icmp-type|icmpv6-type|uid-owner|gid-owner|socket-exists|"
    r"limit|limit-burst|hashlimit|string|mac-source|length|frag|probability|src-type|dst-type|"
    r"physdev-in|physdev-out))(?:\s|=)", re.I
)
IGNORABLE_MATCH_MODULES = {
    "comment", "tcp", "udp", "icmp", "icmp6", "ipv6-icmp", "multiport",
    "conntrack", "state", "mark", "connmark",
}

def iptables_selector_categories(line: str) -> list[str]:
    """Return selector *types*, never selector values, for a saved iptables rule."""
    selectors = {name for name, pattern in SELECTOR_PATTERNS.items() if pattern.search(line)}
    if OTHER_SELECTOR_RE.search(line):
        selectors.add("other")
    modules = re.findall(r"(?:^|\s)(?:-m|--match)\s+([^\s]+)", line, re.I)
    if any(module.lower() not in IGNORABLE_MATCH_MODULES for module in modules):
        selectors.add("other")
    return sorted(selectors)


def parse_iptables_save(text: str) -> dict[str, Any]:
    table = None
    policies: dict[tuple[str, str], str] = {}
    rules: dict[tuple[str, str], dict[str, int]] = defaultdict(
        lambda: {"rules": 0, **{cat: 0 for cat in CATEGORIES}}
    )
    notrack_rules: list[dict[str, Any]] = []
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
                policies[(table, fields[0])] = fields[1] if len(fields) > 1 else "-"
            continue
        if not line.startswith("-A "):
            continue
        fields = line.split(None, 2)
        if len(fields) < 2:
            continue
        counts = rules[(table, fields[1])]
        counts["rules"] += 1
        if NOTRACK_RE.search(line):
            counts["notrack"] += 1
            notrack_rules.append({
                "table": table, "chain": fields[1],
                "selectors": iptables_selector_categories(line),
            })
        if MARK_RE.search(line): counts["packet_mark"] += 1
        if NAT_RE.search(line): counts["nat"] += 1
        if DROP_RE.search(line): counts["drop_reject"] += 1
        if ACCEPT_RE.search(line): counts["accept"] += 1
    return {"policies": policies, "rules": dict(rules), "notrack_rules": notrack_rules}

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

def audit_iptables(command: str, family: str) -> None:
    rc, output = run_readonly([command])
    if rc != 0:
        print(f"WARN {family}_iptables_save=query_failed_or_unavailable; state is unknown")
        return
    parsed = parse_iptables_save(output)
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
        print(f"{family}_iptables_notrack_scope table={key[0]} chain={key[1]} rule={chain_indices[key]} selectors={selectors}")

def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only firewall inventory; raw rules are never printed.")
    parser.add_argument("--role", choices=("dialer", "gateway", "both"), default="both")
    args = parser.parse_args()
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
    audit_nft()
    audit_iptables("iptables-save", "ipv4")
    audit_iptables("ip6tables-save", "ipv6")
    print("READ-ONLY GUARANTEE: no files, routes, sysctls, firewall state or services were changed.")
    print("This inventory supports lab design; it is not approval to apply network changes.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
