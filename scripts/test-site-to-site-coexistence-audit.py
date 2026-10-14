#!/usr/bin/env python3
import importlib.util
import pathlib
import unittest

SCRIPT = pathlib.Path(__file__).with_name("site-to-site-coexistence-audit.py")
spec = importlib.util.spec_from_file_location("coexistence_audit", SCRIPT)
audit = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(audit)

class AuditParserTests(unittest.TestCase):
    def test_nft_summarizes_notrack_mark_nat_drop(self):
        fixture = {"nftables": [
            {"table": {"family": "inet", "name": "host"}},
            {"chain": {"family": "inet", "table": "host", "name": "forward", "type": "filter", "hook": "forward", "prio": 0, "policy": "drop"}},
            {"rule": {"family": "inet", "table": "host", "chain": "forward", "expr": [{"notrack": None}]}},
            {"rule": {"family": "inet", "table": "host", "chain": "forward", "expr": [{"mangle": {"key": {"meta": {"key": "mark"}}, "value": 7}}]}},
            {"rule": {"family": "inet", "table": "host", "chain": "forward", "expr": [{"dnat": {"addr": "203.0.113.44", "port": 8443}}]}},
            {"rule": {"family": "inet", "table": "host", "chain": "forward", "expr": [{"drop": None}]}}
        ]}
        parsed = audit.parse_nft_json(fixture)
        counts = parsed["rules"][("inet", "host", "forward")]
        self.assertEqual(counts["rules"], 4)
        self.assertEqual(counts["notrack"], 1)
        self.assertEqual(counts["packet_mark"], 1)
        self.assertEqual(counts["nat"], 1)
        self.assertEqual(counts["drop_reject"], 1)
        self.assertEqual(parsed["chains"][("inet", "host", "forward")]["policy"], "drop")

    def test_iptables_categories_and_chain_policy(self):
        fixture = """*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp -j NOTRACK
COMMIT
*mangle
:PREROUTING ACCEPT [0:0]
-A PREROUTING -j MARK --set-xmark 0x20/0xffffffff
COMMIT
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -j DNAT --to-destination 203.0.113.8:443
COMMIT
*filter
:FORWARD DROP [0:0]
-A FORWARD -j DROP
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture)
        self.assertEqual(parsed["rules"][("raw", "PREROUTING")]["notrack"], 1)
        self.assertEqual(parsed["rules"][("mangle", "PREROUTING")]["packet_mark"], 1)
        self.assertEqual(parsed["rules"][("nat", "PREROUTING")]["nat"], 1)
        self.assertEqual(parsed["rules"][("filter", "FORWARD")]["drop_reject"], 1)
        self.assertEqual(parsed["policies"][("filter", "FORWARD")], "DROP")

    def test_accept_is_counted(self):
        parsed = audit.parse_iptables_save("*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -j ACCEPT\nCOMMIT\n")
        self.assertEqual(parsed["rules"][("filter", "FORWARD")]["accept"], 1)

if __name__ == "__main__":
    unittest.main()
