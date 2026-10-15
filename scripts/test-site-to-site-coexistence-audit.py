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

    def test_nft_json_xtables_compat_targets_are_classified(self):
        fixture = {"nftables": [
            {"table": {"family": "ip", "name": "raw"}},
            {"chain": {"family": "ip", "table": "raw", "name": "PREROUTING",
                       "type": "filter", "hook": "prerouting", "prio": -300,
                       "policy": "accept"}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "target", "name": "NOTRACK"}}]}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "target", "name": "DNAT"}}]}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "target", "name": "MARK"}}]}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "target", "name": "DROP"}}]}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "target", "name": "ACCEPT"}}]}},
        ]}
        parsed = audit.parse_nft_json(fixture)
        counts = parsed["rules"][("ip", "raw", "PREROUTING")]
        self.assertEqual(counts["rules"], 5)
        self.assertEqual(counts["notrack"], 1)
        self.assertEqual(counts["nat"], 1)
        self.assertEqual(counts["packet_mark"], 1)
        self.assertEqual(counts["drop_reject"], 1)
        self.assertEqual(counts["accept"], 1)
        self.assertEqual(counts["xt_fallback"], 5)
        self.assertEqual(counts["xt_opaque"], 0)
        self.assertEqual(counts["xt_target"], 5)
        self.assertEqual(counts["xt_match"], 0)
        self.assertEqual(counts["xt_target_other"], 0)

    def test_xt_match_names_do_not_masquerade_as_targets(self):
        fixture = {"nftables": [
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "match", "name": "mark"}}]}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "target", "name": "LOG"}}]}},
        ]}
        parsed = audit.parse_nft_json(fixture)
        counts = parsed["rules"][("ip", "raw", "PREROUTING")]
        self.assertEqual(counts["xt_match"], 1)
        self.assertEqual(counts["xt_target"], 1)
        self.assertEqual(counts["xt_target_other"], 1)
        self.assertEqual(counts["packet_mark"], 0)
        self.assertEqual(counts["drop_reject"], 0)
        self.assertEqual(counts["nat"], 0)

    def test_nft_json_opaque_xt_fallback_is_visible_but_not_misclassified(self):
        fixture = {"nftables": [
            {"table": {"family": "ip", "name": "raw"}},
            {"chain": {"family": "ip", "table": "raw", "name": "PREROUTING",
                       "type": "filter", "hook": "prerouting", "prio": -300,
                       "policy": "accept"}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": None}]}},
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": None}]}},
        ]}
        parsed = audit.parse_nft_json(fixture)
        counts = parsed["rules"][("ip", "raw", "PREROUTING")]
        self.assertEqual(counts["rules"], 2)
        self.assertEqual(counts["xt_fallback"], 2)
        self.assertEqual(counts["xt_opaque"], 2)
        self.assertEqual(counts["xt_match"], 0)
        self.assertEqual(counts["xt_target"], 0)
        self.assertEqual(counts["notrack"], 0)

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

    def test_selector_categories_ignore_option_like_text_inside_comments(self):
        line = (
            '-A OUTPUT -p tcp --dport 8443 -m comment '
            '--comment "--ctstate NEW --uid-owner 1000 --dport 80 -m owner" '
            '-j NOTRACK'
        )
        self.assertEqual(
            audit.iptables_selector_categories(line),
            ["port", "protocol"],
        )
        status, reason, _, _ = audit.candidate_tcp_flow_overlap_detail(
            line, 8443, (32768, 60999), "dialer", "OUTPUT"
        )
        self.assertEqual((status, reason), ("match", "known_conditions_allow_flow"))

    def test_selector_categories_remain_conservative_for_unparseable_rules(self):
        self.assertEqual(
            audit.iptables_selector_categories('-A OUTPUT --comment "unterminated -j DROP'),
            ["other"],
        )

    def test_notrack_scope_reports_selector_types_without_values(self):
        fixture = """*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i wan0 -p tcp -s 203.0.113.7 --dport 443 -j NOTRACK
-A PREROUTING -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture)
        self.assertEqual(parsed["rules"][("raw", "PREROUTING")]["notrack"], 2)
        self.assertEqual(parsed["notrack_rules"][0], {
            "table": "raw",
            "chain": "PREROUTING",
            "selectors": ["address", "interface", "port", "protocol"],
            "mechanism": "direct_target",
        })
        self.assertEqual(parsed["notrack_rules"][1]["selectors"], [])
        self.assertEqual(parsed["notrack_rules"][1]["mechanism"], "direct_target")
        self.assertNotIn("203.0.113.7", repr(parsed["notrack_rules"]))
        self.assertNotIn("443", repr(parsed["notrack_rules"]))

    def test_notrack_mechanism_distinguishes_ct_option_and_direct_target(self):
        fixture = """*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 8443 -j CT --notrack
-A PREROUTING -p udp --dport 9000 -j NOTRACK
-A PREROUTING -p udp --dport 9001 -j CT --notrack
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture)
        observed = [rule["mechanism"] for rule in parsed["notrack_rules"]]
        self.assertEqual(observed, [
            "ct_target_option",
            "direct_target",
            "ct_target_option",
        ])
        self.assertNotIn("8443", repr(parsed["notrack_rules"]))
        self.assertNotIn("9000", repr(parsed["notrack_rules"]))

    def test_ct_xt_target_is_not_guessed_to_be_notrack(self):
        fixture = {"nftables": [
            {"rule": {"family": "ip", "table": "raw", "chain": "PREROUTING",
                      "expr": [{"xt": {"type": "target", "name": "CT"}}]}},
        ]}
        parsed = audit.parse_nft_json(fixture)
        counts = parsed["rules"][("ip", "raw", "PREROUTING")]
        self.assertEqual(counts["xt_ct_target"], 1)
        self.assertEqual(counts["xt_target_other"], 0)
        self.assertEqual(counts["notrack"], 0)

    def test_candidate_tcp_port_overlap_is_role_aware_and_redacted(self):
        fixture = """*raw
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp -m tcp --dport 8443 -j NOTRACK
-A OUTPUT -p tcp --sport 443 -j NOTRACK
-A OUTPUT -p udp --dport 8443 -j NOTRACK
-A OUTPUT -p tcp -m multiport --dports 443,8443 -j NOTRACK
-A OUTPUT -p tcp --dport 9000:9100 -j NOTRACK
-A OUTPUT -p tcp --dport 8443 -m conntrack --ctstate NEW -j NOTRACK
-A OUTPUT -p tcp ! --dport 8443 -j NOTRACK
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --sport 8443 -j NOTRACK
-A PREROUTING -p tcp --dport 8443 -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture, candidate_port=8443, role="dialer")
        observed = [r["candidate_overlap"] for r in parsed["notrack_rules"]]
        self.assertEqual(observed, [
            "match", "unknown", "no_match", "match", "no_match",
            "unknown", "no_match", "match", "unknown",
        ])
        self.assertEqual(
            [r["endpoint_port_side"] for r in parsed["notrack_rules"]],
            ["destination"] * 7 + ["source"] * 2,
        )
        self.assertNotIn("8443", repr(parsed["notrack_rules"]))
        self.assertNotIn("9000", repr(parsed["notrack_rules"]))

    def test_candidate_tcp_port_overlap_is_gateway_direction_aware(self):
        fixture = """*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 8443 -j NOTRACK
-A PREROUTING -p tcp --sport 8443 -j NOTRACK
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --sport 8443 -j NOTRACK
-A OUTPUT -p tcp --dport 8443 -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture, candidate_port=8443, role="gateway")
        self.assertEqual(
            [r["candidate_overlap"] for r in parsed["notrack_rules"]],
            ["match", "unknown", "match", "unknown"],
        )
        self.assertEqual(
            [r["endpoint_port_side"] for r in parsed["notrack_rules"]],
            ["destination", "destination", "source", "source"],
        )

    def test_candidate_port_matches_default_tcp_rule_without_port_selector(self):
        fixture = """*raw
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture, candidate_port=8443, role="dialer")
        self.assertEqual(parsed["notrack_rules"][0]["candidate_overlap"], "match")

    def test_candidate_port_with_service_name_is_unknown_without_resolving(self):
        fixture = """*raw
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --dport https -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture, candidate_port=8443, role="dialer")
        self.assertEqual(parsed["notrack_rules"][0]["candidate_overlap"], "unknown")
        self.assertNotIn("https", repr(parsed["notrack_rules"]))

    def test_candidate_port_is_unknown_without_dialer_or_gateway_role(self):
        fixture = """*raw
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --dport 8443 -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture, candidate_port=8443, role="both")
        self.assertEqual(parsed["notrack_rules"][0]["candidate_overlap"], "unknown")
        self.assertEqual(parsed["notrack_rules"][0]["endpoint_port_side"], "unknown")


    def test_inspect_tcp_port_checks_source_and_destination_separately(self):
        fixture = """*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 443 -j NOTRACK
-A PREROUTING -p tcp --sport 80 -j NOTRACK
-A PREROUTING -p udp --dport 443 -j NOTRACK
-A PREROUTING -p tcp --dport https -j NOTRACK
-A PREROUTING -p tcp -j NOTRACK
-A PREROUTING -p tcp --ports 443 -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture, inspect_tcp_port=443)
        rules = parsed["notrack_rules"]
        self.assertEqual(
            [(r["source_port_overlap"], r["destination_port_overlap"]) for r in rules],
            [
                ("unknown", "match"),
                ("no_match", "unknown"),
                ("no_match", "no_match"),
                ("unknown", "unknown"),
                ("match", "match"),
                ("match", "match"),
            ],
        )
        self.assertEqual(rules[0]["destination_port_overlap_reason"], "known_conditions_allow_port")
        self.assertEqual(rules[0]["source_port_overlap_reason"], "opposite_port_selector_present")
        self.assertEqual(rules[2]["source_port_overlap_reason"], "protocol_excludes_tcp")
        self.assertEqual(rules[3]["destination_port_overlap_reason"], "unsupported_port_spec")
        self.assertNotIn("443", repr(rules))
        self.assertNotIn("https", repr(rules))
        self.assertNotIn("80", repr(rules))

    def test_candidate_check_reports_redacted_reason_codes(self):
        fixture = """*raw
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --dport https -j NOTRACK
-A OUTPUT -p udp --dport 8443 -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(fixture, candidate_port=8443, role="dialer")
        self.assertEqual(
            [r["candidate_overlap_reason"] for r in parsed["notrack_rules"]],
            ["unsupported_port_spec", "protocol_excludes_tcp"],
        )
        self.assertNotIn("https", repr(parsed["notrack_rules"]))
        self.assertNotIn("8443", repr(parsed["notrack_rules"]))


    def test_outer_flow_dialer_checks_ephemeral_and_listener_ports_as_a_tuple(self):
        fixture = """*raw
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --sport 40000 -j NOTRACK
-A OUTPUT -p tcp --sport 80 -j NOTRACK
-A OUTPUT -p tcp --dport 443 -j NOTRACK
-A OUTPUT -p tcp --sport 40000 --dport 443 -j NOTRACK
-A OUTPUT -p udp --sport 40000 -j NOTRACK
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --dport 40000 -j NOTRACK
-A PREROUTING -p tcp --dport 443 -j NOTRACK
-A PREROUTING -p tcp --sport 443 -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(
            fixture, role="dialer", flow_listener_port=8443, flow_ephemeral_range=(32768, 60999)
        )
        observed = [r["flow_overlap"] for r in parsed["notrack_rules"]]
        self.assertEqual(observed, [
            "match", "no_match", "no_match", "no_match", "no_match",
            "match", "no_match", "no_match",
        ])
        self.assertEqual(
            [(r["flow_source_port_role"], r["flow_destination_port_role"]) for r in parsed["notrack_rules"]],
            [
                ("client_ephemeral_range", "gateway_listener"),
                ("client_ephemeral_range", "gateway_listener"),
                ("client_ephemeral_range", "gateway_listener"),
                ("client_ephemeral_range", "gateway_listener"),
                ("client_ephemeral_range", "gateway_listener"),
                ("gateway_listener", "client_ephemeral_range"),
                ("gateway_listener", "client_ephemeral_range"),
                ("gateway_listener", "client_ephemeral_range"),
            ],
        )
        self.assertEqual(parsed["notrack_rules"][0]["flow_overlap_reason"], "known_conditions_allow_flow")
        self.assertEqual(parsed["notrack_rules"][4]["flow_overlap_reason"], "protocol_excludes_tcp")
        self.assertNotIn("8443", repr(parsed["notrack_rules"]))
        self.assertNotIn("40000", repr(parsed["notrack_rules"]))
        self.assertNotIn("60999", repr(parsed["notrack_rules"]))

    def test_outer_flow_gateway_direction_and_extra_selectors(self):
        fixture = """*raw
:PREROUTING ACCEPT [0:0]
-A PREROUTING -p tcp --sport 40000 -j NOTRACK
-A PREROUTING -p tcp --dport 443 -j NOTRACK
-A PREROUTING -p tcp -m conntrack --ctstate NEW -j NOTRACK
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --dport 40000 -j NOTRACK
-A OUTPUT -p tcp --sport 8443 -j NOTRACK
COMMIT
"""
        parsed = audit.parse_iptables_save(
            fixture, role="gateway", flow_listener_port=8443, flow_ephemeral_range=(32768, 60999)
        )
        self.assertEqual(
            [r["flow_overlap"] for r in parsed["notrack_rules"]],
            ["match", "no_match", "unknown", "match", "match"],
        )
        self.assertEqual(parsed["notrack_rules"][2]["flow_overlap_reason"], "additional_selector_present")
        self.assertNotIn("8443", repr(parsed["notrack_rules"]))

    def test_outer_tcp_rst_audit_classifies_filter_output_rules_and_redacts_values(self):
        fixture = """*filter
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp -m tcp --sport 40000 --dport 8443 --tcp-flags RST RST -j DROP
-A OUTPUT -p tcp --tcp-flags ALL SYN -j DROP
-A OUTPUT -p tcp --sport 80 -j REJECT
-A OUTPUT -p udp --sport 40000 -j DROP
-A OUTPUT -p tcp --sport https -j DROP
-A OUTPUT -p tcp -j DROP
COMMIT
*raw
:OUTPUT ACCEPT [0:0]
-A OUTPUT -p tcp --sport 40000 -j DROP
COMMIT
"""
        parsed = audit.parse_iptables_save(
            fixture, role="dialer", inspect_outer_tcp_rst=(8443, (32768, 60999))
        )
        rules = parsed["outer_tcp_rst_rules"]
        self.assertEqual(len(rules), 6)
        self.assertEqual([r["action"] for r in rules], ["drop", "drop", "reject", "drop", "drop", "drop"])
        self.assertEqual(
            [r["overlap"] for r in rules],
            ["match", "no_match", "no_match", "no_match", "unknown", "match"],
        )
        self.assertEqual(rules[0]["reason"], "known_conditions_allow_rst_flow")
        self.assertEqual(rules[1]["reason"], "tcp_flags_exclude_rst")
        self.assertEqual(rules[3]["reason"], "protocol_excludes_tcp")
        self.assertEqual(rules[4]["reason"], "unsupported_port_spec")
        self.assertIn("tcp_flags", rules[0]["selectors"])
        rendered = repr(rules)
        self.assertNotIn("40000", rendered)
        self.assertNotIn("8443", rendered)
        self.assertNotIn("60999", rendered)
        self.assertNotIn("https", rendered)
        self.assertNotIn("203.0.113.", rendered)

    def test_outer_tcp_rst_syn_shortcut_does_not_overlap_rst_packets(self):
        status, reason = audit.candidate_tcp_rst_flow_overlap_detail(
            "-A OUTPUT -p tcp --syn -j DROP", 8443, (32768, 60999), "dialer"
        )
        self.assertEqual((status, reason), ("no_match", "tcp_flags_exclude_rst"))

    def test_accept_is_counted(self):
        parsed = audit.parse_iptables_save("*filter\n:FORWARD ACCEPT [0:0]\n-A FORWARD -j ACCEPT\nCOMMIT\n")
        self.assertEqual(parsed["rules"][("filter", "FORWARD")]["accept"], 1)

if __name__ == "__main__":
    unittest.main()
