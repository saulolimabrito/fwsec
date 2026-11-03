# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwsec import config, migration, rules, transaction


def fixture(family=4, rules_text="", source="ufw", out="DROP"):
    chain = "ufw-user-input" if source == "ufw" else "ALLOWIN"
    return f'''*filter
:INPUT DROP [0:0]
:OUTPUT {out} [0:0]
:FORWARD DROP [0:0]
:{chain} - [0:0]
-A INPUT -j {chain}
{rules_text}
COMMIT
'''


def policy(v4="", v6="", source="ufw"):
    a, b = fixture(4, v4, source), fixture(6, v6, source)
    first = migration.plan(source, a, b)
    return migration.plan(source, a, b, approve=first["fingerprint"])


class MigrationTests(unittest.TestCase):
    def test_ipv6_only_port_does_not_open_ipv4(self):
        doc = policy(v6="-A ufw-user-input -p tcp --dport 8443 -j ACCEPT")
        migration.verify(doc)
        self.assertFalse(doc["families"][0]["rules"][-1]["action"] == "ACCEPT")
        text = migration.render(doc)
        before_v6 = text.split("chain fwsec_m6_INPUT")[0]
        self.assertNotIn("8443", before_v6)
        self.assertIn("meta nfproto ipv6 jump fwsec_m6_INPUT", text)

    def test_source_destination_interface_and_order_preserved(self):
        doc = policy(v4='-A ufw-user-input -s 192.0.2.0/24 -d 198.51.100.3 '
                     '-i eth0 -p tcp --dport 443 -j ACCEPT\n'
                     '-A ufw-user-input -p tcp --dport 443 -j DROP')
        text = migration.render(doc)
        self.assertIn('ip saddr 192.0.2.0/24 ip daddr 198.51.100.3/32 iifname "eth0"', text)
        self.assertLess(text.index("192.0.2.0/24"), text.index("dport { 443 } drop"))

    def test_output_default_drop_is_enforced(self):
        doc = policy(v4="-A OUTPUT -p tcp --dport 443 -j ACCEPT")
        text = migration.render(doc)
        output_chain = text.split("chain fwsec_m4_OUTPUT {")[1].split("}", 2)
        self.assertIn("443", output_chain[0])
        self.assertIn("drop", text.split("chain fwsec_m4_OUTPUT {")[1].split("chain ")[0])

    def test_requires_approval_for_ambiguous_direct_base_rules(self):
        v4 = fixture(rules_text="-A INPUT -p tcp --dport 22 -j ACCEPT")
        doc = migration.plan("ufw", v4, fixture(6))
        self.assertEqual(doc["status"], "requires-approval")
        with self.assertRaises(ValueError):
            migration.verify(doc)
        self.assertEqual(migration.plan("ufw", v4, fixture(6),
                                       approve=doc["fingerprint"])["status"], "ready")

    def test_unapproved_source_change_invalidates_approval(self):
        first = migration.plan("ufw", fixture(), fixture(6))
        changed = migration.plan("ufw", fixture(rules_text="-A INPUT -j ACCEPT"),
                                 fixture(6), approve=first["fingerprint"])
        self.assertEqual(changed["status"], "requires-approval")

    def test_unknown_extensions_block_even_with_approval(self):
        for rule in ("-A INPUT -m limit --limit 1/sec -j ACCEPT",
                     "-A INPUT -m set --match-set cc_cn src -j DROP",
                     "-A INPUT -j REJECT", "-A INPUT ! -s 192.0.2.1 -j DROP",
                     "-A INPUT -i eth+ -j ACCEPT", "-A INPUT -j LOG"):
            with self.subTest(rule=rule):
                d = policy(v4=rule)
                self.assertEqual(d["status"], "blocked")
                with self.assertRaises(ValueError):
                    migration.render(d)

    def test_nat_is_never_silently_discarded(self):
        v4 = fixture() + "*nat\n:PREROUTING ACCEPT [0:0]\n-A PREROUTING -j DNAT\nCOMMIT\n"
        d = migration.plan("ufw", v4, fixture(6))
        self.assertEqual(d["status"], "blocked")
        self.assertIn("nat:", " ".join(d["unsupported"]))

    def test_unknown_third_party_chain_blocks_retirement(self):
        d = migration.plan("ufw", fixture().replace("COMMIT", ":libvirt - [0:0]\nCOMMIT"),
                           fixture(6))
        self.assertIn("Third-party", " ".join(d["unsupported"]))

    def test_native_firewalld_is_not_flattened(self):
        d = migration.plan("firewalld", fixture(source="csf"), fixture(6, source="csf"),
                           {"nftables": [{"table": {"family": "inet", "name": "firewalld"}}]})
        self.assertEqual(d["status"], "blocked")
        self.assertIn("native nft", " ".join(d["unsupported"]))

    def test_bad_or_missing_snapshot_blocks(self):
        self.assertEqual(migration.plan("ufw", "", fixture(6))["status"], "blocked")
        self.assertEqual(migration.plan("ufw", "*filter\ninvalid\nCOMMIT", fixture(6))[
            "status"], "blocked")

    def test_cycle_is_rejected(self):
        self.assertEqual(policy(v4="-A ufw-user-input -j INPUT")["status"], "blocked")

    def test_comments_never_become_executable_nft(self):
        doc = policy(v4='-A ufw-user-input -m comment --comment "flush ruleset;" -j ACCEPT')
        self.assertNotIn("flush ruleset", migration.render(doc))
        self.assertIn("flush ruleset", doc["families"][0]["rules"][-1]["comment"])

    def test_model_cannot_diverge_from_original_snapshot(self):
        doc = policy(v4="-A ufw-user-input -s 192.0.2.1 -j ACCEPT")
        modified = copy.deepcopy(doc)
        modified["families"][0]["rules"][-1]["matches"] = []
        with self.assertRaises(ValueError):
            migration.render(modified)

    def test_csf_supported_chain_graph(self):
        doc = policy(v4="-A ALLOWIN -s 192.0.2.1 -j ACCEPT", source="csf")
        self.assertEqual(doc["status"], "ready")
        self.assertIn("jump fwsec_m4_ALLOWIN", migration.render(doc))

    def test_ports_and_states(self):
        doc = policy(v4="""-A OUTPUT -p tcp -m multiport --dports 443,8000:8080 -j ACCEPT
-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT""")
        text = migration.render(doc)
        self.assertIn("{ 443, 8000-8080 }", text)
        self.assertIn("ct state { established,related }", text)

    def test_retirement_has_no_blanket_flush(self):
        doc = policy(v4="-A ufw-user-input -s 192.0.2.1 -j ACCEPT")
        batch = migration.retirement(doc, 4, doc["snapshots"]["4"])
        self.assertIn("-D INPUT -j ufw-user-input", batch)
        self.assertIn("-F ufw-user-input", batch)
        self.assertNotIn("\n-F\n", batch)
        self.assertNotIn("\n-X\n", batch)
        self.assertNotIn("flush ruleset", batch)

    def test_retirement_refuses_new_or_changed_source_rules(self):
        doc = policy()
        with self.assertRaisesRegex(ValueError, "changed"):
            changed = doc["snapshots"]["4"].replace("COMMIT", "-A INPUT -j DROP\nCOMMIT")
            migration.retirement(doc, 4, changed)

    def test_finalize_needs_confirmation_and_matching_kernel_policy(self):
        doc = policy()
        with patch.object(migration, "active_digest", return_value="kernel"), \
                patch("subprocess.run") as command:
            with self.assertRaises(ValueError):
                migration.finalize(doc, {})
            command.assert_not_called()

    def test_legacy_default_config_unchanged(self):
        self.assertIn("policy accept", rules.generate_filter_table(config.FwsecConfig(), [22]))

    def test_inherited_policy_uses_own_chains_not_global_ports(self):
        doc = policy(v6="-A ufw-user-input -p tcp --dport 8443 -j ACCEPT")
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps(doc))
            c = config.FwsecConfig(tcp_in=["7777"], inherited_policy=path)
            transaction.validate(c, [22])
            self.assertNotIn("7777", rules.generate_filter_table(c, [22]))
            self.assertIn("fwsec_m6", rules.generate_fwsec_table(c))

    def test_return_in_base_chain_obeys_its_default_policy(self):
        doc = policy(v4="-A INPUT -j RETURN")
        text = migration.render(doc).split("chain fwsec_m4_INPUT {")[1].split("}")[0]
        self.assertNotIn("return", text)
        self.assertIn("drop", text)

    def test_missing_commit_is_blocked(self):
        doc = migration.plan("ufw", fixture().replace("COMMIT", ""), fixture(6))
        self.assertEqual(doc["status"], "blocked")

    def test_builtin_policy_cannot_be_empty(self):
        doc = migration.plan("ufw", fixture().replace(":INPUT DROP", ":INPUT -"), fixture(6))
        self.assertEqual(doc["status"], "blocked")

    def test_snapshot_comments_do_not_invalidate_approval(self):
        doc = policy()
        batch = migration.retirement(doc, 4, "# timestamp changed\n" + doc["snapshots"]["4"])
        self.assertIn("COMMIT", batch)

    def test_native_backend_evidence_is_revalidated(self):
        doc = policy()
        doc["snapshots"]["nft"] = {"nftables": [{"table": {
            "name": "firewalld", "family": "inet"}}]}
        with self.assertRaises(ValueError):
            migration.verify(doc)

    def test_distinct_user_chain_names_do_not_collide(self):
        self.assertNotEqual(migration.chain_name(4, "ufw-a-b"),
                            migration.chain_name(4, "ufw-a_b"))


if __name__ == "__main__":
    unittest.main()
