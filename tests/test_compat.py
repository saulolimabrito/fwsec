# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import unittest
from unittest.mock import Mock, patch

from fwsec import compat, config, transaction


class CompatibilityTests(unittest.TestCase):
    def test_only_anonymous_observation_counters_are_ignored(self):
        live = {"expr": [{"counter": {"packets": 2, "bytes": 100}}, {"accept": None}]}
        candidate = {"expr": [{"accept": None}]}
        self.assertEqual(compat.normalize(live), compat.normalize(candidate))
        named = {"expr": [{"counter": {"name": "custom"}}, {"accept": None}]}
        self.assertNotEqual(compat.normalize(named), compat.normalize(candidate))

    def test_sets_are_unordered_but_rules_are_ordered(self):
        self.assertEqual(compat.normalize({"set": [443, 80]}),
                         compat.normalize({"set": [80, 443]}))
        self.assertNotEqual(compat.normalize({"expr": [{"drop": None}, {"accept": None}]}),
                            compat.normalize({"expr": [{"accept": None}, {"drop": None}]}))

    def test_singleton_set_has_same_membership_as_scalar(self):
        self.assertEqual(compat.normalize({"set": [24959]}), 24959)

    def test_timed_elements_compare_remaining_life_not_full_duration(self):
        old = {"elem": {"val": "192.0.2.1", "timeout": 3600, "expires": 60}}
        new = {"elem": {"val": "192.0.2.1", "timeout": 59, "expires": 58}}
        self.assertTrue(compat.equivalent(compat.normalize(old), compat.normalize(new)))
        new["elem"]["expires"] = 500
        self.assertFalse(compat.equivalent(compat.normalize(old), compat.normalize(new)))
        self.assertFalse(compat.equivalent(compat.normalize(old), "192.0.2.1"))

    def test_packet_modification_is_not_ignored(self):
        self.assertFalse(compat.equivalent({"expr": [{"mangle": {"value": 1}}]},
                                           {"expr": [{"accept": None}]}))

    def test_shared_foreign_chain_is_not_claimed(self):
        rows = [{"chain": {"family": "inet", "table": "filter", "name": "foreign"}},
                {"rule": {"family": "inet", "table": "filter", "chain": "foreign",
                          "expr": [{"drop": None}]}}]
        self.assertFalse(compat.objects(rows, "filter", "filter", {})["chains"])

    def test_unknown_fwsec_objects_are_not_discarded(self):
        rows = [{"map": {"family": "inet", "table": "fwsec", "name": "custom"}}]
        self.assertTrue(compat.objects(rows, "fwsec", "fwsec", {})["other"])

    def test_unexpected_chain_comment_is_not_erased(self):
        self.assertEqual(compat.normalize({"comment": transaction.MARKER}), {})
        self.assertNotEqual(compat.normalize({"comment": "administrator rule"}), {})

    def test_probe_is_unhooked_and_is_cleaned_on_mismatch(self):
        c = config.FwsecConfig()
        script = '''add table inet filter
table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;
    }
}
table inet fwsec {
    chain whitelist {
        type filter hook input priority -100; policy accept;
    }
}
'''
        # Empty live objects deliberately differ from the candidate.
        uuid = Mock(hex="a" * 32)
        with patch("fwsec.compat.uuid.uuid4", return_value=uuid), \
                patch.object(transaction, "check"), \
                patch.object(transaction, "_objects", return_value=[{"chain": {
                    "family": "inet", "table": "filter", "name": "input", "hook": "input",
                    "type": "filter", "prio": 0, "policy": "drop"}}]), \
                patch("fwsec.nft._run_script") as run:
            with self.assertRaisesRegex(RuntimeError, "differs"):
                compat.prove(c, script)
        self.assertEqual(run.call_count, 2)
        probe = run.call_args_list[0].args[0]
        self.assertNotIn("type filter hook", probe)
        self.assertNotIn("inet filter\n", probe)
        cleanup = run.call_args_list[1].args[0]
        self.assertIn("delete table inet fwsec_upgrade_", cleanup)
        self.assertNotIn("delete table inet fwsec\n", cleanup)

    def test_inherited_policy_requires_explicit_review(self):
        from pathlib import Path
        with self.assertRaisesRegex(RuntimeError, "operator review"):
            compat.prove(config.FwsecConfig(inherited_policy=Path("policy.json")), "")


if __name__ == "__main__":
    unittest.main()
