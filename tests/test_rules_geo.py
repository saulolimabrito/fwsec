# SPDX-License-Identifier: GPL-2.0-only

import unittest

from fwsec import rules
from fwsec.config import FwsecConfig


class GeoSectionTest(unittest.TestCase):
    def test_off_generates_no_geo(self):
        cfg = FwsecConfig()
        table = rules.generate_fwsec_table(cfg)
        self.assertNotIn("geo4", table)
        self.assertNotIn("geo_blacklist", table)

    def test_deny_mode(self):
        cfg = FwsecConfig(geo_block=["cn", "ru"])
        table = rules.generate_fwsec_table(cfg)
        self.assertIn("set geo4 {", table)
        self.assertIn("set geo6 {", table)
        self.assertIn("chain geo_blacklist {", table)
        self.assertIn("type filter hook input priority -40; policy accept;", table)
        self.assertIn("ip  saddr @geo4 drop", table)
        self.assertIn("ip6 saddr @geo6 drop", table)
        # allow list evaluated before the geo drop
        self.assertLess(
            table.find("ip  saddr @allow4 accept"),
            table.find("ip  saddr @geo4 drop"),
        )
        self.assertNotIn("geo_blacklist_forward", table)  # GEO_FORWARD=0

    def test_deny_mode_forward(self):
        cfg = FwsecConfig(geo_block=["cn"], geo_forward=True)
        table = rules.generate_fwsec_table(cfg)
        self.assertIn("chain geo_blacklist_forward {", table)
        self.assertIn("type filter hook forward priority -40; policy accept;", table)

    def test_allow_mode_is_deny_all(self):
        cfg = FwsecConfig(geo_allow=["br", "us"])
        table = rules.generate_fwsec_table(cfg)
        self.assertIn(
            "type filter hook input priority -40; policy drop;", table
        )
        self.assertIn("ip  saddr @allow4 accept", table)
        self.assertIn("ip  saddr @geo4 accept", table)
        # internal traffic exemptions
        self.assertIn("192.168.0.0/16", table)
        self.assertIn("127.0.0.0/8", table)
        self.assertIn("fe80::/10", table)
        self.assertNotIn("ip  saddr @geo4 drop", table)

    def test_block_and_allow_together_raise(self):
        cfg = FwsecConfig(geo_block=["cn"], geo_allow=["br"])
        with self.assertRaises(ValueError):
            rules.generate_fwsec_table(cfg)

    def test_whitelist_mark_still_works_with_geo(self):
        cfg = FwsecConfig(geo_allow=["br"], whitelist_mark=True)
        table = rules.generate_fwsec_table(cfg)
        self.assertIn("meta mark set 0x46575345", table)

    def test_no_geo_regression_on_default(self):
        cfg = FwsecConfig()
        table = rules.generate_fwsec_table(cfg)
        self.assertNotIn("meta mark", table)  # WHITELIST_MARK=0
        self.assertIn("ip  saddr @allow4 accept", table)


if __name__ == "__main__":
    unittest.main()
