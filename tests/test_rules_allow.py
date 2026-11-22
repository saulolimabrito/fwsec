# SPDX-License-Identifier: GPL-2.0-only
"""fwsec.allow must win in every base chain, not only in inet fwsec/whitelist.

nftables `accept` ends only the current base chain; every later base chain on
the same hook must accept the allow mark before any drop decision.
"""
from __future__ import annotations

import re
import unittest

from fwsec import rules
from fwsec.config import FwsecConfig

MASKED = "meta mark & 0x46575345 == 0x46575345 accept"
EXACT = "meta mark 0x46575345 accept"


def chain(text: str, name: str) -> str:
    m = re.search(rf"chain {name} \{{(.*?)\n    \}}", text, re.S)
    assert m, name
    return m.group(1)


def first_rule(body: str) -> str:
    lines = [ln.strip() for ln in body.splitlines()
             if ln.strip() and not ln.strip().startswith(("#", "type "))]
    return lines[0]


class AllowPrecedence(unittest.TestCase):
    def check(self, cfg: FwsecConfig, match: str, tag: str) -> None:
        fw = rules.generate_fwsec_table(cfg)
        filt = rules.generate_filter_table(cfg, [22])
        self.assertIn(f"ip  saddr @allow4 {tag} accept", chain(fw, "whitelist"))
        self.assertIn(f"ip6 saddr @allow6 {tag} accept", chain(fw, "whitelist"))
        self.assertIn(f"ip  saddr @allow4 {tag} accept", chain(fw, "whitelist_forward"))
        for name in ("blacklist", "blacklist_forward"):
            self.assertEqual(first_rule(chain(fw, name)), match, name)
        for name in ("input", "forward"):
            self.assertEqual(first_rule(chain(filt, name)), match, name)
        # The allow bypass is evaluated before CrowdSec and the port policy.
        body = chain(filt, "input")
        self.assertLess(body.index(match), body.index("@crowdsec-blacklists"))
        self.assertNotIn(match, chain(filt, "output"))

    def test_default_masked_mark_preserves_foreign_bits(self) -> None:
        self.check(FwsecConfig(), MASKED, "meta mark set meta mark | 0x46575345")

    def test_whitelist_mark_keeps_exact_historical_value(self) -> None:
        self.check(FwsecConfig(whitelist_mark=True), EXACT, "meta mark set 0x46575345")

    def test_container_mode_forward(self) -> None:
        self.check(FwsecConfig(container_mode=True), MASKED,
                   "meta mark set meta mark | 0x46575345")

    def test_geo_chains_accept_allow_list_first(self) -> None:
        for cfg in (FwsecConfig(geo_block=["cn"], geo_forward=True),
                    FwsecConfig(geo_allow=["br"], geo_forward=True)):
            fw = rules.generate_fwsec_table(cfg)
            for name in ("geo_blacklist", "geo_blacklist_forward"):
                self.assertEqual(first_rule(chain(fw, name)), "ip  saddr @allow4 accept")

    def test_container_filter_accepts_allow_list_first(self) -> None:
        text = rules.generate_container_filter([80], [], [])
        self.assertEqual(first_rule(chain(text, "containers")), "ip  saddr @allow4 accept")


if __name__ == "__main__":
    unittest.main()
