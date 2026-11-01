# SPDX-License-Identifier: GPL-2.0-only

import tempfile
import unittest
from pathlib import Path

from fwsec import geo


class ParseZoneTest(unittest.TestCase):
    def test_valid_cidrs_and_plain_ips(self):
        data = b"1.0.0.0/8\n\n# comment\n2.16.0.0/13\n1.2.3.4\nnot-an-ip\n"
        nets = geo.parse_zone(data)
        self.assertIn("1.0.0.0/8", nets)
        self.assertIn("2.16.0.0/13", nets)
        self.assertIn("1.2.3.4/32", nets)
        self.assertNotIn("not-an-ip", nets)

    def test_ipv6(self):
        data = b"2001:db8::/32\n2400::/12\n"
        nets = geo.parse_zone(data)
        self.assertIn("2001:db8::/32", nets)
        self.assertIn("2400::/12", nets)


class RenderApplyFileTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "br.zone").write_text("177.0.0.0/8\n191.0.0.0/8\n")
        (self.dir / "br6.zone").write_text("2801:80::/32\n")
        (self.dir / "us.zone").write_text("6.0.0.0/8\n")  # no IPv6 zone

    def test_structure(self):
        script = geo.render_apply_file(["br", "us"], self.dir)
        lines = script.splitlines()
        self.assertEqual("flush set inet fwsec geo4", lines[0])
        self.assertEqual("flush set inet fwsec geo6", lines[1])
        self.assertIn("add element inet fwsec geo4 { 177.0.0.0/8, 191.0.0.0/8 }", script)
        self.assertIn("add element inet fwsec geo6 { 2801:80::/32 }", script)
        # us has no IPv6 zone — no empty add element statement
        self.assertEqual(script.count("add element inet fwsec geo6"), 1)

    def test_resolve_all(self):
        c4, c6 = geo.resolve_all(["br", "us"], self.dir)
        self.assertEqual(sorted(c4), ["177.0.0.0/8", "191.0.0.0/8", "6.0.0.0/8"])
        self.assertEqual(c6, ["2801:80::/32"])


class LookupCountryTest(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        (self.dir / "br.zone").write_text("177.0.0.0/8\n191.5.0.0/16\n")
        (self.dir / "us.zone").write_text("6.0.0.0/8\n")

    def test_longest_prefix_wins(self):
        # 191.5.0.0/16 (br) is more specific than nothing else overlapping
        self.assertEqual(geo.lookup_country("191.5.1.1", ["br"], self.dir), "br")
        self.assertEqual(geo.lookup_country("177.20.1.1", ["br"], self.dir), "br")
        self.assertEqual(geo.lookup_country("6.1.1.1", ["us", "br"], self.dir), "us")
        self.assertIsNone(geo.lookup_country("8.8.8.8", ["br", "us"], self.dir))
        self.assertIsNone(geo.lookup_country("not-an-ip", ["br"], self.dir))

    def test_overlapping_prefixes(self):
        (self.dir / "xx.zone").write_text("191.5.1.0/24\n")
        self.assertEqual(
            geo.lookup_country("191.5.1.99", ["br", "xx"], self.dir), "xx"
        )
        self.assertEqual(
            geo.lookup_country("191.5.2.99", ["br", "xx"], self.dir), "br"
        )


class ZoneCountsTest(unittest.TestCase):
    def test_counts_and_last_updated(self):
        d = Path(tempfile.mkdtemp())
        (d / "br.zone").write_text("1.0.0.0/8\n2.0.0.0/8\n")
        (d / "br6.zone").write_text("2801:80::/32\n")
        self.assertEqual(geo.zone_counts(["br"], d), {"br": 3})
        self.assertIsNotNone(geo.zones_last_updated(d))
        self.assertIsNone(geo.zones_last_updated(Path(tempfile.mkdtemp())))


if __name__ == "__main__":
    unittest.main()
