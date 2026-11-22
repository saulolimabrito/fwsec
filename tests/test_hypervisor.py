# SPDX-License-Identifier: GPL-2.0-only
"""Hypervisor detection, VM network filter and hypervisor-mode policy."""
from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwsec import compat, config, hypervisor, rules, transaction, ui
from fwsec.config import FwsecConfig

NAT_XML = """<network>
  <name>default</name>
  <forward mode='nat'/>
  <bridge name='virbr0'/>
  <ip address='192.168.122.1' netmask='255.255.255.0'>
    <dhcp><range start='192.168.122.2' end='192.168.122.254'/></dhcp>
  </ip>
  <ip family="ipv6" address="fd00:122::1" prefix="64"/>
</network>"""

ROUTED_XML = """<network><name>lab</name><forward mode="route"/>
  <ip prefix="24" address="10.10.0.1"/></network>"""

BRIDGE_XML = """<network><name>host-bridge</name><forward mode='bridge'/>
  <bridge name='br0'/></network>"""


def chain(text: str, name: str) -> str:
    m = re.search(rf"chain {name} \{{(.*?)\n    \}}", text, re.S)
    assert m, name
    return m.group(1)


class Detection(unittest.TestCase):
    def test_parse_nat_netmask_and_ipv6_prefix(self) -> None:
        self.assertEqual(hypervisor.parse_network_xml(NAT_XML),
                         ["192.168.122.0/24", "fd00:122::/64"])

    def test_parse_routed_any_attribute_order(self) -> None:
        self.assertEqual(hypervisor.parse_network_xml(ROUTED_XML), ["10.10.0.0/24"])

    def test_parse_bridge_name(self) -> None:
        self.assertEqual(hypervisor.parse_network(NAT_XML)[0], "virbr0")
        self.assertEqual(hypervisor.parse_network(BRIDGE_XML), ("", []))

    def test_layer2_and_invalid_networks_have_no_subnet(self) -> None:
        self.assertEqual(hypervisor.parse_network_xml(BRIDGE_XML), [])
        self.assertEqual(hypervisor.parse_network_xml("<network"), [])

    def test_vm_networks_from_virsh(self) -> None:
        outputs = {("virsh", "net-list", "--name"): (0, "default\nlab\n\n"),
                   ("virsh", "net-dumpxml", "default"): (0, NAT_XML),
                   ("virsh", "net-dumpxml", "lab"): (0, ROUTED_XML)}
        with patch("shutil.which", return_value="/usr/bin/virsh"), \
                patch.object(hypervisor, "_run", side_effect=lambda c: outputs[tuple(c)]):
            self.assertEqual(hypervisor.vm_networks(),
                             ["10.10.0.0/24", "192.168.122.0/24", "fd00:122::/64"])

    def test_vm_networks_without_virsh(self) -> None:
        with patch("shutil.which", return_value=None):
            self.assertEqual(hypervisor.vm_networks(), [])

    def test_bridge_classification(self) -> None:
        out = ("3: virbr0: <BROADCAST> mtu 1500\n4: docker0: <NO-CARRIER> mtu 1500\n"
               "5: br-1a2b3c: <BROADCAST> mtu 1500\n6: vmbr0: <BROADCAST> mtu 1500\n"
               "7: lxdbr0: <BROADCAST> mtu 1500\n")
        with patch.object(hypervisor, "_run", return_value=(0, out)):
            self.assertEqual(hypervisor.vm_bridges(), ["virbr0", "vmbr0"])

    def test_br_netfilter_states(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(hypervisor, "BR_NF", root):
                self.assertEqual(hypervisor.br_netfilter(), {"ipv4": None, "ipv6": None})
                (root / "bridge-nf-call-iptables").write_text("1\n")
                (root / "bridge-nf-call-ip6tables").write_text("0\n")
                self.assertEqual(hypervisor.br_netfilter(), {"ipv4": True, "ipv6": False})

    def test_detect(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pve = Path(tmp) / "pve"
            pve.mkdir()
            which = {"virsh": "/usr/bin/virsh"}
            with patch.object(hypervisor, "PVE_DIR", pve), \
                    patch.object(hypervisor, "XEN_PROC", Path(tmp) / "xen"), \
                    patch("shutil.which", side_effect=which.get):
                self.assertEqual(hypervisor.detect(), ["proxmox", "libvirt"])


class Policy(unittest.TestCase):
    def test_forward_chain_follows_mode(self) -> None:
        for cfg, policy in ((FwsecConfig(), "drop"),
                            (FwsecConfig(hypervisor_mode=True), "accept"),
                            (FwsecConfig(container_mode=True), "accept")):
            body = chain(rules.generate_filter_table(cfg, [22]), "forward")
            self.assertIn(f"policy {policy};", body)
            if policy == "accept":
                self.assertIn("ip  saddr @crowdsec-blacklists  drop", body)

    def test_libvirt_dns_dhcp_only_in_hypervisor_mode(self) -> None:
        on = rules.generate_filter_table(FwsecConfig(hypervisor_mode=True), [22])
        self.assertIn('iifname "virbr*" udp dport { 53, 67, 547 } accept', chain(on, "input"))
        self.assertIn('iifname "virbr*" tcp dport 53 accept', chain(on, "input"))
        self.assertNotIn("virbr", chain(on, "output"))  # OUTPUT_POLICY accept
        drop = rules.generate_filter_table(
            FwsecConfig(hypervisor_mode=True, output_policy="drop"), [22])
        self.assertIn('oifname "virbr*" udp dport { 68, 546 } accept', chain(drop, "output"))
        self.assertNotIn("virbr", rules.generate_filter_table(FwsecConfig(), [22]))

    def test_vm_filter_order(self) -> None:
        text = rules.generate_vm_filter(["192.168.122.0/24", "fd00:122::/64", "10.10.0.0/24"])
        body = chain(text, "vms")
        self.assertIn("type filter hook forward priority -55; policy accept;", body)
        lines = [ln.strip() for ln in body.splitlines()[2:] if ln.strip()]
        self.assertEqual(lines, [
            "ip  saddr @allow4 accept",
            "ip6 saddr @allow6 accept",
            "ct state established,related accept",
            "ip  saddr { 10.10.0.0/24, 192.168.122.0/24 } accept",
            "ip  daddr { 10.10.0.0/24, 192.168.122.0/24 } ct state new drop",
            "ip6 saddr { fd00:122::/64 } accept",
            "ip6 daddr { fd00:122::/64 } ct state new drop",
        ])

    def test_vm_filter_without_networks_is_inert(self) -> None:
        body = chain(rules.generate_vm_filter([]), "vms")
        self.assertNotIn("drop", body)

    def test_vm_policy_requires_hypervisor_mode(self) -> None:
        self.assertFalse(transaction.vm_filtered(FwsecConfig(vm_policy="filtered")))
        self.assertTrue(transaction.vm_filtered(
            FwsecConfig(hypervisor_mode=True, vm_policy="filtered")))

    def test_compat_specs(self) -> None:
        specs = compat.hooks(FwsecConfig(hypervisor_mode=True), False, vms=True)
        self.assertEqual(specs["filter"]["forward"]["policy"], "accept")
        self.assertEqual(specs["fwsec"]["vms"]["prio"], -55)
        self.assertNotIn("vms", compat.hooks(FwsecConfig(), False)["fwsec"])

    def test_validate_rejects_unknown_vm_policy(self) -> None:
        with self.assertRaisesRegex(ValueError, "VM_POLICY"):
            transaction.validate(FwsecConfig(vm_policy="closed"), [22])

    def test_config_section_optional(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            conf = Path(tmp) / "fwsec.conf"
            with patch.object(config, "CONF_FILE", conf):
                conf.write_text("[firewall]\nTCP_IN = 80\n")
                c = config.load_config()
                self.assertEqual((c.hypervisor_mode, c.vm_policy), (False, "open"))
                conf.write_text("[hypervisor]\nHYPERVISOR_MODE = 1\nVM_POLICY = Filtered\n")
                c = config.load_config()
                self.assertEqual((c.hypervisor_mode, c.vm_policy), (True, "filtered"))


class Diagnostics(unittest.TestCase):
    def status(self, cfg: FwsecConfig, detected: list[str], bridges: list[str],
               br_nf: dict[str, bool | None], pve: bool = False,
               networks: dict[str, list[str]] | None = None) -> dict[str, object]:
        with patch.object(hypervisor, "detect", return_value=detected), \
                patch.object(hypervisor, "vm_bridges", return_value=bridges), \
                patch.object(hypervisor, "libvirt_networks", return_value=networks or {}), \
                patch.object(hypervisor, "br_netfilter", return_value=br_nf), \
                patch.object(hypervisor, "pve_firewall_active", return_value=pve):
            return ui.hypervisor_status(cfg)

    def test_no_hypervisor_is_silent(self) -> None:
        data = self.status(FwsecConfig(), [], [], {"ipv4": None, "ipv6": None})
        self.assertEqual(data["warnings"], [])

    def test_mode_off_on_hypervisor_warns(self) -> None:
        data = self.status(FwsecConfig(), ["libvirt"], ["virbr0"], {"ipv4": None, "ipv6": None})
        self.assertTrue(any("HYPERVISOR_MODE = 0" in w for w in data["warnings"]))  # type: ignore[attr-defined]

    def test_libvirt_nat_bridge_is_routed_not_bridged(self) -> None:
        data = self.status(FwsecConfig(hypervisor_mode=True), ["libvirt"], ["virbr0"],
                           {"ipv4": None, "ipv6": None},
                           networks={"virbr0": ["192.168.122.0/24"]})
        self.assertEqual(data["warnings"], [])
        self.assertEqual(data["lan_bridges"], [])
        self.assertEqual(data["vm_networks"], ["192.168.122.0/24"])

    def test_bridged_vms_without_br_netfilter_and_pve(self) -> None:
        data = self.status(FwsecConfig(hypervisor_mode=True, vm_policy="filtered"),
                           ["proxmox"], ["vmbr0"], {"ipv4": None, "ipv6": None}, pve=True)
        text = " ".join(data["warnings"])  # type: ignore[arg-type]
        self.assertIn("br_netfilter is not loaded", text)
        self.assertIn("pve-firewall is active", text)
        self.assertIn("no active libvirt", text)


if __name__ == "__main__":
    unittest.main()
