# SPDX-License-Identifier: GPL-2.0-only

"""
Hypervisor and bridge detection (KVM/libvirt, Proxmox VE, Xen).

NAT/routed VM traffic (libvirt's default virbr0 network) always traverses the
nftables forward hook. Bridged VM traffic is layer 2 and only reaches the L3
hooks when br_netfilter is loaded with bridge-nf-call-iptables=1, so this
module reports that state instead of letting it change filtering silently.

Everything is best-effort and read-only: missing binaries yield empty results.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

# Bridge name prefixes owned by container runtimes / orchestrators, not VMs.
CONTAINER_BRIDGES = ("docker", "podman", "cni", "br-", "lxcbr", "lxdbr", "incusbr",
                     "nerdctl", "cbr", "flannel", "kube", "cilium")

BR_NF = Path("/proc/sys/net/bridge")
PVE_DIR = Path("/etc/pve")
XEN_PROC = Path("/proc/xen")


def _run(cmd: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout
    except (OSError, subprocess.SubprocessError):
        return 1, ""


def detect() -> list[str]:
    """Hypervisor stacks present on this host (proxmox, libvirt, xen)."""
    found = []
    if PVE_DIR.is_dir() or shutil.which("pveversion"):
        found.append("proxmox")
    if shutil.which("virsh"):
        found.append("libvirt")
    if shutil.which("xl") and XEN_PROC.exists():
        found.append("xen")
    return found


@dataclass
class Bridge:
    name: str
    kind: str  # "vm" | "container"


def classify(name: str) -> str:
    return "container" if name.startswith(CONTAINER_BRIDGES) else "vm"


def bridges() -> list[Bridge]:
    """Bridge interfaces, classified as VM or container bridges."""
    rc, out = _run(["ip", "-o", "link", "show", "type", "bridge"])
    if rc != 0:
        return []
    result = []
    for line in out.splitlines():
        m = re.match(r"\d+:\s*([^:@\s]+)", line)
        if m:
            result.append(Bridge(m.group(1), classify(m.group(1))))
    return result


def vm_bridges() -> list[str]:
    return [b.name for b in bridges() if b.kind == "vm"]


def br_netfilter() -> dict[str, bool | None]:
    """Whether bridged IPv4/IPv6 traffic traverses the nftables L3 hooks.

    None means the br_netfilter module is not loaded (bridged VMs bypass
    fwsec entirely, including bans).
    """
    state: dict[str, bool | None] = {}
    for family, name in (("ipv4", "bridge-nf-call-iptables"),
                         ("ipv6", "bridge-nf-call-ip6tables")):
        try:
            state[family] = (BR_NF / name).read_text().strip() == "1"
        except OSError:
            state[family] = None
    return state


def parse_network(xml: str) -> tuple[str, list[str]]:
    """(bridge, subnets) of a libvirt <network> with a host-routed subnet.

    NAT, routed and isolated networks have a host IP: their VMs are routed
    through the forward hook. Layer-2 attached networks (bridge, macvtap,
    hostdev) have no host subnet and yield ("", []).
    """
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return "", []
    forward = root.find("forward")
    if forward is not None and forward.get("mode") in ("bridge", "hostdev", "passthrough",
                                                        "private", "vepa"):
        return "", []
    subnets = []
    for ip in root.findall("ip"):
        address = ip.get("address")
        mask = ip.get("prefix") or ip.get("netmask")
        if not address or not mask:
            continue
        try:
            subnets.append(str(ipaddress.ip_interface(f"{address}/{mask}").network))
        except ValueError:
            continue
    bridge = root.find("bridge")
    name = bridge.get("name", "") if bridge is not None and subnets else ""
    return name, subnets


def parse_network_xml(xml: str) -> list[str]:
    return parse_network(xml)[1]


def libvirt_networks() -> dict[str, list[str]]:
    """Active libvirt NAT/routed networks: {bridge: subnets}."""
    if not shutil.which("virsh"):
        return {}
    rc, out = _run(["virsh", "net-list", "--name"])
    if rc != 0:
        return {}
    result: dict[str, list[str]] = {}
    for net in out.split():
        rc, xml = _run(["virsh", "net-dumpxml", net])
        if rc == 0:
            bridge, subnets = parse_network(xml)
            if subnets:
                result.setdefault(bridge or net, []).extend(subnets)
    return result


def vm_networks(networks: dict[str, list[str]] | None = None) -> list[str]:
    """Subnets (CIDR) of active libvirt-managed NAT/routed VM networks."""
    nets = libvirt_networks() if networks is None else networks
    subnets = {s for values in nets.values() for s in values}
    return sorted(subnets, key=lambda s: (":" in s, s))


def pve_firewall_active() -> bool:
    rc, out = _run(["systemctl", "is-active", "pve-firewall"])
    return rc == 0 and out.strip() == "active"

