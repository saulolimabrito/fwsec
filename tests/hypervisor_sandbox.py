# SPDX-License-Identifier: GPL-2.0-only
"""Real-packet hypervisor-mode checks. ONLY run via unshare --net, not on a host.

Invocation: sudo env PYTHONPATH=src unshare --net python3 tests/hypervisor_sandbox.py

The sandbox namespace plays the hypervisor host and routes between two
namespaces: a client (10.199.0.0/24, fd99::/64) and a "VM" on a libvirt-like
NAT/routed network (192.168.122.0/24, fd00:122::/64). IPv4 and IPv6 TCP SYNs
cross the forward hook, exercising HYPERVISOR_MODE, VM_POLICY, the allow list
and forward bans.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from fwsec import config, nft, rules, transaction
from fwsec.state import State

PID = os.getpid()
CLI_NS, VM_NS = f"fwh-cli-{PID}", f"fwh-vm-{PID}"
NETS = {"cli": ("10.199.0", "fd99:"), "vm": ("192.168.122", "fd00:122:")}
VM_NETWORKS = ["192.168.122.0/24", "fd00:122::/64"]
VM_PORT, CLI_PORT = 18100, 18200


def sh(*args: str) -> None:
    subprocess.run(args, check=True)


def addr(side: str, host: int, v: int) -> str:
    v4, v6 = NETS[side]
    return f"{v4}.{host}" if v == 4 else f"{v6}:{host}"


def setup_network() -> list[subprocess.Popen[bytes]]:
    sh("ip", "link", "set", "lo", "up")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("1")
    Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text("1")
    servers = []
    for side, ns, port in (("cli", CLI_NS, CLI_PORT), ("vm", VM_NS, VM_PORT)):
        host_if, peer_if = f"fh{side}0", f"fh{side}1"
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "add", host_if, "type", "veth", "peer", "name", peer_if)
        sh("ip", "link", "set", peer_if, "netns", ns)
        sh("ip", "addr", "add", f"{addr(side, 1, 4)}/24", "dev", host_if)
        sh("ip", "addr", "add", f"{addr(side, 1, 6)}/64", "dev", host_if, "nodad")
        sh("ip", "link", "set", host_if, "up")
        for cmd in (["ip", "link", "set", "lo", "up"],
                    ["ip", "addr", "add", f"{addr(side, 2, 4)}/24", "dev", peer_if],
                    ["ip", "addr", "add", f"{addr(side, 2, 6)}/64", "dev", peer_if, "nodad"],
                    ["ip", "link", "set", peer_if, "up"],
                    ["ip", "route", "add", "default", "via", addr(side, 1, 4)],
                    ["ip", "-6", "route", "add", "default", "via", addr(side, 1, 6)]):
            sh("ip", "netns", "exec", ns, *cmd)
        listen = (
            "import socket,time\n"
            "socks=[]\n"
            f"for fam,a in ((socket.AF_INET,{addr(side, 2, 4)!r}),"
            f"(socket.AF_INET6,{addr(side, 2, 6)!r})):\n"
            "    s=socket.socket(fam);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)\n"
            f"    s.bind((a,{port}));s.listen(256);socks.append(s)\n"
            "time.sleep(3600)\n")
        servers.append(subprocess.Popen(["ip", "netns", "exec", ns, sys.executable, "-I",
                                         "-c", listen]))
    time.sleep(1)
    return servers


def reachable(src_ns: str, dst: str, port: int) -> bool:
    family = "AF_INET6" if ":" in dst else "AF_INET"
    probe = (f"import socket,sys\ns=socket.socket(socket.{family});s.settimeout(1.5)\n"
             f"sys.exit(0 if s.connect_ex(({dst!r},{port}))==0 else 1)\n")
    return subprocess.run(["ip", "netns", "exec", src_ns, sys.executable, "-I", "-c",
                           probe]).returncode == 0


def expect(label: str, src_ns: str, dst: str, port: int, wanted: bool) -> None:
    got = reachable(src_ns, dst, port)
    print(f"{'ok ' if got == wanted else 'FAIL'} {label}: {'open' if got else 'blocked'}")
    if got != wanted:
        print(nft._run("list", "ruleset")[1])
        raise AssertionError(f"{label}: expected {'open' if wanted else 'blocked'}")


def element(op: str, table: str, set_name: str, ip: str) -> None:
    nft._run(op, "element", "inet", table, set_name, f"{{ {ip} }}", check=True)


def apply(c: config.FwsecConfig) -> None:
    before = transaction.snapshot()
    extra = rules.generate_vm_filter(VM_NETWORKS) if transaction.vm_filtered(c) else ""
    with patch("fwsec.state.load", return_value=State({}, {}, {})):
        script = transaction.build(c, [22], before, extra)
    with transaction.locked():
        transaction.apply(script, before)


def scenarios() -> None:
    for v in (4, 6):
        client, vm = addr("cli", 2, v), addr("vm", 2, v)
        crowdsec = "crowdsec-blacklists" if v == 4 else "crowdsec6-blacklists"
        inbound = f"v{v} client -> VM"
        outbound = f"v{v} VM -> client"

        print(f"-- v{v} HYPERVISOR_MODE = 0 (forward drops VM traffic)")
        apply(config.FwsecConfig())
        expect(inbound, CLI_NS, vm, VM_PORT, False)
        expect(outbound, VM_NS, client, CLI_PORT, False)

        print(f"-- v{v} HYPERVISOR_MODE = 1, VM_POLICY = open")
        apply(config.FwsecConfig(hypervisor_mode=True))
        expect(inbound, CLI_NS, vm, VM_PORT, True)
        expect(outbound, VM_NS, client, CLI_PORT, True)
        element("add", "fwsec", f"deny{v}", client)
        expect(inbound + " (client deny-listed)", CLI_NS, vm, VM_PORT, False)
        element("delete", "fwsec", f"deny{v}", client)
        element("add", "filter", crowdsec, client)
        expect(inbound + " (client banned by CrowdSec)", CLI_NS, vm, VM_PORT, False)
        element("delete", "filter", crowdsec, client)

        print(f"-- v{v} HYPERVISOR_MODE = 1, VM_POLICY = filtered")
        apply(config.FwsecConfig(hypervisor_mode=True, vm_policy="filtered"))
        expect(inbound, CLI_NS, vm, VM_PORT, False)
        expect(outbound + " (VM outbound keeps working)", VM_NS, client, CLI_PORT, True)
        element("add", "fwsec", f"allow{v}", client)
        expect(inbound + " (client allow-listed)", CLI_NS, vm, VM_PORT, True)
        element("add", "fwsec", f"deny{v}", client)
        element("add", "filter", crowdsec, client)
        expect(inbound + " (allow + deny + CrowdSec: allow wins)", CLI_NS, vm, VM_PORT, True)
        for table, name in (("fwsec", f"allow{v}"), ("fwsec", f"deny{v}"), ("filter", crowdsec)):
            element("delete", table, name, client)
        expect(inbound + " (cleared)", CLI_NS, vm, VM_PORT, False)

        print(f"-- v{v} VM_POLICY = filtered without HYPERVISOR_MODE is inert")
        apply(config.FwsecConfig(container_mode=True, vm_policy="filtered"))
        expect(inbound + " (container mode only)", CLI_NS, vm, VM_PORT, True)
        assert nft._run("list", "chain", "inet", "fwsec", "vms")[0] != 0


def run() -> None:
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("Refusing to test in the host's network namespace")
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        config.ALLOW_FILE = base / "allow"
        config.DENY_FILE = base / "deny"
        config.IGNORE_FILE = base / "ignore"
        config.CONF_FILE = base / "fwsec.conf"
        config.STATE_FILE = base / "state"
        config.EXECUTABLE = base / "fwsec-wrapper"
        config.MIGRATION_RECEIPT = base / "receipt"
        config.APPLIED_FILE = base / "applied.json"
        transaction.ROOT = base / "transactions"
        transaction.LOCK = base / "lock"
        transaction.LOADER_DEBIAN = base / "nftables.conf"
        transaction.LOADER_RHEL = base / "sysconfig.conf"
        transaction.LOADER_ALPINE = base / "alpine.nft"
        transaction.INCLUDE = base / "fwsec.nft"
        for path in (config.ALLOW_FILE, config.DENY_FILE, config.IGNORE_FILE):
            path.write_text("")
        servers: list[subprocess.Popen[bytes]] = []
        try:
            servers = setup_network()
            scenarios()
        finally:
            for server in servers:
                server.kill()
            for ns in (CLI_NS, VM_NS):
                subprocess.run(["ip", "netns", "delete", ns], check=False)
    print("PASS: hypervisor forward policy, VM_POLICY filtering, allow precedence and "
          "forward bans (IPv4 and IPv6, real packets)")


if __name__ == "__main__":
    run()
