# SPDX-License-Identifier: GPL-2.0-only
"""Real-packet allow-list precedence. ONLY run via unshare --net, not on a host.

Invocation: sudo env PYTHONPATH=src unshare --net python3 tests/allow_sandbox.py

In nftables an `accept` only ends the current base chain, so an allow-listed
source must still survive the deny list (-50), geo (-40), CrowdSec and the
port policy of the main filter (0). This sends real IPv4/IPv6 TCP SYNs from a
client namespace over a veth pair and asserts that fwsec.allow wins.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from fwsec import config, nft, transaction
from fwsec.state import State

CLIENT_NS = f"fwsec-allow-{os.getpid()}"
SERVER4, CLIENT4 = "10.199.0.1", "10.199.0.2"
SERVER6, CLIENT6 = "fd99::1", "fd99::2"
SSH_PORT, CLOSED_PORT = 18022, 18090


def sh(*args: str) -> None:
    subprocess.run(args, check=True)


def reachable(server: str, port: int) -> bool:
    family = "AF_INET6" if ":" in server else "AF_INET"
    probe = (f"import socket,sys\ns=socket.socket(socket.{family});s.settimeout(1.5)\n"
             f"sys.exit(0 if s.connect_ex(({server!r},{port}))==0 else 1)\n")
    r = subprocess.run(["ip", "netns", "exec", CLIENT_NS, sys.executable, "-I", "-c", probe])
    return r.returncode == 0


def expect(label: str, server: str, port: int, wanted: bool) -> None:
    got = reachable(server, port)
    print(f"{'ok ' if got == wanted else 'FAIL'} {label}: {'open' if got else 'blocked'}")
    if got != wanted:
        print(nft._run("list", "ruleset")[1])
        raise AssertionError(f"{label}: expected {'open' if wanted else 'blocked'}")


def element(op: str, table: str, set_name: str, ip: str) -> None:
    nft._run(op, "element", "inet", table, set_name, f"{{ {ip} }}", check=True)


def setup_network() -> None:
    sh("ip", "link", "set", "lo", "up")
    sh("ip", "netns", "add", CLIENT_NS)
    sh("ip", "link", "add", "fwa0", "type", "veth", "peer", "name", "fwa1")
    sh("ip", "link", "set", "fwa1", "netns", CLIENT_NS)
    sh("ip", "addr", "add", f"{SERVER4}/24", "dev", "fwa0")
    sh("ip", "addr", "add", f"{SERVER6}/64", "dev", "fwa0", "nodad")
    sh("ip", "link", "set", "fwa0", "up")
    for cmd in (["ip", "addr", "add", f"{CLIENT4}/24", "dev", "fwa1"],
                ["ip", "addr", "add", f"{CLIENT6}/64", "dev", "fwa1", "nodad"],
                ["ip", "link", "set", "fwa1", "up"], ["ip", "link", "set", "lo", "up"]):
        sh("ip", "netns", "exec", CLIENT_NS, *cmd)


def listeners() -> list[socket.socket]:
    socks = []
    for family, addr in ((socket.AF_INET, SERVER4), (socket.AF_INET6, SERVER6)):
        for port in (SSH_PORT, CLOSED_PORT):
            s = socket.socket(family, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((addr, port))
            s.listen(128)
            socks.append(s)
    return socks


def geo_zone(cc: str, directory: object = None) -> tuple[list[str], list[str]]:
    # Test country "zz" covers the client, so geo would drop it.
    return [f"{CLIENT4}/32"], [f"{CLIENT6}/128"]


def apply(c: config.FwsecConfig) -> None:
    before = transaction.snapshot()
    with patch("fwsec.state.load", return_value=State({}, {}, {})), \
            patch("fwsec.geo.country_cidrs", side_effect=geo_zone):
        script = transaction.build(c, [SSH_PORT], before)
    with transaction.locked():
        transaction.apply(script, before)


def scenarios(c: config.FwsecConfig, label: str) -> None:
    print(f"-- {label}")
    geo_blocked = "zz" in c.geo_block  # the client's "country" is blocked
    apply(c)
    for server, client, v in ((SERVER4, CLIENT4, "4"), (SERVER6, CLIENT6, "6")):
        crowdsec = "crowdsec-blacklists" if v == "4" else "crowdsec6-blacklists"
        expect(f"v{v} unlisted, SSH", server, SSH_PORT, not geo_blocked)
        expect(f"v{v} unlisted, port outside TCP_IN", server, CLOSED_PORT, False)

        element("add", "fwsec", f"allow{v}", client)
        expect(f"v{v} allow-listed, port outside TCP_IN", server, CLOSED_PORT, True)
        element("add", "fwsec", f"deny{v}", client)
        expect(f"v{v} allow + deny (allow wins)", server, SSH_PORT, True)
        element("add", "filter", crowdsec, client)
        expect(f"v{v} allow + deny + CrowdSec (allow wins)", server, SSH_PORT, True)
        expect(f"v{v} allow + deny + CrowdSec, port outside TCP_IN", server, CLOSED_PORT,
               True)

        element("delete", "fwsec", f"allow{v}", client)
        expect(f"v{v} deny + CrowdSec only", server, SSH_PORT, False)
        element("delete", "fwsec", f"deny{v}", client)
        expect(f"v{v} CrowdSec only", server, SSH_PORT, False)
        element("delete", "filter", crowdsec, client)
        element("add", "fwsec", f"deny{v}", client)
        expect(f"v{v} deny only", server, SSH_PORT, False)
        element("delete", "fwsec", f"deny{v}", client)
        expect(f"v{v} cleared", server, SSH_PORT, not geo_blocked)


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
        try:
            setup_network()
            socks = listeners()
            scenarios(config.FwsecConfig(), "default (masked allow mark)")
            scenarios(config.FwsecConfig(whitelist_mark=True), "WHITELIST_MARK = 1")
            scenarios(config.FwsecConfig(container_mode=True), "CONTAINER_MODE = 1")
            scenarios(config.FwsecConfig(geo_block=["zz"], geo_forward=True),
                      "geo deny mode, client's country blocked")
            for s in socks:
                s.close()
        finally:
            subprocess.run(["ip", "netns", "delete", CLIENT_NS], check=False)
    print("PASS: fwsec.allow takes precedence over deny, CrowdSec, port policy "
          "and geo (IPv4 and IPv6, real packets)")


if __name__ == "__main__":
    run()
