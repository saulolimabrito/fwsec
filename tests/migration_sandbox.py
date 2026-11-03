# SPDX-License-Identifier: GPL-2.0-only
"""Real packet parity test; refuses the initial/host network namespace."""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import tempfile
from pathlib import Path

from fwsec import cli, config, migration, nft, transaction


def source_rules(version: int) -> str:
    allowed = 18080 if version == 4 else 18081
    addr = "127.0.0.1/32" if version == 4 else "::1/128"
    return f'''*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:FORWARD DROP [0:0]
:ufw-user-input - [0:0]
-A INPUT -j ufw-user-input
-A ufw-user-input -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A ufw-user-input -s {addr} -d {addr} -i lo -p tcp --dport {allowed} -j ACCEPT
-A ufw-user-input -p tcp --dport 18082 -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p tcp -m multiport --dports 18080,18081 -j ACCEPT
COMMIT
'''


def connect(family: int, port: int) -> bool:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        try:
            sock.connect(("127.0.0.1" if family == socket.AF_INET else "::1", port))
            return True
        except OSError:
            return False


def observe() -> list[bool]:
    return [connect(f, p) for f in (socket.AF_INET, socket.AF_INET6)
            for p in (18080, 18081, 18082)]


def run() -> None:
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("Refusing the host network namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    servers = []
    try:
        for family, address in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
            for port in (18080, 18081, 18082):
                server = socket.socket(family, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((address, port))
                server.listen(16)
                servers.append(server)
        for binary, version in (("iptables-restore", 4), ("ip6tables-restore", 6)):
            subprocess.run([binary], input=source_rules(version), text=True, check=True)
        expected = [True, False, False, False, True, False]
        assert observe() == expected, "Original fixture did not enforce the expected policy"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config.CONFIG_DIR = root
            config.CONF_FILE = root / "fwsec.conf"
            config.ALLOW_FILE = root / "allow"
            config.DENY_FILE = root / "deny"
            config.IGNORE_FILE = root / "ignore"
            config.MIGRATION_RECEIPT = root / "receipt.json"
            transaction.ROOT = root / "transactions"
            transaction.LOCK = root / "lock"
            transaction.LOADER_DEBIAN = root / "loader"
            transaction.LOADER_RHEL = root / "sysconfig"
            transaction.INCLUDE = root / "rules.nft"
            first = migration.capture("ufw", root / "plan.json")
            assert first["status"] == "requires-approval"
            document = migration.capture("ufw", root / "plan.json", first["fingerprint"])
            assert document["status"] == "ready"
            config.CONF_FILE.write_text(f"[firewall]\nINHERITED_POLICY = {root / 'plan.json'}\n")
            nft._run_script("table inet management { chain unrelated { counter; } }")
            args = argparse.Namespace(apply_safe=True, timeout=30,
                                      adopt_legacy=False, dry_run=False)
            with transaction.locked():
                cli.cmd_start(args)
            assert observe() == expected, "Policy changed during the migration trial"
            ident = transaction.pending()[0].parent.name
            with transaction.locked():
                transaction.confirm(ident)
                receipt = json.loads(config.MIGRATION_RECEIPT.read_text())
                migration.finalize(document, receipt, manage_services=False)
            assert observe() == expected, "Policy changed after source retirement"
            assert nft._run("list", "table", "inet", "management")[0] == 0
            assert "ufw-user-input" not in subprocess.run(
                ["iptables-save"], capture_output=True, text=True, check=True).stdout
            # The persisted script reloads the exact same inherited policy.
            nft._run_script(transaction.INCLUDE.read_text())
            assert observe() == expected, "Persisted reload changed policy"
        print("PASS: IPv4/IPv6 packet parity, source/destination/interface scope, OUTPUT DROP, "
              "safe confirmation, scoped source retirement, persistence")
    finally:
        for server in servers:
            server.close()


if __name__ == "__main__":
    run()
