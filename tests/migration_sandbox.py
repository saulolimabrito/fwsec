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


def source_rules(version: int, source: str) -> str:
    allowed = 18080 if version == 4 else 18081
    addr = "127.0.0.1/32" if version == 4 else "::1/128"
    chain = "ALLOWIN" if source == "csf" else "ufw-user-input"
    return f'''*filter
:INPUT DROP [0:0]
:OUTPUT DROP [0:0]
:FORWARD DROP [0:0]
:{chain} - [0:0]
-A INPUT -j {chain}
-A {chain} -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A {chain} -s {addr} -d {addr} -i lo -p tcp --dport {allowed} -j ACCEPT
-A {chain} -p tcp --dport 18082 -j ACCEPT
-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A OUTPUT -p tcp -m multiport --dports 18080,18081 -j ACCEPT
COMMIT
'''


def connect(family: int, port: int, source: str = "", destination: str = "") -> bool:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.4)
        try:
            if source:
                sock.bind((source, 0))
            address = destination or ("127.0.0.1" if family == socket.AF_INET else "::1")
            sock.connect((address, port))
            return True
        except OSError:
            return False


def observe() -> list[bool]:
    results = [connect(f, p) for f in (socket.AF_INET, socket.AF_INET6)
               for p in (18080, 18081, 18082)]
    results.append(connect(socket.AF_INET, 18080, source="127.0.0.2"))
    results.append(connect(socket.AF_INET, 18080, source="127.0.0.1", destination="127.0.0.2"))
    return results


def run(source: str) -> None:
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
        alternate = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alternate.bind(("127.0.0.2", 18080))
        alternate.listen(16)
        servers.append(alternate)
        for binary, version in (("iptables-restore", 4), ("ip6tables-restore", 6)):
            subprocess.run([binary], input=source_rules(version, source), text=True, check=True)
        expected = [True, False, False, False, True, False, False, False]
        assert observe() == expected, "Original fixture did not enforce the expected policy"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config.CONFIG_DIR = root
            config.EXECUTABLE = root / "fwsec-wrapper"
            config.STATE_FILE = root / "state"
            config.APPLIED_FILE = root / "applied.json"
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
            first = migration.capture(source, root / "plan.json")
            assert first["status"] == "requires-approval"
            document = migration.capture(source, root / "plan.json", first["fingerprint"])
            assert document["status"] == "ready"
            config.CONF_FILE.write_text(f"[firewall]\nINHERITED_POLICY = {root / 'plan.json'}\n")
            nft._run_script('''
table inet management {
    chain unrelated {
        counter
    }
}
''')
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
            old_chain = "ALLOWIN" if source == "csf" else "ufw-user-input"
            assert old_chain not in subprocess.run(
                ["iptables-save"], capture_output=True, text=True, check=True).stdout
            # The persisted script reloads the exact same inherited policy.
            nft._run_script(transaction.INCLUDE.read_text())
            assert observe() == expected, "Persisted reload changed policy"
        print(f"PASS ({source}): IPv4/IPv6 packet parity, endpoint/interface scope, OUTPUT DROP, "
              "safe confirmation, scoped source retirement, persistence")
    finally:
        for server in servers:
            server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", choices=("ufw", "csf"), default="ufw")
    run(parser.parse_args().source)
