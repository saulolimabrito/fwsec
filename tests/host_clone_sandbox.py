# SPDX-License-Identifier: GPL-2.0-only
"""Clone real host policy into a new net namespace; never apply to the host."""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from fwsec import cli, config, nft, transaction


def run() -> None:
    if "--child" not in sys.argv:
        parts = []
        for name in ("filter", "fwsec", "host_input_guard"):
            result = subprocess.run(["nft", "-s", "list", "table", "inet", name],
                                    capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                parts.append(result.stdout)
        payload = {"ports": cli._detect_ssh_ports(), "rules": "\n".join(parts)}
        subprocess.run(["unshare", "--net", sys.executable, __file__, "--child"],
                       input=json.dumps(payload), text=True, check=True, timeout=120)
        return
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("Refusing host network namespace")
    payload = json.load(sys.stdin)
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        nft._run_script(payload["rules"])
        guard = nft._run("-s", "list", "table", "inet", "host_input_guard")[1]
        for name in ("CONF_FILE", "ALLOW_FILE", "DENY_FILE", "IGNORE_FILE", "STATE_FILE",
                     "EXECUTABLE", "MIGRATION_RECEIPT", "APPLIED_FILE"):
            old = getattr(config, name)
            new = root / name
            if old.exists():
                shutil.copy2(old, new)
            setattr(config, name, new)
        config.CONFIG_DIR = root
        for name in ("LOADER_DEBIAN", "LOADER_RHEL", "LOADER_ALPINE", "INCLUDE"):
            old = getattr(transaction, name)
            new = root / name
            if old.exists():
                shutil.copy2(old, new)
            setattr(transaction, name, new)
        transaction.ROOT = root / "transactions"
        transaction.LOCK = root / "lock"
        args = argparse.Namespace(upgrade_apply=True, upgrade_state=root / "id",
                                  apply_safe=False, adopt_legacy=False, dry_run=False, timeout=180)
        with patch.object(cli, "_detect_ssh_ports", return_value=payload["ports"]):
            with transaction.locked():
                ident = cli.cmd_start(args)
        assert ident
        with transaction.locked():
            transaction.activate_upgrade(ident)
        transaction.snapshot()
        assert not transaction.pending()
        assert guard == nft._run("-s", "list", "table", "inet", "host_input_guard")[1]
        print("PASS: cloned LIVE policy, equivalence, activation, confirmation, persistence, guard")


if __name__ == "__main__":
    run()
