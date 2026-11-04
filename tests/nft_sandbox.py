# SPDX-License-Identifier: GPL-2.0-only
"""Linux integration checks. ONLY run via unshare --net in CI, not on a host.

Invocation: sudo env PYTHONPATH=src unshare --net python3 tests/nft_sandbox.py
No network interfaces/routes are changed outside that disposable namespace.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from fwsec import config, nft, transaction


def run() -> None:
    # Require a non-initial network namespace even when called by mistake.
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("Refusing to test in the host's network namespace")
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        config.ALLOW_FILE = base / "allow"
        config.DENY_FILE = base / "deny"
        config.IGNORE_FILE = base / "ignore"
        config.CONF_FILE = base / "fwsec.conf"
        config.STATE_FILE = base / "state"
        transaction.ROOT = base / "transactions"
        transaction.LOCK = base / "lock"
        transaction.LOADER_DEBIAN = base / "nftables.conf"
        transaction.LOADER_RHEL = base / "sysconfig.conf"
        transaction.INCLUDE = base / "fwsec.nft"
        config.ALLOW_FILE.write_text("192.0.2.1\n")
        c = config.FwsecConfig(container_mode=True)
        # Third-party table, a shared-table chain and live bouncer elements.
        nft._run_script('''
table inet management {
    chain guard { type filter hook input priority 20; policy accept; }
}
table inet filter {
    set crowdsec-blacklists { type ipv4_addr; flags timeout;
        elements = { 198.51.100.10 timeout 600s }; }
    chain foreign { counter; }
}
''')
        foreign_before = nft._run("-s", "list", "chain", "inet", "filter", "foreign")[1]
        before = transaction.snapshot()
        with patch("fwsec.state.load") as load:
            from fwsec.state import State
            load.return_value = State({}, {}, {})
            script = transaction.build(c, [22], before)
        with transaction.locked():
            transaction.apply(script, before)
        assert nft.element_exists("allow4", "192.0.2.1")
        assert nft._run("get", "element", "inet", "filter", "crowdsec-blacklists",
                        "{ 198.51.100.10 }")[0] == 0
        assert foreign_before == nft._run(
            "-s", "list", "chain", "inet", "filter", "foreign")[1]
        assert nft._run("list", "table", "inet", "management")[0] == 0
        # Repeat reload: base chains remain valid and bouncer set stays populated.
        before = transaction.snapshot()
        with patch("fwsec.state.load", return_value=State({}, {}, {})):
            script = transaction.build(c, [22], before)
        with transaction.locked():
            transaction.apply(script, before)
        old = nft._run("-s", "list", "table", "inet", "fwsec")[1]
        try:
            transaction.apply(script + "this is invalid nft syntax\n", before)
        except RuntimeError:
            pass
        else:
            raise AssertionError("Invalid transaction was accepted")
        assert old == nft._run("-s", "list", "table", "inet", "fwsec")[1]
        # Scoped boot script must load repeatedly without duplicates or global flush.
        transaction.persist()
        boot_script = transaction.INCLUDE.read_text()
        nft._run_script(boot_script)
        nft._run_script(boot_script)
        assert nft._run("list", "table", "inet", "management")[0] == 0
        assert nft._run("get", "element", "inet", "filter", "crowdsec-blacklists",
                        "{ 198.51.100.10 }")[0] == 0
        # A real detached worker must survive the launching process exiting.
        # The 30s minimum is intentional; run this once per CI job.
        nft._run_script("add element inet fwsec deny4 { 192.0.2.99 timeout 60s, "
                        "192.0.2.98 timeout 2s }\n")
        before = transaction.snapshot()
        (base / "before.json").write_text(__import__("json").dumps(before))
        launcher = '''
import json, sys
from pathlib import Path
from fwsec import transaction
base = Path(sys.argv[1])
transaction.ROOT = base / "transactions"
transaction.LOCK = base / "lock"
before = json.loads((base / "before.json").read_text())
with transaction.locked():
    ident = transaction.apply("add element inet fwsec allow4 { 203.0.113.7 }", before, 30)
(base / "id").write_text(ident)
'''
        subprocess.run([os.sys.executable, "-c", launcher, str(base)], check=True)
        assert nft.element_exists("allow4", "203.0.113.7")
        ident = (base / "id").read_text()
        deadline = time.monotonic() + 40
        while time.monotonic() < deadline:
            if (transaction.ROOT / ident / "rolled-back").exists():
                break
            time.sleep(0.2)
        else:
            raise AssertionError((transaction.ROOT / ident / "watchdog.log").read_text())
        assert not nft.element_exists("allow4", "203.0.113.7")
        assert nft.element_exists("allow4", "192.0.2.1")
        assert nft.element_exists("deny4", "192.0.2.99")
        assert not nft.element_exists("deny4", "192.0.2.98"), "Expired ban was resurrected"
        timed = transaction.deny_snapshot(transaction._objects())["deny4"]
        remaining = next(e["deadline"] - time.monotonic()
                         for e in timed if e["value"] == "192.0.2.99")
        assert 10 < remaining < 35, f"Rollback reset the original 60s timeout: {remaining}"
        assert nft._run("list", "table", "inet", "management")[0] == 0
        print("PASS: nft validation, atomic apply, reload, scoped persistence, detached rollback")


if __name__ == "__main__":
    run()
