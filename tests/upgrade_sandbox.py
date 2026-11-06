# SPDX-License-Identifier: GPL-2.0-only
"""Legacy adoption/activation/rollback checks in a disposable net namespace."""
from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from fwsec import cli, config, nft, rules, state, transaction


def run() -> None:
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("Refusing the host network namespace")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config.CONFIG_DIR = root
        config.STATE_FILE = root / "state"
        config.APPLIED_FILE = root / "applied.json"
        config.CONF_FILE = root / "fwsec.conf"
        config.ALLOW_FILE = root / "allow"
        config.DENY_FILE = root / "deny"
        config.IGNORE_FILE = root / "ignore"
        config.EXECUTABLE = root / "fwsec"
        config.MIGRATION_RECEIPT = root / "receipt"
        transaction.ROOT = root / "transactions"
        transaction.LOCK = root / "lock"
        transaction.LOADER_DEBIAN = root / "loader"
        transaction.LOADER_RHEL = root / "sysconfig"
        transaction.LOADER_ALPINE = root / "alpine.nft"
        transaction.INCLUDE = root / "rules.nft"
        config.CONF_FILE.write_text("[firewall]\nWHITELIST_MARK=1\n"
                                    "[containers]\nCONTAINER_MODE=1\n")
        config.ALLOW_FILE.write_text("192.0.2.1\n192.0.2.2\n198.51.100.0/24\n")
        config.EXECUTABLE.write_text("old installed wrapper")
        config.EXECUTABLE.chmod(0o755)
        old_venv = root / "old-venv"
        old_venv.mkdir()
        (old_venv / "sentinel").write_text("old package must remain available")
        c = config.load_config()
        legacy = rules.generate_filter_table(c, [24959]) + rules.generate_fwsec_table(c)
        # Legacy hypervisor variants included anonymous counters on bypass rules.
        legacy = legacy.replace("0x46575345 accept", "0x46575345 counter accept")
        legacy += "add element inet fwsec allow4 { 192.0.2.1, 192.0.2.2, 198.51.100.0/24 }\n"
        nft._run_script(legacy)
        nft._run_script('''
table inet host_input_guard {
    chain input {
        type filter hook input priority 20; policy accept;
        counter
    }
}
''')
        foreign = nft._run("-s", "list", "table", "inet", "host_input_guard")[1]
        args = argparse.Namespace(upgrade_apply=True, upgrade_state=root / "id",
                                  apply_safe=False, timeout=180, adopt_legacy=False, dry_run=False)
        # A custom rule must refuse the candidate without activating code or a trial.
        nft._run_script("add rule inet filter input tcp dport 60606 accept\n")
        with patch.object(cli, "_detect_ssh_ports", return_value=[24959]), \
                patch.object(state, "load", return_value=state.State({}, {}, {})):
            try:
                with transaction.locked():
                    cli.cmd_start(args)
            except RuntimeError as exc:
                assert "differs" in str(exc), str(exc)
            else:
                raise AssertionError("Custom legacy rules were silently adopted")
        assert config.EXECUTABLE.read_text() == "old installed wrapper"
        assert not transaction.pending()
        rows = transaction._objects()
        custom = [o["rule"]["handle"] for o in rows if o.get("rule", {}).get("table") == "filter"
                  and o["rule"].get("chain") == "input"][-1]
        nft._run("delete", "rule", "inet", "filter", "input", "handle", str(custom), check=True)
        # A genuinely equivalent legacy policy is automatically adoptable.
        with patch.object(cli, "_detect_ssh_ports", return_value=[24959]), \
                patch.object(state, "load", return_value=state.State({}, {}, {})):
            with transaction.locked():
                ident = cli.cmd_start(args)
        assert ident and (root / "id").read_text() == ident
        assert config.EXECUTABLE.read_text() == "old installed wrapper"
        transaction.snapshot()  # ownership markers now exist
        with transaction.locked():
            transaction.activate_upgrade(ident)
        candidate_wrapper = config.EXECUTABLE.read_text()
        assert ' -m fwsec "$@"' in candidate_wrapper
        assert config.EXECUTABLE.stat().st_mode & 0o777 == 0o755
        assert not transaction.pending()
        assert nft.element_exists("allow4", "192.0.2.1")
        assert foreign == nft._run("-s", "list", "table", "inet", "host_input_guard")[1]
        assert not any(o.get("table", {}).get("name", "").startswith("fwsec_upgrade_")
                       for o in transaction._objects())
        # A wrapper activation/confirmation failure restores the previous wrapper.
        before = transaction.snapshot()
        with transaction.locked():
            ident = transaction.apply("add element inet fwsec allow4 { 203.0.113.7 }\n", before, 30)
            assert ident
            transaction.atomic_write(config.EXECUTABLE, "broken wrapper activation")
            transaction.rollback(ident)
        assert config.EXECUTABLE.read_text() == candidate_wrapper
        assert not nft.element_exists("allow4", "203.0.113.7")
        assert (old_venv / "sentinel").exists()
        print("PASS: equivalent legacy adoption, custom-policy refusal, management guard, "
              "atomic wrapper activation and code/rules rollback")


if __name__ == "__main__":
    run()
