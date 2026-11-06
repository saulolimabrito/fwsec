# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fwsec import cli, config, state, transaction


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ("ALLOW_FILE", "DENY_FILE", "IGNORE_FILE", "CONF_FILE", "EXECUTABLE",
                     "APPLIED_FILE"):
            p = patch.object(config, name, self.root / name)
            p.start()
            self.addCleanup(p.stop)
        for name, path in (("ROOT", "transactions"), ("LOCK", "lock"),
                            ("LOADER_DEBIAN", "nftables.conf"),
                            ("LOADER_RHEL", "sysconfig"), ("INCLUDE", "fwsec.nft")):
            p = patch.object(transaction, name, self.root / path)
            p.start()
            self.addCleanup(p.stop)
        alpine = patch.object(transaction, "LOADER_ALPINE", self.root / "alpine.nft")
        alpine.start()
        self.addCleanup(alpine.stop)
        self.before = {"fwsec": "", "filter_exists": False, "chains": {}, "sets": []}
        receipt = patch.object(transaction, "record_applied")
        receipt.start()
        self.addCleanup(receipt.stop)
        wrapper = patch.object(transaction, "verify_activation_wrapper")
        wrapper.start()
        self.addCleanup(wrapper.stop)

    def test_invalid_ports_rejected(self):
        for ports in (["0"], ["65536"], ["100:20"], ["22; flush ruleset"], ["1:2:3"]):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                transaction.validate(config.FwsecConfig(tcp_in=ports), [22])

    def test_old_nft_chain_ownership_text_fallback(self):
        text = ('table inet filter {\n\tchain input {\n'
                f'\t\tcomment "{transaction.MARKER}"\n'
                '\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n')
        with patch.object(transaction, "_dump", return_value=text) as dump:
            self.assertTrue(transaction.owns_chain("filter", {"name": "input"}))
        dump.assert_called_once_with("chain", "inet", "filter", "input")

    def test_rule_comment_cannot_claim_chain_ownership(self):
        for rule in (f'counter comment "{transaction.MARKER}"',
                     f'ip saddr {{ 192.0.2.1 }} accept comment "{transaction.MARKER}"',
                     'comment "administrator"', ''):
            text = f'table inet filter {{\n chain input {{\n  {rule}\n }}\n}}\n'
            with patch.object(transaction, "_dump", return_value=text):
                self.assertFalse(transaction.owns_chain("filter", {"name": "input"}))

    def test_json_ownership_is_authoritative_when_present(self):
        with patch.object(transaction, "_dump") as dump:
            self.assertTrue(transaction.owns_chain("filter", {
                "name": "input", "comment": transaction.MARKER}))
            self.assertFalse(transaction.owns_chain("filter", {
                "name": "input", "comment": "administrator"}))
        dump.assert_not_called()

    def test_portable_sentinel_requires_inert_first_rule(self):
        marker = {"family": "inet", "table": "filter", "chain": "input",
                  "comment": transaction.MARKER, "expr": [{"counter": {"packets": 0, "bytes": 0}}]}
        with patch.object(transaction, "_dump", return_value=""):
            self.assertTrue(transaction.owns_chain("filter", {"name": "input"}, [{"rule": marker}]))
            other = {**marker, "expr": [{"accept": None}]}
            self.assertFalse(transaction.owns_chain("filter", {"name": "input"}, [{"rule": other}]))
            rows = [{"rule": {**marker, "comment": "other"}}, {"rule": marker}]
            self.assertFalse(transaction.owns_chain("filter", {"name": "input"}, rows))
        self.assertFalse(transaction.ownership_rule({**marker, "expr": [
            {"counter": {"name": "administrator"}}]}))

    def test_invalid_ip_in_file_rejected(self):
        config.ALLOW_FILE.write_text("not-an-ip # test\n")
        with self.assertRaisesRegex(ValueError, "Invalid IP/CIDR"):
            transaction.validate(config.FwsecConfig(), [22])

    def test_geo_allow_requires_every_country_and_family(self):
        with patch("fwsec.geo.country_cidrs", return_value=(["1.0.0.0/8"], [])):
            with self.assertRaisesRegex(ValueError, "Incomplete geo"):
                transaction.validate(config.FwsecConfig(geo_allow=["br"]), [22])

    def test_bulk_lists_in_one_transaction_and_expired_temp_not_permanent(self):
        config.ALLOW_FILE.write_text("192.0.2.1\n2001:db8::1\n")
        config.DENY_FILE.write_text("198.51.100.1\n198.51.100.2\n")
        temps = {
            "198.51.100.1": state.TempEntry("198.51.100.1", "", time.time() + 200, 200),
            "198.51.100.2": state.TempEntry("198.51.100.2", "", time.time() - 1, 200),
        }
        with patch("fwsec.state.load", return_value=state.State(temps, {}, {})):
            script = transaction.build(config.FwsecConfig(), [22], self.before)
        self.assertIn("add element inet fwsec allow4 { 192.0.2.1/32 }", script)
        self.assertIn("198.51.100.1/32 timeout", script)
        self.assertNotIn("198.51.100.2", script)
        self.assertNotIn("flush ruleset", script)
        self.assertNotIn("flush table inet filter", script)

    def test_explicit_permanent_ban_wins_over_old_temp_metadata(self):
        config.DENY_FILE.write_text("192.0.2.1\n")
        temp = state.TempEntry("192.0.2.1", "", time.time() - 1, 10)
        permanent = state.DenyEntry("192.0.2.1", "permanent", time.time())
        record = state.State({temp.ip: temp}, {}, {permanent.ip: permanent})
        with patch("fwsec.state.load", return_value=record):
            script = transaction.build(config.FwsecConfig(), [22], self.before)
        self.assertIn("add element inet fwsec deny4 { 192.0.2.1/32 }", script)
        self.assertNotIn("192.0.2.1/32 timeout", script)

    def test_validation_failure_never_applies(self):
        with patch.object(transaction, "check", side_effect=RuntimeError("invalid")), \
                patch("fwsec.nft._run_script") as apply:
            with self.assertRaises(RuntimeError):
                transaction.apply("invalid", self.before)
            apply.assert_not_called()

    def test_atomic_apply_is_one_call(self):
        with patch.object(transaction, "check"), patch("fwsec.nft._run_script") as apply:
            transaction.apply("transaction", self.before)
            apply.assert_called_once_with("transaction")

    def test_foreign_chains_require_explicit_adoption(self):
        objs = [{"table": {"name": "filter", "family": "inet"}},
                {"chain": {"family": "inet", "table": "filter", "name": "input",
                           "hook": "input", "type": "filter"}}]
        with patch.object(transaction, "_objects", return_value=objs), \
                patch.object(transaction, "_dump", return_value="snapshot"):
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                transaction.snapshot()
            self.assertEqual(transaction.snapshot(adopt=True)["chains"], {"input": "snapshot"})

    def test_adoption_still_refuses_non_base_chains(self):
        objs = [{"chain": {"family": "inet", "table": "filter", "name": "input"}}]
        with patch.object(transaction, "_objects", return_value=objs):
            with self.assertRaisesRegex(RuntimeError, "base chain"):
                transaction.snapshot(adopt=True)

    def test_rollback_is_scoped(self):
        objs = [{"table": {"name": "fwsec", "family": "inet"}},
                {"chain": {"family": "inet", "table": "filter", "name": "input"}},
                {"chain": {"family": "inet", "table": "libvirt", "name": "forward"}}]
        before = dict(self.before, fwsec="table inet fwsec {}\n",
                      chains={"input": "table inet filter { chain input {} }"})
        with patch.object(transaction, "_objects", return_value=objs):
            script = transaction.restore_script(before)
        self.assertIn("delete table inet fwsec", script)
        self.assertIn("delete chain inet filter input", script)
        self.assertNotIn("libvirt", script)
        self.assertNotIn("flush ruleset", script)
        self.assertNotIn("flush table inet filter", script)

    def test_rollback_preserves_remaining_timeout_not_original_duration(self):
        objects = [{"set": {"family": "inet", "table": "fwsec", "name": "deny4", "elem": [
            {"elem": {"val": "192.0.2.1", "timeout": 600, "expires": 10}},
            "198.51.100.1",
        ]}}]
        with patch("time.monotonic", return_value=100):
            elements = transaction.deny_snapshot(objects)
        before = {"fwsec": '''table inet fwsec {
    set deny4 {
        type ipv4_addr
        flags interval,timeout
        elements = { 192.0.2.1 timeout 10m, 198.51.100.1 }
    }
}
''', "deny_elements": elements}
        with patch("time.monotonic", return_value=106):
            restored = transaction.restore_timeouts(before)
        self.assertIn("192.0.2.1 timeout 4000ms", restored)
        self.assertIn("198.51.100.1", restored)
        self.assertNotIn("timeout 10m", restored)
        with patch("time.monotonic", return_value=112):
            restored = transaction.restore_timeouts(before)
        self.assertNotIn("192.0.2.1", restored)
        self.assertIn("198.51.100.1", restored)

    def test_ambiguous_timed_snapshot_is_rejected(self):
        item = {"set": {"family": "inet", "table": "fwsec", "name": "deny4", "elem": [
            {"elem": {"val": "192.0.2.1", "timeout": 600}}
        ]}}
        with self.assertRaisesRegex(ValueError, "remaining deny timeout"):
            transaction.deny_snapshot([item])

    def test_reading_temporary_blocks_does_not_write_outside_writer_lock(self):
        entry = state.TempEntry("192.0.2.1", "", time.time() - 1, 10)
        with patch("fwsec.state.load", return_value=state.State({entry.ip: entry}, {}, {})), \
                patch("fwsec.state.save") as save:
            self.assertEqual(state.list_temp_blocks(), [])
        save.assert_not_called()

    def test_persistence_preserves_foreign_loader_includes(self):
        transaction.LOADER_RHEL.write_text('include "management.nft"\n')
        _, content = transaction.loader_content()
        self.assertIn('include "management.nft"', content)
        self.assertIn(str(transaction.INCLUDE), content)

    def test_legacy_managed_loader_loses_global_flush(self):
        transaction.LOADER_DEBIAN.write_text("# Managed by fwsec\nflush ruleset\nold rules")
        _, content = transaction.loader_content()
        self.assertNotIn("flush ruleset", content)
        self.assertNotIn("old rules", content)

    def test_managed_loader_keeps_administrator_includes(self):
        transaction.LOADER_DEBIAN.write_text(
            '# Managed by fwsec\nflush ruleset\ninclude "management.nft"\n'
        )
        _, content = transaction.loader_content()
        self.assertIn('include "management.nft"', content)
        self.assertNotIn("flush ruleset", content)

    def test_foreign_global_flush_is_not_overwritten(self):
        transaction.LOADER_DEBIAN.write_text("flush ruleset\n")
        with self.assertRaisesRegex(RuntimeError, "administrator-owned"):
            transaction.loader_content()
        self.assertEqual(transaction.LOADER_DEBIAN.read_text(), "flush ruleset\n")

    def test_restore_files_and_permissions(self):
        transaction.INCLUDE.write_text("previous")
        transaction.INCLUDE.chmod(0o640)
        saved = {"files": transaction.snapshot_files()}
        transaction.INCLUDE.write_text("new")
        transaction.LOADER_DEBIAN.write_text("new file")
        transaction.restore_files(saved)
        self.assertEqual(transaction.INCLUDE.read_text(), "previous")
        self.assertEqual(transaction.INCLUDE.stat().st_mode & 0o777, 0o640)
        self.assertFalse(transaction.LOADER_DEBIAN.exists())

    def test_administrator_symlinks_are_not_silently_replaced(self):
        target = self.root / "administrator.nft"
        target.write_text("original")
        transaction.INCLUDE.symlink_to(target)
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            transaction.atomic_write(transaction.INCLUDE, "replacement")
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            transaction.snapshot_files()
        self.assertTrue(transaction.INCLUDE.is_symlink())
        self.assertEqual(target.read_text(), "original")

    def trial(self, expired=False):
        ident = "a" * 32
        directory = transaction.ROOT / ident
        directory.mkdir(parents=True)
        (directory / "pending").write_text(str(time.monotonic() + (-1 if expired else 100)))
        (directory / "applied").write_text("yes")
        (directory / "before.json").write_text(json.dumps(self.before))
        return ident, directory

    def test_pending_trial_excludes_writers(self):
        self.trial()
        with self.assertRaisesRegex(RuntimeError, "pending"):
            transaction.require_no_pending()

    def test_confirm_persists_then_cancels_rollback(self):
        ident, directory = self.trial()
        with patch.object(transaction, "persist"), patch("fwsec.config.set_enabled"):
            transaction.confirm(ident)
        self.assertTrue((directory / "confirmed").exists())
        self.assertFalse((directory / "pending").exists())

    def test_persist_failure_keeps_rollback_armed(self):
        ident, directory = self.trial()
        with patch.object(transaction, "persist", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                transaction.confirm(ident)
        self.assertTrue((directory / "pending").exists())

    def test_expired_confirmation_rejected(self):
        ident, _ = self.trial(expired=True)
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            transaction.confirm(ident)

    def test_watchdog_restores_after_deadline(self):
        ident, directory = self.trial(expired=True)
        with patch.object(transaction, "restore_script", return_value="restore"), \
                patch.object(transaction, "check"), patch.object(transaction, "restore_files"), \
                patch("fwsec.nft._run_script") as apply:
            transaction.watchdog(ident)
        apply.assert_called_once_with("restore")
        self.assertTrue((directory / "rolled-back").exists())

    def test_upgrade_rollback_restores_previous_wrapper(self):
        config.EXECUTABLE.write_text("previous executable wrapper")
        config.EXECUTABLE.chmod(0o755)
        self.before["files"] = transaction.snapshot_files()
        ident, directory = self.trial()
        config.EXECUTABLE.write_text("new candidate wrapper")
        with patch.object(transaction, "restore_script", return_value="restore"), \
                patch.object(transaction, "check"), patch("fwsec.nft._run_script"):
            with transaction.locked():
                transaction.rollback(ident)
        self.assertEqual(config.EXECUTABLE.read_text(), "previous executable wrapper")
        self.assertEqual(config.EXECUTABLE.stat().st_mode & 0o777, 0o755)
        self.assertTrue((directory / "rolled-back").exists())

    def test_upgrade_cannot_activate_after_rollback_or_expiry(self):
        config.EXECUTABLE.write_text("old wrapper")
        ident, directory = self.trial()
        (directory / "pending").write_text(str(time.monotonic() - 1))
        with self.assertRaisesRegex(RuntimeError, "deadline expired"):
            transaction.activate_upgrade(ident)
        (directory / "pending").rename(directory / "rolled-back")
        with self.assertRaisesRegex(RuntimeError, "no longer"):
            transaction.activate_upgrade(ident)
        self.assertEqual(config.EXECUTABLE.read_text(), "old wrapper")

    def test_upgrade_activation_failure_restores_wrapper(self):
        config.EXECUTABLE.write_text("old wrapper")
        self.before["files"] = transaction.snapshot_files()
        ident, directory = self.trial()
        with patch.object(transaction, "confirm", side_effect=RuntimeError("persist failed")), \
                patch.object(transaction, "restore_script", return_value="restore"), \
                patch.object(transaction, "check"), patch("fwsec.nft._run_script"):
            with transaction.locked():
                with self.assertRaisesRegex(RuntimeError, "persist failed"):
                    transaction.activate_upgrade(ident)
        self.assertEqual(config.EXECUTABLE.read_text(), "old wrapper")
        self.assertTrue((directory / "rolled-back").exists())

    def test_wrapper_verification_failure_rolls_back_before_confirmation(self):
        config.EXECUTABLE.write_text("old wrapper")
        self.before["files"] = transaction.snapshot_files()
        ident, directory = self.trial()
        with patch.object(transaction, "verify_activation_wrapper",
                          side_effect=ValueError("invalid candidate")), \
                patch.object(transaction, "confirm") as confirm, \
                patch.object(transaction, "restore_script", return_value="restore"), \
                patch.object(transaction, "check"), patch("fwsec.nft._run_script"):
            with transaction.locked():
                with self.assertRaisesRegex(ValueError, "invalid candidate"):
                    transaction.activate_upgrade(ident)
        confirm.assert_not_called()
        self.assertEqual(config.EXECUTABLE.read_text(), "old wrapper")
        self.assertTrue((directory / "rolled-back").exists())

    def test_no_watchdog_means_no_apply(self):
        with patch.object(transaction, "check"), patch("subprocess.Popen", return_value=Mock()), \
                patch("time.sleep"), patch("fwsec.nft._run_script") as apply:
            with self.assertRaisesRegex(RuntimeError, "worker did not start"):
                transaction.apply("new", self.before, 120)
        apply.assert_not_called()
        self.assertFalse(transaction.pending())

    def test_restart_does_not_flush_first(self):
        with patch.object(cli, "_require_root"), patch.object(cli, "cmd_start") as start, \
                patch("fwsec.nft.flush_table") as flush:
            cli.cmd_restart(Mock())
        start.assert_called_once()
        flush.assert_not_called()

    def test_safe_commands_are_mutually_exclusive(self):
        parser = cli.build_parser()
        args = parser.parse_args(["--apply-safe", "--timeout", "90", "--adopt-legacy"])
        self.assertTrue(args.apply_safe)
        self.assertTrue(args.adopt_legacy)
        self.assertEqual(args.timeout, 90)
        self.assertEqual(parser.parse_args(["--confirm", "a" * 32]).confirm, "a" * 32)


if __name__ == "__main__":
    unittest.main()
