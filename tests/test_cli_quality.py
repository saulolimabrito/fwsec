# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fwsec import cli, config, crowdsec, nft, state, transaction, ui


class InterfaceTests(unittest.TestCase):
    def invoke(self, args):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with patch("sys.argv", ["fwsec"] + args), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(err):
            try:
                cli.main()
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def test_short_version_and_no_ansi(self):
        code, out, err = self.invoke(["--version"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 1)
        self.assertNotIn("\033", out + err)

    def test_version_json(self):
        code, out, err = self.invoke(["--version", "--json"])
        self.assertEqual(code, 0)
        self.assertIn("fwsec", json.loads(out)["data"])
        self.assertEqual(err, "")

    def test_no_color_environment_even_on_terminal(self):
        with patch.dict(os.environ, {"NO_COLOR": "1"}), \
                patch("sys.stdout.isatty", return_value=True):
            ui.configure_output(argparse.Namespace(color="auto", json=False))
        self.assertEqual(cli.RED, "")
        self.assertNotIn("\033", ui.safe("comment\033[31m\nsecond line"))

    def test_menu_invalid_choice_then_exit(self):
        with patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), \
                patch("builtins.input", side_effect=["9", "0"]) as prompt:
            cli.cmd_menu(argparse.Namespace())
        self.assertEqual(prompt.call_count, 2)

    def test_canonical_ip_and_network_aliases(self):
        self.assertEqual(cli._resolve("192.0.2.1/32"), "192.0.2.1")
        self.assertEqual(cli._resolve("192.0.2.7/24"), "192.0.2.0/24")
        self.assertEqual(cli._resolve("2001:0db8::1"), "2001:db8::1")

    def test_receipt_tracks_static_drift_not_dynamic_set_elements(self):
        rows = [{"table": {"family": "inet", "name": "fwsec"}},
                {"set": {"family": "inet", "table": "fwsec", "name": "deny4",
                         "type": "ipv4_addr", "elem": ["192.0.2.1"]}}]
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(config, "APPLIED_FILE", Path(tmp) / "applied.json"), \
                patch.object(config, "load_config", return_value=config.FwsecConfig()):
            receipt = transaction.static_receipt(rows, [22])
            config.APPLIED_FILE.write_text(json.dumps(receipt))
            self.assertEqual(transaction.applied_status(rows, [22]), "verified")
            rows[1]["set"]["elem"] = ["198.51.100.1"]
            self.assertEqual(transaction.applied_status(rows, [22]), "verified")
            self.assertEqual(transaction.applied_status(rows, [24959]), "changed")
            config.APPLIED_FILE.write_text("invalid")
            self.assertIn("not verified", transaction.applied_status(rows, [22]))

    def test_missing_element_variants_are_idempotent_only_when_set_exists(self):
        for error in ("No such file or directory", "Error: element does not exist"):
            with patch.object(nft, "_run", side_effect=[(1, "", error), (0, "set", "")]):
                self.assertFalse(nft.delete_element("deny4", "192.0.2.1"))
        with patch.object(nft, "_run", side_effect=[(1, "", "No such file or directory"),
                                                    (1, "", "set missing")]):
            with self.assertRaises(RuntimeError):
                nft.delete_element("deny4", "192.0.2.1")

    def test_help_grouped_and_default_short(self):
        _, out, _ = self.invoke(["--help"])
        for group in ("Inspect (read-only)", "Block / allow", "Apply / recover", "Maintenance"):
            self.assertIn(group, out)
        _, out, _ = self.invoke([])
        self.assertLess(len(out.splitlines()), 8)

    def test_incompatible_options_rejected(self):
        for args in (["--timeout", "60"], ["--list", "--timeout", "60"],
                     ["--list", "--adopt-legacy"], ["--all"], ["--version", "--section", "deny"],
                     ["--status", "--verbose"], ["--json", "--stop"],
                     ["--apply-safe", "--timeout", "5"], ["--list", "--limit", "0"],
                     ["--status", "--yes"], ["--migration-approve", "abc"]):
            with self.subTest(args=args):
                self.assertEqual(self.invoke(args)[0], 2)

    def test_menu_refuses_nonterminal(self):
        code, _, err = self.invoke(["--menu"])
        self.assertEqual(code, 1)
        self.assertIn("interactive terminal", err)

    def test_health_problem_exit_and_json(self):
        data = {"problems": ["disabled"], "warnings": []}
        with patch.object(ui, "health", return_value=data), \
                patch.object(cli, "_detect_ssh_ports", return_value=[22]):
            code, out, err = self.invoke(["--check", "--json"])
        self.assertEqual(code, 3)
        self.assertFalse(json.loads(out)["ok"])
        self.assertEqual(err, "")

    def test_partial_health_exit(self):
        with patch.object(ui, "health", return_value={"problems": [], "warnings": ["unknown"]}), \
                patch.object(cli, "_detect_ssh_ports", return_value=[22]):
            code, out, _ = self.invoke(["--status", "--json"])
        self.assertEqual(code, 4)
        self.assertEqual(json.loads(out)["data"]["warnings"], ["unknown"])

    def test_runtime_json_error_is_structured(self):
        with patch.object(ui, "health", side_effect=RuntimeError("nft permission denied")), \
                patch.object(cli, "_detect_ssh_ports", return_value=[22]):
            code, out, err = self.invoke(["--status", "--json"])
        self.assertEqual(code, 1)
        self.assertIn("permission denied", json.loads(out)["error"])
        self.assertEqual(err, "")

    def test_duration_rendering_and_timezone(self):
        self.assertEqual(ui.duration(90061), "1d 1h 1m 1s")
        self.assertRegex(ui.timestamp(0), r"[+-]\d\d:\d\d$")

    def test_zero_negative_invalid_duration_never_changes_kernel(self):
        for value in ("0", "-1", "oops", "2147483648"):
            with self.subTest(value=value), patch.object(cli, "_require_root"), \
                    patch.object(nft, "deny") as deny:
                with self.assertRaises(ValueError):
                    cli.cmd_temp_deny(argparse.Namespace(ip="192.0.2.1", duration=value))
                deny.assert_not_called()

    def test_self_ban_requires_acknowledgement(self):
        with patch.dict(os.environ, {"SSH_CONNECTION": "192.0.2.1 1234 198.51.100.1 22"}), \
                patch.object(cli, "_require_root"), patch.object(nft, "deny") as deny, \
                patch("sys.stdin.isatty", return_value=False):
            with self.assertRaisesRegex(ValueError, "--yes"):
                cli.cmd_deny(argparse.Namespace(ip="192.0.2.0/24", comment="QA"))
            deny.assert_not_called()

    def test_interactive_cancel_does_not_stop(self):
        with patch.object(cli, "_require_root"), patch("sys.stdin.isatty", return_value=True), \
                patch("sys.stdout.isatty", return_value=True), \
                patch("builtins.input", return_value="n"), \
                patch.object(transaction, "snapshot") as snapshot:
            with self.assertRaises(SystemExit) as exc:
                cli.cmd_stop(argparse.Namespace())
            self.assertEqual(exc.exception.code, 130)
            snapshot.assert_not_called()

    def test_missing_remove_reports_no_change(self):
        out = io.StringIO()
        with patch.object(cli, "_require_root"), patch.object(nft, "undeny", return_value=False), \
                patch.object(config, "remove_deny", return_value=False), \
                patch.object(state, "remove_deny_meta"), \
                patch.object(config, "load_config", return_value=config.FwsecConfig(
                    crowdsec_enabled=False)), contextlib.redirect_stdout(out):
            cli.cmd_deny_remove(argparse.Namespace(ip="192.0.2.1"))
        self.assertIn("No change", out.getvalue())

    def test_failed_sync_is_partial_failure(self):
        with patch.object(cli, "_require_root"), patch.object(nft, "deny"), \
                patch.object(config, "add_deny"), patch.object(state, "add_deny_meta"), \
                patch.object(config, "load_config", return_value=config.FwsecConfig(
                    crowdsec_enabled=True, crowdsec_sync_deny=True)), \
                patch("shutil.which", return_value="cscli"), \
                patch.object(crowdsec, "add_decision", return_value=False):
            with self.assertRaisesRegex(cli.PartialFailure, "Local change completed"):
                cli.cmd_deny(argparse.Namespace(ip="192.0.2.1", comment="QA", yes=True))

    def test_temp_remove_never_removes_permanent_without_temp(self):
        with patch.object(cli, "_require_root"), \
                patch.object(state, "load", return_value=state.State({}, {}, {})), \
                patch.object(nft, "undeny") as delete:
            cli.cmd_temp_remove(argparse.Namespace(ip="192.0.2.1"))
        delete.assert_not_called()

    def test_failed_geo_apply_is_partial(self):
        with patch.object(cli, "_require_root"), \
                patch.object(config, "load_config", return_value=config.FwsecConfig(
                    geo_block=["br"])), \
                patch.object(ui.geo, "update_zones", return_value=(["br"], [])), \
                patch.object(ui.geo, "resolve_all", return_value=([], [])), \
                patch.object(ui.geo, "render_apply_file", return_value="QA"), \
                patch.object(transaction, "validate"), \
                patch.object(nft, "table_exists", return_value=True), \
                patch.object(nft, "_run_script", side_effect=RuntimeError("apply error")):
            with self.assertRaisesRegex(cli.PartialFailure, "NOT applied"):
                cli.cmd_geo_update(argparse.Namespace())

    def test_crowdsec_failure_distinct_from_no_bans(self):
        with patch.object(crowdsec, "_cscli", return_value=(1, "", "connection refused")):
            with self.assertRaises(RuntimeError):
                crowdsec.list_decisions(strict=True)
        with patch.object(crowdsec, "_cscli", return_value=(0, "[]", "")):
            self.assertEqual(crowdsec.list_decisions(strict=True), [])

    def test_search_reports_each_ip_and_cidr_membership(self):
        with patch.object(config, "load_config", return_value=config.FwsecConfig(
                crowdsec_enabled=False)), patch.object(transaction, "_objects", return_value=[]), \
                patch.object(socket, "getaddrinfo", return_value=[
                    (2, 0, 0, "", ("192.0.2.1", 0)), (2, 0, 0, "", ("198.51.100.1", 0))]), \
                patch.object(config, "read_allow", return_value=[config.IpEntry("192.0.2.0/24")]), \
                patch.object(config, "read_deny", return_value=[]), \
                patch.object(config, "read_ignore", return_value=[]), \
                patch.object(nft, "is_allowed", return_value=False), \
                patch.object(nft, "is_denied", return_value=False), \
                patch.object(state, "list_temp_blocks", return_value=[]), \
                patch.object(ui.containers, "find_ip", return_value=[]):
            data = ui.search("qa.invalid")
        results = {r["ip"]: r for r in data["results"]}
        self.assertTrue(results["192.0.2.1"]["found"])
        self.assertFalse(results["198.51.100.1"]["found"])

    def test_removal_backend_error_is_not_absence(self):
        with patch.object(nft, "_run", side_effect=[(1, "", "permission denied"),
                                                    (1, "", "permission denied")]):
            with self.assertRaises(RuntimeError):
                nft.delete_element("deny4", "192.0.2.1")

    def test_empty_migration_is_helpful(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(config, "load_config", return_value=config.FwsecConfig()):
            code, out, _ = self.invoke(["--migration-report", "--migration-output",
                                       str(Path(tmp) / "absent"), "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["data"]["available"])
        self.assertIn("next_step", json.loads(out)["data"])

    def test_listing_limit_and_sections(self):
        with patch.object(config, "load_config", return_value=config.FwsecConfig(
                crowdsec_enabled=False)), patch.object(transaction, "_objects", return_value=[]), \
                patch.object(nft, "get_summary", return_value=nft.SetSummary(
                    ["192.0.2.1", "192.0.2.2"], [], [], [])), \
                patch.object(nft, "table_exists", return_value=True):
            data = ui.listing(argparse.Namespace(section="allow", all=False, limit=1), [22])
        self.assertEqual(list(data["sections"]), ["allow"])
        self.assertEqual(data["sections"]["allow"]["total"], 2)
        self.assertEqual(len(data["sections"]["allow"]["items"]), 1)


if __name__ == "__main__":
    unittest.main()
