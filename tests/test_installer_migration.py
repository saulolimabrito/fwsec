# SPDX-License-Identifier: GPL-2.0-only
"""Installer safety paths with fake commands; never executes the installer."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path


class InstallerMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.script = (Path(__file__).resolve().parents[1] / "install.sh").read_text()
        match = re.search(r"(?ms)^run_migration_stage\(\) \{.*?^\}", self.script)
        assert match
        self.stage = match.group(0)
        python = self.root / "refuse"
        python.write_text('#!/bin/sh\ntouch "$TEST_TMP/planner-called"\nexit 2\n')
        python.chmod(0o700)

    def run_stage(self, sources="csf"):
        prefix = '''
set -euo pipefail
CONFIG_DIR="$TEST_TMP/config"
SCRIPT_DIR="$TEST_TMP/source"
PYTHON="$TEST_TMP/refuse"
MIGRATION_APPROVE=""
MIGRATION_BACKUP="$TEST_TMP/backup"
MIGRATION_STAGED=0
MIGRATION_SUMMARY=()
die() { echo "$*"; exit 2; }
migration_backup() { mkdir -p "$MIGRATION_BACKUP"; }
'''
        commands = prefix + self.stage + '\nMIGRATION_SOURCES="' + sources + '"\n'
        commands += 'run_migration_stage\ntouch "$TEST_TMP/would-disable-source"\n'
        return subprocess.run(["bash"], input=commands, capture_output=True, text=True,
                              env={**os.environ, "TEST_TMP": str(self.root)})

    def test_unsupported_plan_aborts_before_any_source_retirement(self):
        result = self.run_stage()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertTrue((self.root / "planner-called").exists())
        self.assertFalse((self.root / "config").exists())
        self.assertFalse((self.root / "would-disable-source").exists())

    def test_existing_config_is_not_implicitly_merged(self):
        path = self.root / "config" / "fwsec.conf"
        path.parent.mkdir()
        path.write_text("original config")
        self.assertEqual(self.run_stage().returncode, 2)
        self.assertEqual(path.read_text(), "original config")
        self.assertFalse((self.root / "planner-called").exists())

    def test_multiple_sources_abort_without_guessing_precedence(self):
        self.assertEqual(self.run_stage("csf ufw").returncode, 2)
        self.assertFalse((self.root / "planner-called").exists())
        self.assertFalse((self.root / "would-disable-source").exists())

    def test_no_blanket_cleanup_commands_remain(self):
        for unsafe in ("iptables -F", "iptables -X", "ip6tables -F", "ip6tables -X",
                       "systemctl stop firewalld", 'rm -rf "$CSF_DIR"', "ufw --force disable"):
            self.assertNotIn(unsafe, self.script)


if __name__ == "__main__":
    unittest.main()
