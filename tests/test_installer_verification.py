# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from fwsec import installer

ROOT = Path(__file__).resolve().parents[1]


class InstallerVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = {"id": "ubuntu", "version": "24.04", "architecture": "x86_64",
                    "init": "none", "package_manager": "apt-get", "testing_tier": "VM-boot"}

    def shell(self, commands):
        code = f'FWSEC_INSTALLER_LIBRARY=1 source "{ROOT / "install.sh"}"\n' + commands
        return subprocess.run(["bash"], input=code, capture_output=True, text=True,
                              env={**os.environ, "TEST_DIR": str(self.root)})

    def test_unknown_flags_rejected_before_root_or_writes(self):
        for args in (["--check-ony"], ["--force", "--verify-only"],
                     ["--verify-only", "--adopt-vendor-loader"], ["--upgrade", "--install-only"]):
            result = subprocess.run(["bash", str(ROOT / "install.sh"), *args],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2, result.stderr)

    def test_source_only_has_no_install_side_effects(self):
        result = self.shell('printf "loaded\\n"\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "loaded\n")

    def test_stage_failure_does_not_remove_old_runtime(self):
        result = self.shell('''
INSTALL_DIR="$TEST_DIR/install"; BIN="$TEST_DIR/fwsec"; PYTHON="/unused"
mkdir -p "$INSTALL_DIR/venv"
echo "old runtime" > "$INSTALL_DIR/venv/sentinel"
echo "old wrapper" > "$BIN"
uv() { return 1; }
install_fwsec_package
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.root / "install/venv/sentinel").read_text(), "old runtime\n")
        self.assertEqual((self.root / "fwsec").read_text(), "old wrapper\n")

    def test_package_error_not_hidden_by_missing_command_success(self):
        result = self.shell('''
INSTALL_LOG="$TEST_DIR/log"; PKG=apt; PACKAGES_REFRESHED=0
pkg_refresh() { return 1; }
ensure_command command_that_does_not_exist required-package
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Repository refresh failed", result.stderr)

    def test_detect_init_requires_live_manager(self):
        # Do not assume the presence of systemctl means systemd is PID 1.
        text = (ROOT / "install.sh").read_text()
        self.assertIn('[[ -d /run/systemd/system ]]', text)
        self.assertIn('[[ -d /run/openrc ]]', text)

    def test_readonly_functions_never_install_packages(self):
        text = (ROOT / "install.sh").read_text()
        start = text.index('if [[ "$PREFLIGHT_ONLY" -eq 1 || "$VERIFY_ONLY" -eq 1 ]]; then',
                           text.index("main()"))
        end = text.index("INSTALL_LOG=$(mktemp", start)
        block = text[start:end]
        self.assertIn("run_diagnostic", block)
        self.assertNotIn("pkg_install", block)
        self.assertNotIn("bootstrap_source", block)

    def test_support_floors_and_unknown_derivatives(self):
        for identity, version in (("ubuntu", "20.04"), ("alpine", "3.17"),
                                  ("fedora", "40"), ("rocky", "7"), ("amzn", "2")):
            with self.subTest(identity=identity):
                env = {**self.env, "id": identity, "version": version}
                self.assertTrue(installer.support_errors(env, True))
        self.assertFalse(installer.support_errors(self.env, False))
        unknown = {**self.env, "id": "my-derivative"}
        self.assertTrue(installer.support_errors(unknown, False))
        self.assertFalse(installer.support_errors(unknown, True))

    def test_os_release_data_not_shell_execution(self):
        path = self.root / "os-release"
        path.write_text('ID=cloudlinux\nVERSION_ID="8.10"\nID_LIKE="rhel fedora"\n'
                        'PRETTY_NAME="CloudLinux $(never-execute)"\n')
        data = installer.os_release(path)
        self.assertEqual(data["VERSION_ID"], "8.10")
        self.assertIn("$(never-execute)", data["PRETTY_NAME"])

    def test_wrapper_version_import_and_origin_verified(self):
        wrapper = self.root / "fwsec"
        interpreter = self.root / "venv/bin/python"
        interpreter.parent.mkdir(parents=True)
        interpreter.touch()
        wrapper.write_text(f'#!/bin/sh\nexec "{interpreter}" -I -B -m fwsec "$@"\n')
        wrapper.chmod(0o755)
        metadata = {"version": "1.6.1", "prefix": str(self.root / "venv"),
                    "module": str(self.root / "venv/lib/site-packages/fwsec/__init__.py")}
        outputs = [json.dumps(metadata), "fwsec 1.6.1\n", '{"data":{"fwsec":"1.6.1"}}']
        with patch.object(installer, "run", side_effect=[
            subprocess.CompletedProcess([], 0, out, "") for out in outputs]) as run:
            self.assertEqual(installer.verify_wrapper(wrapper, "1.6.1"), metadata)
        self.assertEqual(run.call_count, 3)
        wrapper.write_text(f'#!/bin/sh\necho side-effect\nexec "{interpreter}" -m fwsec "$@"\n')
        with patch.object(installer, "run") as run:
            with self.assertRaises(ValueError):
                installer.verify_wrapper(wrapper)
            run.assert_not_called()

    def test_wrapper_symlink_refused(self):
        wrapper = self.root / "fwsec"
        wrapper.symlink_to(self.root / "admin-script")
        with self.assertRaises(ValueError):
            installer.verify_wrapper(wrapper)

    def test_path_alias_allowed_but_shadowing_rejected(self):
        canonical = self.root / "fwsec"
        canonical.write_text("wrapper")
        alias = self.root / "alias"
        alias.symlink_to(canonical)
        shadow = self.root / "shadow"
        shadow.write_text("wrapper")
        self.assertTrue(installer.same_file(str(alias), canonical))
        self.assertFalse(installer.same_file(str(shadow), canonical))
        self.assertFalse(installer.same_file(None, canonical))

    def test_lazy_hashed_ca_store(self):
        hashed = self.root / "abcdef12.0"
        hashed.write_text("certificate")
        context = Mock()
        context.cert_store_stats.side_effect = [{"x509_ca": 0}, {"x509_ca": 1}]
        with patch.object(installer.ssl, "create_default_context", return_value=context), \
                patch.object(installer.ssl, "get_default_verify_paths",
                             return_value=Mock(capath=str(self.root))):
            self.assertTrue(installer.ca_trust_available())
        context.load_verify_locations.assert_called_once_with(cafile=str(hashed))

    def test_invalid_hashed_ca_not_accepted(self):
        (self.root / "abcdef12.0").write_text("invalid certificate")
        context = Mock()
        context.cert_store_stats.return_value = {"x509_ca": 0}
        context.load_verify_locations.side_effect = installer.ssl.SSLError("invalid")
        with patch.object(installer.ssl, "create_default_context", return_value=context), \
                patch.object(installer.ssl, "get_default_verify_paths",
                             return_value=Mock(capath=str(self.root))):
            self.assertFalse(installer.ca_trust_available())

    def test_snapshot_restore_preserves_mode_and_absence(self):
        backup = self.root / "backup"
        backup.mkdir(mode=0o700)
        existing, absent = self.root / "existing", self.root / "new"
        existing.write_text("original")
        existing.chmod(0o640)
        installer.snapshot(backup, paths=[existing, absent])
        existing.write_text("changed")
        existing.chmod(0o600)
        absent.write_text("created by installer")
        installer.snapshot(backup, restore=True)
        self.assertEqual(existing.read_text(), "original")
        self.assertEqual(existing.stat().st_mode & 0o777, 0o640)
        self.assertFalse(absent.exists())

    def test_snapshot_refuses_administrator_symlink(self):
        backup = self.root / "backup"
        backup.mkdir()
        link = self.root / "link"
        link.symlink_to(self.root / "target")
        with self.assertRaises(ValueError):
            installer.snapshot(backup, paths=[link])

    def probe(self, mode, health=None, **kwargs):
        health = health or {"policy_loaded": True, "ownership_verified": True,
                            "static_rules": "verified", "pending": [], "crowdsec": "operational"}
        def run(args, **kw):
            out = json.dumps({"data": health}) if "--status" in args else '{"nftables":[]}'
            return subprocess.CompletedProcess(args, 0, out, "")
        with patch.object(installer, "environment", return_value=self.env), \
                patch.object(installer, "run", side_effect=run), \
                patch.object(installer, "verify_wrapper", return_value={"version": "1.6.1"}), \
                patch.object(installer.shutil, "which", return_value=str(installer.BIN)), \
                patch.object(installer.ssl, "create_default_context", return_value=Mock(
                    cert_store_stats=lambda: {"x509_ca": 1})):
            return installer.probe(mode, check_path=False, **kwargs)

    def test_code_only_never_claims_runtime_or_boot(self):
        result = self.probe("code")
        self.assertEqual(result["state"], "CODE_INSTALLED")
        self.assertNotIn("runtime", result["data"]["checks"])
        self.assertNotIn("boot_enabled", result["data"]["checks"])

    def test_pending_not_reported_as_operational(self):
        result = self.probe("pending", {"policy_loaded": True, "ownership_verified": True,
                            "static_rules": "unknown", "pending": [{"id": "test"}],
                            "crowdsec": "disabled"})
        self.assertEqual(result["state"], "PENDING_CONFIRMATION")
        self.assertEqual(result["exit_code"], 3)

    def test_required_boot_failure_blocks_success(self):
        result = self.probe("runtime", require_boot=True)
        self.assertEqual(result["state"], "FAILED")
        self.assertIn("fwsec boot integration is not enabled", result["data"]["errors"])

    def test_optional_and_required_crowdsec_distinct(self):
        health = {"policy_loaded": True, "ownership_verified": True, "static_rules": "verified",
                  "pending": [], "crowdsec": "unavailable"}
        optional = self.probe("pending", {**health, "pending": [{"id": "test"}]})
        self.assertEqual(optional["exit_code"], 3)
        required = self.probe("pending", {**health, "pending": [{"id": "test"}]},
                              require_crowdsec=True)
        self.assertEqual(required["state"], "FAILED")


if __name__ == "__main__":
    unittest.main()
