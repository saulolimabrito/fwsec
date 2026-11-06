# SPDX-License-Identifier: GPL-2.0-only
"""Exercise real user actions in disposable network AND filesystem state."""
from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from fwsec import cli, config, geo, nft, state, transaction


def call(*args: str, expected: int = 0) -> str:
    out, err = io.StringIO(), io.StringIO()
    code = 0
    with patch("sys.argv", ["fwsec", *args]), \
            patch.object(cli, "_detect_ssh_ports", return_value=[22]), \
            contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            cli.main()
        except SystemExit as exc:
            code = exc.code
    assert code == expected, (args, code, out.getvalue(), err.getvalue())
    assert "\033" not in out.getvalue() + err.getvalue()
    return out.getvalue()


def run() -> None:
    if os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"):
        raise RuntimeError("Refusing host namespace")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        config.CONFIG_DIR = root
        for name in ("CONF_FILE", "ALLOW_FILE", "DENY_FILE", "IGNORE_FILE", "STATE_FILE",
                     "EXECUTABLE", "MIGRATION_RECEIPT", "APPLIED_FILE"):
            setattr(config, name, root / name)
        state.STATE_FILE = config.STATE_FILE
        for name in ("LOADER_DEBIAN", "LOADER_RHEL", "LOADER_ALPINE", "INCLUDE", "ROOT", "LOCK"):
            setattr(transaction, name, root / name)
        config.CONF_FILE.write_text("[firewall]\nENABLED=1\nTCP_IN=22\n"
                                    "[crowdsec]\nENABLED=0\n")
        call("--version")
        call("--help")
        call("--start")
        status = json.loads(call("--status", "--json"))["data"]
        assert status["static_rules"] == "verified", status
        call("--check", "--json")
        call("--deny", "192.0.2.10", "QA permanent")
        assert nft.is_denied("192.0.2.10")
        call("--deny-remove", "192.0.2.10")
        assert not nft.is_denied("192.0.2.10")
        assert "No change" in call("--deny-remove", "192.0.2.10")
        call("--deny", "2001:db8::10", "QA IPv6 permanent")
        assert nft.is_denied("2001:db8::10")
        call("--deny-remove", "2001:db8::10")
        assert not nft.is_denied("2001:db8::10")
        call("--temp-deny", "192.0.2.11", "60", "QA temporary")
        assert json.loads(call("--temp-list", "--json"))["data"]["items"]
        call("--temp-remove", "192.0.2.11")
        call("--temp-deny", "2001:db8::11", "60", "QA IPv6 temporary")
        assert nft.is_denied("2001:db8::11")
        call("--temp-remove", "2001:db8::11")
        assert not nft.is_denied("2001:db8::11")
        call("--temp-deny", "192.0.2.12", "0", expected=1)
        assert not nft.is_denied("192.0.2.12")
        for ip in ("192.0.2.13", "2001:db8::13"):
            call("--allow", ip, "QA allow")
            assert nft.is_allowed(ip)
            assert json.loads(call("--grep", ip, "--json"))["data"]["results"][0]["found"]
            call("--allow-remove", ip)
            assert not nft.is_allowed(ip)
        call("--list", "--section", "allow", "--limit", "1", "--json")
        call("--list", "--all", "--json")
        call("--geo-status", "--json")
        call("--migration-report", "--json")
        call("--stop", "--yes")
        assert not nft.table_exists()
        call("--start")
        call("--disable", "--yes")
        assert not config.load_config().enabled
        call("--start")  # Disabled service boot/restart must NOT reenable filtering.
        assert not nft.table_exists()
        call("--check", "--json", expected=3)
        call("--enable", "--yes")
        assert config.load_config().enabled and nft.table_exists()
        script = call("--dry-run")
        assert "[*]" not in script
        transaction.check(script)
        call("--apply-safe", "--timeout", "30")
        ident = transaction.pending()[0].parent.name
        call("--status", "--json", expected=3)
        call("--rollback", ident)
        call("--apply-safe", "--timeout", "30")
        call("--confirm", transaction.pending()[0].parent.name)
        assert not transaction.pending()
        call("--restart", "--yes")
        call("--status", "--json")
        # Fixture-backed downloads exercise real validation, disk cache and nft apply.
        with contextlib.ExitStack() as stack:
            for name in ("update_zones", "country_cidrs", "resolve_all", "zone_counts",
                         "zones_last_updated", "render_apply_file", "lookup_country"):
                fn = getattr(geo, name)
                defaults = tuple(root / "geo" if isinstance(v, Path) else v
                                 for v in fn.__defaults__)
                stack.enter_context(patch.object(fn, "__defaults__", defaults))
            stack.enter_context(patch.object(geo, "_fetch", side_effect=lambda url:
                b"2001:db8::/32\n" if "ipv6" in url else b"192.0.2.0/24\n"))
            original = config.CONF_FILE.read_text()
            config.CONF_FILE.write_text(original.replace("TCP_IN=22", "TCP_IN=22\nGEO_BLOCK=br"))
            call("--geo-update", expected=4)  # No geo sets until the policy is applied.
            call("--apply-safe", "--timeout", "30")
            call("--confirm", transaction.pending()[0].parent.name)
            call("--geo-update")
            status = json.loads(call("--geo-status", "--json"))["data"]
            assert status["mode"] == "deny" and status["loaded_ipv4"] == 1
            config.CONF_FILE.write_text(original)
            call("--restart", "--yes")
        # Static drift must be detected, not silently certified as healthy.
        nft._run_script("add rule inet filter input tcp dport 60606 accept\n")
        status = json.loads(call("--status", "--json", expected=3))["data"]
        assert status["static_rules"] == "changed"
        print("PASS: real CLI allow/deny/temp IPv4+IPv6, list/search/JSON, stop/disable/enable, "
              "safe confirmation/rollback, receipt drift, exit statuses, clean dry-run")


if __name__ == "__main__":
    run()
