# SPDX-License-Identifier: GPL-2.0-only

"""
fwsec — nftables + CrowdSec firewall manager
CSF-style CLI interface
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

from fwsec import (
    __version__,
    compat,
    containers,
    crowdsec,
    geo,
    migration,
    nft,
    rules,
    state,
    transaction,
    ui,
    upgrade,
)
from fwsec import config as cfg

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def _ok(msg: str) -> None:
    print(f"{GREEN}[OK]{RESET} {ui.safe(msg)}")


def _err(msg: str) -> None:
    print(f"{RED}[ERR]{RESET} {ui.safe(msg)}", file=sys.stderr)


def _info(msg: str) -> None:
    print(f"{CYAN}[*]{RESET} {ui.safe(msg)}")


def _warn(msg: str) -> None:
    print(f"{YELLOW}[!]{RESET} {ui.safe(msg)}")


def _header(title: str) -> None:
    width = min(60, max(20, shutil.get_terminal_size((80, 24)).columns - 2))
    print(f"\n{BOLD}{CYAN}{'─' * width}{RESET}")
    print(f"{BOLD}{CYAN}  {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─' * width}{RESET}")


class PartialFailure(RuntimeError):
    """Primary change succeeded but an integration/application step failed."""


def _confirm_action(args: argparse.Namespace, message: str, required: bool = False) -> None:
    if getattr(args, "yes", False):
        return
    if sys.stdin.isatty() and sys.stdout.isatty():
        if input(message + " [y/N]: ").strip().lower() not in ("y", "yes"):
            _info("Cancelled. No changes made.")
            raise SystemExit(130)
    elif required:
        raise ValueError(message + " Explicit acknowledgement required: add --yes.")


def _protect_admin(args: argparse.Namespace, ip: str) -> None:
    peer = os.environ.get("SSH_CONNECTION", "").split()
    if peer and ipaddress.ip_address(peer[0]) in ipaddress.ip_network(ip, strict=False):
        _confirm_action(args, f"This targets your current SSH client {peer[0]} and may cut access.",
                        required=True)


def _sync_failed(success: bool, action: str) -> None:
    if not success:
        raise PartialFailure("Local change completed; CrowdSec " + action +
                             " failed. Check the LAPI and retry the integration.")


def _require_root() -> None:
    import os
    if os.geteuid() != 0:
        _err("fwsec requires root. Run with sudo or as root.")
        sys.exit(1)


# ---------------------------------------------------------------------------
# SSH port detection
# ---------------------------------------------------------------------------

_SSHD_CANDIDATES = ("/usr/sbin/sshd", "/usr/local/sbin/sshd")


def _sshd_binary() -> str | None:
    found = shutil.which("sshd")
    if found:
        return found
    for candidate in _SSHD_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


def _ssh_ports_from_sshd_t() -> list[int]:
    """Ports reported by `sshd -T` (effective configuration, includes drop-ins)."""
    sshd = _sshd_binary()
    if not sshd:
        return []
    try:
        r = subprocess.run([sshd, "-T"], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    if r.returncode != 0:
        return []
    ports: list[int] = []
    for line in r.stdout.splitlines():
        if line.startswith("port "):
            try:
                ports.append(int(line.split()[1]))
            except (IndexError, ValueError):
                pass
    return ports


def _ssh_ports_from_config() -> list[int]:
    """Parse /etc/ssh/sshd_config plus every file reachable through its Include
    directives (Ubuntu 22.10+, RHEL 9 and Fedora use sshd_config.d drop-ins).

    Collects every Port directive — sshd may listen on several ports at once.
    """
    ports: list[int] = []
    seen_files: set[Path] = set()

    def _parse(path: Path) -> None:
        if path in seen_files or not path.is_file():
            return
        seen_files.add(path)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            include = re.match(r"(?i)^Include\s+(.+)$", stripped)
            if include:
                for pattern in include.group(1).split():
                    inc = Path(pattern)
                    if not inc.is_absolute():
                        inc = Path("/etc/ssh") / inc
                    if "*" in inc.name or "?" in inc.name:
                        parent = inc.parent
                        if not parent.is_dir():
                            continue
                        pattern_re = re.escape(inc.name).replace(r"\*", ".*").replace(r"\?", ".")
                        for child in sorted(parent.iterdir()):
                            if re.fullmatch(pattern_re, child.name):
                                _parse(child)
                    elif inc.exists():
                        _parse(inc)
                continue
            port = re.match(r"(?i)^Port\s+(\d+)", stripped)
            if port:
                ports.append(int(port.group(1)))

    _parse(Path("/etc/ssh/sshd_config"))
    return ports


def _detect_ssh_ports() -> list[int]:
    """Effective SSH listening ports, deduplicated.

    `sshd -T` reflects the effective configuration; config parsing is the
    fallback when sshd is unavailable and also catches extra Port directives
    that some sshd -T versions omit. Opening a superset is always safe —
    the alternative is locking yourself out of the server.
    """
    ports = _ssh_ports_from_sshd_t()
    for p in _ssh_ports_from_config():
        if p not in ports:
            ports.append(p)
    return sorted(set(ports)) or [22]


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_version(args: argparse.Namespace) -> None:
    ui.query("version", args, [])


def cmd_start(_args: argparse.Namespace) -> str | None:
    _require_root()
    if not getattr(_args, "dry_run", False):
        _info("Starting fwsec firewall...")

    try:
        nft.preflight()
    except RuntimeError as e:
        _err(str(e))
        sys.exit(1)

    c = cfg.load_config()

    if not c.enabled and not any(getattr(_args, name, False) for name in (
        "enable", "apply_safe", "dry_run", "upgrade_apply"
    )):
        _info("No change: fwsec is disabled in configuration. Use fwsec --enable to enable it.")
        return None

    ssh_ports = _detect_ssh_ports()
    transaction.validate(c, ssh_ports)
    if c.inherited_policy and not getattr(_args, "dry_run", False):
        digest = migration.fingerprint(migration.load(c.inherited_policy))
        receipt = json.loads(cfg.MIGRATION_RECEIPT.read_text()) if (
            cfg.MIGRATION_RECEIPT.exists()) else {}
        if receipt.get("digest") != digest and not getattr(_args, "apply_safe", False):
            raise ValueError("An unconfirmed inherited policy requires --apply-safe, not -s/-r.")
    transaction.loader_content()  # refuse unsafe persistence before changing kernel rules
    before = transaction.snapshot(adopt=(getattr(_args, "adopt_legacy", False)
                                        or getattr(_args, "upgrade_apply", False)))
    extra = ""
    if c.container_mode and c.container_policy == "filtered":
        published = containers.externally_published_ports()
        extra = rules.generate_container_filter(
            [p.host_port for p in published if p.proto == "tcp"],
            [p.host_port for p in published if p.proto == "udp"],
            containers.container_networks(),
        )
    script = transaction.build(c, ssh_ports, before, extra)
    if getattr(_args, "upgrade_apply", False):
        if not c.enabled or not before["fwsec"] or len(before["chains"]) != 3:
            raise RuntimeError("Automatic upgrade requires an enabled, active fwsec installation")
        if not _args.upgrade_state:
            raise ValueError("--upgrade-apply requires --upgrade-state PATH")
        try:
            transaction.snapshot()
        except RuntimeError:
            probe = transaction.build(c, ssh_ports, {"fwsec": "", "chains": {}}, extra)
            compat.prove(c, probe, filtered=bool(extra))
        _args.apply_safe = True
        _args.timeout = 180
    if getattr(_args, "dry_run", False):
        transaction.check(script)
        print(script)
        return None
    timeout = _args.timeout if getattr(_args, "apply_safe", False) else None
    ident = transaction.apply(script, before, timeout)
    if ident:
        if getattr(_args, "upgrade_apply", False):
            transaction.atomic_write(_args.upgrade_state, ident)
        if c.inherited_policy:
            transaction.atomic_write(transaction.ROOT / ident / "migration.json", json.dumps({
                "path": str(c.inherited_policy),
                "digest": migration.fingerprint(migration.load(c.inherited_policy)),
                "source": migration.load(c.inherited_policy)["source"],
            }))
        _warn(f"Rules applied provisionally. Automatic rollback in {_args.timeout}s.")
        if getattr(_args, "upgrade_apply", False):
            _info("Upgrade installer will activate and confirm automatically; "
                  "rollback stays armed.")
        else:
            _info(f"From a NEW SSH connection confirm: fwsec --confirm {ident}")
        _info("Boot persistence is unchanged until confirmation.")
    else:
        try:
            _persist_nftables()
            cfg.set_enabled(True)
        except (OSError, RuntimeError):
            nft._run_script(transaction.restore_script(before))
            transaction.restore_files(before)
            raise
        _ok("fwsec started (one validated atomic transaction).")
    return ident


def _apply_container_filter() -> None:
    """Build the `containers` chain restricting published ports to the allow list."""
    published = containers.externally_published_ports()
    tcp_ports = [p.host_port for p in published if p.proto == "tcp"]
    udp_ports = [p.host_port for p in published if p.proto == "udp"]
    subnets = containers.container_networks()

    if not tcp_ports and not udp_ports:
        _info("No externally published container ports to filter.")
        return

    script = rules.generate_container_filter(tcp_ports, udp_ports, subnets)
    try:
        nft._run_script(script)
        plist = ", ".join(
            f"{p.host_port}/{p.proto} ({p.container})" for p in published
        )
        _ok(f"Published container ports restricted to the allow list: {plist}")
    except RuntimeError as e:
        _warn(f"Could not apply the container port filter: {e}")


def cmd_stop(_args: argparse.Namespace) -> None:
    _require_root()
    _confirm_action(_args, "Stop fwsec filtering? Third-party firewalls remain active.")
    before = transaction.snapshot(adopt=getattr(_args, "adopt_legacy", False))
    script = "delete table inet fwsec\n" if before["fwsec"] else ""
    for name in before["chains"]:
        script += f"flush chain inet filter {name}\n"
        script += (f"add chain inet filter {name} {{ type filter hook {name} "
                    f'priority 0; policy accept; comment "{transaction.MARKER}"; }}\n')
        script += f'add rule inet filter {name} counter comment "{transaction.MARKER}"\n'
    if script:
        transaction.check(script)
        nft._run_script(script)
        try:
            _persist_nftables()
        except (OSError, RuntimeError):
            nft._run_script(transaction.restore_script(before))
            transaction.restore_files(before)
            raise
    _ok("fwsec stopped. Third-party rules and CrowdSec sets were not removed.")


def cmd_disable(_args: argparse.Namespace) -> None:
    _require_root()
    cmd_stop(_args)
    cfg.set_enabled(False)
    _ok("fwsec disabled. It will not start automatically.")


def cmd_enable(_args: argparse.Namespace) -> None:
    _require_root()
    cmd_start(_args)


def cmd_restart(_args: argparse.Namespace) -> None:
    _require_root()
    if not cfg.load_config().enabled:
        _info("No change: fwsec is disabled. Use fwsec --enable.")
        return
    _info("Restarting fwsec...")
    cmd_start(_args)
    _ok("fwsec restarted.")


def cmd_check(args: argparse.Namespace) -> None:
    ui.query("check", args, _detect_ssh_ports())


def cmd_list(args: argparse.Namespace) -> None:
    ui.query("list", args, _detect_ssh_ports())


def cmd_deny(args: argparse.Namespace) -> None:
    _require_root()
    ip = _resolve(args.ip)
    _protect_admin(args, ip)
    comment = args.comment or ""

    _info(f"Blocking {ip} permanently...")
    try:
        nft.deny(ip)
    except RuntimeError as e:
        _err(f"nftables: {e}")
        sys.exit(1)

    cfg.add_deny(ip, comment)
    state.add_deny_meta(ip, comment)

    c = cfg.load_config()
    if c.crowdsec_enabled and c.crowdsec_sync_deny and shutil.which("cscli"):
        _sync_failed(crowdsec.add_decision(ip, reason=comment or "fwsec manual ban"), "sync")

    _ok(f"Blocked: {ip}{f'  ({comment})' if comment else ''}")


def cmd_deny_remove(args: argparse.Namespace) -> None:
    _require_root()
    ip = _resolve(args.ip)
    _info(f"Removing block for {ip}...")

    removed = nft.undeny(ip)
    configured = cfg.remove_deny(ip)
    state.remove_deny_meta(ip)

    c = cfg.load_config()
    if c.crowdsec_enabled and shutil.which("cscli"):
        _sync_failed(crowdsec.delete_decision(ip), "removal")

    _ok(f"Block removed: {ip}" if removed or configured else
        f"No change: {ip} was not in the local deny list.")


def cmd_temp_deny(args: argparse.Namespace) -> None:
    _require_root()
    ip = _resolve(args.ip)
    try:
        duration_sec = int(args.duration)
    except ValueError as exc:
        raise ValueError("Duration must be a positive number of seconds; example: 3600.") from exc
    if not 1 <= duration_sec <= 2147483647:
        raise ValueError("Duration must be between 1 and 2147483647 seconds; example: 3600.")
    _protect_admin(args, ip)
    if state.load().deny_meta.get(ip):
        raise ValueError("IP has a permanent local ban. Remove it before creating a temporary ban.")
    comment = args.comment or ""

    _info(f"Temporarily blocking {ip} for {_fmt_duration(duration_sec)}...")
    try:
        nft.deny(ip, timeout_sec=duration_sec)
    except RuntimeError as e:
        _err(f"nftables: {e}")
        sys.exit(1)

    state.add_temp_block(ip, duration_sec, comment)
    cfg.add_deny(ip, comment)

    c = cfg.load_config()
    if c.crowdsec_enabled and c.crowdsec_sync_deny and shutil.which("cscli"):
        _sync_failed(crowdsec.add_decision(
            ip, reason=comment or "fwsec temp ban", duration=f"{duration_sec}s"), "sync")

    expires = ui.timestamp(time.time() + duration_sec)
    suffix = f"  ({comment})" if comment else ""
    _ok(f"Temp blocked: {ip} until {expires}{suffix}")


def cmd_temp_list(args: argparse.Namespace) -> None:
    ui.query("temp-list", args, [])


def cmd_temp_remove(args: argparse.Namespace) -> None:
    _require_root()
    ip = _resolve(args.ip)
    record = state.load()
    if ip not in record.temp_blocks:
        _ok(f"No change: {ip} has no temporary block. Permanent blocks were not touched.")
        return
    if ip in record.deny_meta:
        raise ValueError("IP also has a permanent ban; use --deny-remove to review/remove it.")
    _info(f"Removing temporary block for {ip}...")

    nft.undeny(ip)
    state.remove_temp_block(ip)
    cfg.remove_deny(ip)

    c = cfg.load_config()
    if c.crowdsec_enabled and shutil.which("cscli"):
        _sync_failed(crowdsec.delete_decision(ip), "removal")

    _ok(f"Temporary block removed: {ip}")


def cmd_allow(args: argparse.Namespace) -> None:
    _require_root()
    ip = _resolve(args.ip)
    comment = args.comment or ""

    _info(f"Whitelisting {ip}...")
    try:
        nft.allow(ip)
    except RuntimeError as e:
        _err(f"nftables: {e}")
        sys.exit(1)

    cfg.add_allow(ip, comment)
    state.add_allow_meta(ip, comment)

    # Remove from deny if present
    nft.undeny(ip)
    cfg.remove_deny(ip)
    state.remove_temp_block(ip)
    state.remove_deny_meta(ip)

    # Remove CrowdSec ban if any
    c = cfg.load_config()
    if c.crowdsec_enabled and shutil.which("cscli"):
        _sync_failed(crowdsec.delete_decision(ip), "removal")

    _ok(f"Allowed: {ip}{f'  ({comment})' if comment else ''}")


def cmd_allow_remove(args: argparse.Namespace) -> None:
    _require_root()
    ip = _resolve(args.ip)
    _protect_admin(args, ip)
    _info(f"Removing {ip} from whitelist...")

    removed = nft.unallow(ip)
    configured = cfg.remove_allow(ip)
    state.remove_allow_meta(ip)

    _ok(f"Removed from whitelist: {ip}" if removed or configured else
        f"No change: {ip} was not in the local allow list.")


def cmd_grep(args: argparse.Namespace) -> None:
    ui.query("search", args, [])


def cmd_geo_update(_args: argparse.Namespace) -> None:
    """Refresh country zone data and reload the geo sets."""
    _require_root()
    c = cfg.load_config()
    codes = c.geo_block or c.geo_allow
    if not codes:
        _err("Geo policy is disabled. Set GEO_BLOCK or GEO_ALLOW in "
             f"{cfg.CONF_FILE} first.")
        sys.exit(1)
    mode = cfg.geo_mode(c)
    _info(f"Updating country zones ({', '.join(codes)}) [mode: {mode}]...")

    updated, failed = geo.update_zones(codes)
    if failed:
        _warn(f"Failed to update: {', '.join(failed)} (previous zones kept)")
    if not updated:
        _err("No country zone was updated.")
        sys.exit(1)
    g4, g6 = geo.resolve_all(updated)
    _ok(f"Zones updated: {len(updated)} countries, "
        f"{len(g4)} IPv4 + {len(g6)} IPv6 CIDRs.")

    if nft.table_exists():
        try:
            transaction.validate(c, _detect_ssh_ports())
        except ValueError as exc:
            raise PartialFailure("Zones downloaded but NOT applied: " + str(exc)) from exc
        # render_apply_file flushes the sets; include cached zones for failed
        # countries too, never silently drop them from the active policy.
        script = geo.render_apply_file(codes)
        try:
            nft._run_script(script)
            _ok("geo4/geo6 sets reloaded in nftables.")
        except RuntimeError as e:
            raise PartialFailure(f"Zones downloaded, but NOT applied: {e}. "
                                 "Inspect fwsec --geo-status; review fwsec --dry-run.") from e
    else:
        _info("fwsec table not loaded — run 'fwsec -s' to apply the geo policy.")
    if failed:
        raise PartialFailure("Only some zones were updated. "
                             "Previous zones kept for failed countries.")


def cmd_geo_status(args: argparse.Namespace) -> None:
    ui.query("geo-status", args, [])


def cmd_upgrade(_args: argparse.Namespace) -> None:
    """Update fwsec from the GitHub repository, preserving local configuration."""
    _require_root()
    _info(f"Installed version : {__version__}")
    _info(f"Checking the repository ({upgrade.REPO}) for updates...")

    remote = upgrade.fetch_remote_version()
    if not remote:
        _err("Could not query the latest version. Check network connectivity.")
        sys.exit(1)
    _info(f"Repository version: {remote}")

    if not upgrade.is_newer(remote, __version__):
        _ok(f"fwsec {__version__} is already up to date. Nothing to do.")
        return

    _info(f"Downloading fwsec {remote}...")
    src = upgrade.download_source(remote)
    if not src:
        _err("Failed to download the new version from the repository.")
        sys.exit(1)

    installer = src / "install.sh"
    if not installer.exists():
        _err("Downloaded source has no install.sh; aborting.")
        sys.exit(1)

    _info("Local configuration in /etc/fwsec (fwsec.conf, allow/deny/ignore "
           "lists, state) is preserved — only code and executable are updated.")
    sys.stdout.flush()
    sys.stderr.flush()
    rc = subprocess.call(["bash", str(installer), "--upgrade"],
                         env={**os.environ, "FWSEC_COLOR": getattr(_args, "color", "auto")})
    sys.exit(rc)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _resolve(ip_or_host: str) -> str:
    """Resolve hostname to IP, or return IP as-is."""
    try:
        return cfg.normalize_ip(ip_or_host)
    except ValueError:
        try:
            return socket.gethostbyname(ip_or_host)
        except socket.gaierror:
            _err(f"Cannot resolve: {ip_or_host}")
            sys.exit(1)


def _fmt_duration(sec: int) -> str:
    return ui.duration(sec)


def _persist_nftables() -> None:
    """Persist only fwsec-owned objects, without any global ruleset flush."""
    transaction.persist()


# ---------------------------------------------------------------------------
# CLI parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="fwsec",
        usage="fwsec ACTION [OPTIONS]",
        description="nftables + CrowdSec firewall manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  fwsec --upgrade                   Update fwsec from GitHub (config preserved)
  fwsec --geo-update                Refresh country zones and reload geo sets
  fwsec --geo-status                Show the geo policy status
  fwsec -s                          Start firewall
  fwsec -r                          Reload rules
  fwsec -l                          List loaded rules
  fwsec -d 1.2.3.4                  Block IP permanently
  fwsec -d 1.2.3.4 "SSH attack"    Block with comment
  fwsec -td 1.2.3.4 3600 "Brute"   Temp block for 1 hour
  fwsec -t                          List temporary blocks
  fwsec -tr 1.2.3.4                 Remove temp block
  fwsec -dr 1.2.3.4                 Remove permanent block
  fwsec -a 1.2.3.4 "Office"        Whitelist IP
  fwsec -ar 1.2.3.4                 Remove from whitelist
  fwsec -g 1.2.3.4                  Search IP in all lists
  fwsec -g example.com              Search domain
""",
    )

    g = p.add_mutually_exclusive_group()
    g.add_argument("--status", action="store_true",
                   help="Show actual policy and integration health")
    g.add_argument("--menu", action="store_true", help="Open an optional read-only terminal menu")
    p.add_argument("--json", action="store_true", help="Structured output for read-only queries")
    p.add_argument("--verbose", action="store_true", help="Include dependency details in --version")
    p.add_argument("--all", action="store_true", help="Show every entry with --list")
    p.add_argument("--limit", type=int, default=10, help="Entries per --list section (default: 10)")
    p.add_argument("--section", choices=("all", "allow", "deny", "crowdsec"), default="all",
                   help="Filter --list to a section")
    p.add_argument("--color", choices=("auto", "always", "never"), default="auto",
                   help="Color output (default: auto; respects NO_COLOR)")
    p.add_argument("--yes", action="store_true", help="Acknowledge dangerous interactive actions")

    g.add_argument("--dry-run", action="store_true",
                   help="Validate and print the transaction without applying it (root)")
    g.add_argument("--apply-safe", action="store_true",
                   help="Apply provisionally; roll back unless confirmed from a new SSH session")
    g.add_argument("--confirm", metavar="ID", help="Confirm a pending safe apply")
    g.add_argument("--rollback", metavar="ID",
                   help="Cancel a pending apply and restore its snapshot")
    g.add_argument("--upgrade-apply", action="store_true", help=argparse.SUPPRESS)
    g.add_argument("--upgrade-activate", metavar="ID", help=argparse.SUPPRESS)
    p.add_argument("--upgrade-state", type=Path, help=argparse.SUPPRESS)
    g.add_argument("--migration-report", action="store_true",
                   help="Show the complete inherited-policy report")
    g.add_argument("--migration-plan", choices=("csf", "ufw", "firewalld"),
                   help="Capture and classify live policy without changing rules")
    g.add_argument("--migration-finalize", action="store_true",
                   help="Retire exact legacy rules after safe-apply confirmation")
    p.add_argument("--migration-output", type=Path,
                   default=Path("/var/lib/fwsec/migration-plan.json"),
                   help="Path for a live migration plan/report")
    p.add_argument("--migration-approve", default="",
                   help="Explicitly approve the exact source fingerprint after ownership review")
    p.add_argument("--timeout", type=int, default=120,
                   help="Safe-apply confirmation deadline in seconds (30–3600)")
    p.add_argument("--adopt-legacy", action="store_true",
                   help="Explicitly adopt unmarked fwsec tables/chains after inspecting them")

    g.add_argument("-v", "--version",   action="store_true", help="Show version")
    g.add_argument("--upgrade",         action="store_true",
                   help="Update fwsec from the GitHub repository "
                        "(local configuration is preserved)")
    g.add_argument("--geo-update",      dest="geo_update", action="store_true",
                   help="Refresh country zones and reload the geo sets")
    g.add_argument("--geo-status",      dest="geo_status", action="store_true",
                   help="Show the geo policy status")
    g.add_argument("-l", "--list",      action="store_true", help="List loaded rules")
    g.add_argument("-s", "--start",     action="store_true", help="Start firewall")
    g.add_argument("-f", "--stop",      action="store_true", help="Stop firewall (flush rules)")
    g.add_argument("-x", "--disable",   action="store_true", help="Disable fwsec")
    g.add_argument("-e", "--enable",    action="store_true", help="Enable fwsec")
    g.add_argument("-r", "--restart",   action="store_true", help="Restart / reload rules")
    g.add_argument("-c", "--check",     action="store_true", help="Check configuration")

    # Deny
    g.add_argument("-d", "--deny",      nargs="+", metavar=("IP", "COMMENT"),
                   help="Block IP permanently: -d IP [comment]")
    g.add_argument("-dr", "--deny-remove", dest="deny_remove", metavar="IP",
                   help="Remove permanent block")

    # Temp deny
    g.add_argument("-td", "--temp-deny", dest="temp_deny", nargs="+",
                   metavar=("IP", "SECONDS"),
                   help="Block IP temporarily: -td IP SECONDS [comment]")
    g.add_argument("-t",  "--temp-list",   dest="temp_list",   action="store_true",
                   help="List temporary blocks")
    g.add_argument("-tr", "--temp-remove", dest="temp_remove", metavar="IP",
                   help="Remove temporary block")

    # Allow
    g.add_argument("-a",  "--allow",        nargs="+", metavar=("IP", "COMMENT"),
                   help="Whitelist IP: -a IP [comment]")
    g.add_argument("-ar", "--allow-remove", dest="allow_remove", metavar="IP",
                   help="Remove IP from whitelist")

    # Grep
    g.add_argument("-g", "--grep", metavar="IP_OR_DOMAIN",
                   help="Search IP or domain in all lists")

    # Organize help independently from the shared mutually-exclusive action set.
    categories = {
        "Inspect (read-only)": {"status", "menu", "version", "list", "check", "grep",
                                 "temp_list", "geo_status", "migration_report"},
        "Block / allow": {"deny", "deny_remove", "temp_deny", "temp_remove", "allow",
                          "allow_remove"},
        "Apply / recover": {"start", "restart", "stop", "disable", "enable", "dry_run",
                             "apply_safe", "confirm", "rollback", "adopt_legacy", "timeout"},
        "Maintenance": {"upgrade", "geo_update", "migration_plan", "migration_finalize",
                         "migration_approve", "migration_output"},
    }
    for title, names in categories.items():
        group = p.add_argument_group(title)
        for action in list(p._optionals._group_actions):
            if action.dest in names:
                p._optionals._group_actions.remove(action)
                group._group_actions.append(action)
    return p


def _validate_options(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    supplied = set(sys.argv[1:])
    def used(name: str) -> bool:
        return any(a == name or a.startswith(name + "=") for a in supplied)
    if not 1 <= args.limit <= 10000:
        parser.error("--limit must be between 1 and 10000")
    for option in ("--all", "--limit", "--section"):
        if used(option) and not args.list:
            parser.error(option + " is only valid with --list")
    if used("--timeout") and not args.apply_safe:
        parser.error("--timeout is only valid with --apply-safe")
    if args.apply_safe and not 30 <= args.timeout <= 3600:
        parser.error("--timeout must be between 30 and 3600 seconds")
    if args.adopt_legacy and not any((args.dry_run, args.apply_safe)):
        parser.error("--adopt-legacy requires --dry-run or --apply-safe after ownership review")
    if args.migration_approve and not args.migration_plan:
        parser.error("--migration-approve requires --migration-plan")
    if used("--migration-output") and not (args.migration_plan or args.migration_report):
        parser.error("--migration-output requires --migration-plan or --migration-report")
    if args.verbose and not args.version:
        parser.error("--verbose is only valid with --version")
    if args.yes and not any((args.deny, args.temp_deny, args.allow_remove,
                             args.stop, args.disable, args.enable, args.restart, args.start)):
        parser.error("--yes is only valid with an action that changes firewall state")
    if args.json and not any((args.status, args.check, args.list, args.version, args.grep,
                              args.temp_list, args.geo_status, args.migration_report)):
        parser.error("--json requires a read-only query, e.g. --status --json")


def cmd_menu(args: argparse.Namespace) -> None:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("--menu requires an interactive terminal. Use --status or --help.")
    choices = {"1": "status", "2": "list", "3": "temp-list", "4": "geo-status"}
    while True:
        print("\nfwsec — read-only menu\n"
              "1 Status  2 Lists  3 Temporary bans  4 Geo  5 Search  0 Exit")
        choice = input("> ").strip()
        if choice == "0":
            return
        command = choices.get(choice)
        if choice == "5":
            args.target = input("IP / hostname: ").strip()
            command = "search"
        if command:
            try:
                ui.query(command, args, _detect_ssh_ports())
            except (ValueError, RuntimeError, OSError) as exc:
                _err(str(exc))
            except SystemExit as exc:
                if exc.code not in (3, 4):
                    raise
        else:
            _warn("Choose 0–5. No changes are performed by this menu.")


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    _validate_options(parser, args)
    ui.configure_output(args)
    try:
        read_only = any((args.status, args.menu, args.version, args.list, args.check, args.grep,
                         args.geo_status, args.temp_list, args.migration_report))
        if read_only:
            _run_command(parser, args)
        elif args.upgrade:
            # The installer invokes fwsec -r as a child; don't hold a lock
            # across that subprocess. Still refuse an upgrade during a trial.
            _require_root()
            with transaction.locked():
                transaction.require_no_pending()
            cmd_upgrade(args)
        elif not any(vars(args).get(k) for k in (
            "start", "restart", "enable", "stop", "disable", "deny", "deny_remove",
            "temp_deny", "temp_remove", "allow", "allow_remove", "geo_update",
            "dry_run", "apply_safe", "confirm", "rollback", "upgrade_apply", "upgrade_activate",
            "migration_finalize", "migration_plan",
        )):
            print("fwsec — nftables + CrowdSec firewall manager\n"
                  "Inspect: fwsec --status | --list | --check\n"
                  "Help:    fwsec --help | --menu\n"
                  "Safe apply: fwsec --apply-safe (confirm from a new SSH session)")
        else:
            _require_root()
            with transaction.locked():
                if not args.confirm and not args.rollback and not args.upgrade_activate:
                    transaction.require_no_pending()
                _run_command(parser, args)
    except (KeyboardInterrupt, EOFError):
        _warn("Cancelled. If an apply was pending, its watchdog remains responsible for recovery.")
        sys.exit(130)
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as e:
        # Configuration errors (e.g. GEO_BLOCK and GEO_ALLOW set together)
        if args.json:
            print(json.dumps({"schema": 1, "ok": False, "error": str(e)}))
        else:
            _err(str(e))
        sys.exit(4 if isinstance(e, PartialFailure) else 1)


def _run_command(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    # Map parsed args to command functions
    if args.menu:
        cmd_menu(args)
        return
    for flag, command in (("status", "status"), ("version", "version"), ("check", "check"),
                          ("list", "list"), ("grep", "search"), ("temp_list", "temp-list"),
                          ("geo_status", "geo-status"), ("migration_report", "migration-report")):
        if getattr(args, flag, False):
            args.target = args.grep
            ui.query(command, args, _detect_ssh_ports() if command in (
                "status", "check", "list") else [])
            return
    if args.version:
        cmd_version(args)

    elif args.confirm:
        transaction.confirm(args.confirm)
        _ok("Safe apply confirmed and persisted.")

    elif args.rollback:
        transaction.rollback(args.rollback)
        _ok("Previous rules, persistence and wrapper restored.")

    elif args.upgrade_activate:
        transaction.activate_upgrade(args.upgrade_activate)
        _ok("Candidate wrapper activated and upgrade confirmed.")

    elif args.migration_report:
        c = cfg.load_config()
        path = c.inherited_policy or args.migration_output
        print(migration.report_text(json.loads(path.read_text())))

    elif args.migration_plan:
        document = migration.capture(args.migration_plan, args.migration_output,
                                     args.migration_approve)
        print(migration.report_text(document))
        if document["status"] != "ready":
            raise ValueError("Migration is blocked or requires fingerprint approval; "
                             "nothing changed.")

    elif args.migration_finalize:
        c = cfg.load_config()
        if not c.inherited_policy or not cfg.MIGRATION_RECEIPT.exists():
            raise ValueError("No confirmed inherited policy is available")
        policy = migration.load(c.inherited_policy)
        receipt = json.loads(cfg.MIGRATION_RECEIPT.read_text())
        migration.finalize(policy, receipt)
        _ok("Exact reviewed legacy rules retired; configuration/packages retained for recovery.")
        _info("Old startup disabled without a global flush; "
              "packages/configs retained for recovery.")

    elif args.dry_run or args.apply_safe or args.upgrade_apply:
        cmd_start(args)

    elif args.upgrade:
        cmd_upgrade(args)

    elif args.geo_update:
        cmd_geo_update(args)

    elif args.geo_status:
        cmd_geo_status(args)

    elif args.list:
        cmd_list(args)

    elif args.start:
        cmd_start(args)

    elif args.stop:
        cmd_stop(args)

    elif args.disable:
        cmd_disable(args)

    elif args.enable:
        cmd_enable(args)

    elif args.restart:
        cmd_restart(args)

    elif args.check:
        cmd_check(args)

    elif args.deny:
        comment = " ".join(args.deny[1:]) if len(args.deny) > 1 else ""
        ns = argparse.Namespace(ip=args.deny[0], comment=comment, yes=args.yes)
        cmd_deny(ns)

    elif args.deny_remove:
        cmd_deny_remove(argparse.Namespace(ip=args.deny_remove))

    elif args.temp_deny:
        if len(args.temp_deny) < 2:
            parser.error("-td requires IP and SECONDS: fwsec -td 1.2.3.4 3600 [comment]")
        ns = argparse.Namespace(
            ip=args.temp_deny[0],
            duration=args.temp_deny[1],
            yes=args.yes,
            comment=" ".join(args.temp_deny[2:]) if len(args.temp_deny) > 2 else "",
        )
        cmd_temp_deny(ns)

    elif args.temp_list:
        cmd_temp_list(args)

    elif args.temp_remove:
        cmd_temp_remove(argparse.Namespace(ip=args.temp_remove))

    elif args.allow:
        comment = " ".join(args.allow[1:]) if len(args.allow) > 1 else ""
        ns = argparse.Namespace(ip=args.allow[0], comment=comment)
        cmd_allow(ns)

    elif args.allow_remove:
        cmd_allow_remove(argparse.Namespace(ip=args.allow_remove, yes=args.yes))

    elif args.grep:
        cmd_grep(argparse.Namespace(target=args.grep))

    else:
        parser.print_help()
