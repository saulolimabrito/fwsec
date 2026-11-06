# SPDX-License-Identifier: GPL-2.0-only
"""Checked, scoped nft transactions and an SSH-independent rollback watchdog.

Never flush the ruleset or the shared filter table. Only input/forward/output
chains explicitly owned (or adopted by the operator) are replaced there;
CrowdSec sets and other chains/tables stay in the kernel untouched.
"""
from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Iterator
from dataclasses import asdict
from pathlib import Path
from typing import Any

from fwsec import config, geo, migration, nft, rules, state

ROOT = Path("/var/lib/fwsec/transactions")
LOCK = Path("/run/fwsec.lock")
MARKER = "fwsec managed"
CHAINS = ("input", "forward", "output")


@contextlib.contextmanager
def locked() -> Iterator[None]:
    """One CLI writer at a time; pending safe applies also exclude writers."""
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(LOCK), os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def pending() -> list[Path]:
    return [p for p in ROOT.glob("*/pending") if p.is_file()]


def require_no_pending() -> None:
    if pending():
        raise RuntimeError("A safe apply is pending. Confirm it or wait for rollback first.")


def validate(c: config.FwsecConfig, ssh_ports: list[int]) -> None:
    config.geo_mode(c)
    if c.inherited_policy:
        migration.load(c.inherited_policy)
    for name in ("tcp_in", "tcp_out", "udp_in", "udp_out"):
        for token in getattr(c, name):
            if not re.fullmatch(r"\d+(?::\d+)?", token):
                raise ValueError(f"Invalid {name}: {token!r}")
            ports = [int(p) for p in token.split(":")]
            if any(not 1 <= p <= 65535 for p in ports) or ports[0] > ports[-1]:
                raise ValueError(f"Invalid {name} port/range: {token!r}")
    if not ssh_ports or any(not 1 <= p <= 65535 for p in ssh_ports):
        raise ValueError("No valid SSH listening port detected.")
    if c.container_policy not in ("open", "filtered"):
        raise ValueError("CONTAINER_POLICY must be open or filtered.")
    if c.output_policy not in ("accept", "drop"):
        raise ValueError("OUTPUT_POLICY must be accept or drop.")
    for cc in c.geo_allow + c.geo_block:
        if not re.fullmatch(r"[a-z]{2}", cc):
            raise ValueError(f"Invalid country code: {cc!r}")
        v4, v6 = geo.country_cidrs(cc)
        if not v4 or (c.ipv6 and not v6):
            raise ValueError(f"Incomplete geo data for {cc}; run fwsec --geo-update first.")
        for family, cidrs in ((4, v4), (6, v6)):
            for cidr in cidrs:
                if ipaddress.ip_network(cidr).version != family:
                    raise ValueError(f"Wrong address family in geo data for {cc}.")
    for path in (config.ALLOW_FILE, config.DENY_FILE, config.IGNORE_FILE):
        if path.exists():
            for number, raw in enumerate(path.read_text().splitlines(), 1):
                value = raw.split("#", 1)[0].strip()
                if value:
                    try:
                        ipaddress.ip_network(value, strict=False)
                    except ValueError as exc:
                        raise ValueError(f"Invalid IP/CIDR: {path}:{number}: {value}") from exc


def _objects() -> list[dict[str, Any]]:
    rc, out, err = nft._run("-j", "list", "ruleset")
    if rc:
        raise RuntimeError(f"Cannot inspect current nftables rules: {err}")
    result: list[dict[str, Any]] = json.loads(out)["nftables"]
    return result


def _dump(*args: str) -> str:
    rc, out, err = nft._run("-s", "list", *args)
    if rc:
        raise RuntimeError(f"Cannot snapshot nft {' '.join(args)}: {err}")
    return out


def _address(value: Any) -> str:
    if isinstance(value, str):
        return str(ipaddress.ip_network(value, strict=False)) if "/" in value else str(
            ipaddress.ip_address(value))
    if isinstance(value, dict) and "prefix" in value:
        prefix = value["prefix"]
        return str(ipaddress.ip_network(f"{prefix['addr']}/{prefix['len']}", strict=False))
    if isinstance(value, dict) and "range" in value:
        return _address(value["range"][0]) + "-" + _address(value["range"][1])
    raise ValueError("Cannot safely snapshot this deny-set element encoding")


def deny_snapshot(objects: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep absolute monotonic expiry, not the original full ban duration."""
    result: dict[str, Any] = {}
    now = time.monotonic()
    for obj in objects:
        item = obj.get("set", {})
        if item.get("family") != "inet" or item.get("table") != "fwsec" or item.get(
            "name"
        ) not in ("deny4", "deny6"):
            continue
        entries = []
        for raw in item.get("elem", []):
            metadata = raw.get("elem") if isinstance(raw, dict) else None
            if metadata is None:
                entries.append({"value": _address(raw), "deadline": None})
                continue
            if metadata.get("timeout") and "expires" not in metadata:
                raise ValueError("Cannot determine remaining deny timeout; refusing to apply")
            # libnftables JSON timeout/expires are seconds (unlike netlink's
            # millisecond attributes). Do not divide the JSON value by 1000.
            entries.append({"value": _address(metadata["val"]), "deadline": (
                now + metadata["expires"] if "expires" in metadata else None)})
        result[item["name"]] = entries
    return result


def restore_timeouts(before: dict[str, Any]) -> str:
    text = str(before["fwsec"])
    for name, entries in before.get("deny_elements", {}).items():
        values = []
        for entry in entries:
            if entry["deadline"] is None:
                values.append(entry["value"])
            else:
                remaining_ms = int((entry["deadline"] - time.monotonic()) * 1000)
                if remaining_ms > 0:
                    values.append(f"{entry['value']} timeout {remaining_ms}ms")
        pattern = rf"(\bset\s+{name}\s*\{{)(.*?)(\n\s*\}})"

        def replace(match: re.Match[str]) -> str:
            body = re.sub(r"elements\s*=\s*\{.*?\}", "", match.group(2), flags=re.S)
            if values:
                body += "\n        elements = { " + ", ".join(values) + " }"
            return match.group(1) + body + match.group(3)

        text = re.sub(pattern, replace, text, flags=re.S)
    return text


def ownership_rule(rule: dict[str, Any]) -> bool:
    """Only an inert anonymous-counter sentinel is a portable ownership claim."""
    expr = rule.get("expr", [])
    return bool(rule.get("comment") == MARKER and len(expr) == 1
                and isinstance(expr[0], dict) and set(expr[0]) == {"counter"}
                and isinstance(expr[0]["counter"], dict)
                and set(expr[0]["counter"]) <= {"packets", "bytes"})


def owns_chain(table: str, chain: dict[str, Any],
               rows: list[dict[str, Any]] | None = None) -> bool:
    """Old nft JSON omits chain comments; accept only a scoped declaration.

    An arbitrary rule comment is NOT a chain ownership claim; only the exact
    inert first-rule sentinel is accepted on kernels lacking chain userdata.
    nft's canonical text prints chain comments on a standalone declaration line.
    """
    if "comment" in chain:
        return bool(chain["comment"] == MARKER)
    if rows is not None:
        first: dict[str, Any] = next((o["rule"] for o in rows if "rule" in o
                      and o["rule"].get("family") == "inet"
                      and o["rule"].get("table") == table
                      and o["rule"].get("chain") == chain["name"]), {})
        if ownership_rule(first):
            return True
    text = _dump("chain", "inet", table, chain["name"])
    depth = 0
    scoped = False
    for line in text.splitlines():
        if depth == 1 and line.strip() == f'chain {chain["name"]} {{':
            scoped = True
        if scoped and depth == 2 and re.fullmatch(
            r'\s*comment\s+"' + re.escape(MARKER) + r'"\s*;?\s*', line
        ):
            return True
        # Quoted strings may themselves contain braces, e.g. rule comments.
        unquoted = re.sub(r'"(?:\\.|[^"\\])*"', '', line)
        depth += unquoted.count("{") - unquoted.count("}")
        if depth < 2:
            scoped = False
    return False


def snapshot(adopt: bool = False) -> dict[str, Any]:
    objects = _objects()
    tables = {o["table"]["name"] for o in objects
              if "table" in o and o["table"]["family"] == "inet"}
    chains = {o["chain"]["name"]: o["chain"] for o in objects
              if "chain" in o and o["chain"]["family"] == "inet"
              and o["chain"]["table"] == "filter"}
    fw_chains = [o["chain"] for o in objects if "chain" in o
                 and o["chain"]["family"] == "inet" and o["chain"]["table"] == "fwsec"]
    if not adopt:
        for name in CHAINS:
            if name in chains and not owns_chain("filter", chains[name], objects):
                raise RuntimeError(
                    f"inet filter/{name} has no fwsec ownership marker. "
                    "Inspect --dry-run, then use --adopt-legacy only if these chains "
                    "belong to fwsec. Third-party chains must not be adopted."
                )
        if "fwsec" in tables and not any(
            ch.get("name") == "whitelist" and owns_chain("fwsec", ch, objects)
            for ch in fw_chains
        ):
            raise RuntimeError("inet fwsec is unmarked; inspect before --adopt-legacy.")
    for name in CHAINS:
        if name in chains and (chains[name].get("hook") != name
                               or chains[name].get("type") != "filter"):
            raise RuntimeError(f"inet filter/{name} is not the expected base chain; refusing.")
    return {
        "fwsec": _dump("table", "inet", "fwsec") if "fwsec" in tables else "",
        "filter_exists": "filter" in tables,
        "chains": {name: _dump("chain", "inet", "filter", name)
                   for name in CHAINS if name in chains},
        "sets": [o["set"]["name"] for o in objects if "set" in o
                 and o["set"]["family"] == "inet" and o["set"]["table"] == "filter"],
        "files": snapshot_files(),
        "deny_elements": deny_snapshot(objects),
    }


def _elements(name: str, values: list[str]) -> str:
    return (f"add element inet fwsec {name} {{ {', '.join(values)} }}\n" if values else "")


def build(c: config.FwsecConfig, ssh_ports: list[int], before: dict[str, Any],
          container_script: str = "") -> str:
    """Compile everything BEFORE calling nft (including allow/deny/temp/geo)."""
    validate(c, ssh_ports)
    # Keep shared sets: a bouncer may be updating them while this runs.
    filt = rules.generate_filter_table(c, ssh_ports)
    filt = filt.replace("flush table inet filter", "# Shared table is never flushed")
    for name in CHAINS:
        filt = filt.replace(f"chain {name} {{", f'chain {name} {{\n        comment "{MARKER}"')
    sentinel = f'\n        counter comment "{MARKER}"'
    declaration = r'(type filter hook (?:input|forward|output) priority [^;]+; policy [^;]+;)'
    filt = re.sub(declaration, lambda m: m.group(1) + sentinel, filt)
    prefix = ""
    if before["fwsec"]:
        prefix += "delete table inet fwsec\n"
    for name in CHAINS:
        if name in before["chains"]:
            prefix += (f"flush chain inet filter {name}\n"
                       f"delete chain inet filter {name}\n")
    fw = rules.generate_fwsec_table(c).replace(
        "chain whitelist {", f'chain whitelist {{\n        comment "{MARKER}"'
    )
    fw = re.sub(declaration, lambda m: m.group(1) + sentinel, fw, count=1)
    script = prefix + filt + fw
    record = state.load()
    permanent = {ipaddress.ip_network(e.ip, strict=False) for e in record.deny_meta.values()}
    temps = {ip: entry for ip, entry in record.temp_blocks.items()
             if ipaddress.ip_network(entry.ip, strict=False) not in permanent}
    temporary = {ipaddress.ip_network(e.ip, strict=False) for e in temps.values()}
    for kind, entries in (("allow", config.read_allow()), ("deny", config.read_deny())):
        for family in (4, 6):
            values = sorted({str(ipaddress.ip_network(e.ip, strict=False)) for e in entries
                             if ipaddress.ip_network(e.ip, strict=False).version == family
                             and (kind != "deny" or ipaddress.ip_network(
                                 e.ip, strict=False) not in temporary)})
            script += _elements(f"{kind}{family}", values)
    # Temporary blocks must not be restored as permanent entries.
    for entry in temps.values():
        network = ipaddress.ip_network(entry.ip, strict=False)
        remaining = int(entry.expires_at - time.time())
        if remaining > 0:
            name = f"deny{network.version}"
            script += _elements(name, [f"{network} timeout {remaining}s"])
    if config.geo_mode(c) != "off":
        script += geo.render_apply_file(c.geo_allow or c.geo_block)
    return script + container_script


def check(script: str) -> None:
    r = subprocess.run(["nft", "--check", "-f", "-"], input=script,
                       capture_output=True, text=True, timeout=60)
    if r.returncode:
        raise RuntimeError(f"nft validation failed (nothing applied): {r.stderr.strip()}")


def restore_script(before: dict[str, Any]) -> str:
    """Restore only affected objects; no global/table-wide shared flush."""
    current = _objects()
    has_fwsec = any(o.get("table", {}).get("family") == "inet"
                    and o["table"].get("name") == "fwsec" for o in current)
    names = {o["chain"]["name"] for o in current if "chain" in o
             and o["chain"].get("family") == "inet"
             and o["chain"].get("table") == "filter"}
    script = "delete table inet fwsec\n" if has_fwsec else ""
    for name in CHAINS:
        if name in names:
            script += f"flush chain inet filter {name}\n"
            script += f"delete chain inet filter {name}\n"
    script += restore_timeouts(before)
    script += "\n".join(before["chains"].values())
    # Empty bouncer sets created on a fresh install are left in place: deleting
    # them could race a bouncer or third party referencing them.
    return script


def atomic_write(path: Path, text: str) -> None:
    if path.is_symlink():
        raise RuntimeError(f"Refusing to replace an administrator symlink: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        with os.fdopen(fd, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        path.chmod(mode)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def apply(script: str, before: dict[str, Any], timeout: int | None = None) -> str | None:
    """Caller holds locked(). Safe applies defer persistence until confirmation."""
    require_no_pending()
    check(script)
    if timeout is None:
        nft._run_script(script)  # one netlink transaction, no intermediate rules
        return None
    if not 30 <= timeout <= 3600:
        raise ValueError("Safe-apply timeout must be between 30 and 3600 seconds.")
    ident = uuid.uuid4().hex
    directory = ROOT / ident
    directory.mkdir(parents=True, mode=0o700)
    atomic_write(directory / "before.json", json.dumps(before))
    atomic_write(directory / "pending", str(time.monotonic() + timeout))
    # Detached from the SSH terminal; uses the installed interpreter and module.
    # No service-manager dependency: the same worker works on OpenRC/systemd.
    with (directory / "watchdog.log").open("ab") as log:
        subprocess.Popen([sys.executable, "-m", "fwsec.transaction", ident,
                          str(ROOT), str(LOCK)],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                         start_new_session=True, close_fds=True)
    ready = directory / "ready"
    for _ in range(100):
        if ready.exists():
            break
        time.sleep(0.05)
    else:
        (directory / "pending").unlink()
        raise RuntimeError("Rollback worker did not start; nothing applied.")
    try:
        nft._run_script(script)
        atomic_write(directory / "applied", "yes")
    except BaseException:
        # Kernel transactions are atomic. The watchdog still attempts a scoped
        # restore if the process is killed after commit but before this returns.
        raise
    return ident


LOADER_DEBIAN = Path("/etc/nftables.conf")
LOADER_RHEL = Path("/etc/sysconfig/nftables.conf")
LOADER_ALPINE = Path("/etc/nftables.nft")
INCLUDE = Path("/etc/nftables/fwsec.nft")
PERSIST_MARKER = "# Managed by fwsec"


def loader_content() -> tuple[Path, str]:
    loader = (LOADER_RHEL if LOADER_RHEL.exists() else
              LOADER_ALPINE if LOADER_ALPINE.exists() else LOADER_DEBIAN)
    content = loader.read_text() if loader.exists() else ""
    if PERSIST_MARKER in content:
        # Replace an old fwsec-generated wholesale snapshot, including its
        # destructive flush ruleset, with a scoped include.
        includes = [line for line in content.splitlines()
                    if re.match(r"^\s*include\s+", line) and str(INCLUDE) not in line]
        content = "#!/usr/sbin/nft -f\n" + PERSIST_MARKER + "\n"
        content += "\n".join(includes) + ("\n" if includes else "")
    elif re.search(r"(?m)^\s*flush\s+ruleset\b", content):
        raise RuntimeError(
            f"{loader} is administrator-owned and contains 'flush ruleset'. "
            "Remove that global flush after reviewing the loader; fwsec will not overwrite it."
        )
    include = f'include "{INCLUDE}"'
    if include not in content:
        content = content.rstrip() + "\n" + include + "\n"
    return loader, content


def snapshot_files() -> dict[str, Any]:
    result: dict[str, Any] = {}
    for path in (LOADER_DEBIAN, LOADER_RHEL, LOADER_ALPINE, INCLUDE,
                 config.CONF_FILE, config.EXECUTABLE,
                 config.MIGRATION_RECEIPT, config.APPLIED_FILE):
        if path.is_symlink():
            raise RuntimeError(f"Review symlinked persistence/configuration "
                               f"before applying: {path}")
        result[str(path)] = ({"text": path.read_text(), "mode": path.stat().st_mode & 0o777}
                             if path.exists() else None)
    return result


def restore_files(before: dict[str, Any]) -> None:
    for name, value in before.get("files", {}).items():
        path = Path(name)
        if value is None:
            if path.exists():
                path.unlink()
        else:
            atomic_write(path, value["text"])
            path.chmod(value["mode"])


def persist() -> None:
    """Idempotent, scoped boot script; do not persist bouncer dynamic elements."""
    loader, content = loader_content()
    before = snapshot()
    script = "add table inet filter\n"
    for name, family in (("crowdsec-blacklists", "ipv4_addr"),
                         ("crowdsec6-blacklists", "ipv6_addr")):
        script += f"add set inet filter {name} {{ type {family}; flags timeout; }}\n"
    for name, dump in before["chains"].items():
        script += f"add chain inet filter {name}\nflush chain inet filter {name}\n{dump}\n"
    script += "add table inet fwsec\ndelete table inet fwsec\n" + before["fwsec"]
    check(script)
    atomic_write(INCLUDE, PERSIST_MARKER + "\n" + script)
    atomic_write(loader, content)
    record_applied()


def static_receipt(rows: list[dict[str, Any]], ports: list[int]) -> dict[str, Any]:
    from fwsec import compat
    c = config.load_config()
    settings = asdict(c)
    settings.pop("enabled", None)
    effective = json.loads(json.dumps(settings, default=str))
    if c.inherited_policy:
        effective["inherited_document"] = migration.load(c.inherited_policy)
    selected = []
    for row in rows:
        copy = json.loads(json.dumps(row))
        if "set" in copy:
            copy["set"].pop("elem", None)  # Dynamic list contents/expiry are not static rules.
        selected.append(copy)
    specs = compat.hooks(c, c.container_mode and c.container_policy == "filtered")
    kernel = {name: compat.objects(selected, name, name, specs[name])
              for name in ("filter", "fwsec")}
    return {"config": effective, "ssh_ports": ports, "kernel": kernel}


def record_applied() -> None:
    from fwsec.cli import _detect_ssh_ports
    atomic_write(config.APPLIED_FILE, json.dumps(static_receipt(_objects(), _detect_ssh_ports())))


def applied_status(rows: list[dict[str, Any]], ports: list[int]) -> str:
    if not config.APPLIED_FILE.exists():
        return "not verified (no receipt from this version)"
    try:
        old = json.loads(config.APPLIED_FILE.read_text())
        current = static_receipt(rows, ports)
        return "verified" if old == current else "changed"
    except (ValueError, OSError, KeyError):
        return "not verified (invalid receipt)"


def _directory(ident: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", ident):
        raise ValueError("Invalid transaction ID.")
    return ROOT / ident


def confirm(ident: str) -> None:
    directory = _directory(ident)
    marker = directory / "pending"
    if not marker.exists() or not (directory / "applied").exists():
        raise RuntimeError("Transaction is not awaiting confirmation.")
    if time.monotonic() >= float(marker.read_text()):
        raise RuntimeError("Confirmation deadline expired; rollback is pending.")
    candidate = directory / "migration.json"
    receipt = None
    if candidate.exists():
        receipt = json.loads(candidate.read_text())
        candidate_digest = migration.fingerprint(json.loads(Path(receipt["path"]).read_text()))
        if candidate_digest != receipt["digest"]:
            raise RuntimeError("Inherited policy changed during the trial; rollback remains armed.")
        receipt["kernel_digest"] = migration.active_digest(migration.load(Path(receipt["path"])))
    # Keep pending until persistence succeeds: a write failure must still rollback.
    persist()
    config.set_enabled(True)
    if receipt:
        atomic_write(config.MIGRATION_RECEIPT, json.dumps(receipt))
    marker.rename(directory / "confirmed")


def activate_upgrade(ident: str, confirm_now: bool = True) -> None:
    """Caller holds locked(); never switch a wrapper after watchdog rollback."""
    directory = _directory(ident)
    marker = directory / "pending"
    if not marker.exists() or not (directory / "applied").exists():
        raise RuntimeError("Upgrade is no longer awaiting activation")
    if time.monotonic() >= float(marker.read_text()):
        raise RuntimeError("Upgrade deadline expired; wrapper activation refused")
    interpreter = Path(sys.executable)
    if not interpreter.is_file() or not interpreter.is_absolute():
        raise RuntimeError("Invalid candidate interpreter")
    # JSON quoting is not shell quoting: use shlex for paths with spaces/quotes.
    import shlex
    wrapper = '#!/bin/sh\nexec ' + shlex.quote(str(interpreter)) + ' -I -B -m fwsec "$@"\n'
    try:
        atomic_write(config.EXECUTABLE, wrapper)
        config.EXECUTABLE.chmod(0o755)
        verify_activation_wrapper()
        if confirm_now:
            confirm(ident)
    except BaseException:
        rollback(ident)
        raise


def verify_activation_wrapper() -> None:
    from fwsec import __version__
    from fwsec.installer import verify_wrapper
    verify_wrapper(config.EXECUTABLE, __version__)


def watchdog(ident: str) -> None:
    directory = _directory(ident)
    atomic_write(directory / "ready", "yes")
    marker = directory / "pending"
    while marker.exists():
        if time.monotonic() < float(marker.read_text()):
            time.sleep(0.25)
            continue
        with locked():
            if not marker.exists():
                return
            try:
                rollback(ident)
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                atomic_write(directory / "rollback-error", str(exc))
                print(f"Rollback failed; retrying: {exc}", flush=True)
                time.sleep(1)
                continue
        return


def rollback(ident: str) -> None:
    """Caller holds locked(); restore rules, persistence and executable wrapper."""
    directory = _directory(ident)
    marker = directory / "pending"
    if not marker.exists():
        raise RuntimeError("Transaction is not awaiting confirmation")
    before = json.loads((directory / "before.json").read_text())
    script = restore_script(before)
    check(script)
    nft._run_script(script)
    restore_files(before)
    marker.rename(directory / "rolled-back")


if __name__ == "__main__":
    if len(sys.argv) == 4:
        ROOT = Path(sys.argv[2])
        LOCK = Path(sys.argv[3])
    watchdog(sys.argv[1])
