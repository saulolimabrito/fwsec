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
from pathlib import Path
from typing import Any

from fwsec import config, geo, nft, rules, state

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
            if name in chains and chains[name].get("comment") != MARKER:
                raise RuntimeError(
                    f"inet filter/{name} has no fwsec ownership marker. "
                    "Inspect --dry-run, then use --adopt-legacy only if these chains "
                    "belong to fwsec. Third-party chains must not be adopted."
                )
        if "fwsec" in tables and not any(
            ch.get("name") == "whitelist" and ch.get("comment") == MARKER
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
    script = prefix + filt + fw
    temps = state.load().temp_blocks
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
    script += str(before["fwsec"])
    script += "\n".join(before["chains"].values())
    # Empty bouncer sets created on a fresh install are left in place: deleting
    # them could race a bouncer or third party referencing them.
    return script


def atomic_write(path: Path, text: str) -> None:
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
INCLUDE = Path("/etc/nftables/fwsec.nft")
PERSIST_MARKER = "# Managed by fwsec"


def loader_content() -> tuple[Path, str]:
    loader = LOADER_RHEL if LOADER_RHEL.exists() else LOADER_DEBIAN
    content = loader.read_text() if loader.exists() else ""
    if PERSIST_MARKER in content:
        # Replace an old fwsec-generated wholesale snapshot, including its
        # destructive flush ruleset, with a scoped include.
        content = "#!/usr/sbin/nft -f\n" + PERSIST_MARKER + "\n"
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
    for path in (LOADER_DEBIAN, LOADER_RHEL, INCLUDE, config.CONF_FILE):
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
    # Keep pending until persistence succeeds: a write failure must still rollback.
    persist()
    config.set_enabled(True)
    marker.rename(directory / "confirmed")


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
                before = json.loads((directory / "before.json").read_text())
                script = restore_script(before)
                check(script)
                nft._run_script(script)
                restore_files(before)
                marker.rename(directory / "rolled-back")
            except (RuntimeError, OSError, subprocess.SubprocessError) as exc:
                atomic_write(directory / "rollback-error", str(exc))
                print(f"Rollback failed; retrying: {exc}", flush=True)
                time.sleep(1)
                continue
        return


if __name__ == "__main__":
    if len(sys.argv) == 4:
        ROOT = Path(sys.argv[2])
        LOCK = Path(sys.argv[3])
    watchdog(sys.argv[1])
