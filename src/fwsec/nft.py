# SPDX-License-Identifier: GPL-2.0-only

"""
nftables abstraction layer.

fwsec owns a dedicated table `inet fwsec` with two hook chains:
  - whitelist  priority -100  (accept before the main filter)
  - blacklist  priority  -50  (drop before the main filter)

The existing `inet filter` table (crowdsec + SSH allow) is left untouched.
"""
from __future__ import annotations

import ipaddress
import re
import shutil
import subprocess
from dataclasses import dataclass

NFT_FAMILY = "inet"
NFT_TABLE = "fwsec"

SET_ALLOW4 = "allow4"
SET_ALLOW6 = "allow6"
SET_DENY4 = "deny4"
SET_DENY6 = "deny6"

# `priority filter` (symbolic), `auto-merge` and `ct original proto-dst`
# require nftables 0.9.0+ / kernel 4.18+ (RHEL 8, Debian 10, Ubuntu 18.04).
MIN_NFT_VERSION = (0, 9, 0)


# ---------------------------------------------------------------------------
# Low-level runner
# ---------------------------------------------------------------------------

def _run(*args: str, check: bool = False) -> tuple[int, str, str]:
    try:
        r = subprocess.run(["nft", *args], capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError):
        return 127, "", "nft binary is not available"
    if check and r.returncode != 0:
        raise RuntimeError(f"nft {' '.join(args)}: {r.stderr.strip()}")
    return r.returncode, r.stdout, r.stderr


def _run_script(script: str, check: bool = True) -> tuple[int, str, str]:
    try:
        r = subprocess.run(["nft", "-f", "-"], input=script, capture_output=True, text=True)
    except (OSError, subprocess.SubprocessError) as e:
        if check:
            raise RuntimeError(f"nft is not available: {e}")
        return 127, "", str(e)
    if check and r.returncode != 0:
        raise RuntimeError(f"nft script error: {r.stderr.strip()}")
    return r.returncode, r.stdout, r.stderr


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------

def _ip_version(ip: str) -> int:
    try:
        return ipaddress.ip_network(ip, strict=False).version
    except ValueError:
        raise ValueError(f"Invalid IP/CIDR: {ip}")


def _set_for(ip: str, kind: str) -> str:
    """Return the set name for the given IP and kind ('allow'|'deny')."""
    v = _ip_version(ip)
    return f"{kind}{v}"


# ---------------------------------------------------------------------------
# Environment preflight
# ---------------------------------------------------------------------------

def version() -> tuple[int, ...] | None:
    """Installed nft version as a tuple, or None when it cannot be parsed."""
    rc, out, _ = _run("--version")
    if rc != 0:
        return None
    m = re.search(r"v?(\d+)\.(\d+)(?:\.(\d+))?", out)
    if not m:
        return None
    return tuple(int(x) if x else 0 for x in m.groups())


def preflight() -> None:
    """Fail with a clear, actionable message when nftables is unusable here.

    Covers the common cross-distro failure modes: missing binary, version
    below the 0.9.0 syntax floor, and kernels without nf_tables support
    (OpenVZ/Virtuozzo containers, stripped-down VPS kernels).
    """
    if shutil.which("nft") is None:
        raise RuntimeError(
            "The nftables binary ('nft') was not found. "
            "Install nftables with the distribution package manager."
        )

    ver = version()
    if ver is not None and ver < MIN_NFT_VERSION:
        ver_str = ".".join(str(x) for x in ver)
        min_str = ".".join(str(x) for x in MIN_NFT_VERSION)
        raise RuntimeError(
            f"nftables {ver_str} is too old (fwsec requires >= {min_str}, "
            "which needs kernel >= 4.18)."
        )

    rc, _, err = _run("list", "ruleset")
    if rc != 0:
        raise RuntimeError(
            "nftables is not usable on this kernel: 'nft list ruleset' failed"
            + (f" ({err.strip()})" if err.strip() else "")
            + ". This happens on kernels without nf_tables support "
            "(e.g. OpenVZ/Virtuozzo) or with missing nf_tables kernel modules."
        )


# ---------------------------------------------------------------------------
# Table lifecycle
# ---------------------------------------------------------------------------

def table_exists() -> bool:
    rc, out, _ = _run("list", "table", NFT_FAMILY, NFT_TABLE)
    return rc == 0


def flush_table() -> None:
    if table_exists():
        _run("delete", "table", NFT_FAMILY, NFT_TABLE)


def create_table() -> None:
    """Create the fwsec table with sets and hook chains."""
    script = f"""
table {NFT_FAMILY} {NFT_TABLE} {{

    set {SET_ALLOW4} {{
        type ipv4_addr
        flags interval
        auto-merge
    }}

    set {SET_ALLOW6} {{
        type ipv6_addr
        flags interval
        auto-merge
    }}

    set {SET_DENY4} {{
        type ipv4_addr
        flags interval, timeout
    }}

    set {SET_DENY6} {{
        type ipv6_addr
        flags interval, timeout
    }}

    chain whitelist {{
        type filter hook input priority -100; policy accept;
        ip  saddr @{SET_ALLOW4} accept
        ip6 saddr @{SET_ALLOW6} accept
    }}

    chain blacklist {{
        type filter hook input priority -50; policy accept;
        ip  saddr @{SET_DENY4} drop
        ip6 saddr @{SET_DENY6} drop
    }}

    chain whitelist_forward {{
        type filter hook forward priority -100; policy accept;
        ip  saddr @{SET_ALLOW4} accept
        ip6 saddr @{SET_ALLOW6} accept
    }}

    chain blacklist_forward {{
        type filter hook forward priority -50; policy accept;
        ip  saddr @{SET_DENY4} drop
        ip6 saddr @{SET_DENY6} drop
    }}
}}
"""
    _run_script(script)


# ---------------------------------------------------------------------------
# Set element management
# ---------------------------------------------------------------------------

def add_element(set_name: str, ip: str, timeout_sec: int | None = None) -> None:
    if timeout_sec is not None:
        element = f"{{ {ip} timeout {timeout_sec}s }}"
    else:
        element = f"{{ {ip} }}"
    _run("add", "element", NFT_FAMILY, NFT_TABLE, set_name, element, check=True)


def delete_element(set_name: str, ip: str) -> bool:
    rc, _, _ = _run("delete", "element", NFT_FAMILY, NFT_TABLE, set_name, f"{{ {ip} }}")
    return rc == 0


def list_elements(set_name: str) -> list[str]:
    rc, out, _ = _run("list", "set", NFT_FAMILY, NFT_TABLE, set_name)
    if rc != 0:
        return []
    # Parse: elements = { 1.2.3.4, 5.6.7.8 timeout 1h expires 59m58s, ... }
    m = re.search(r"elements\s*=\s*\{([^}]*)\}", out, re.DOTALL)
    if not m:
        return []
    raw = m.group(1)
    # Strip timeout/expires annotations, split by comma
    entries = []
    for token in raw.split(","):
        # Each token may be "1.2.3.4 timeout Xh expires Ym"
        ip_part = token.strip().split()[0] if token.strip() else ""
        if ip_part:
            entries.append(ip_part)
    return entries


def element_exists(set_name: str, ip: str) -> bool:
    return ip in list_elements(set_name)


# ---------------------------------------------------------------------------
# High-level operations
# ---------------------------------------------------------------------------

def allow(ip: str) -> None:
    set_name = _set_for(ip, "allow")
    add_element(set_name, ip)


def unallow(ip: str) -> bool:
    set_name = _set_for(ip, "allow")
    return delete_element(set_name, ip)


def deny(ip: str, timeout_sec: int | None = None) -> None:
    set_name = _set_for(ip, "deny")
    add_element(set_name, ip, timeout_sec)


def undeny(ip: str) -> bool:
    set_name = _set_for(ip, "deny")
    return delete_element(set_name, ip)


def is_allowed(ip: str) -> bool:
    try:
        return element_exists(_set_for(ip, "allow"), ip)
    except (ValueError, RuntimeError):
        return False


def is_denied(ip: str) -> bool:
    try:
        return element_exists(_set_for(ip, "deny"), ip)
    except (ValueError, RuntimeError):
        return False


# ---------------------------------------------------------------------------
# List / status helpers
# ---------------------------------------------------------------------------

@dataclass
class SetSummary:
    allow4: list[str]
    allow6: list[str]
    deny4: list[str]
    deny6: list[str]


def get_summary() -> SetSummary:
    if not table_exists():
        return SetSummary([], [], [], [])
    return SetSummary(
        allow4=list_elements(SET_ALLOW4),
        allow6=list_elements(SET_ALLOW6),
        deny4=list_elements(SET_DENY4),
        deny6=list_elements(SET_DENY6),
    )


def list_ruleset() -> str:
    _, out, _ = _run("list", "ruleset")
    return out


def list_fwsec_tables() -> str:
    """Return only the tables fwsec owns (inet filter + inet fwsec).

    Used for persistence: saving the full ruleset would freeze dynamic rules
    from other owners (Docker, Podman, libvirt) into /etc/nftables.conf.
    """
    parts = []
    for table in ("filter", NFT_TABLE):
        rc, out, _ = _run("list", "table", NFT_FAMILY, table)
        if rc == 0 and out.strip():
            parts.append(out.strip())
    return ("\n\n".join(parts) + "\n") if parts else ""


def get_full_set_output(set_name: str) -> str:
    """Return raw nft output for a specific set (includes timeouts)."""
    rc, out, _ = _run("list", "set", NFT_FAMILY, NFT_TABLE, set_name)
    return out if rc == 0 else ""


# ---------------------------------------------------------------------------
# Populate sets from config lists on startup
# ---------------------------------------------------------------------------

def load_allow_list(ips: list[str]) -> None:
    for ip in ips:
        try:
            allow(ip)
        except (ValueError, RuntimeError):
            pass


def load_deny_list(ips: list[str]) -> None:
    for ip in ips:
        try:
            deny(ip)
        except (ValueError, RuntimeError):
            pass
