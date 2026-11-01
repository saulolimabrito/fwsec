# SPDX-License-Identifier: GPL-2.0-only

"""
Country (geolocation) policy data for fwsec.

Downloads per-country CIDR zones (ipdeny.com by default), validates every
line, stores them atomically under GEO_DIR (/etc/fwsec/geo) and renders
nftables element files for bulk loading into the geo4/geo6 interval sets.

Modes (fwsec.conf [firewall]):
    GEO_BLOCK = "cn,ru"   deny-list: drop traffic from the listed countries
    GEO_ALLOW  = "br,us"  allow-list: drop everything EXCEPT the listed
                          countries ("deny all, allow a few")
They are mutually exclusive (see fwsec.config.geo_mode).

The interval sets are loaded with a single `nft -f` file — thousands of
CIDRs apply in seconds. A failed download never destroys what is already
applied: zones are written atomically (tmp + rename) and sets are only
flushed when new data is fully in place.
"""
from __future__ import annotations

import ipaddress
import os
import re
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Union

from fwsec.config import GEO_DIR

ZONE_URL_V4 = "https://www.ipdeny.com/ipblocks/data/countries/{cc}.zone"
ZONE_URL_V6 = "https://www.ipdeny.com/ipv6/ipblocks/data/countries/{cc}.zone"
_TIMEOUT = 30

_CC_RE = re.compile(r"^[a-z]{2}$")
# One CIDR or plain address per line ("1.0.0.0/8", "2001:db8::/32")
_LINE_RE = re.compile(r"^([0-9a-fA-F.:]+)(/\d{1,3})?$")


class GeoUpdateError(Exception):
    """One or more country zones could not be updated."""


# ---------------------------------------------------------------------------
# Download + validation
# ---------------------------------------------------------------------------

def _fetch(url: str) -> bytes | None:
    req = urllib.request.Request(url, headers={"User-Agent": "fwsec-geo"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data: bytes = resp.read()
            return data
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def parse_zone(data: bytes) -> list[str]:
    """Validate zone lines and return the CIDRs (plain IPs get /32 or /128)."""
    networks: list[str] = []
    for raw in data.decode("utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _LINE_RE.match(line)
        if not m:
            continue
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        networks.append(str(net))
    return networks


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".")
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(text)
        os.replace(tmp_name, path)
    except OSError:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)
        raise


def update_zones(
    codes: list[str], directory: Path = GEO_DIR, include_v6: bool = True
) -> tuple[list[str], list[str]]:
    """Refresh the zone files for `codes`; returns (updated, failed).

    A country counts as updated when its IPv4 zone was downloaded (the IPv6
    zone failing is a warning, not a failure). The CIDR index is rebuilt from
    the freshly written files. Already-installed zones are only replaced on
    success — a bad download leaves the previous data in place.
    """
    updated: list[str] = []
    failed: list[str] = []
    for cc in codes:
        if not _CC_RE.match(cc):
            failed.append(cc)
            continue
        try:
            data4 = _fetch(ZONE_URL_V4.format(cc=cc))
            if data4 is None:
                raise GeoUpdateError(f"IPv4 zone unavailable for {cc}")
            nets4 = parse_zone(data4)
            if not nets4:
                raise GeoUpdateError(f"IPv4 zone for {cc} parsed to zero CIDRs")
            _atomic_write(directory / f"{cc}.zone", "\n".join(nets4) + "\n")

            if include_v6:
                data6 = _fetch(ZONE_URL_V6.format(cc=cc))
                if data6 is not None:
                    nets6 = parse_zone(data6)
                    if nets6:
                        _atomic_write(directory / f"{cc}6.zone", "\n".join(nets6) + "\n")
            updated.append(cc)
        except GeoUpdateError:
            failed.append(cc)
    if updated:
        _write_index(updated, directory)
    return updated, failed


# ---------------------------------------------------------------------------
# Index (cidr -> country) for fwsec -g lookups
# ---------------------------------------------------------------------------

def _write_index(codes: list[str], directory: Path = GEO_DIR) -> None:
    lines: list[str] = []
    for cc in codes:
        for zone, family in ((f"{cc}.zone", 4), (f"{cc}6.zone", 6)):
            path = directory / zone
            if not path.exists():
                continue
            for cidr in _read_zone_cidrs(path):
                lines.append(f"{family}\t{cc}\t{cidr}")
    _atomic_write(
        _index_path(directory), "\n".join(lines) + ("\n" if lines else "")
    )


def _index_path(directory: Path) -> Path:
    return directory / "index.tsv"


def _read_zone_cidrs(path: Path) -> list[str]:
    try:
        return [line.strip() for line in path.read_text().splitlines() if line.strip()]
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Country CIDRs
# ---------------------------------------------------------------------------

def country_cidrs(
    cc: str, directory: Path = GEO_DIR
) -> tuple[list[str], list[str]]:
    """Read (ipv4, ipv6) CIDRs for a country from the local zone files."""
    return _read_zone_cidrs(directory / f"{cc}.zone"), _read_zone_cidrs(
        directory / f"{cc}6.zone"
    )


def resolve_all(
    codes: list[str], directory: Path = GEO_DIR
) -> tuple[list[str], list[str]]:
    """Union of (ipv4, ipv6) CIDRs across all configured countries."""
    all4: list[str] = []
    all6: list[str] = []
    for cc in codes:
        c4, c6 = country_cidrs(cc, directory)
        all4.extend(c4)
        all6.extend(c6)
    return all4, all6


def zone_counts(codes: list[str], directory: Path = GEO_DIR) -> dict[str, int]:
    """Total CIDR count per country (v4 + v6) for status display."""
    counts: dict[str, int] = {}
    for cc in codes:
        c4, c6 = country_cidrs(cc, directory)
        counts[cc] = len(c4) + len(c6)
    return counts


def zones_last_updated(directory: Path = GEO_DIR) -> float | None:
    """Newest mtime across the zone files (unix timestamp), None if absent."""
    mtimes = [
        p.stat().st_mtime
        for p in directory.glob("*.zone")
        if p.exists()
    ]
    return max(mtimes) if mtimes else None


# ---------------------------------------------------------------------------
# nftables element file (bulk load into the geo4/geo6 interval sets)
# ---------------------------------------------------------------------------

def render_apply_file(codes: list[str], directory: Path = GEO_DIR) -> str:
    """Render the `nft -f` script that replaces the geo sets' contents.

    One `add element` statement per country keeps a parse failure attributable
    to a single zone. Empty families are skipped — `add element` with an empty
    list is an nft syntax error.
    """
    lines = ["flush set inet fwsec geo4", "flush set inet fwsec geo6"]
    for cc in codes:
        c4, c6 = country_cidrs(cc, directory)
        if c4:
            lines.append(
                "add element inet fwsec geo4 { " + ", ".join(c4) + " }"
            )
        if c6:
            lines.append(
                "add element inet fwsec geo6 { " + ", ".join(c6) + " }"
            )
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# IP -> country lookup (fwsec -g)
# ---------------------------------------------------------------------------

def lookup_country(
    ip: str, codes: list[str], directory: Path = GEO_DIR
) -> str | None:
    """Country of `ip` among the configured zones (longest-prefix match)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return None
    family = addr.version
    best_cc: str | None = None
    best_prefix = -1
    for cc in codes:
        nets = _network_cache(cc, family, directory)
        for net in nets:
            if addr in net and net.prefixlen > best_prefix:
                best_cc, best_prefix = cc, net.prefixlen
    return best_cc


_GeoNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_NET_CACHE: dict[tuple[str, int, str], list[_GeoNetwork]] = {}


def _network_cache(
    cc: str, family: int, directory: Path
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    key = (cc, family, str(directory))
    cached = _NET_CACHE.get(key)
    if cached is not None:
        return cached
    c4, c6 = country_cidrs(cc, directory)
    nets = []
    for cidr in (c4 if family == 4 else c6):
        try:
            nets.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    _NET_CACHE[key] = nets
    return nets
