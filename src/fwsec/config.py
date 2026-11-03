# SPDX-License-Identifier: GPL-2.0-only

"""
Config management: fwsec.conf, fwsec.allow, fwsec.deny, fwsec.ignore
"""
from __future__ import annotations

import configparser
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path

CONFIG_DIR = Path("/etc/fwsec")
CONF_FILE = CONFIG_DIR / "fwsec.conf"
ALLOW_FILE = CONFIG_DIR / "fwsec.allow"
DENY_FILE = CONFIG_DIR / "fwsec.deny"
IGNORE_FILE = CONFIG_DIR / "fwsec.ignore"
STATE_FILE = CONFIG_DIR / "fwsec.state.json"
MIGRATION_FILE = CONFIG_DIR / "inherited.json"
MIGRATION_RECEIPT = CONFIG_DIR / "migration-confirmed.json"
GEO_DIR = CONFIG_DIR / "geo"
GEO_INDEX_FILE = GEO_DIR / "index.tsv"

DEFAULTS: dict[str, dict[str, str]] = {
    "firewall": {
        "ENABLED": "1",
        "TCP_IN": "1157",
        "TCP_OUT": "80,443,53,25,587,993,995",
        "OUTPUT_POLICY": "accept",
        "UDP_IN": "53",
        "UDP_OUT": "53,123",
        "ICMP_IN": "1",
        "IPV6": "1",
        "WHITELIST_MARK": "0",
        "GEO_BLOCK": "",
        "GEO_ALLOW": "",
        "GEO_FORWARD": "0",
        "INHERITED_POLICY": "",
        "DENY_TEMP_IP_LIMIT": "100",
        "DENY_IP_LIMIT": "1000",
    },
    "containers": {
        "CONTAINER_MODE": "0",
        "CONTAINER_POLICY": "open",
    },
    "crowdsec": {
        "ENABLED": "1",
        "API_URL": "http://127.0.0.1:8080",
        "SYNC_DENY": "1",
    },
    "logging": {
        "LOG_FILE": "/var/log/fwsec.log",
        "LOG_LEVEL": "INFO",
    },
}


@dataclass
class FwsecConfig:
    enabled: bool = True
    tcp_in: list[str] = field(default_factory=list)
    tcp_out: list[str] = field(default_factory=list)
    output_policy: str = "accept"
    udp_in: list[str] = field(default_factory=list)
    udp_out: list[str] = field(default_factory=list)
    icmp_in: bool = True
    ipv6: bool = True
    whitelist_mark: bool = False
    geo_block: list[str] = field(default_factory=list)
    geo_allow: list[str] = field(default_factory=list)
    geo_forward: bool = False
    inherited_policy: Path | None = None
    deny_temp_limit: int = 100
    deny_limit: int = 1000
    container_mode: bool = False
    container_policy: str = "open"
    crowdsec_enabled: bool = True
    crowdsec_api: str = "http://127.0.0.1:8080"
    crowdsec_sync_deny: bool = True
    log_file: Path = Path("/var/log/fwsec.log")
    log_level: str = "INFO"


def load_config() -> FwsecConfig:
    parser = configparser.ConfigParser(interpolation=None)
    for section, values in DEFAULTS.items():
        parser[section] = values

    if CONF_FILE.exists():
        parser.read(CONF_FILE)

    fw = parser["firewall"]
    ct = parser["containers"]
    cs = parser["crowdsec"]
    lg = parser["logging"]

    return FwsecConfig(
        enabled=fw.getboolean("ENABLED", True),
        tcp_in=_parse_ports(fw.get("TCP_IN", "")),
        tcp_out=_parse_ports(fw.get("TCP_OUT", "")),
        output_policy=fw.get("OUTPUT_POLICY", "accept").strip().lower(),
        udp_in=_parse_ports(fw.get("UDP_IN", "")),
        udp_out=_parse_ports(fw.get("UDP_OUT", "")),
        icmp_in=fw.getboolean("ICMP_IN", True),
        ipv6=fw.getboolean("IPV6", True),
        whitelist_mark=fw.getboolean("WHITELIST_MARK", False),
        geo_block=parse_country_codes(fw.get("GEO_BLOCK", "")),
        geo_allow=parse_country_codes(fw.get("GEO_ALLOW", "")),
        geo_forward=fw.getboolean("GEO_FORWARD", False),
        inherited_policy=Path(fw["INHERITED_POLICY"]) if fw.get("INHERITED_POLICY") else None,
        deny_temp_limit=fw.getint("DENY_TEMP_IP_LIMIT", 100),
        deny_limit=fw.getint("DENY_IP_LIMIT", 1000),
        container_mode=ct.getboolean("CONTAINER_MODE", False),
        container_policy=ct.get("CONTAINER_POLICY", "open").strip().lower(),
        crowdsec_enabled=cs.getboolean("ENABLED", True),
        crowdsec_api=cs.get("API_URL", "http://127.0.0.1:8080"),
        crowdsec_sync_deny=cs.getboolean("SYNC_DENY", True),
        log_file=Path(lg.get("LOG_FILE", "/var/log/fwsec.log")),
        log_level=lg.get("LOG_LEVEL", "INFO"),
    )


def _parse_ports(value: str) -> list[str]:
    return [p.strip() for p in value.split(",") if p.strip()]


def parse_country_codes(value: str) -> list[str]:
    """Parse a comma-separated ISO-3166 alpha-2 country list ("br, us")."""
    codes = []
    for raw in value.split(","):
        cc = raw.strip().lower()
        if cc:
            codes.append(cc)
    return codes


def geo_mode(cfg: FwsecConfig) -> str:
    """Resolve the geo policy mode: 'off', 'deny' or 'allow'.

    GEO_BLOCK (deny-list countries) and GEO_ALLOW (deny everything except the
    listed countries) are mutually exclusive — raising here surfaces the
    misconfiguration on every command that loads the config.
    """
    if cfg.geo_block and cfg.geo_allow:
        raise ValueError(
            "GEO_BLOCK and GEO_ALLOW are mutually exclusive: use one or the other."
        )
    if cfg.geo_allow:
        return "allow"
    if cfg.geo_block:
        return "deny"
    return "off"


# ---------------------------------------------------------------------------
# IP list files (allow / deny / ignore)
# ---------------------------------------------------------------------------

_COMMENT_RE = re.compile(r"^#\s*(.*)$")
_ENTRY_RE = re.compile(r"^([^\s#]+)(?:\s+#\s*(.*))?$")


@dataclass
class IpEntry:
    ip: str
    comment: str = ""

    def is_valid(self) -> bool:
        try:
            ipaddress.ip_network(self.ip, strict=False)
            return True
        except ValueError:
            return False


def _read_ip_file(path: Path) -> list[IpEntry]:
    if not path.exists():
        return []
    entries = []
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = _ENTRY_RE.match(line)
        if m:
            entries.append(IpEntry(ip=m.group(1), comment=m.group(2) or ""))
    return entries


def _write_ip_file(path: Path, entries: list[IpEntry]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for e in entries:
        if e.comment:
            lines.append(f"{e.ip}  # {e.comment}")
        else:
            lines.append(e.ip)
    path.write_text("\n".join(lines) + ("\n" if lines else ""))


def read_allow() -> list[IpEntry]:
    return _read_ip_file(ALLOW_FILE)


def read_deny() -> list[IpEntry]:
    return _read_ip_file(DENY_FILE)


def read_ignore() -> list[IpEntry]:
    return _read_ip_file(IGNORE_FILE)


def add_allow(ip: str, comment: str = "") -> None:
    entries = read_allow()
    if any(e.ip == ip for e in entries):
        return
    entries.append(IpEntry(ip=ip, comment=comment))
    _write_ip_file(ALLOW_FILE, entries)


def remove_allow(ip: str) -> bool:
    entries = read_allow()
    new = [e for e in entries if e.ip != ip]
    if len(new) == len(entries):
        return False
    _write_ip_file(ALLOW_FILE, new)
    return True


def add_deny(ip: str, comment: str = "") -> None:
    entries = read_deny()
    if any(e.ip == ip for e in entries):
        return
    entries.append(IpEntry(ip=ip, comment=comment))
    _write_ip_file(DENY_FILE, entries)


def remove_deny(ip: str) -> bool:
    entries = read_deny()
    new = [e for e in entries if e.ip != ip]
    if len(new) == len(entries):
        return False
    _write_ip_file(DENY_FILE, new)
    return True


def is_ignored(ip: str) -> bool:
    return any(e.ip == ip for e in read_ignore())


def set_enabled(value: bool) -> None:
    """Toggle the ENABLED flag in the [firewall] section of fwsec.conf.

    Edits only that line: rewriting the file through configparser would
    lowercase every key and destroy the documented template's comments.
    """
    flag = "1" if value else "0"
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if not CONF_FILE.exists():
        CONF_FILE.write_text(f"[firewall]\nENABLED = {flag}\n")
        return

    lines = CONF_FILE.read_text().splitlines()
    in_firewall = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("["):
            in_firewall = stripped.lower() == "[firewall]"
        elif in_firewall and re.match(r"(?i)^ENABLED\s*=", stripped):
            lines[i] = f"ENABLED = {flag}"
            break
    else:
        # No ENABLED line found — add one (inside [firewall] if it exists)
        for i, line in enumerate(lines):
            if line.strip().lower() == "[firewall]":
                lines.insert(i + 1, f"ENABLED = {flag}")
                break
        else:
            lines = ["[firewall]", f"ENABLED = {flag}", ""] + lines

    CONF_FILE.write_text("\n".join(lines) + "\n")
