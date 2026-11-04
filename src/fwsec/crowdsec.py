# SPDX-License-Identifier: GPL-2.0-only

"""
CrowdSec abstraction — wraps cscli for decisions, bouncers and hub status.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


def _cscli(*args: str) -> tuple[int, str, str]:
    # Timeout guards against a hung LAPI (e.g. crowdsec down): fwsec commands
    # must degrade gracefully instead of blocking forever.
    try:
        r = subprocess.run(
            ["cscli", *args], capture_output=True, text=True, timeout=15
        )
    except (OSError, subprocess.SubprocessError):
        return 1, "", "cscli unavailable or timed out"
    return r.returncode, r.stdout, r.stderr


def available() -> bool:
    rc, _, _ = _cscli("version")
    return rc == 0


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------

@dataclass
class Decision:
    id: int
    ip: str
    reason: str
    duration: str
    origin: str
    type: str
    scope: str


def list_decisions(ip: str | None = None, strict: bool = False) -> list[Decision]:
    args = ["decisions", "list", "-o", "json"]
    if ip:
        args += ["--ip", ip]
    rc, out, err = _cscli(*args)
    if strict and rc != 0:
        raise RuntimeError("CrowdSec decisions unavailable: " + (err.strip() or "cscli failed"))
    if strict and not out.strip():
        raise RuntimeError("CrowdSec returned an empty response; decisions are unknown")
    if rc != 0 or not out.strip() or out.strip() == "null":
        return []
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        if strict:
            raise RuntimeError("CrowdSec returned invalid decisions JSON") from None
        return []
    if not raw:
        return []
    if not isinstance(raw, list) or any(not isinstance(item, dict) for item in raw):
        if strict:
            raise RuntimeError("CrowdSec returned an unsupported decisions format")
        return []
    result = []
    for item in raw:
        # `cscli decisions list -o json` returns a list of ALERTS, each with a
        # nested `decisions` array; flatten it. Keep supporting plain decision
        # objects in case a future cscli returns them directly.
        nested = item.get("decisions")
        for d in nested if nested is not None else [item]:
            result.append(Decision(
                id=d.get("id", 0),
                ip=d.get("value", ""),
                reason=d.get("scenario") or item.get("scenario") or d.get("reason", ""),
                duration=d.get("duration", ""),
                origin=d.get("origin", ""),
                type=d.get("type", "ban"),
                scope=d.get("scope", "Ip"),
            ))
    return result


def add_decision(
    ip: str,
    reason: str = "manual ban",
    duration: str | None = None,
) -> bool:
    """Add a ban decision. duration=None means permanent (100y)."""
    args = ["decisions", "add", "--ip", ip, "--reason", reason, "--type", "ban"]
    args += ["--duration", duration if duration else "87600h"]
    rc, _, err = _cscli(*args)
    return rc == 0


def delete_decision(ip: str) -> bool:
    rc, _, _ = _cscli("decisions", "delete", "--ip", ip)
    return rc == 0


def decision_exists(ip: str) -> bool:
    return len(list_decisions(ip=ip)) > 0


# ---------------------------------------------------------------------------
# Bouncers
# ---------------------------------------------------------------------------

@dataclass
class Bouncer:
    name: str
    ip_address: str
    valid: bool
    last_pull: str
    type: str
    version: str


def list_bouncers(strict: bool = False) -> list[Bouncer]:
    rc, out, err = _cscli("bouncers", "list", "-o", "json")
    if strict and (rc != 0 or not out.strip()):
        raise RuntimeError("CrowdSec bouncer status unavailable: "
                           + (err.strip() or "empty response"))
    if rc != 0 or not out.strip() or out.strip() == "null":
        return []
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        if strict:
            raise RuntimeError("CrowdSec returned invalid bouncers JSON") from None
        return []
    result = []
    for b in raw or []:
        result.append(Bouncer(
            name=b.get("name", ""),
            ip_address=b.get("ip_address", ""),
            valid=b.get("revoked", False) is False,
            last_pull=b.get("last_pull", ""),
            type=b.get("type", ""),
            version=b.get("version", ""),
        ))
    return result


# ---------------------------------------------------------------------------
# Alerts / metrics summary
# ---------------------------------------------------------------------------

@dataclass
class AlertSummary:
    total: int
    last_event: str


def get_alert_summary() -> AlertSummary:
    rc, out, _ = _cscli("alerts", "list", "-o", "json")
    if rc != 0 or not out.strip() or out.strip() == "null":
        return AlertSummary(0, "")
    try:
        raw = json.loads(out)
    except json.JSONDecodeError:
        return AlertSummary(0, "")
    alerts = raw or []
    last = alerts[0].get("created_at", "") if alerts else ""
    return AlertSummary(total=len(alerts), last_event=last)


# ---------------------------------------------------------------------------
# Hub / collections status
# ---------------------------------------------------------------------------

def hub_status() -> str:
    _, out, _ = _cscli("hub", "list")
    return out


def version() -> str:
    _, out, _ = _cscli("version")
    return out.strip()


# ---------------------------------------------------------------------------
# Search across CrowdSec decisions for a given IP
# ---------------------------------------------------------------------------

def grep_ip(ip: str) -> list[Decision]:
    return list_decisions(ip=ip)
