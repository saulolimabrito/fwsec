# SPDX-License-Identifier: GPL-2.0-only

"""
Persistent JSON state — tracks metadata for IPs managed by fwsec.

Stores:
  - Comments for allow/deny entries
  - Temporary block expiry times (nftables handles the actual expiry,
    but we track metadata here for `fwsec -t` display)
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from typing import Any

from fwsec.config import STATE_FILE


@dataclass
class TempEntry:
    ip: str
    comment: str
    expires_at: float  # unix timestamp
    duration_sec: int


@dataclass
class AllowEntry:
    ip: str
    comment: str
    added_at: float


@dataclass
class DenyEntry:
    ip: str
    comment: str
    added_at: float


@dataclass
class State:
    temp_blocks: dict[str, TempEntry]    # ip -> TempEntry
    allow_meta: dict[str, AllowEntry]    # ip -> AllowEntry
    deny_meta: dict[str, DenyEntry]      # ip -> DenyEntry


def _load_raw() -> dict[str, Any]:
    if not STATE_FILE.exists():
        return {"temp_blocks": {}, "allow_meta": {}, "deny_meta": {}}
    try:
        data: dict[str, Any] = json.loads(STATE_FILE.read_text())
        return data
    except (json.JSONDecodeError, OSError):
        return {"temp_blocks": {}, "allow_meta": {}, "deny_meta": {}}


def _save_raw(data: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(data, indent=2))


def load() -> State:
    raw = _load_raw()
    temp = {
        ip: TempEntry(**v)
        for ip, v in raw.get("temp_blocks", {}).items()
    }
    allow_meta = {
        ip: AllowEntry(**v)
        for ip, v in raw.get("allow_meta", {}).items()
    }
    deny_meta = {
        ip: DenyEntry(**v)
        for ip, v in raw.get("deny_meta", {}).items()
    }
    return State(temp_blocks=temp, allow_meta=allow_meta, deny_meta=deny_meta)


def save(state: State) -> None:
    _save_raw({
        "temp_blocks": {ip: asdict(e) for ip, e in state.temp_blocks.items()},
        "allow_meta": {ip: asdict(e) for ip, e in state.allow_meta.items()},
        "deny_meta": {ip: asdict(e) for ip, e in state.deny_meta.items()},
    })


# ---------------------------------------------------------------------------
# Convenience mutators
# ---------------------------------------------------------------------------

def add_temp_block(ip: str, duration_sec: int, comment: str = "") -> None:
    state = load()
    state.temp_blocks[ip] = TempEntry(
        ip=ip,
        comment=comment,
        expires_at=time.time() + duration_sec,
        duration_sec=duration_sec,
    )
    save(state)


def remove_temp_block(ip: str) -> bool:
    state = load()
    if ip not in state.temp_blocks:
        return False
    del state.temp_blocks[ip]
    save(state)
    return True


def list_temp_blocks() -> list[TempEntry]:
    state = load()
    now = time.time()
    # Queries must not race a CLI writer by saving a pruned read/modify/write
    # snapshot outside its transaction lock. Expiry is enforced by the kernel;
    # retain metadata so an expired temp entry in the historical deny file is
    # not accidentally restored as a permanent ban on the next reload.
    active = {ip: e for ip, e in state.temp_blocks.items() if e.expires_at > now}
    return list(active.values())


def add_allow_meta(ip: str, comment: str = "") -> None:
    state = load()
    state.allow_meta[ip] = AllowEntry(ip=ip, comment=comment, added_at=time.time())
    save(state)


def remove_allow_meta(ip: str) -> None:
    state = load()
    state.allow_meta.pop(ip, None)
    save(state)


def add_deny_meta(ip: str, comment: str = "") -> None:
    state = load()
    state.deny_meta[ip] = DenyEntry(ip=ip, comment=comment, added_at=time.time())
    save(state)


def remove_deny_meta(ip: str) -> None:
    state = load()
    state.deny_meta.pop(ip, None)
    save(state)


def get_comment(ip: str) -> str:
    state = load()
    if ip in state.allow_meta:
        return state.allow_meta[ip].comment
    if ip in state.deny_meta:
        return state.deny_meta[ip].comment
    if ip in state.temp_blocks:
        return state.temp_blocks[ip].comment
    return ""


def purge_expired() -> int:
    state = load()
    now = time.time()
    before = len(state.temp_blocks)
    state.temp_blocks = {ip: e for ip, e in state.temp_blocks.items() if e.expires_at > now}
    removed = before - len(state.temp_blocks)
    if removed:
        save(state)
    return removed
