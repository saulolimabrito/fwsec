# SPDX-License-Identifier: GPL-2.0-only
"""Prove legacy policy equivalence before automatic ownership adoption.

Compile the candidate into unique UNHOOKED scratch tables, letting nftables
canonicalize expressions and interval sets. Compare the resulting kernel JSON
with the live objects. No regex-based guess about a firewall's owner is used.
Scratch tables have no hooks and are removed even on a mismatch. Unknown rules,
objects or altered defaults refuse adoption before package activation.
"""
from __future__ import annotations

import json
import re
import uuid
from typing import Any

from fwsec import config, nft, transaction


def normalize(value: Any, key: str = "") -> Any:
    if isinstance(value, list):
        values = [normalize(v) for v in value if not (
            key == "expr" and isinstance(v, dict) and "counter" in v
            and isinstance(v["counter"], dict)
            and set(v["counter"]) <= {"packets", "bytes"}
        )]
        if key in ("set", "elem", "flags"):
            def identity(v: Any) -> str:
                if key == "elem" and isinstance(v, dict):
                    metadata = v.get("elem", v)
                    if isinstance(metadata, dict) and "val" in metadata:
                        return json.dumps(metadata["val"], sort_keys=True)
                return json.dumps(v, sort_keys=True)
            values.sort(key=identity)
        return values
    if isinstance(value, dict):
        result = {}
        for name, item in value.items():
            if name in ("handle", "family", "table"):
                continue
            if name == "comment" and item == transaction.MARKER:
                continue
            # A timed element's *remaining* life is relevant, not the full
            # duration originally used to create it. Permanent vs timed stays
            # distinct; expires is compared with a small serialization tolerance.
            if name == "timeout" and "val" in value and "expires" in value:
                continue
            result[name] = normalize(item, name)
        if set(result) == {"set"} and len(result["set"]) == 1:
            return result["set"][0]
        return result
    return value


def equivalent(left: Any, right: Any, key: str = "") -> bool:
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(
            equivalent(left[k], right[k], k) for k in left)
    if isinstance(left, list) and isinstance(right, list):
        return len(left) == len(right) and all(equivalent(a, b) for a, b in zip(left, right))
    if key == "expires" and isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return abs(left - right) <= 3
    return bool(left == right)


def hooks(c: config.FwsecConfig, filtered: bool) -> dict[str, dict[str, dict[str, Any]]]:
    def spec(hook: str, priority: int, policy: str = "accept") -> dict[str, Any]:
        return {"type": "filter", "hook": hook, "prio": priority, "policy": policy}

    result = {
        "filter": {
            "input": spec("input", 0, "drop"),
            "forward": spec("forward", 0, "accept" if c.container_mode else "drop"),
            "output": spec("output", 0, c.output_policy),
        },
        "fwsec": {
            "whitelist": spec("input", -100), "blacklist": spec("input", -50),
            "whitelist_forward": spec("forward", -100),
            "blacklist_forward": spec("forward", -50),
        },
    }
    mode = config.geo_mode(c)
    if mode != "off":
        policy = "drop" if mode == "allow" else "accept"
        result["fwsec"]["geo_blacklist"] = spec("input", -40, policy)
        if c.geo_forward:
            result["fwsec"]["geo_blacklist_forward"] = spec("forward", -40, policy)
    if filtered:
        result["fwsec"]["containers"] = spec("forward", -60)
    return result


def objects(rows: list[dict[str, Any]], table: str, name: str,
            specs: dict[str, dict[str, Any]], probe: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"chains": {}, "sets": {}, "other": []}
    for row in rows:
        for kind, item in row.items():
            if not isinstance(item, dict) or item.get("family") != "inet":
                continue
            if kind == "table":
                if item.get("name") == table and name == "fwsec":
                    result["table"] = normalize({**item, "name": "fwsec"})
                elif item.get("name") == table and item.get("flags"):
                    result["table_flags"] = normalize(item["flags"], "flags")
                continue
            if item.get("table") != table:
                continue
            chain = item.get("name") if kind == "chain" else item.get("chain")
            if name == "filter" and (kind not in ("chain", "rule") or chain not in specs):
                continue  # other chains and bouncer sets remain untouched
            if kind == "chain":
                if not isinstance(chain, str):
                    raise RuntimeError("Invalid nft chain name during upgrade comparison")
                value = normalize(item)
                if probe:
                    value.update(specs.get(chain, {}))
                result["chains"][chain] = {"attributes": value, "rules": []}
            elif kind == "rule":
                if chain not in result["chains"]:
                    raise RuntimeError("Unexpected nft JSON ordering while checking legacy policy")
                result["chains"][chain]["rules"].append(normalize(item))
            elif kind == "set":
                result["sets"][item["name"]] = normalize(item)
            else:
                result["other"].append(normalize({kind: item}))
    return result


def prove(c: config.FwsecConfig, candidate: str, filtered: bool = False) -> None:
    if c.inherited_policy:
        raise RuntimeError("Unmarked inherited policies require explicit operator review")
    names = {"filter": "fwsec_upgrade_filter_" + uuid.uuid4().hex,
             "fwsec": "fwsec_upgrade_lists_" + uuid.uuid4().hex}
    probe = candidate
    for original, scratch in names.items():
        probe = re.sub(rf"\binet {original}\b", "inet " + scratch, probe)
    # Every generated hook declaration is a complete line. Refuse anything
    # left over rather than risk ever hooking a scratch chain into traffic.
    probe = re.sub(r"(?m)^\s*type filter hook (?:input|forward|output) "
                   r"priority [^;]+; policy [^;]+;\s*$", "", probe)
    if re.search(r"\btype\s+\w+\s+hook\b", probe):
        raise RuntimeError("Cannot safely create an unhooked upgrade comparison")
    probe = "".join(f"create table inet {n}\n" for n in names.values()) + probe
    transaction.check(probe)
    created = False
    try:
        nft._run_script(probe)
        created = True
        rows = transaction._objects()
        specs = hooks(c, filtered)
        for original, scratch in names.items():
            if any(row.get("chain", {}).get("table") == scratch
                   and "hook" in row["chain"] for row in rows):
                raise RuntimeError("Upgrade scratch table unexpectedly has a hook")
            live = objects(rows, original, original, specs[original])
            expected = objects(rows, scratch, original, specs[original], probe=True)
            if not equivalent(live, expected):
                raise RuntimeError(
                    f"Legacy inet {original} differs from the configured candidate. "
                    "Upgrade refused before activation; existing code/rules are retained. "
                    "Review custom rules/configuration instead of automatically adopting them."
                )
    finally:
        if created:
            nft._run_script("".join(f"delete table inet {n}\n" for n in names.values()))
