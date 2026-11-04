# SPDX-License-Identifier: GPL-2.0-only
"""Read-only, structured CLI views. Unknown is never presented as empty/healthy."""
from __future__ import annotations

import datetime
import ipaddress
import json
import os
import re
import shutil
import socket
import sys
import time
from dataclasses import asdict
from typing import Any

from fwsec import config, containers, crowdsec, geo, migration, nft, state, transaction

SCHEMA = 1


def safe(value: Any) -> str:
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(value))


def duration(seconds: int) -> str:
    seconds = max(0, seconds)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return " ".join(f"{n}{unit}" for n, unit in (
        (days, "d"), (hours, "h"), (minutes, "m"), (seconds, "s")) if n) or "0s"


def timestamp(value: float) -> str:
    return datetime.datetime.fromtimestamp(value).astimezone().isoformat(timespec="seconds")


def decisions() -> tuple[list[dict[str, Any]] | None, str | None]:
    if not shutil.which("cscli"):
        return None, "CrowdSec is not installed (optional integration)."
    try:
        return [asdict(d) for d in crowdsec.list_decisions(strict=True)], None
    except RuntimeError as exc:
        return None, str(exc)


def health(ports: list[int]) -> dict[str, Any]:
    c = config.load_config()
    transaction.validate(c, ports)
    problems = []
    warnings = []
    if not config.CONF_FILE.exists():
        warnings.append(f"Configuration file missing: {config.CONF_FILE}; defaults are in use.")
    rows = transaction._objects()  # Permission/backend failures are errors, not NOT LOADED.
    loaded = any(o.get("table", {}).get("family") == "inet"
                 and o["table"].get("name") == "fwsec" for o in rows)
    chains = {o["chain"]["name"] for o in rows if "chain" in o
              and o["chain"].get("family") == "inet" and o["chain"].get("table") == "filter"}
    if not c.enabled:
        problems.append("Firewall disabled in configuration. Run: fwsec --enable")
    if not loaded or not set(transaction.CHAINS) <= chains:
        problems.append("Firewall policy is not fully loaded. Run: fwsec --apply-safe")
    ownership = False
    if loaded:
        owned_filter = [o["chain"] for o in rows if "chain" in o
                        and o["chain"].get("family") == "inet"
                        and o["chain"].get("table") == "filter"
                        and o["chain"].get("name") in transaction.CHAINS]
        owned_fwsec = [o["chain"] for o in rows if "chain" in o
                       and o["chain"].get("family") == "inet"
                       and o["chain"].get("table") == "fwsec"
                       and o["chain"].get("name") == "whitelist"]
        ownership = (len(owned_filter) == 3 and bool(owned_fwsec)
                     and all(transaction.owns_chain("filter", ch, rows) for ch in owned_filter)
                     and transaction.owns_chain("fwsec", owned_fwsec[0], rows))
        if not ownership:
            problems.append("Ownership is unverified; inspect the rules before adoption or reload.")
    pending = [{"id": p.parent.name, "remaining_seconds": max(
        0, int(float(p.read_text()) - time.monotonic()))} for p in transaction.pending()]
    if pending:
        problems.append("A provisional transaction awaits confirmation or rollback.")
    verified = transaction.applied_status(rows, ports)
    if verified != "verified":
        warnings.append("Static rules/configuration: " + verified +
                        ". Review fwsec --dry-run before using --apply-safe.")
    if verified == "changed":
        problems.append("Configuration or static kernel rules changed since the last apply.")
    bans, error = decisions() if c.crowdsec_enabled else (None, None)
    cs_status = "disabled" if not c.crowdsec_enabled else (
        "unavailable" if error else "operational")
    if error:
        warnings.append(error)
        if shutil.which("cscli"):
            problems.append("CrowdSec decisions API is unavailable; protection status unknown.")
    if cs_status == "operational":
        try:
            bouncers = crowdsec.list_bouncers(strict=True)
            recent = []
            for b in bouncers:
                if not b.valid or not b.last_pull:
                    continue
                try:
                    value = re.sub(r'(\.\d{6})\d+', r'\1', b.last_pull)
                    dt = datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
                    if dt.tzinfo is not None and 0 <= time.time() - dt.timestamp() <= 120:
                        recent.append(b)
                except ValueError:
                    continue
            if not recent:
                cs_status = "degraded"
                problems.append("No valid bouncer pulled decisions in the last 120s. "
                                "Check crowdsec-firewall-bouncer service and LAPI credentials.")
        except RuntimeError as exc:
            cs_status = "unknown"
            warnings.append(str(exc))
    return {"enabled": c.enabled, "policy_loaded": loaded,
            "ownership_verified": ownership,
            "static_rules": verified, "pending": pending, "crowdsec": cs_status,
            "crowdsec_bans": len(bans) if bans is not None else None,
            "ssh_ports": ports, "output_policy": "inherited" if c.inherited_policy else
            c.output_policy, "container_mode": c.container_mode,
            "allow_entries": len(config.read_allow()), "deny_entries": len(config.read_deny()),
            "problems": problems, "warnings": warnings,
            "verification_scope": "Configuration and static rules; not end-to-end reachability."}


def listing(args: Any, ports: list[int]) -> dict[str, Any]:
    c = config.load_config()
    # Check access first: nft helpers otherwise flatten access failures into empty lists.
    transaction._objects()
    summary = nft.get_summary()
    bans, error = decisions() if c.crowdsec_enabled else (None, None)
    sections = {"allow": summary.allow4 + summary.allow6,
                "deny": summary.deny4 + summary.deny6,
                "crowdsec": bans}
    selected = getattr(args, "section", "all")
    limit = None if getattr(args, "all", False) else getattr(args, "limit", 10)
    result: dict[str, Any] = {"policy_loaded": nft.table_exists(),
        "configured_ports": {"tcp_in": c.tcp_in, "tcp_out": c.tcp_out,
                             "udp_in": c.udp_in, "udp_out": c.udp_out},
        "ssh_ports": ports, "output_policy": "inherited" if c.inherited_policy else c.output_policy,
        "policy_source": "inherited" if c.inherited_policy else "configuration",
        "note": "Ports above are configuration, not an effective reachability test.",
        "sections": {}, "warnings": [error] if error else []}
    result["icmp_in"] = c.icmp_in
    result["ipv6"] = c.ipv6
    result["containers"] = {"mode": c.container_mode, "policy": c.container_policy,
                             "published": [asdict(p) for p in containers.published_ports()]}
    result["geo"] = {"mode": config.geo_mode(c), "countries": c.geo_block or c.geo_allow}
    if not result["policy_loaded"]:
        result["warnings"].append("Kernel policy is not loaded; local active lists are unknown.")
        sections["allow"] = None
        sections["deny"] = None
    for key, values in sections.items():
        if selected != "all" and selected != key:
            continue
        result["sections"][key] = {"total": len(values) if values is not None else None,
                                   "items": values[:limit] if values is not None else None}
    return result


def search(target: str) -> dict[str, Any]:
    c = config.load_config()
    kernel_rows = transaction._objects()
    try:
        network = ipaddress.ip_network(target, strict=False)
        ips = [str(network) if "/" in target else
               str(ipaddress.ip_address(target))]
    except ValueError:
        try:
            ips = sorted({str(row[4][0]) for row in socket.getaddrinfo(target, None)})
        except socket.gaierror as exc:
            raise ValueError(f"Cannot resolve '{target}'. "
                             "Enter a valid IP, CIDR or hostname.") from exc
    bans, error = decisions() if c.crowdsec_enabled else (None, None)
    rows = []
    for ip in ips:
        query_net = ipaddress.ip_network(ip, strict=False)
        matches: list[dict[str, Any]] = []
        for label, entries in (("allow file", config.read_allow()),
                               ("deny file", config.read_deny()),
                               ("ignore file", config.read_ignore())):
            for entry in entries:
                entry_net = ipaddress.ip_network(entry.ip, strict=False)
                if query_net.version == entry_net.version and query_net.overlaps(entry_net):
                    matches.append({"source": label, "entry": entry.ip, "comment": entry.comment})
        for label, fn in (("kernel allow", nft.is_allowed), ("kernel deny", nft.is_denied)):
            if fn(ip):
                matches.append({"source": label, "entry": ip})
        for ban in bans or []:
            try:
                ban_net = ipaddress.ip_network(ban["ip"], strict=False)
                contained = query_net.version == ban_net.version and query_net.overlaps(ban_net)
            except ValueError:
                contained = False
            if contained:
                matches.append({"source": "CrowdSec", **ban})
        for block in state.list_temp_blocks():
            block_net = ipaddress.ip_network(block.ip, strict=False)
            if query_net.version == block_net.version and query_net.overlaps(block_net):
                matches.append({"source": "temporary", **asdict(block),
                                "expires": timestamp(block.expires_at)})
        mode = config.geo_mode(c)
        if mode != "off":
            member = nft.element_exists(f"geo{query_net.version}", ip)
            matches.append({"source": "geo", "mode": mode, "member": member,
                            "note": "Geo membership only; other rules may override it."})
        matches.extend({"source": "container", "entry": m} for m in containers.find_ip(ip))
        rows.append({"ip": ip, "matches": matches, "found": bool(matches)})
    warnings = [error] if error else []
    if not any(o.get("table", {}).get("family") == "inet"
               and o["table"].get("name") == "fwsec" for o in kernel_rows):
        warnings.append("Kernel policy is not loaded; only persistent entries were checked.")
    return {"target": target, "results": rows, "warnings": warnings,
            "note": "List membership is not a guarantee of acceptance or rejection."}


def render(command: str, data: dict[str, Any], args: Any) -> None:
    if getattr(args, "json", False):
        print(json.dumps({"schema": SCHEMA, "command": command,
                          "ok": not data.get("problems") and not data.get("warnings"),
                          "data": data}, ensure_ascii=True))
        return
    from fwsec import cli
    cli._header("fwsec — " + command)
    if command in ("status", "check"):
        for key in ("enabled", "policy_loaded", "ownership_verified", "static_rules",
                    "crowdsec", "crowdsec_bans",
                    "output_policy", "ssh_ports", "allow_entries", "deny_entries"):
            print(f"  {key.replace('_', ' ').capitalize():<20}: {data[key]}")
        for p in data["pending"]:
            cli._warn(f"Pending {p['id']}: {p['remaining_seconds']}s remaining. "
                      f"Confirm: fwsec --confirm {p['id']} | cancel: fwsec --rollback {p['id']}")
        cli._info(data["verification_scope"])
        for problem in data["problems"]:
            cli._err(problem)
        if not data["problems"]:
            cli._ok("Checks completed; review any warnings below.")
    elif command == "list":
        print("  Configured ports (not a live reachability test):")
        for key, values in data["configured_ports"].items():
            print(f"    {key}: {', '.join(values) or '(none)'}")
        print(f"  SSH: {data['ssh_ports']}; policy source: {data['policy_source']}")
        print(f"  ICMP in: {data['icmp_in']}; IPv6: {data['ipv6']}; Geo: {data['geo']}")
        print(f"  Container forwarding: {data['containers']['mode']} "
              f"({data['containers']['policy']})")
        for port in data["containers"]["published"]:
            print(f"    {safe(port['host_ip'])}:{port['host_port']}/{port['proto']} → "
                  f"{safe(port['container'])}:{port['container_port']}")
        print(f"  OUTPUT policy: {data['output_policy']}" + (
            " — new outbound connections are not restricted by TCP_OUT/UDP_OUT"
            if data["output_policy"] == "accept" else ""))
        for name, section in data["sections"].items():
            print(f"\n  {name.upper()}: " + (
                str(section["total"]) if section["total"] is not None else "UNKNOWN"))
            for row in section["items"] or []:
                print("    " + safe(f"{row['ip']} [{row['duration']}] {row['reason']}"
                                   if isinstance(row, dict) else row))
            if section["total"] is not None and len(section["items"]) < section["total"]:
                cli._info(f"Showing {len(section['items'])}/{section['total']}. "
                          f"Use: fwsec --list --section {name} --all")
    elif command == "search":
        for result in data["results"]:
            print(f"\n  IP: {result['ip']}")
            for match in result["matches"]:
                details = "; ".join(f"{key}: {safe(value)}" for key, value in match.items()
                                    if key != "source")
                print(f"    {safe(match['source'])}: {details}")
            if not result["found"]:
                cli._info("No matching entry" + (
                    "; some sources are unknown (see warnings)." if data["warnings"] else "."))
        cli._info(data["note"])
    elif command == "temp-list":
        if not data["items"]:
            print("  No active temporary blocks.")
        for row in data["items"]:
            print(f"  {row['ip']}\n    Expires: {row['expires']} | remaining: "
                  f"{duration(row['remaining_seconds'])} | {safe(row['comment'])}")
    elif command == "migration-report" and data.get("available"):
        print(migration.report_text(data["report"]))
    else:
        for key, value in data.items():
            if key != "warnings":
                print(f"  {key}: {value}")
    for warning in data.get("warnings", []):
        cli._warn(warning)


def query(command: str, args: Any, ports: list[int]) -> None:
    data: dict[str, Any]
    if command in ("status", "check"):
        data = health(ports)
    elif command == "list":
        data = listing(args, ports)
    elif command == "search":
        data = search(args.target)
    elif command == "temp-list":
        now = time.time()
        data = {"items": [{**asdict(b), "expires": timestamp(b.expires_at),
                           "remaining_seconds": max(0, int(b.expires_at - now))}
                          for b in sorted(state.list_temp_blocks(), key=lambda x: x.expires_at)]}
    elif command == "geo-status":
        c = config.load_config()
        mode = config.geo_mode(c)
        data = {"mode": mode, "countries": c.geo_block or c.geo_allow,
                "warnings": []}
        if mode == "off":
            data["next_step"] = f"Set GEO_BLOCK or GEO_ALLOW in {config.CONF_FILE}."
        else:
            transaction._objects()
            data["zone_counts"] = geo.zone_counts(data["countries"])
            data["loaded_ipv4"] = len(nft.list_elements("geo4"))
            data["loaded_ipv6"] = len(nft.list_elements("geo6"))
            ts = geo.zones_last_updated()
            data["updated"] = timestamp(ts) if ts else None
            if not ts or time.time() - ts > 30 * 86400:
                data["warnings"].append("Missing/stale zones. Run: fwsec --geo-update")
    elif command == "migration-report":
        c = config.load_config()
        path = c.inherited_policy or args.migration_output
        if c.inherited_policy and not path.exists():
            raise ValueError("Configured inherited policy is missing: " + str(path))
        data = {"available": path.exists(), "path": str(path)}
        if path.exists():
            data["report"] = json.loads(path.read_text())
            try:
                migration.report_text(data["report"])
            except (KeyError, TypeError) as exc:
                raise ValueError("Invalid migration report. "
                                 "Capture a new --migration-plan.") from exc
        else:
            data["next_step"] = ("No migration configured. To capture a plan without retiring "
                                 "rules, run: fwsec --migration-plan ufw (or csf/firewalld)")
    elif command == "version":
        from fwsec import __version__
        data = {"fwsec": __version__}
        if getattr(args, "verbose", False):
            data["nftables"] = nft._run("--version")[1].strip()
            data["crowdsec"] = crowdsec.version() if shutil.which("cscli") else None
        if not getattr(args, "json", False) and not getattr(args, "verbose", False):
            print("fwsec " + __version__)
            return
    else:
        raise ValueError("Unknown query: " + command)
    render(command, data, args)
    if data.get("problems"):
        raise SystemExit(3)
    if data.get("warnings"):
        raise SystemExit(4)


def configure_output(args: Any) -> None:
    from fwsec import cli
    use_color = (getattr(args, "color", "auto") == "always" or
                 (getattr(args, "color", "auto") == "auto" and sys.stdout.isatty()
                  and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"))
    palette = {"RED": "\033[91m", "GREEN": "\033[92m", "YELLOW": "\033[93m",
               "CYAN": "\033[96m", "BOLD": "\033[1m", "RESET": "\033[0m"}
    for name, value in palette.items():
        setattr(cli, name, value if use_color and not getattr(args, "json", False) else "")
