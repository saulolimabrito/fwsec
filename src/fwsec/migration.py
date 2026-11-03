# SPDX-License-Identifier: GPL-2.0-only
"""Strict live-policy migration. Unknown semantics block, never widen access.

Use iptables-save snapshots, not human-facing status tables or service-name
guesses. The intermediate policy preserves ordered rules and chain graphs,
IPv4/IPv6 separation, endpoints, interfaces and per-direction default policy.
Pure nftables firewalld policies are reported as unsupported, not flattened.
This module is also executable standalone by the bootstrap installer.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

BUILTINS = ("INPUT", "OUTPUT", "FORWARD")
CSF_CHAINS = {
    "ALLOWIN", "ALLOWOUT", "DENYIN", "DENYOUT", "LOCALINPUT", "LOCALOUTPUT",
    "LOGDROPIN", "LOGDROPOUT", "INVALID", "CC_DENY", "CC_ALLOW", "CC_ALLOWF",
    "SYNFLOOD", "PORTFLOOD", "CONNLIMIT", "UDPFLOOD", "SYNFLOOD_LOG",
}


def canonical(snapshot: str) -> str:
    return "\n".join(s.strip() for s in snapshot.splitlines()
                     if s.strip() and not s.startswith("#"))


def fingerprint(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def owned_chain(name: str, source: str) -> bool:
    if name in BUILTINS:
        return True
    if source == "csf":
        return name in CSF_CHAINS
    if source == "ufw":
        return name.startswith("ufw-")
    return bool(re.fullmatch(r"(?:IN|OUT|FWDI|FWDO|INPUT|OUTPUT|FORWARD|PRE|POST)_\w+", name))


def ports(value: str) -> str:
    result = []
    for token in value.split(","):
        if not re.fullmatch(r"\d+(?::\d+)?", token):
            raise ValueError(f"Unsupported port: {token}")
        pair = [int(n) for n in token.split(":")]
        if any(not 1 <= n <= 65535 for n in pair) or pair[0] > pair[-1]:
            raise ValueError(f"Invalid port: {token}")
        result.append(token.replace(":", "-"))
    return "{ " + ", ".join(result) + " }"


def parse_rule(line: str, family: int) -> dict[str, Any]:
    args = shlex.split(line)
    if args[:1] != ["-A"] or len(args) < 4:
        raise ValueError("Invalid iptables rule")
    rule: dict[str, Any] = {"chain": args[1], "family": family, "matches": [],
                            "action": "", "original": line}
    i = 2
    protocol = ""
    while i < len(args):
        key = args[i]
        if i + 1 >= len(args):
            raise ValueError(f"Unsupported/incomplete option {key}")
        value = args[i + 1]
        if key in ("-p", "--protocol"):
            if value not in ("tcp", "udp", "icmp", "ipv6-icmp", "icmpv6", "all"):
                raise ValueError(f"Unsupported protocol {value}")
            protocol = value
            if value != "all":
                rule["matches"].append(["protocol", value])
        elif key in ("-s", "--source", "-d", "--destination"):
            net = ipaddress.ip_network(value, strict=False)
            if net.version != family:
                raise ValueError("Wrong source/destination address family")
            rule["matches"].append(["source" if key in ("-s", "--source") else "dest", str(net)])
        elif key in ("-i", "--in-interface", "-o", "--out-interface"):
            # Wildcards / interface groups are not approximated.
            if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value):
                raise ValueError(f"Unsupported interface selector {value}")
            rule["matches"].append(["in" if key in ("-i", "--in-interface") else "out", value])
        elif key == "-m":
            if value not in ("tcp", "udp", "conntrack", "state", "multiport", "comment"):
                raise ValueError(f"Unsupported match module {value}")
        elif key in ("--dport", "--dports", "--sport", "--sports"):
            if protocol not in ("tcp", "udp"):
                raise ValueError("Port match requires explicit TCP/UDP protocol")
            ports(value)
            rule["matches"].append(["dport" if key in ("--dport", "--dports") else "sport",
                                    value])
        elif key in ("--ctstate", "--state"):
            states = value.lower().split(",")
            if not set(states) <= {"new", "established", "related", "invalid", "untracked"}:
                raise ValueError("Unsupported connection state")
            rule["matches"].append(["states", ",".join(states)])
        elif key == "--comment":
            rule["comment"] = value
        elif key in ("-j", "--jump"):
            if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
                raise ValueError("Invalid jump target")
            rule["action"] = value
        else:
            raise ValueError(f"Unsupported option {key} (no automatic approximation)")
        i += 2
    if not rule["action"]:
        raise ValueError("Rule has no terminal action/jump")
    # Reject has backend-specific defaults; reject-with, rate limits, log,
    # tcp flags, negation, ipsets, NAT and extension modules require review.
    if rule["action"] in ("REJECT", "LOG", "NFLOG", "QUEUE", "MARK"):
        raise ValueError(f"Unsupported target {rule['action']}")
    return rule


def parse_save(text: str, family: int, source: str) -> dict[str, Any]:
    result: dict[str, Any] = {"family": family, "chains": {}, "rules": [],
                              "unsupported": [], "review": []}
    table = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("*"):
            if table:
                result["unsupported"].append("Unterminated table in source snapshot")
            table = line[1:]
        elif line == "COMMIT":
            table = ""
        elif line.startswith(":") and table == "filter":
            fields = line[1:].split()
            if len(fields) < 2 or not re.fullmatch(r"[A-Za-z0-9_-]+", fields[0]):
                result["unsupported"].append(f"Invalid chain declaration: {line}")
                continue
            name, policy = fields[:2]
            if policy not in ("ACCEPT", "DROP", "-"):
                result["unsupported"].append(f"Unsupported chain policy: {line}")
            if (name in BUILTINS) != (policy in ("ACCEPT", "DROP")):
                result["unsupported"].append(f"Invalid base/user chain policy: {line}")
            if not owned_chain(name, source):
                result["unsupported"].append(f"Third-party/unowned chain preserved: {name}")
            result["chains"][name] = policy
        elif line.startswith("-A"):
            if table != "filter":
                result["unsupported"].append(f"{table}: {line}")
                continue
            try:
                rule = parse_rule(line, family)
                result["rules"].append(rule)
                if rule["chain"] in BUILTINS and rule["action"] in ("ACCEPT", "DROP", "RETURN"):
                    result["review"].append(
                        f"Ownership of direct {rule['chain']} rule must be approved: {line}"
                    )
            except ValueError as exc:
                result["unsupported"].append(f"{line}: {exc}")
        elif table == "filter" and not line.startswith(":"):
            result["unsupported"].append(f"Unrecognized filter statement: {line}")
    for rule in result["rules"]:
        target = rule["action"]
        if target in BUILTINS:
            result["unsupported"].append(f"Jump to a base chain is invalid: {target}")
        if target not in ("ACCEPT", "DROP", "RETURN") and target not in result["chains"]:
            result["unsupported"].append(f"Unknown jump target {target}")
        if rule["chain"] not in result["chains"]:
            result["unsupported"].append(f"Undeclared chain {rule['chain']}")
    if table:
        result["unsupported"].append("Missing COMMIT in source snapshot")
    if not set(BUILTINS) <= set(result["chains"]):
        result["unsupported"].append("Incomplete live filter snapshot (missing base chains)")
    # Cycles are rejected even if they originated in an invalid offline fixture.
    graph: dict[str, list[str]] = {name: [] for name in result["chains"]}
    for rule in result["rules"]:
        if rule["action"] in graph and rule["chain"] in graph:
            graph[rule["chain"]].append(rule["action"])

    def visit(name: str, stack: set[str]) -> None:
        if name in stack:
            raise ValueError("Cycle in inherited chain graph")
        for child in graph[name]:
            visit(child, stack | {name})

    try:
        for name in graph:
            visit(name, set())
    except ValueError as exc:
        result["unsupported"].append(str(exc))
    return result


def plan(source: str, ipv4: str, ipv6: str, nft_json: dict[str, Any] | None = None,
         approve: str = "") -> dict[str, Any]:
    if source not in ("csf", "ufw", "firewalld"):
        raise ValueError("Expected exactly one supported migration source")
    families = [parse_save(ipv4, 4, source), parse_save(ipv6, 6, source)]
    blocked = [f"IPv{f['family']}: {s}" for f in families for s in f["unsupported"]]
    review = [f"IPv{f['family']}: {s}" for f in families for s in f["review"]]
    for obj in (nft_json or {}).get("nftables", []):
        table = obj.get("table", {})
        if source == "firewalld" and table.get("name") == "firewalld":
            blocked.append("firewalld nft backend: native nft policy cannot be approximated "
                           "from port/service lists; original table will not be removed")
    native = {"nftables": [o for o in (nft_json or {}).get("nftables", []) if "table" in o]}
    identity = {"source": source, "ipv4": canonical(ipv4), "ipv6": canonical(ipv6),
                "native": native}
    digest = fingerprint(identity)
    return {"schema": 1, "source": source, "fingerprint": digest, "families": families,
            "snapshots": {"4": ipv4, "6": ipv6, "nft": native},
            "unsupported": blocked, "review": review,
            "status": "blocked" if blocked else (
                "ready" if not review or approve == digest else "requires-approval"),
            "approved": approve == digest,
            "summary": {"rules": sum(len(f["rules"]) for f in families),
                        "policies": {str(f["family"]): {k: v for k, v in f["chains"].items()
                                                        if k in BUILTINS} for f in families}}}


def verify(document: dict[str, Any]) -> None:
    if document.get("schema") != 1:
        raise ValueError("Unsupported migration schema")
    original = plan(document["source"], document["snapshots"]["4"],
                    document["snapshots"]["6"], nft_json=document["snapshots"].get("nft"),
                    approve=(document["fingerprint"]
                                                       if document.get("approved") else ""))
    # Derived rule objects are never trusted independently of their snapshots.
    if original["fingerprint"] != document["fingerprint"] or original["families"] != document[
        "families"
    ] or document.get("unsupported") or original["status"] != "ready":
        raise ValueError("Migration is blocked, unapproved or its policy was modified")


def load(path: Path) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(path.read_text())
    verify(document)
    return document


def chain_name(family: int, name: str) -> str:
    return f"fwsec_m{family}_" + name


def render_rule(rule: dict[str, Any], base_policy: str = "") -> str:
    prefix = "ip" if rule["family"] == 4 else "ip6"
    match = []
    protocol = ""
    for key, value in rule["matches"]:
        if key == "protocol":
            protocol = "ipv6-icmp" if value == "icmpv6" else value
            match.append(f"meta l4proto {protocol}")
        elif key in ("source", "dest"):
            match.append(f"{prefix} {'saddr' if key == 'source' else 'daddr'} {value}")
        elif key in ("in", "out"):
            match.append(f'{"iifname" if key == "in" else "oifname"} "{value}"')
        elif key in ("dport", "sport"):
            match.append(f"{protocol} {key} {ports(value)}")
        elif key == "states":
            match.append(f"ct state {{ {value} }}")
    target = rule["action"]
    if target == "RETURN" and rule["chain"] in BUILTINS:
        target = base_policy
    match.append(target.lower() if target in ("ACCEPT", "DROP", "RETURN") else
                 "jump " + chain_name(rule["family"], target))
    return " ".join(match)


def render(document: dict[str, Any]) -> str:
    verify(document)
    output = []
    for family in document["families"]:
        version = family["family"]
        for name, policy in family["chains"].items():
            output.append(f"chain {chain_name(version, name)} {{")
            output.extend("    " + render_rule(r, policy) for r in family["rules"]
                          if r["chain"] == name)
            if name in BUILTINS:
                output.append("    " + policy.lower())
            output.append("}")
    for direction in BUILTINS:
        hook = direction.lower()
        output.append(f"chain fwsec_inherited_{hook} {{")
        output.append(f"    type filter hook {hook} priority 0; policy accept;")
        for version, nfproto in ((4, "ipv4"), (6, "ipv6")):
            output.append(f"    meta nfproto {nfproto} jump {chain_name(version, direction)}")
        output.append("}")
    return "\n".join(output) + "\n"


def retirement(document: dict[str, Any], family: int, live: str) -> str:
    """A --noflush batch scoped to the explicitly approved, unchanged source."""
    verify(document)
    if canonical(live) != canonical(document["snapshots"][str(family)]):
        raise ValueError("Source rules changed since the plan: capture and review a new plan")
    policy = next(f for f in document["families"] if f["family"] == family)
    batch = ["*filter"]
    batch.extend(f":{name} ACCEPT [0:0]" for name in BUILTINS)
    batch.extend(r["original"].replace("-A ", "-D ", 1) for r in policy["rules"]
                 if r["chain"] in BUILTINS)
    custom = [n for n in policy["chains"] if n not in BUILTINS]
    batch.extend(f"-F {name}" for name in custom)
    batch.extend(f"-X {name}" for name in custom)
    return "\n".join(batch + ["COMMIT", ""])


def capture(source: str, output: Path, approve: str = "") -> dict[str, Any]:
    snapshots = []
    for binary in ("iptables-save", "ip6tables-save"):
        r = subprocess.run([binary], capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise ValueError(f"Cannot snapshot {binary}: {r.stderr.strip()}")
        snapshots.append(r.stdout)
    r = subprocess.run(["nft", "-j", "list", "ruleset"], capture_output=True,
                       text=True, timeout=30)
    if r.returncode:
        raise ValueError("Cannot audit native nftables policy; migration refused")
    report = plan(source, snapshots[0], snapshots[1],
                  nft_json=json.loads(r.stdout), approve=approve)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    output.chmod(0o600)
    return report


def active_digest(document: dict[str, Any]) -> str:
    chains = []
    for family in document["families"]:
        for name in family["chains"]:
            r = subprocess.run(["nft", "-s", "list", "chain", "inet", "fwsec",
                                chain_name(family["family"], name)],
                               capture_output=True, text=True, timeout=30)
            if r.returncode:
                raise ValueError("Inherited policy is not active in nftables")
            chains.append(r.stdout)
    return fingerprint(chains)


def finalize(document: dict[str, Any], receipt: dict[str, Any],
             manage_services: bool = True) -> None:
    """Retire exact reviewed legacy objects only AFTER safe-apply confirmation.

    Do not execute CSF uninstallers, ufw disable or firewalld stop scripts:
    those may globally flush a mixed host ruleset. Keep configs/packages for
    recovery. Disable boot/autoupdate jobs only after successful retirement.
    """
    verify(document)
    if receipt.get("digest") != fingerprint(document) or receipt.get("kernel_digest") != (
        active_digest(document)
    ):
        raise ValueError("The exact inherited policy must be confirmed and still active")
    batches = []
    for family, save, restore in ((4, "iptables-save", "iptables-restore"),
                                  (6, "ip6tables-save", "ip6tables-restore")):
        r = subprocess.run([save], capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise ValueError(f"Cannot recheck {save}")
        batch = retirement(document, family, r.stdout)
        r = subprocess.run([restore, "--test", "--noflush"], input=batch,
                           capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise ValueError(f"Scoped retirement check failed: {r.stderr}")
        batches.append((restore, batch))
    if manage_services:
        retire_startup(document["source"], Path(receipt["path"]).parent / "retired-startup")
    for binary, batch in batches:
        r = subprocess.run([binary, "--noflush"], input=batch,
                           capture_output=True, text=True, timeout=30)
        if r.returncode:
            raise ValueError("Retirement incomplete; inherited nft policy remains active: "
                             + r.stderr)


def retire_startup(source: str, backup: Path) -> None:
    """Disable source startup without running a firewall teardown script."""
    if source == "firewalld":
        state = subprocess.run(["firewall-cmd", "--state"], capture_output=True,
                               text=True, timeout=30)
        if state.returncode == 0:
            raise ValueError("Active firewalld daemon requires a reviewed backend-specific "
                             "handover; no legacy rule has been removed")
    if Path("/run/systemd/system").exists() and shutil.which("systemctl"):
        services = ("csf", "lfd") if source == "csf" else (source,)
        if source == "csf":
            active = subprocess.run(["systemctl", "is-active", "--quiet", "lfd"],
                                    capture_output=True, timeout=30)
            if active.returncode == 0:
                subprocess.run(["systemctl", "stop", "lfd"], check=True, timeout=30)
        subprocess.run(["systemctl", "disable", *services], check=True, timeout=30)
        subprocess.run(["systemctl", "enable", "fwsec", "nftables"], check=True, timeout=30)
    elif shutil.which("rc-update"):
        services = ("csf", "lfd") if source == "csf" else (source,)
        if source == "csf" and shutil.which("rc-service"):
            subprocess.run(["rc-service", "lfd", "stop"], check=True, timeout=30)
        for service in services:
            subprocess.run(["rc-update", "del", service, "default"], check=True, timeout=30)
        subprocess.run(["rc-update", "add", "fwsec", "default"], check=True, timeout=30)
        subprocess.run(["rc-update", "add", "nftables", "boot"], check=True, timeout=30)
    else:
        raise ValueError("No supported init system: review source startup before retirement")
    if source == "csf":
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        for name in ("csf-cron", "lfd-cron", "csf_update"):
            path = Path("/etc/cron.d") / name
            if path.exists():
                path.rename(backup / name)


def report_text(document: dict[str, Any]) -> str:
    lines = [f"Source: {document['source']}", f"Status: {document['status']}",
             f"Fingerprint: {document['fingerprint']}",
             f"Translated rules: {document['summary']['rules']}"]
    for family in document["families"]:
        lines.append(f"IPv{family['family']} policies: " + ", ".join(
            f"{name}={family['chains'].get(name, 'MISSING')}" for name in BUILTINS))
        lines.extend(f"  translated: IPv{family['family']} {r['original']}"
                     for r in family["rules"])
    lines.extend("  requires approval: " + s for s in document["review"])
    lines.extend("  NOT translated (blocks migration): " + s for s in document["unsupported"])
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", choices=("csf", "ufw", "firewalld"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approve", default="")
    args = parser.parse_args()
    report = capture(args.source, args.output, args.approve)
    print(json.dumps({k: v for k, v in report.items() if k not in ("families", "snapshots")},
                     indent=2))
    return 0 if report["status"] == "ready" else 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
