# SPDX-License-Identifier: GPL-2.0-only
"""Installer diagnostics. Standalone, stdlib-only, and read-only by default.

No package installs, service changes, downloads or host ruleset changes are
performed by preflight/verify. Backups and vendor-loader adoption are explicit
internal actions used only by the mutating installer.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import ssl
import subprocess
import uuid
from pathlib import Path
from typing import Any

PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
BIN = Path("/usr/local/bin/fwsec")
SCHEMA = 1


def run(args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items()
           if k in ("HOME", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "TZ")}
    env.update(PATH=PATH, NO_COLOR="1", PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run(args, capture_output=True, text=True, timeout=60, cwd="/",
                          env=env, **kwargs)


def os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    result = {}
    for line in path.read_text().splitlines():
        if "=" not in line or line.startswith("#"):
            continue
        key, value = line.split("=", 1)
        words = shlex.split(value)
        result[key] = " ".join(words)
    return result


def environment() -> dict[str, Any]:
    release = os_release()
    libc, libc_version = platform.libc_ver()
    if not libc and list(Path("/lib").glob("ld-musl-*.so.1")):
        libc = "musl"
    init = "none"
    if Path("/run/systemd/system").is_dir() and shutil.which("systemctl"):
        init = "systemd"
    elif Path("/run/openrc").is_dir() and shutil.which("rc-service"):
        init = "openrc"
    pkg = next((p for p in ("apt-get", "dnf", "microdnf", "yum", "zypper", "pacman", "apk")
                if shutil.which(p)), None)
    identity = release.get("ID", "")
    version = release.get("VERSION_ID", "")
    tier = ("VM-boot" if (identity, version) in (("ubuntu", "24.04"), ("alpine", "3.22"))
            else "container-smoke" if identity in ("debian", "ubuntu", "rocky", "fedora",
                                                    "amzn", "opensuse-leap", "arch", "alpine")
            else "family-capabilities-only")
    return {"id": release.get("ID"), "version": release.get("VERSION_ID"),
            "id_like": release.get("ID_LIKE", "").split(), "name": release.get("PRETTY_NAME"),
            "architecture": platform.machine(), "libc": libc or "unknown",
            "libc_version": libc_version, "kernel": platform.release(), "init": init,
            "package_manager": pkg, "support_reviewed": "2026-11-05", "testing_tier": tier,
            "lifecycle_scope": "Reviewed floors; vendor entitlement/maintenance not certified"}


def support_errors(env: dict[str, Any], allow_untested: bool) -> list[str]:
    floors = {"ubuntu": (22, 4), "debian": (12,), "alpine": (3, 22), "fedora": (43,),
              "amzn": (2023,), "centos": (9,), "opensuse-leap": (16,),
              "sles": (15, 7), "sles_sap": (15, 7), "rocky": (8,), "rhel": (8,),
              "almalinux": (8,), "cloudlinux": (8,), "ol": (8,)}
    identity = env.get("id", "")
    version = tuple(int(n) for n in re.findall(r"\d+", env.get("version") or "0")[:3])
    errors = []
    if identity in floors and version < floors[identity]:
        errors.append("Distribution release is below the reviewed supported floor")
    if identity == "amzn" and version != (2023,):
        errors.append("Only Amazon Linux 2023 is reviewed")
    known = identity in floors or identity in ("arch", "opensuse-tumbleweed")
    if not known and not allow_untested:
        errors.append("Untested derivative: explicit --allow-untested required")
    if env.get("architecture") not in ("x86_64", "aarch64") and not allow_untested:
        errors.append("Untested architecture: explicit --allow-untested required")
    return errors


def ca_trust_available() -> bool:
    context = ssl.create_default_context()
    if context.cert_store_stats().get("x509_ca"):
        return True
    # OpenSSL lazily reads hashed capath stores. A zero initial count is NOT
    # proof that CA trust is absent (e.g. /usr/lib/ssl/certs on Ubuntu/Zimbra).
    paths = ssl.get_default_verify_paths()
    if paths.capath and Path(paths.capath).is_dir():
        for path in Path(paths.capath).iterdir():
            if re.fullmatch(r"[0-9a-fA-F]{8}\.\d+", path.name) and path.is_file():
                try:
                    context.load_verify_locations(cafile=str(path))
                    if context.cert_store_stats().get("x509_ca"):
                        return True
                except (OSError, ssl.SSLError):
                    continue
    return False


def verify_wrapper(binary: Path, expected: str | None = None) -> dict[str, Any]:
    if binary.is_symlink() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError(f"Canonical wrapper missing, symlinked or not executable: {binary}")
    lines = binary.read_text().splitlines()
    commands = [shlex.split(line) for line in lines if line.startswith("exec ")]
    meaningful = [line for line in lines if line.strip()]
    if (len(meaningful) != 2 or meaningful[0] not in ("#!/bin/sh", "#!/usr/bin/env bash")
            or len(commands) != 1 or commands[0][0] != "exec"
            or commands[0][2:] not in (["-m", "fwsec", "$@"],
                                      ["-I", "-m", "fwsec", "$@"],
                                      ["-I", "-B", "-m", "fwsec", "$@"],)):
        raise ValueError("Unrecognized wrapper; review it rather than replacing it blindly")
    interpreter = Path(commands[0][1])
    if not interpreter.is_absolute() or not interpreter.is_file():
        raise ValueError("Wrapper interpreter is missing or not absolute")
    script = ("import json,sys,ssl,fcntl,ipaddress,configparser,importlib.metadata,fwsec; "
              "ssl.create_default_context(); "
              "print(json.dumps({'version':importlib.metadata.version('fwsec'),"
              "'prefix':sys.prefix,'module':fwsec.__file__}))")
    info = run([str(interpreter), "-I", "-B", "-c", script])
    if info.returncode:
        raise ValueError("Isolated Python/package/SSL import failed (inspect candidate runtime)")
    metadata: dict[str, Any] = json.loads(info.stdout)
    prefix = Path(metadata["prefix"])
    if prefix not in Path(metadata["module"]).parents:
        raise ValueError("fwsec imported outside its virtual environment")
    for options in (["--version"], ["--version", "--json"]):
        result = run([str(binary), *options])
        if result.returncode:
            raise ValueError("Installed wrapper cannot execute version query")
        if len(options) == 1:
            match = re.fullmatch(r"fwsec ([\w.\-]+)", result.stdout.strip())
            version = match.group(1) if match else None
        else:
            version = json.loads(result.stdout)["data"]["fwsec"]
        if version != metadata["version"] or (expected and version != expected):
            raise ValueError("Wrapper/package version does not match expected candidate version")
    return metadata


def probe(mode: str, binary: Path = BIN, expected: str | None = None,
          require_boot: bool = False, require_crowdsec: bool = False,
          migration: bool = False, check_path: bool = True,
          allow_untested: bool = False) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    data: dict[str, Any] = {"environment": environment(), "checks": {}, "errors": errors,
                            "warnings": warnings,
                            "scope": "No reboot or external reachability test"}
    checks = data["checks"]
    errors.extend(support_errors(data["environment"], allow_untested))
    if data["environment"].get("testing_tier") == "family-capabilities-only":
        warnings.append("Distribution uses family capability checks; no generic boot certification")
    try:
        ssl.create_default_context()
        checks["python_ssl"] = True
        checks["ca_certificates"] = ca_trust_available()
        checks["external_https_handshake"] = "not tested (SSL and local trust configuration only)"
        if not checks["ca_certificates"]:
            errors.append("No trusted CA certificates; HTTPS downloads cannot be certified")
    except (ImportError, OSError) as exc:
        errors.append("Python SSL/CA initialization failed: " + type(exc).__name__)
    if not data["environment"]["package_manager"]:
        warnings.append("No supported package manager found; requirements cannot be repaired here")
    if mode != "code":
        if not shutil.which("nft"):
            errors.append("Missing nftables binary")
        else:
            result = run(["nft", "-j", "list", "ruleset"])
            if result.returncode:
                errors.append("nftables unavailable: check CAP_NET_ADMIN/permissions and kernel "
                              "nf_tables support separately")
            else:
                checks["nft_json"] = True
                name = "fwsec_install_probe_" + uuid.uuid4().hex
                script = ("create table inet fwsec_install_probe\n"
                          "add set inet fwsec_install_probe deny4 { type ipv4_addr; "
                          "flags interval,timeout; }\n"
                          "add chain inet fwsec_install_probe probe\n"
                          "add rule inet fwsec_install_probe probe counter "
                          "comment \"fwsec managed\"\n"
                          "delete table inet fwsec_install_probe\n")
                script = script.replace("fwsec_install_probe", name)
                result = run(["nft", "--check", "-f", "-"], input=script)
                checks["nft_syntax"] = result.returncode == 0
                if result.returncode:
                    errors.append("Required nft transaction syntax/features "
                                  "failed check-only validation")
        if migration:
            for command in ("iptables-save", "ip6tables-save", "iptables-restore",
                            "ip6tables-restore"):
                if not shutil.which(command):
                    errors.append("Migration requires " + command)
    if mode != "preflight":
        try:
            checks["wrapper"] = verify_wrapper(binary, expected)
        except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
        if check_path:
            resolved = shutil.which("fwsec")
            clean = shutil.which("fwsec", path=PATH)
            checks["path"] = {"current": resolved, "clean": clean, "canonical": str(binary)}
            if not all(same_file(path, binary) for path in (resolved, clean)):
                errors.append("PATH does not select the canonical wrapper. Review PATH/shadowing; "
                              "no shell profiles were changed")
    if mode in ("runtime", "pending") and "wrapper" in checks:
        status = run([str(binary), "--status", "--json"])
        try:
            health = json.loads(status.stdout)["data"]
            checks["runtime"] = health
            if not health["policy_loaded"] or not health.get("ownership_verified"):
                errors.append("Firewall policy is incomplete or ownership is not verified")
            if mode == "pending":
                if not health["pending"]:
                    errors.append("Expected provisional transaction not found")
            elif health["pending"] or health["static_rules"] != "verified":
                errors.append("Rules are pending or static configuration verification failed")
            if health.get("crowdsec") not in ("operational", "disabled"):
                (errors if require_crowdsec else warnings).append(
                    "CrowdSec integration is not operational (core firewall evaluated separately)")
            if require_crowdsec and health.get("crowdsec") != "operational":
                errors.append("CrowdSec was required but is not operational")
        except (ValueError, KeyError, TypeError):
            errors.append("Runtime diagnostic did not return a valid status document")
        init = data["environment"]["init"]
        boot = False
        if init == "systemd":
            boot = run(["systemctl", "is-enabled", "--quiet", "fwsec"]).returncode == 0
        elif init == "openrc":
            boot = Path("/etc/runlevels/default/fwsec").exists()
        checks["boot_enabled"] = boot
        if not boot and mode != "pending":
            (errors if require_boot else warnings).append("fwsec boot integration is not enabled")
        if mode != "pending":
            loader = Path("/etc/sysconfig/nftables.conf")
            if not loader.exists():
                loader = Path("/etc/nftables.nft") if Path("/etc/nftables.nft").exists() else Path(
                    "/etc/nftables.conf")
            if not loader.is_file() or run(["nft", "--check", "-f", str(loader)]).returncode:
                errors.append("Persisted nft loader could not be validated")
    state = ("FAILED" if errors else "PENDING_CONFIRMATION" if mode == "pending" else
             "READY_WITH_WARNINGS" if warnings else "CODE_INSTALLED" if mode == "code" else
             "PREFLIGHT_PASSED" if mode == "preflight" else "OPERATIONAL")
    code = 1 if errors else 3 if mode == "pending" else 4 if warnings else 0
    return {"schema": SCHEMA, "state": state, "exit_code": code, "data": data}


def same_file(path: str | None, canonical: Path) -> bool:
    try:
        return path is not None and os.path.samefile(path, canonical)
    except OSError:
        return False


def snapshot(directory: Path, restore: bool = False, paths: list[Path] | None = None) -> None:
    """Explicit file-only recovery. Never stops services or flushes rulesets."""
    manifest = directory / "files.json"
    if restore:
        for name, meta in json.loads(manifest.read_text()).items():
            target = Path(name)
            if meta is None:
                if target.is_file():
                    target.unlink()
                continue
            if target.is_symlink():
                raise ValueError("Refuse to restore over symlink: " + name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(directory / meta, target)
        boot_file = directory / "boot.json"
        if boot_file.exists():
            boot = json.loads(boot_file.read_text())
            if boot["init"] == "systemd":
                run(["systemctl", "daemon-reload"])
                for name, enabled in boot["services"].items():
                    if run(["systemctl", "enable" if enabled else "disable", name]).returncode:
                        raise RuntimeError("Could not restore boot enablement for " + name)
            elif boot["init"] == "openrc":
                for name, enabled in boot["services"].items():
                    level = "boot" if name == "nftables" else "default"
                    if Path(f"/etc/runlevels/{level}/{name}").exists() != enabled:
                        if run(["rc-update", "add" if enabled else "del", name, level]).returncode:
                            raise RuntimeError("Could not restore OpenRC enablement for " + name)
        return
    default_paths = paths is None
    if default_paths:
        init = environment()["init"]
        services = {}
        for name in ("fwsec", "nftables"):
            if init == "systemd":
                services[name] = run(["systemctl", "is-enabled", "--quiet", name]).returncode == 0
            elif init == "openrc":
                level = "boot" if name == "nftables" else "default"
                services[name] = Path(f"/etc/runlevels/{level}/{name}").exists()
        (directory / "boot.json").write_text(json.dumps({"init": init, "services": services}))
    paths = paths if paths is not None else [
             BIN, Path("/etc/systemd/system/fwsec.service"), Path("/etc/init.d/fwsec"),
             Path("/etc/nftables.conf"), Path("/etc/sysconfig/nftables.conf"),
             Path("/etc/nftables.nft"),
             Path("/etc/nftables/fwsec.nft")]
    config_dir = Path("/etc/fwsec")
    if default_paths:
        paths.extend(config_dir.rglob("*") if config_dir.exists() else [])
        paths.extend(config_dir / n for n in (
            "fwsec.conf", "fwsec.allow", "fwsec.deny", "fwsec.ignore", "inherited.json",
            "applied.json", "migration-confirmed.json"))
    saved: dict[str, str | None] = {}
    for path in dict.fromkeys(paths):
        if path.is_symlink():
            raise ValueError("Review symlink before installation: " + str(path))
        if path.is_dir():
            continue
        if path.is_file():
            item = str(len(saved))
            shutil.copy2(path, directory / item)
            saved[str(path)] = item
        else:
            saved[str(path)] = None
    manifest.write_text(json.dumps(saved))
    manifest.chmod(0o600)


def adopt_vendor_loader() -> None:
    """Operator opt-in AND package-pristine proof required for a stock global flush."""
    path = Path("/etc/sysconfig/nftables.conf")
    if not path.exists():
        path = Path("/etc/nftables.nft") if Path("/etc/nftables.nft").exists() else Path(
            "/etc/nftables.conf")
    if not path.exists() or "flush ruleset" not in path.read_text():
        return
    pristine = False
    if shutil.which("dpkg-query"):
        result = run(["dpkg-query", "-W", "-f=${Conffiles}", "nftables"])
        for line in result.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[0] == str(path):
                digest = hashlib.md5(path.read_bytes()).hexdigest()
                pristine = fields[1] == digest
    elif shutil.which("rpm"):
        pristine = (run(["rpm", "-qf", "--qf", "%{NAME}", str(path)]).stdout == "nftables"
                    and run(["rpm", "-Vf", str(path)]).returncode == 0)
    elif shutil.which("apk"):
        for record in Path("/lib/apk/db/installed").read_text().split("\n\n"):
            if "P:nftables\n" not in record:
                continue
            folder = filename = ""
            for line in record.splitlines():
                if line.startswith("F:"):
                    folder = line[2:]
                elif line.startswith("R:"):
                    filename = line[2:]
                elif line.startswith("Z:") and "/" + folder + "/" + filename == str(path):
                    expected = "Q1" + base64.b64encode(hashlib.sha1(
                        path.read_bytes()).digest()).decode()
                    pristine = line[2:] == expected
    if path.is_symlink() or not pristine:
        raise ValueError("Loader is not provably vendor-pristine; review it manually")
    backup = path.with_name(path.name + ".fwsec-vendor-backup")
    if backup.exists():
        raise ValueError("Vendor loader backup already exists; review before retrying")
    shutil.copy2(path, backup)
    path.write_text("#!/usr/sbin/nft -f\n# Managed by fwsec\n")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("preflight", "code", "runtime", "pending"),
                   default="preflight")
    p.add_argument("--binary", type=Path, default=BIN)
    p.add_argument("--expected")
    p.add_argument("--json", action="store_true")
    p.add_argument("--require-boot", action="store_true")
    p.add_argument("--require-crowdsec", action="store_true")
    p.add_argument("--migration", action="store_true")
    p.add_argument("--allow-untested", action="store_true")
    actions = p.add_mutually_exclusive_group()
    actions.add_argument("--snapshot", type=Path)
    actions.add_argument("--restore", type=Path)
    actions.add_argument("--adopt-vendor-loader", action="store_true")
    args = p.parse_args()
    try:
        if args.snapshot or args.restore:
            snapshot(args.snapshot or args.restore, bool(args.restore))
            return
        if args.adopt_vendor_loader:
            adopt_vendor_loader()
            return
        report = probe(args.mode, args.binary, args.expected, args.require_boot,
                       args.require_crowdsec, args.migration, allow_untested=args.allow_untested)
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError) as exc:
        report = {"schema": SCHEMA, "state": "FAILED", "exit_code": 1,
                  "data": {"errors": [str(exc)], "warnings": []}}
    if args.json:
        print(json.dumps(report))
    else:
        print(report["state"])
        for level in ("errors", "warnings"):
            for item in report["data"].get(level, []):
                print(f"  {level}: {item}")
    raise SystemExit(report["exit_code"])


if __name__ == "__main__":
    main()
