# SPDX-License-Identifier: GPL-2.0-only
"""Full installer + reboot tests in disposable QEMU VMs. Never targets a real host.

Requires qemu-system-x86_64, qemu-img, cloud-localds and ssh on a Linux CI runner.
Only localhost user-network forwarding and a generated ephemeral SSH key are used.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

IMAGES = {
    "ubuntu": ("https://cloud-images.ubuntu.com/noble/current/",
               "noble-server-cloudimg-amd64.img", "SHA256SUMS", "sha256"),
    "alpine": ("https://dl-cdn.alpinelinux.org/alpine/v3.22/releases/cloud/",
               "alpine-3.22.7-x86_64-bios-cloudinit-r0.qcow2",
               "alpine-3.22.7-x86_64-bios-cloudinit-r0.qcow2.sha512", "sha512"),
}


def checked(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def test_vm(kind: str, work: Path) -> None:
    work.mkdir(parents=True, exist_ok=True)
    url, filename, checksum_file, algorithm = IMAGES[kind]
    image = work / "base.qcow2"
    digest = hashlib.new(algorithm)
    with urllib.request.urlopen(url + filename, timeout=120) as response, \
            image.open("wb") as output:
        while True:
            data = response.read(1024 * 1024)
            if not data:
                break
            digest.update(data)
            output.write(data)
    sums = urllib.request.urlopen(url + checksum_file, timeout=60).read().decode()
    assert any(line.split()[0] == digest.hexdigest() and (
        filename in line or len(line.split()) == 1) for line in sums.splitlines()), "image checksum"
    disk = work / "disk.qcow2"
    checked(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(image), str(disk)])
    checked(["qemu-img", "resize", str(disk), "10G"])
    key = work / "key"
    checked(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)])
    pub = key.with_suffix(".pub").read_text().strip()
    userdata = work / "user-data"
    userdata.write_text("#cloud-config\ndisable_root: false\nssh_pwauth: false\n"
                        "users:\n  - name: root\n    ssh_authorized_keys:\n      - " + pub +
                        "\nchpasswd:\n  expire: false\n  users:\n    - name: root\n"
                        "      password: " + secrets.token_hex(24) + "\n      type: text" +
                        "\npackage_update: true\npackages:\n  - bash\n  - curl\n"
                        "  - ca-certificates\n  - python3\n")
    userdata.chmod(0o600)
    metadata = work / "meta-data"
    metadata.write_text("instance-id: fwsec-test\nlocal-hostname: fwsec-test\n")
    seed = work / "seed.img"
    checked(["cloud-localds", str(seed), str(userdata), str(metadata)])
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    ssh = ["ssh", "-i", str(key), "-p", str(port), "-o", "BatchMode=yes",
           "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
           "-o", "ConnectTimeout=5", "root@127.0.0.1"]

    def remote(command: str, data: bytes | None = None, timeout: int = 600,
               accepted: tuple[int, ...] = (0, 4)):
        result = subprocess.run(ssh + [command], input=data, capture_output=True, timeout=timeout)
        if result.returncode not in accepted:
            raise RuntimeError(command + "\n" + result.stdout.decode(errors="replace")[-6000:]
                               + result.stderr.decode(errors="replace")[-6000:])
        return result.stdout.decode()

    def wait_boot(previous: str = ""):
        for _ in range(180):
            result = subprocess.run(ssh + ["cat /proc/sys/kernel/random/boot_id"],
                                    capture_output=True, timeout=10)
            value = result.stdout.decode().strip()
            if result.returncode == 0 and value and value != previous:
                return value
            time.sleep(3)
        raise RuntimeError("VM SSH/reboot deadline exceeded")

    accel = "kvm" if os.access("/dev/kvm", os.R_OK | os.W_OK) else "tcg"
    serial = work / "serial.log"
    qemu = subprocess.Popen(["qemu-system-x86_64", "-accel", accel,
        "-cpu", "host" if accel == "kvm" else "max", "-m", "2048", "-smp", "2",
        "-drive", f"file={disk},if=virtio", "-drive", f"file={seed},format=raw,if=virtio",
        "-nic", f"user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:{port}-:22",
        "-display", "none", "-serial", f"file:{serial}", "-monitor", "none"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        first_boot = wait_boot()
        cloud = json.loads(remote("cloud-init status --wait --format json", accepted=(0, 2)))
        print("cloud-init:", json.dumps(cloud))
        assert cloud.get("status") == "done" and not cloud.get("errors"), cloud
        archive = checked(["git", "archive", "--format=tar.gz", "HEAD"]).stdout
        remote("mkdir /root/fwsec-source; tar -xz -C /root/fwsec-source", archive)
        # An unknown option must fail before any installation, even on a clean VM.
        remote("cd /root/fwsec-source; bash install.sh --typo >/dev/null 2>&1; "
               "rc=$?; test $rc -eq 2 && test ! -e /usr/local/bin/fwsec")
        report = json.loads(remote("cd /root/fwsec-source; "
            "bash install.sh --no-crowdsec --adopt-vendor-loader --json"))
        assert report["state"] in ("OPERATIONAL", "READY_WITH_WARNINGS"), report
        assert report["data"]["checks"]["boot_enabled"], report
        verified = json.loads(remote("cd /root/fwsec-source; bash install.sh --verify-only --json"))
        assert verified["data"]["checks"]["runtime"]["static_rules"] == "verified", verified
        wrapper = remote("sha256sum /usr/local/bin/fwsec").split()[0]
        # Failed candidate builds must leave the installed wrapper and policy alone.
        remote("cp -a /root/fwsec-source /root/fwsec-broken; "
               "printf '[' >> /root/fwsec-broken/pyproject.toml; "
               "cd /root/fwsec-broken; bash install.sh --force --install-only --json "
               ">/root/failure.json 2>/root/failure.log; rc=$?; test $rc -eq 1")
        assert remote("sha256sum /usr/local/bin/fwsec").split()[0] == wrapper
        failure = json.loads(remote("cat /root/failure.json"))
        assert failure["state"] == "FAILED", failure
        remote("cd /root/fwsec-source; bash install.sh --force --no-crowdsec --json")
        remote("env -i HOME=/root PATH=/usr/local/bin:/usr/bin:/bin fwsec --version")
        subprocess.run(ssh + ["reboot"], capture_output=True, timeout=20)
        wait_boot(first_boot)
        for attempt in range(30):
            report = json.loads(remote("cd /root/fwsec-source; "
                                       "bash install.sh --verify-only --json", accepted=(0, 1, 4)))
            if (report["state"] in ("OPERATIONAL", "READY_WITH_WARNINGS") and
                    report["data"]["checks"].get("runtime", {}).get("static_rules") == "verified"):
                break
            time.sleep(2)
        else:
            raise RuntimeError("Post-reboot verification never became ready")
        assert report["data"]["checks"]["boot_enabled"], report
        print(f"PASS {kind}: clean install, failed build recovery, force reinstall, "
              "canonical/PATH command, real reboot and persisted policy")
    except BaseException:
        print(serial.read_text(errors="replace")[-12000:] if serial.exists() else "No serial log")
        raise
    finally:
        qemu.terminate()
        try:
            qemu.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            qemu.kill()
            qemu.communicate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kind", choices=IMAGES)
    parser.add_argument("--work", type=Path)
    args = parser.parse_args()
    if args.work:
        test_vm(args.kind, args.work.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="fwsec-boot-") as folder:
            test_vm(args.kind, Path(folder))
