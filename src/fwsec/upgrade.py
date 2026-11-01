# SPDX-License-Identifier: GPL-2.0-only

"""
Self-upgrade from the GitHub repository.

Downloads the latest fwsec release and hands the installation over to the
bundled `install.sh --upgrade`, which replaces only the package and the
executable. Local configuration under /etc/fwsec (fwsec.conf, allow/deny/
ignore lists, state) is never touched.
"""
from __future__ import annotations

import json
import re
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

REPO = "saulolimabrito/fwsec"
_TIMEOUT = 20


def _get(url: str) -> Optional[bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "fwsec-upgrade"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.read()
    except (urllib.error.URLError, OSError, TimeoutError):
        return None


def fetch_remote_version() -> Optional[str]:
    """Latest version in the repository: release tag, else pyproject on main."""
    data = _get(f"https://api.github.com/repos/{REPO}/releases/latest")
    if data:
        try:
            tag = json.loads(data).get("tag_name", "")
            m = re.match(r"v?(\d[\w.\-]*)", tag)
            if m:
                return m.group(1)
        except json.JSONDecodeError:
            pass

    data = _get(f"https://raw.githubusercontent.com/{REPO}/main/pyproject.toml")
    if data:
        m = re.search(r'^version\s*=\s*"([^"]+)"', data.decode(errors="replace"), re.M)
        if m:
            return m.group(1)
    return None


def _version_tuple(v: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4]) or (0,)


def is_newer(remote: str, local: str) -> bool:
    return _version_tuple(remote) > _version_tuple(local)


def _extract_safely(tar: tarfile.TarFile, destination: Path) -> None:
    """Extract a source archive without allowing writes outside destination."""
    if hasattr(tarfile, "data_filter"):
        tar.extractall(destination, filter="data")
        return

    # Python 3.10/3.11 do not provide extraction filters. Validate every
    # member and reject links and device files before using extractall().
    root = destination.resolve()
    for member in tar.getmembers():
        target = (destination / member.name).resolve()
        if target != root and root not in target.parents:
            raise tarfile.TarError(f"archive member escapes destination: {member.name}")
        if member.issym() or member.islnk() or member.isdev():
            raise tarfile.TarError(f"unsafe archive member: {member.name}")
    tar.extractall(destination)


def download_source(version: str) -> Optional[Path]:
    """Download and extract the source tarball; returns the source directory."""
    data = _get(f"https://github.com/{REPO}/archive/refs/tags/v{version}.tar.gz")
    if data is None:
        # No tag published for this version — fall back to the main branch
        data = _get(f"https://github.com/{REPO}/archive/refs/heads/main.tar.gz")
    if data is None:
        return None

    tmp = Path(tempfile.mkdtemp(prefix="fwsec-upgrade."))
    tarball = tmp / "src.tar.gz"
    tarball.write_bytes(data)
    try:
        with tarfile.open(tarball) as tar:
            _extract_safely(tar, tmp)
    except tarfile.TarError:
        return None

    for entry in sorted(tmp.iterdir()):
        if entry.is_dir() and (entry / "pyproject.toml").exists():
            return entry
    return None
