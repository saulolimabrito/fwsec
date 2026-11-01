# SPDX-License-Identifier: GPL-2.0-only

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version

try:
    __version__ = _pkg_version("fwsec")
except PackageNotFoundError:
    # Running from a source checkout without an installed distribution:
    # read the version from pyproject.toml as a best effort.
    import re
    from pathlib import Path

    try:
        _pyproject = Path(__file__).resolve().parents[2] / "pyproject.toml"
        _m = re.search(r'^version\s*=\s*"([^"]+)"', _pyproject.read_text(), re.M)
        __version__ = _m.group(1) if _m else "0.0.0"
    except OSError:
        __version__ = "0.0.0"
