from __future__ import annotations

import ctypes
import os
import shutil
import sys
from pathlib import Path
from typing import Any

from . import __version__


def _python_implementation() -> str:
    name = str(getattr(sys.implementation, "name", "python"))
    return {"cpython": "CPython", "pypy": "PyPy"}.get(name.casefold(), name)


def _platform_label() -> str:
    """Describe the host without platform.py's command fallbacks on Windows."""
    if os.name == "nt":
        version = sys.getwindowsversion()
        if version.build >= 22000:
            release = "11"
        elif version.build >= 10240:
            release = "10"
        else:
            release = f"{version.major}.{version.minor}.{version.build}"
        architecture = (
            os.environ.get("PROCESSOR_ARCHITEW6432")
            or os.environ.get("PROCESSOR_ARCHITECTURE")
            or ("AMD64" if sys.maxsize > 2**32 else "x86")
        )
        return f"Windows-{release}-{architecture}"
    if hasattr(os, "uname"):
        info = os.uname()
        return "-".join(x for x in (info.sysname, info.release, info.machine) if x)
    return sys.platform


def _is_admin() -> bool | None:
    if os.name != "nt":
        return None
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def _long_paths_enabled() -> bool | None:
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\FileSystem") as key:
            value, _ = winreg.QueryValueEx(key, "LongPathsEnabled")
            return bool(int(value))
    except Exception:
        return None


def doctor(root: str = "C:\\") -> dict[str, Any]:
    """Run a non-destructive environment/readiness diagnostic.

    This function never launches external tools. It only inspects Python/platform
    state, command discoverability, environment paths, and filesystem metadata.
    """
    cleaned = str(root or "").strip().strip('"').strip("'").strip()
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    p = Path(os.path.abspath(os.path.expandvars(os.path.expanduser(cleaned))))
    tools = [
        "powershell.exe", "pwsh.exe", "wsl.exe", "docker.exe", "dism.exe",
        "vssadmin.exe", "fsutil.exe", "powercfg.exe", "compact.exe",
        "VBoxManage.exe", "winget.exe",
    ]
    found = {name: shutil.which(name) for name in tools}
    usage = None
    try:
        du = shutil.disk_usage(str(p))
        usage = {"total_bytes": int(du.total), "used_bytes": int(du.used), "free_bytes": int(du.free)}
    except Exception:
        pass

    warnings: list[str] = []
    if not p.exists():
        warnings.append("Requested scan root does not exist from this runtime.")
    elif not p.is_dir():
        warnings.append("Requested scan root is not a directory.")
    if os.name == "nt" and _is_admin() is False:
        warnings.append("Not elevated: the scan remains safe/read-only, but some protected locations and system inventory may be inaccessible.")
    if os.name == "nt" and not (found.get("powershell.exe") or found.get("pwsh.exe")):
        warnings.append("PowerShell was not found in PATH; several Windows inventory collectors will be unavailable.")
    if sys.version_info < (3, 11):
        warnings.append("Python 3.11+ is recommended for this ReconSpace build.")

    env_keys = ["SystemDrive", "SystemRoot", "WINDIR", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA", "APPDATA", "USERPROFILE"]
    return {
        "reconspace_version": __version__,
        "python_version": ".".join(str(x) for x in sys.version_info[:3]),
        "python_implementation": _python_implementation(),
        "platform": _platform_label(),
        "os_name": os.name,
        "is_windows": os.name == "nt",
        "is_admin": _is_admin(),
        "long_paths_enabled": _long_paths_enabled(),
        "root": str(p),
        "root_exists": p.exists(),
        "root_is_directory": p.is_dir(),
        "disk_usage": usage,
        "tools": found,
        "environment_paths": {k: os.environ.get(k, "") for k in env_keys},
        "warnings": warnings,
        "safety": "READ_ONLY_DIAGNOSTIC_NO_EXTERNAL_COMMAND_EXECUTION",
    }
