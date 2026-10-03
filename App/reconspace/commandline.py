from __future__ import annotations

import ntpath
import os
import re

_EXE_RE = re.compile(r"(?i)\.exe(?:\s|$)")


def extract_windows_executable(command: str) -> str:
    """Best-effort extraction of an executable target from a Windows command line.

    This function never executes or resolves the command. It is intentionally
    conservative and is used only to improve persistence inventory hints.
    """
    text = os.path.expandvars(str(command or "").strip())
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        if end > 1:
            return text[1:end]
    # Services frequently contain an unquoted absolute executable path followed
    # by arguments. Stop at the first .exe boundary even when spaces are present.
    match = _EXE_RE.search(text)
    if match:
        return text[: match.start() + 4].strip().strip('"')
    # Script/shortcut-style commands: take the first token as a weak fallback.
    return text.split(None, 1)[0].strip('"')


def absolute_target_exists(target: str) -> bool | None:
    if not target:
        return None
    expanded = os.path.expandvars(os.path.expanduser(target))
    host_abs = os.path.isabs(expanded)
    windows_abs = ntpath.isabs(expanded)
    if not (host_abs or windows_abs):
        return None
    if windows_abs and os.name != "nt" and not host_abs:
        return None
    try:
        return os.path.exists(expanded)
    except OSError:
        return None


def looks_user_writable_windows_path(path: str) -> bool:
    p = str(path or "").replace("/", "\\").casefold()
    tokens = (
        "\\users\\",
        "\\appdata\\",
        "\\temp\\",
        "\\downloads\\",
        "\\desktop\\",
        "\\public\\",
    )
    return any(t in p for t in tokens)


def has_unquoted_service_path_risk(command: str) -> bool:
    text = os.path.expandvars(str(command or "").strip())
    if not text or text.startswith('"'):
        return False
    target = extract_windows_executable(text)
    return bool(target and " " in target and (os.path.isabs(target) or ntpath.isabs(target)))
