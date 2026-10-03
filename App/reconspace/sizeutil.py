from __future__ import annotations

import os


def allocated_size(path: str, logical_size: int | None = None) -> int | None:
    """Return physical/allocated file bytes when the OS exposes them.

    This is metadata-only. On Windows GetCompressedFileSizeW reports disk space
    used by compressed/sparse files without opening or modifying the file.
    """
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            fn = kernel32.GetCompressedFileSizeW
            fn.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(wintypes.DWORD)]
            fn.restype = wintypes.DWORD
            high = wintypes.DWORD(0)
            ctypes.set_last_error(0)
            low = fn(path, ctypes.byref(high))
            if low == 0xFFFFFFFF and ctypes.get_last_error() != 0:
                return None
            return (int(high.value) << 32) | int(low)
        except (OSError, AttributeError, ValueError):
            return None

    try:
        st = os.stat(path, follow_symlinks=False)
        blocks = getattr(st, "st_blocks", None)
        if blocks is not None:
            return int(blocks) * 512
        return int(st.st_size if logical_size is None else logical_size)
    except OSError:
        return None
