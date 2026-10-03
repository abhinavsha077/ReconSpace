from __future__ import annotations

import ctypes
import json
import os
import re
import time
from ctypes import wintypes
from pathlib import Path
from typing import Any

from .plan import verify_plan_manifest

IS_WINDOWS = os.name == "nt"

# Win32 Shell File Operations
FO_DELETE = 0x0003
FOF_MULTIDESTFILES = 0x0001
FOF_CONFIRMMOUSE = 0x0002
FOF_SILENT = 0x0004
FOF_RENAMEONCOLLISION = 0x0008
FOF_NOCONFIRMATION = 0x0010
FOF_WANTMAPPINGHANDLE = 0x0020
FOF_ALLOWUNDO = 0x0040
FOF_FILESONLY = 0x0080
FOF_SIMPLEPROGRESS = 0x0100
FOF_NOCONFIRMMKDIR = 0x0200
FOF_NOERRORUI = 0x0400


class SHFILEOPSTRUCTW(ctypes.Structure):
    _fields_ = [
        ("hwnd", wintypes.HWND),
        ("wFunc", wintypes.UINT),
        ("pFrom", wintypes.LPCWSTR),
        ("pTo", wintypes.LPCWSTR),
        ("fFlags", wintypes.WORD),
        ("fAnyOperationsAborted", wintypes.BOOL),
        ("hNameMappings", ctypes.c_void_p),
        ("lpszProgressTitle", wintypes.LPCWSTR),
    ]


def is_system_protected_path(path: str) -> bool:
    """Check if a path is a protected Windows operating system directory that must NEVER be deleted."""
    if not path or not isinstance(path, str) or not path.strip():
        return True

    clean = os.path.normcase(os.path.normpath(os.path.abspath(path.strip())))

    # 1. Drive roots (e.g. C:\, C:, \\?\C:\) and root slashes
    if re.match(r"^(?:\\\\\?\\)?[a-z]:[\\/]?$", clean):
        return True
    drive, rest = os.path.splitdrive(clean)
    if rest in ("", "\\", "/"):
        return True
    if clean.startswith("\\\\"):
        parts = [p for p in clean.split("\\") if p]
        if len(parts) <= 2:
            return True

    # 2. Prevent unlinking or recycling directory junctions or symlinks
    if os.path.islink(clean):
        return True

    # 3. System and Windows roots
    sys_root = os.path.normcase(os.environ.get("SystemRoot", "C:\\Windows"))
    sys_drive = os.path.normcase(os.environ.get("SystemDrive", "C:").rstrip("\\/") + "\\")
    user_prof = os.path.normcase(os.environ.get("USERPROFILE", ""))

    # Critical directory trees where the folder itself AND all descendants are protected
    critical_trees = [
        sys_root,
        os.path.join(sys_drive, "program files"),
        os.path.join(sys_drive, "program files (x86)"),
        os.path.join(sys_drive, "programdata", "microsoft"),
        os.path.join(sys_drive, "recovery"),
        os.path.join(sys_drive, "system volume information"),
        os.path.join(sys_drive, "$recycle.bin"),
        os.path.join(sys_drive, "boot"),
        os.path.join(sys_drive, "efi"),
        os.path.join(sys_drive, "perflogs"),
        os.path.join(sys_drive, "users", "default"),
        os.path.join(sys_drive, "users", "public"),
        os.path.join(sys_drive, "users", "all users"),
    ]
    if user_prof:
        for personal in ("desktop", "documents", "pictures", "music", "videos", "contacts", "searches", "saved games"):
            critical_trees.append(os.path.join(user_prof, personal))

    for tree in critical_trees:
        norm_t = os.path.normcase(os.path.normpath(tree))
        if clean == norm_t or clean.startswith(norm_t + os.sep):
            return True

    # Critical exact roots (the directory itself is protected)
    exact_roots = {
        os.path.join(sys_drive, "users"),
        os.path.join(sys_drive, "programdata"),
    }
    if user_prof:
        exact_roots.add(user_prof)
        exact_roots.add(os.path.join(user_prof, "downloads"))
        exact_roots.add(os.path.join(user_prof, "onedrive"))

    for r in exact_roots:
        if clean == os.path.normcase(os.path.normpath(r)):
            return True

    return False


def safe_recycle_path(path: str) -> tuple[bool, str]:
    """Move path to Windows Recycle Bin if supported, or error safely."""
    if not path or not os.path.exists(path):
        return False, "Target path does not exist"

    if is_system_protected_path(path):
        return False, "Target path is protected by Windows safety invariants"

    # Reject directory symlinks or junctions to prevent deleting targets
    if os.path.islink(path):
        return False, "Target path is a symbolic link or junction; deletion rejected"

    if IS_WINDOWS:
        # Check for remote / network mapped drive or UNC share
        clean_abs = os.path.abspath(path).rstrip("\\/")
        if clean_abs.startswith("\\\\"):
            return False, "Windows Recycle Bin is not supported on UNC network shares; permanent deletion blocked"

        drive = os.path.splitdrive(clean_abs)[0]
        if drive:
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive + "\\")
            # DRIVE_REMOTE = 4
            if drive_type == 4:
                return False, f"Windows Recycle Bin is not supported on remote drive {drive}; permanent deletion blocked"

        try:
            # SHFileOperationW requires double-null terminated string without trailing backslash
            double_null_path = clean_abs + "\x00\x00"
            file_op = SHFILEOPSTRUCTW()
            file_op.hwnd = None
            file_op.wFunc = FO_DELETE
            file_op.pFrom = double_null_path
            file_op.pTo = None
            file_op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT | FOF_NOERRORUI

            res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(file_op))
            if res == 0 and not file_op.fAnyOperationsAborted:
                return True, "Successfully moved to Windows Recycle Bin"
            else:
                err_desc = ctypes.FormatError(res).strip() if res else "Operation aborted"
                return False, f"Recycle operation failed (Win32 code {res}): {err_desc}"
        except Exception as exc:
            return False, f"Recycle operation failed: {type(exc).__name__}: {exc}"
    else:
        # Non-Windows fallback (simulation)
        return True, "Simulated recycle operation on non-Windows environment"



def execute_approved_plan(
    plan_data: dict[str, Any],
    dry_run: bool = True,
    confirm: bool = False,
    approved_ids: list[str] | None = None,
) -> dict[str, Any]:
    """Execute user-approved plan items with strict cryptographic and safety preconditions."""
    if not isinstance(plan_data, dict):
        return {
            "success": False,
            "error": "Plan manifest must be a dictionary object",
            "dry_run": dry_run,
            "actions": [],
            "freed_bytes": 0,
        }

    # 1. Verify Manifest Integrity
    valid, reason = verify_plan_manifest(plan_data)
    if not valid:
        return {
            "success": False,
            "error": f"Plan manifest integrity verification failed: {reason}",
            "dry_run": dry_run,
            "actions": [],
            "freed_bytes": 0,
        }

    items = plan_data.get("items") or []
    approved_set = set(approved_ids or [])
    plan_item_ids = {it.get("id") for it in items if isinstance(it, dict) and it.get("id")}
    actions_log: list[dict[str, Any]] = []
    freed_bytes = 0

    # Log unknown approved IDs requested by user
    missing_ids = approved_set - plan_item_ids
    for mid in sorted(missing_ids):
        actions_log.append({
            "id": mid,
            "path": "",
            "status": "REJECTED_UNKNOWN_ID",
            "detail": f"Item ID '{mid}' was not found in the plan manifest.",
            "freed_bytes": 0,
        })

    for it in items:
        if not isinstance(it, dict):
            continue
        item_id = it.get("id")
        path = it.get("path")
        disposition = it.get("disposition")
        est_bytes = int(it.get("estimated_reclaimable_bytes") or 0)
        status = it.get("approval_status")

        # Must be explicitly approved (either via approved_ids or status == 'APPROVED')
        is_approved = (item_id in approved_set) or (status == "APPROVED")
        if not is_approved:
            continue

        # Strict safety guard: only probably_safe_cleanup disposition is executable
        if disposition != "probably_safe_cleanup":
            actions_log.append({
                "id": item_id,
                "path": path,
                "status": "REJECTED_UNSAFE_DISPOSITION",
                "detail": f"Disposition '{disposition}' cannot be executed automatically; manual user action required.",
                "freed_bytes": 0,
            })
            continue

        if not path or not os.path.exists(path):
            actions_log.append({
                "id": item_id,
                "path": path,
                "status": "SKIPPED_NOT_FOUND",
                "detail": "Target path does not exist on disk.",
                "freed_bytes": 0,
            })
            continue

        if is_system_protected_path(path):
            actions_log.append({
                "id": item_id,
                "path": path,
                "status": "REJECTED_PROTECTED_PATH",
                "detail": "Path matches Windows system protection invariants.",
                "freed_bytes": 0,
            })
            continue

        if dry_run:
            actions_log.append({
                "id": item_id,
                "path": path,
                "status": "SIMULATED_RECYCLE",
                "detail": "Dry run: item would be safely moved to Windows Recycle Bin.",
                "freed_bytes": est_bytes,
            })
            freed_bytes += est_bytes
        else:
            if not confirm:
                actions_log.append({
                    "id": item_id,
                    "path": path,
                    "status": "REJECTED_NO_CONFIRMATION",
                    "detail": "Execution requires explicit user confirmation flag.",
                    "freed_bytes": 0,
                })
                continue

            success, op_msg = safe_recycle_path(path)
            if success:
                actions_log.append({
                    "id": item_id,
                    "path": path,
                    "status": "SUCCESS_RECYCLED",
                    "detail": op_msg,
                    "freed_bytes": est_bytes,
                })
                freed_bytes += est_bytes
            else:
                actions_log.append({
                    "id": item_id,
                    "path": path,
                    "status": "FAILED",
                    "detail": op_msg,
                    "freed_bytes": 0,
                })

    return {
        "success": True,
        "dry_run": dry_run,
        "manifest_verified": True,
        "manifest_sha256": plan_data.get("manifest_sha256"),
        "total_actions": len(actions_log),
        "total_freed_bytes": freed_bytes,
        "timestamp": time.time(),
        "actions": actions_log,
    }
