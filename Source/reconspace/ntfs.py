from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes
from typing import Any

from .models import CollectorResult

IS_WINDOWS = os.name == "nt"

# IOCTL codes
FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064
FSCTL_QUERY_USN_JOURNAL = 0x000900F4

# Win32 Flags
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_SHARE_DELETE = 4
OPEN_EXISTING = 3
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000


class NTFS_VOLUME_DATA_BUFFER(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber", ctypes.c_int64),
        ("NumberSectors", ctypes.c_int64),
        ("TotalClusters", ctypes.c_int64),
        ("FreeClusters", ctypes.c_int64),
        ("TotalReserved", ctypes.c_int64),
        ("BytesPerSector", wintypes.DWORD),
        ("BytesPerCluster", wintypes.DWORD),
        ("BytesPerFileRecordSegment", wintypes.DWORD),
        ("ClustersPerFileRecordSegment", wintypes.DWORD),
        ("MftValidDataLength", ctypes.c_int64),
        ("MftStartLcn", ctypes.c_int64),
        ("Mft2StartLcn", ctypes.c_int64),
        ("MftZoneStart", ctypes.c_int64),
        ("MftZoneEnd", ctypes.c_int64),
    ]


class USN_JOURNAL_DATA(ctypes.Structure):
    _fields_ = [
        ("UsnJournalID", ctypes.c_uint64),
        ("FirstUsn", ctypes.c_int64),
        ("NextUsn", ctypes.c_int64),
        ("LowestValidUsn", ctypes.c_int64),
        ("MaxUsn", ctypes.c_int64),
        ("MaximumSize", ctypes.c_uint64),
        ("AllocationDelta", ctypes.c_uint64),
    ]


def _drive_root(path: str) -> str:
    cleaned = str(path or "").strip().strip('"').strip("'")
    if not cleaned:
        return "C:\\"
    match = re.match(r"^([A-Za-z]:)", cleaned)
    if match:
        return match.group(1) + "\\"
    return "C:\\"


def inspect_ntfs_volume_metadata(root: str = "C:\\") -> dict[str, Any]:
    """Inspect NTFS volume geometry, MFT allocation, and USN journal metadata safely in read-only mode."""
    if not IS_WINDOWS:
        return {
            "supported": False,
            "error": "NTFS inspection is only supported on Windows hosts.",
        }

    drive_root = _drive_root(root)
    kernel32 = ctypes.windll.kernel32

    # Query file system name and volume flags via GetVolumeInformationW
    buf_vol_name = ctypes.create_unicode_buffer(260)
    buf_fs_name = ctypes.create_unicode_buffer(260)
    serial = wintypes.DWORD()
    max_component_len = wintypes.DWORD()
    fs_flags = wintypes.DWORD()

    success = kernel32.GetVolumeInformationW(
        drive_root,
        buf_vol_name,
        260,
        ctypes.byref(serial),
        ctypes.byref(max_component_len),
        ctypes.byref(fs_flags),
        buf_fs_name,
        260,
    )

    if not success:
        err = kernel32.GetLastError()
        return {
            "supported": False,
            "drive": drive_root,
            "error": f"GetVolumeInformationW failed with Win32 error {err}",
        }

    fs_name = buf_fs_name.value
    vol_name = buf_vol_name.value
    flags_val = int(fs_flags.value)
    is_ntfs = (fs_name.upper() == "NTFS")

    data: dict[str, Any] = {
        "drive": drive_root,
        "volume_name": vol_name,
        "filesystem": fs_name,
        "is_ntfs": is_ntfs,
        "flags": hex(flags_val),
        "supports_reparse_points": bool(flags_val & 0x00000080),
        "supports_sparse_files": bool(flags_val & 0x00000040),
        "supports_compression": bool(flags_val & 0x00000020),
        "supports_object_ids": bool(flags_val & 0x00010000),
        "supports_usn_journal": bool(flags_val & 0x02000000),
        "can_query_ntfs_data": False,
        "can_query_usn_journal": False,
    }

    if not is_ntfs:
        data["note"] = f"Volume {drive_root} uses {fs_name}, not NTFS. Direct MFT indexing is not applicable."
        return data

    # Open directory handle with FILE_FLAG_BACKUP_SEMANTICS for DeviceIoControl
    handle = kernel32.CreateFileW(
        drive_root,
        0,  # Query without read/write data access
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None,
        OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS,
        None,
    )

    if handle == -1 or handle == 0:
        err = kernel32.GetLastError()
        data["open_handle_error"] = f"CreateFileW on volume root returned error {err}"
        return data

    try:
        # 1. Query NTFS Volume Data Buffer (MFT size and cluster geometry)
        vol_buf = NTFS_VOLUME_DATA_BUFFER()
        bytes_returned = wintypes.DWORD()
        res_vol = kernel32.DeviceIoControl(
            handle,
            FSCTL_GET_NTFS_VOLUME_DATA,
            None,
            0,
            ctypes.byref(vol_buf),
            ctypes.sizeof(vol_buf),
            ctypes.byref(bytes_returned),
            None,
        )

        if res_vol:
            data["can_query_ntfs_data"] = True
            data["bytes_per_sector"] = int(vol_buf.BytesPerSector)
            data["bytes_per_cluster"] = int(vol_buf.BytesPerCluster)
            data["bytes_per_file_record"] = int(vol_buf.BytesPerFileRecordSegment)
            data["mft_valid_bytes"] = int(vol_buf.MftValidDataLength)
            data["mft_start_lcn"] = int(vol_buf.MftStartLcn)
            data["mft2_start_lcn"] = int(vol_buf.Mft2StartLcn)
            data["mft_zone_clusters"] = int(vol_buf.MftZoneEnd - vol_buf.MftZoneStart)
            data["total_clusters"] = int(vol_buf.TotalClusters)
            data["free_clusters"] = int(vol_buf.FreeClusters)
            estimated_records = int(vol_buf.MftValidDataLength) // max(1, int(vol_buf.BytesPerFileRecordSegment))
            data["estimated_mft_records"] = estimated_records

        # 2. Query USN Journal Data
        usn_buf = USN_JOURNAL_DATA()
        res_usn = kernel32.DeviceIoControl(
            handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            ctypes.byref(usn_buf),
            ctypes.sizeof(usn_buf),
            ctypes.byref(bytes_returned),
            None,
        )

        if res_usn:
            data["can_query_usn_journal"] = True
            data["usn_journal_id"] = hex(usn_buf.UsnJournalID)
            data["next_usn"] = int(usn_buf.NextUsn)
            data["maximum_journal_size_bytes"] = int(usn_buf.MaximumSize)
            data["allocation_delta_bytes"] = int(usn_buf.AllocationDelta)

    finally:
        kernel32.CloseHandle(handle)

    return data


def collect_ntfs_mft_status(root: str = "C:\\") -> CollectorResult:
    """CollectorResult wrapper for NTFS MFT and volume geometry auditing."""
    if not IS_WINDOWS:
        return CollectorResult(
            name="ntfs_mft_status",
            ok=False,
            data=None,
            error="Windows-only collector",
            applicable=False,
        )

    try:
        data = inspect_ntfs_volume_metadata(root)
        ok = bool(data.get("is_ntfs") and data.get("can_query_ntfs_data"))
        return CollectorResult(
            name="ntfs_mft_status",
            ok=ok,
            data=data,
            error="" if ok else data.get("error", "Volume is not NTFS or could not query MFT geometry"),
        )
    except Exception as exc:
        return CollectorResult(
            name="ntfs_mft_status",
            ok=False,
            data=None,
            error=f"{type(exc).__name__}: {exc}",
        )
