from __future__ import annotations

import json
import ntpath
import os
from pathlib import Path
from typing import Any

MAX_REPORT_BYTES = 256 * 1024 * 1024
REPORT_LIST_SECTIONS = (
    "findings", "top_files", "top_directories", "applications", "duplicates",
    "startup", "services", "scheduled_tasks", "processes", "binary_trust",
    "path_security", "collectors",
)


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def load_report(path: str, max_bytes: int = MAX_REPORT_BYTES) -> dict[str, Any]:
    source = Path(path).expanduser()
    if not source.is_file():
        raise ValueError(f"Report path is not a readable file: {source}")
    size = source.stat().st_size
    if size > max_bytes:
        raise ValueError(f"Report is too large ({size:,} bytes; maximum {max_bytes:,})")
    data = json.loads(source.read_text(encoding="utf-8"), parse_constant=_reject_json_constant)
    if not isinstance(data, dict) or not isinstance(data.get("stats"), dict):
        raise ValueError("Not a ReconSpace-style report JSON: missing stats object")
    for key in REPORT_LIST_SECTIONS:
        if key in data and not isinstance(data[key], list):
            raise ValueError(f"Not a ReconSpace-style report JSON: {key} must be a list")
        if key in data and any(not isinstance(row, dict) for row in data[key]):
            raise ValueError(f"Not a ReconSpace-style report JSON: {key} entries must be objects")
    return data


def _path_map(rows: list[dict[str, Any]], size_key: str = "size_bytes") -> dict[str, int]:
    out: dict[str, int] = {}
    for row in rows or []:
        path = str(row.get("path") or "")
        if path:
            out[path.casefold()] = int(row.get(size_key) or 0)
    return out


def _top_deltas(old_rows: list[dict[str, Any]], new_rows: list[dict[str, Any]], limit: int = 50) -> list[dict[str, Any]]:
    old = _path_map(old_rows)
    new = _path_map(new_rows)
    display = {str(r.get("path") or "").casefold(): str(r.get("path") or "") for r in (new_rows or []) + (old_rows or [])}
    rows = []
    for key in old.keys() | new.keys():
        before, after = old.get(key, 0), new.get(key, 0)
        if after != before:
            rows.append({"path": display.get(key, key), "before_bytes": before, "after_bytes": after, "delta_bytes": after - before})
    rows.sort(key=lambda x: abs(x["delta_bytes"]), reverse=True)
    return rows[:limit]


def _finding_key(row: dict[str, Any]) -> str:
    return f"{str(row.get('title') or '').casefold()}|{str(row.get('path') or '').casefold()}"


def _application_key(row: dict[str, Any]) -> str:
    return "|".join([
        str(row.get("name") or "").casefold(),
        str(row.get("publisher") or "").casefold(),
        str(row.get("scope") or "").casefold(),
        str(row.get("architecture") or "").casefold(),
        str(row.get("package_type") or "").casefold(),
    ])


def _volume_key(path: str) -> str:
    drive, _ = ntpath.splitdrive(str(path or ""))
    if drive:
        return drive.casefold()
    try:
        absolute = os.path.abspath(path)
        if os.path.isabs(absolute):
            return os.path.sep
        return absolute.casefold()
    except Exception:
        return ""


def compare_reports(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    old_stats, new_stats = old.get("stats") or {}, new.get("stats") or {}
    old_root, new_root = str(old_stats.get("root") or ""), str(new_stats.get("root") or "")
    same_root = old_root.replace("/", "\\").rstrip("\\").casefold() == new_root.replace("/", "\\").rstrip("\\").casefold()
    old_volume, new_volume = _volume_key(old_root), _volume_key(new_root)
    legacy_volume_unknown = not old_root and not new_root
    same_volume = legacy_volume_unknown or bool(old_volume and old_volume == new_volume)
    same_profile = str(old.get("profile") or "") == str(new.get("profile") or "")
    warnings: list[str] = []
    if legacy_volume_unknown:
        warnings.append("Legacy reports do not contain scan roots; free-space delta is shown but same-volume identity cannot be verified.")
    elif not same_root:
        warnings.append("Scan roots differ; top-file/top-directory and finding deltas are not directly comparable as one inventory.")
    if not same_profile:
        warnings.append("Scan profiles differ; retention limits, duplicate thresholds and collector depth may differ.")
    if old_stats.get("scan_cancelled") or new_stats.get("scan_cancelled"):
        warnings.append("At least one scan was cancelled; comparison coverage is incomplete.")
    if int(old_stats.get("access_denied") or 0) != int(new_stats.get("access_denied") or 0):
        warnings.append("Access-denied counts changed; some deltas may reflect coverage differences rather than actual storage changes.")

    old_findings = {_finding_key(x): x for x in old.get("findings", [])}
    new_findings = {_finding_key(x): x for x in new.get("findings", [])}
    added_findings = [new_findings[k] for k in new_findings.keys() - old_findings.keys()]
    resolved_findings = [old_findings[k] for k in old_findings.keys() - new_findings.keys()]
    changed_findings = []
    for key in old_findings.keys() & new_findings.keys():
        before, after = int(old_findings[key].get("size_bytes") or 0), int(new_findings[key].get("size_bytes") or 0)
        old_reclaim = int(old_findings[key].get("estimated_reclaimable_bytes") or 0)
        new_reclaim = int(new_findings[key].get("estimated_reclaimable_bytes") or 0)
        if before != after or old_reclaim != new_reclaim:
            changed_findings.append({
                "title": new_findings[key].get("title"), "path": new_findings[key].get("path"),
                "before_bytes": before, "after_bytes": after, "delta_bytes": after - before,
                "before_reclaimable_bytes": old_reclaim, "after_reclaimable_bytes": new_reclaim,
                "reclaimable_delta_bytes": new_reclaim - old_reclaim,
                "disposition": new_findings[key].get("disposition"),
            })
    changed_findings.sort(key=lambda x: abs(x["delta_bytes"]), reverse=True)

    old_apps = {_application_key(x): x for x in old.get("applications", [])}
    new_apps = {_application_key(x): x for x in new.get("applications", [])}
    app_added = [new_apps[k] for k in new_apps.keys() - old_apps.keys()]
    app_removed = [old_apps[k] for k in old_apps.keys() - new_apps.keys()]
    app_changed = []
    for key in old_apps.keys() & new_apps.keys():
        ov, nv = str(old_apps[key].get("version") or ""), str(new_apps[key].get("version") or "")
        osize, nsize = int(old_apps[key].get("estimated_size_bytes") or 0), int(new_apps[key].get("estimated_size_bytes") or 0)
        if ov != nv or osize != nsize:
            app_changed.append({"name": new_apps[key].get("name"), "old_version": ov, "new_version": nv,
                                "old_size_bytes": osize, "new_size_bytes": nsize, "delta_bytes": nsize - osize})

    old_free, new_free = old_stats.get("filesystem_free_bytes"), new_stats.get("filesystem_free_bytes")
    free_delta = new_free - old_free if same_volume and isinstance(old_free, int) and isinstance(new_free, int) else None
    old_reclaim, new_reclaim = old.get("reclaim_summary") or {}, new.get("reclaim_summary") or {}

    return {
        "old_version": old.get("version", "unknown"), "new_version": new.get("version", "unknown"),
        "old_schema_version": old.get("schema_version"), "new_schema_version": new.get("schema_version"),
        "old_finished_at": old_stats.get("finished_at", ""), "new_finished_at": new_stats.get("finished_at", ""),
        "same_root": same_root, "same_volume": same_volume, "same_profile": same_profile, "warnings": warnings,
        "free_space_delta_bytes": free_delta,
        "traversed_bytes_delta": int(new_stats.get("bytes_seen") or 0) - int(old_stats.get("bytes_seen") or 0),
        "files_seen_delta": int(new_stats.get("files_seen") or 0) - int(old_stats.get("files_seen") or 0),
        "access_denied_delta": int(new_stats.get("access_denied") or 0) - int(old_stats.get("access_denied") or 0),
        "conservative_path_reclaim_delta_bytes": int(new_reclaim.get("path_candidates_nonoverlap_bytes") or 0) - int(old_reclaim.get("path_candidates_nonoverlap_bytes") or 0),
        "directory_deltas": _top_deltas(old.get("top_directories", []), new.get("top_directories", [])),
        "file_deltas": _top_deltas(old.get("top_files", []), new.get("top_files", [])),
        "added_findings": sorted(added_findings, key=lambda x: int(x.get("size_bytes") or 0), reverse=True)[:100],
        "resolved_findings": sorted(resolved_findings, key=lambda x: int(x.get("size_bytes") or 0), reverse=True)[:100],
        "changed_findings": changed_findings[:100],
        "applications_added": sorted(app_added, key=lambda x: int(x.get("estimated_size_bytes") or 0), reverse=True),
        "applications_removed": sorted(app_removed, key=lambda x: int(x.get("estimated_size_bytes") or 0), reverse=True),
        "applications_changed": sorted(app_changed, key=lambda x: abs(int(x.get("delta_bytes") or 0)), reverse=True),
        "caveat": "Top file/directory deltas compare retained top-N entries, not a full per-object historical index. Free-space delta is only emitted for reports on the same volume.",
    }
