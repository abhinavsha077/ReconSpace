from __future__ import annotations

"""Explicit multi-report trend and capacity analysis.

ReconSpace never creates background history. This module operates only on JSON
reports the user explicitly selected.
"""

import math
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _root_key(report: dict[str, Any]) -> str:
    root = str((report.get("stats") or {}).get("root") or "")
    match = re.match(r"^([A-Za-z]:)", root)
    if match:
        return match.group(1).casefold()
    return os.path.normcase(os.path.normpath(root))


def _snapshot(report: dict[str, Any], index: int) -> dict[str, Any]:
    stats = report.get("stats") or {}
    timestamp = _parse_time(stats.get("finished_at")) or _parse_time(stats.get("started_at"))
    total = stats.get("filesystem_total_bytes")
    free = stats.get("filesystem_free_bytes")
    used = stats.get("filesystem_used_bytes")
    if not isinstance(used, int) and isinstance(total, int) and isinstance(free, int):
        used = total - free
    reclaim = report.get("reclaim_summary") or {}
    return {
        "source_index": index,
        "timestamp": timestamp,
        "timestamp_iso": timestamp.isoformat() if timestamp else "",
        "root": str(stats.get("root") or ""),
        "profile": report.get("profile"),
        "version": report.get("version"),
        "total_bytes": total if isinstance(total, int) else None,
        "used_bytes": used if isinstance(used, int) else None,
        "free_bytes": free if isinstance(free, int) else None,
        "scanned_bytes": stats.get("bytes_seen") if isinstance(stats.get("bytes_seen"), int) else None,
        "files_seen": stats.get("files_seen") if isinstance(stats.get("files_seen"), int) else None,
        "findings": len(report.get("findings") or []),
        "applications": len(report.get("applications") or []),
        "path_reclaimable_nonoverlap_bytes": reclaim.get("path_candidates_nonoverlap_bytes") if isinstance(reclaim.get("path_candidates_nonoverlap_bytes"), int) else None,
        "report": report,
    }




def _volume_metric_quality(snapshots: list[dict[str, Any]]) -> tuple[bool, list[str]]:
    """Check whether whole-volume counters are suitable for capacity forecasting."""
    warnings: list[str] = []
    invalid = False
    totals: list[int] = []
    for index, snap in enumerate(snapshots, 1):
        total = snap.get("total_bytes")
        used = snap.get("used_bytes")
        free = snap.get("free_bytes")
        for label, value in (("total", total), ("used", used), ("free", free)):
            if isinstance(value, int) and value < 0:
                warnings.append(f"Snapshot {index} has a negative {label}-space value; capacity forecasting is disabled.")
                invalid = True
        if isinstance(total, int) and total > 0:
            totals.append(total)
            tolerance = max(1024 ** 3, int(total * 0.02))
            if isinstance(used, int) and used > total + tolerance:
                warnings.append(f"Snapshot {index} reports used space greater than total capacity; capacity forecasting is disabled.")
                invalid = True
            if isinstance(free, int) and free > total + tolerance:
                warnings.append(f"Snapshot {index} reports free space greater than total capacity; capacity forecasting is disabled.")
                invalid = True
            if isinstance(used, int) and isinstance(free, int) and abs((used + free) - total) > tolerance:
                warnings.append(f"Snapshot {index} has materially inconsistent total/used/free counters; capacity forecasting is disabled.")
                invalid = True
    if len(totals) >= 2:
        largest = max(totals)
        if largest and max(totals) - min(totals) > max(1024 ** 3, int(largest * 0.02)):
            warnings.append("Reported volume capacity changed materially between snapshots; full-drive forecasting is disabled.")
            invalid = True
    return not invalid, warnings

def _linear_regression(points: list[tuple[float, float]]) -> dict[str, float] | None:
    if len(points) < 3:
        return None
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    x_mean = sum(xs) / len(xs)
    y_mean = sum(ys) / len(ys)
    denominator = sum((x - x_mean) ** 2 for x in xs)
    if denominator <= 0:
        return None
    slope = sum((x - x_mean) * (y - y_mean) for x, y in points) / denominator
    intercept = y_mean - slope * x_mean
    predicted = [intercept + slope * x for x in xs]
    ss_res = sum((y - p) ** 2 for y, p in zip(ys, predicted))
    ss_tot = sum((y - y_mean) ** 2 for y in ys)
    r_squared = 1.0 - ss_res / ss_tot if ss_tot > 0 else 1.0
    return {"slope_per_day": slope, "intercept": intercept, "r_squared": max(-1.0, min(1.0, r_squared))}


def _nonoverlap_growth_rows(snapshots: list[dict[str, Any]], key: str, size_field: str, path_field: str, limit: int) -> list[dict[str, Any]]:
    by_path: dict[str, dict[int, int]] = {}
    display: dict[str, str] = {}
    for snap_index, snap in enumerate(snapshots):
        rows = snap["report"].get(key) or []
        for row in rows:
            if not isinstance(row, dict):
                continue
            path = str(row.get(path_field) or "")
            size = row.get(size_field)
            if not path or not isinstance(size, int):
                continue
            normalized = os.path.normcase(os.path.normpath(path))
            by_path.setdefault(normalized, {})[snap_index] = size
            display.setdefault(normalized, path)
    result: list[dict[str, Any]] = []
    first_idx = 0
    last_idx = len(snapshots) - 1
    for path, values in by_path.items():
        if first_idx not in values and last_idx not in values:
            continue
        first = values.get(first_idx, 0)
        last = values.get(last_idx, 0)
        result.append({
            "path": display[path],
            "first_bytes": first,
            "last_bytes": last,
            "delta_bytes": last - first,
            "observations": len(values),
            "series": [values.get(i) for i in range(len(snapshots))],
        })
    result.sort(key=lambda row: abs(row["delta_bytes"]), reverse=True)
    return result[:limit]


def analyze_trend(reports: Iterable[dict[str, Any]], top_paths: int = 50) -> dict[str, Any]:
    materialized = [r for r in reports if isinstance(r, dict)]
    if len(materialized) < 2:
        raise ValueError("trend analysis requires at least two reports")
    snapshots = [_snapshot(report, i) for i, report in enumerate(materialized)]
    if all(s["timestamp"] for s in snapshots):
        snapshots.sort(key=lambda s: s["timestamp"])

    warnings: list[str] = []
    roots = {_root_key(s["report"]) for s in snapshots}
    same_volume = len(roots) == 1 and "" not in roots
    if not same_volume:
        warnings.append("Reports do not all describe the same drive/root; capacity forecasting is disabled.")
    profiles = {str(s.get("profile") or "") for s in snapshots}
    if len(profiles) > 1:
        warnings.append("Scan profiles differ, so retained top-N lists and findings can have different coverage.")
    if any(not s["timestamp"] for s in snapshots):
        warnings.append("One or more reports lack a parseable timestamp; chronological trend confidence is reduced.")

    metric_quality_ok, metric_warnings = _volume_metric_quality(snapshots)
    warnings.extend(metric_warnings)

    public_snapshots = [{k: v for k, v in snap.items() if k not in {"report", "timestamp"}} for snap in snapshots]
    capacity: dict[str, Any] = {
        "available": False,
        "method": "ordinary least squares over explicit report timestamps",
        "forecast_is_estimate": True,
        "warnings": [],
    }
    timed = [(s["timestamp"], s["used_bytes"], s["free_bytes"], s["total_bytes"]) for s in snapshots if s["timestamp"] and isinstance(s["used_bytes"], int)]
    if same_volume and metric_quality_ok and len(timed) >= 3:
        origin = timed[0][0]
        points = [((ts - origin).total_seconds() / 86400.0, float(used)) for ts, used, _, _ in timed]
        fit = _linear_regression(points)
        span_days = points[-1][0] - points[0][0]
        if fit:
            capacity.update({
                "available": True,
                "observations": len(points),
                "span_days": span_days,
                "growth_bytes_per_day": fit["slope_per_day"],
                "growth_bytes_per_30_days": fit["slope_per_day"] * 30.4375,
                "r_squared": fit["r_squared"],
            })
            latest = snapshots[-1]
            if fit["slope_per_day"] > 0 and isinstance(latest["free_bytes"], int):
                days_to_full = latest["free_bytes"] / fit["slope_per_day"]
                if math.isfinite(days_to_full) and days_to_full >= 0:
                    capacity["estimated_days_to_full"] = days_to_full
                    if latest["timestamp"]:
                        capacity["estimated_full_date"] = (latest["timestamp"] + timedelta(days=days_to_full)).date().isoformat()
            else:
                capacity["estimated_days_to_full"] = None
                capacity["estimated_full_date"] = None
                capacity["warnings"].append("Observed storage use is flat or decreasing; no full-drive date is projected.")
            if span_days < 14:
                capacity["warnings"].append("The observation window is under 14 days; the forecast is highly sensitive to short-lived changes.")
            if fit["r_squared"] < 0.5:
                capacity["warnings"].append("The linear fit is weak; storage growth is irregular and the date projection should not be relied on.")
        else:
            capacity["warnings"].append("Timestamps do not span enough time for regression.")
    else:
        if not metric_quality_ok:
            capacity["warnings"].append("Whole-volume counters are inconsistent or the volume capacity changed materially; forecasting is disabled.")
        else:
            capacity["warnings"].append("At least three timestamped reports from the same drive are required for capacity forecasting.")

    first = snapshots[0]
    last = snapshots[-1]
    free_delta = None
    used_delta = None
    if same_volume and isinstance(first["free_bytes"], int) and isinstance(last["free_bytes"], int):
        free_delta = last["free_bytes"] - first["free_bytes"]
    if same_volume and isinstance(first["used_bytes"], int) and isinstance(last["used_bytes"], int):
        used_delta = last["used_bytes"] - first["used_bytes"]

    directory_growth = _nonoverlap_growth_rows(snapshots, "top_directories", "size_bytes", "path", top_paths)
    file_growth = _nonoverlap_growth_rows(snapshots, "top_files", "size_bytes", "path", top_paths)

    app_history: dict[str, list[tuple[int, int]]] = {}
    app_display: dict[str, str] = {}
    for idx, snap in enumerate(snapshots):
        for app in snap["report"].get("applications") or []:
            if not isinstance(app, dict) or not isinstance(app.get("estimated_size_bytes"), int):
                continue
            identity = "|".join([
                str(app.get("name") or "").casefold(),
                str(app.get("publisher") or "").casefold(),
                os.path.normcase(os.path.normpath(str(app.get("install_location") or ""))),
            ])
            app_history.setdefault(identity, []).append((idx, app["estimated_size_bytes"]))
            app_display.setdefault(identity, str(app.get("name") or "(unnamed)"))
    app_changes: list[dict[str, Any]] = []
    for identity, values in app_history.items():
        lookup = dict(values)
        first_size = lookup.get(0)
        last_size = lookup.get(len(snapshots) - 1)
        if first_size is None and last_size is None:
            continue
        first_value = first_size or 0
        last_value = last_size or 0
        app_changes.append({
            "name": app_display[identity],
            "first_bytes": first_value,
            "last_bytes": last_value,
            "delta_bytes": last_value - first_value,
            "observations": len(values),
        })
    app_changes.sort(key=lambda row: abs(row["delta_bytes"]), reverse=True)

    return {
        "report_count": len(snapshots),
        "same_volume": same_volume,
        "warnings": warnings,
        "snapshots": public_snapshots,
        "free_space_delta_bytes": free_delta,
        "used_space_delta_bytes": used_delta,
        "capacity_forecast": capacity,
        "directory_growth": directory_growth,
        "file_growth": file_growth,
        "application_changes": app_changes[:top_paths],
        "methodology": [
            "Only explicitly supplied reports are analyzed; ReconSpace creates no automatic history database.",
            "Path growth is limited to entries retained in each report's top-N tables, so absence does not prove a path did not exist.",
            "Forecasts assume a linear continuation of observed whole-volume used space and are planning hints, not guarantees.",
        ],
    }
