from __future__ import annotations

"""Helpers for conservative logical-vs-physical reclaim estimates."""

from typing import Any


def file_reclaim_basis(record: Any, fraction: float = 1.0) -> tuple[int, dict[str, Any]]:
    """Return a conservative physical reclaim estimate and its evidence.

    A path with multiple hard links does not independently own its allocated
    clusters, so deleting only that path has no guaranteed physical reclaim.
    Otherwise allocated/size-on-disk bytes are preferred when available; logical
    size is retained only as an explicitly labeled fallback estimate.
    """
    logical = max(0, int(getattr(record, "size_bytes", 0) or 0))
    links = max(1, int(getattr(record, "link_count", 1) or 1))
    allocated_raw = getattr(record, "allocated_bytes", None)
    allocated = int(allocated_raw) if isinstance(allocated_raw, int) and allocated_raw >= 0 else None
    fraction = max(0.0, min(1.0, float(fraction)))

    evidence: dict[str, Any] = {
        "logical_size_bytes": logical,
        "allocated_size_bytes": allocated,
        "link_count": links,
    }
    if links > 1:
        evidence.update({
            "reclaim_basis": "hardlink_path_no_independent_reclaim",
            "reclaim_estimate_caveat": "This path has multiple hard links; removing one name alone may free no clusters.",
        })
        return 0, evidence
    if allocated is not None:
        evidence["reclaim_basis"] = "allocated_size_on_disk"
        return max(0, int(allocated * fraction)), evidence
    evidence.update({
        "reclaim_basis": "logical_size_fallback",
        "reclaim_estimate_caveat": "Allocated size was unavailable, so this is a logical-size estimate and may overstate sparse/compressed/cloud storage impact.",
    })
    return max(0, int(logical * fraction)), evidence


def directory_reclaim_evidence() -> dict[str, Any]:
    return {
        "reclaim_basis": "logical_namespace_estimate",
        "reclaim_estimate_caveat": (
            "Directory totals are logical namespace sizes. NTFS hard links, sparse/compressed files and cloud placeholders can make actual physical reclaim differ."
        ),
    }
