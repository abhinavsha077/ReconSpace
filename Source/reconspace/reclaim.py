from __future__ import annotations

import os
from typing import Iterable

from .models import Finding


def _path_key(path: str) -> str:
    p = str(path or "").replace("/", "\\").rstrip("\\").casefold()
    return p


def _is_descendant(child: str, parent: str) -> bool:
    c = _path_key(child)
    p = _path_key(parent)
    return bool(c and p and c != p and c.startswith(p + "\\"))


def _scope_type(f: Finding) -> str:
    return str((f.evidence or {}).get("scope_type") or "")


def build_reclaim_summary(findings: Iterable[Finding]) -> dict:
    """Build conservative, non-additive reclaim summaries.

    Finding-level reclaim estimates are useful for triage but cannot simply be
    summed: a cache folder can contain a flagged file, duplicate groups can overlap
    archive findings, and an app uninstall estimate overlaps its install directory.
    This summary keeps path-scoped candidates separate from duplicate/application
    alternatives and suppresses descendants covered by a full-reclaim parent.
    """
    rows = [
        f for f in findings
        if f.disposition in {"probably_safe_cleanup", "manual_review"}
        and f.estimated_reclaimable_bytes > 0
    ]

    duplicate_bytes = sum(
        f.estimated_reclaimable_bytes for f in rows
        if _scope_type(f) == "duplicate_group" or f.category == "Duplicates"
    )
    platform_bytes = sum(
        f.estimated_reclaimable_bytes for f in rows
        if _scope_type(f) == "platform"
    )
    application_bytes = sum(
        f.estimated_reclaimable_bytes for f in rows
        if _scope_type(f) == "application" or f.category == "Installed applications"
    )

    path_rows = [f for f in rows if _scope_type(f) in {"file", "folder"}]
    # Parent paths first. For equal depth, safer/higher-confidence candidates win.
    disposition_order = {"probably_safe_cleanup": 0, "manual_review": 1}
    path_rows.sort(key=lambda f: (
        _path_key(f.path).count("\\"),
        disposition_order.get(f.disposition, 9),
        -f.priority_score,
    ))

    selected: list[Finding] = []
    suppressed = 0
    for f in path_rows:
        covered = False
        for parent in selected:
            if _scope_type(parent) != "folder":
                continue
            # Only a near-full parent reclaim estimate can cover descendants.
            parent_fraction = parent.estimated_reclaimable_bytes / max(1, parent.size_bytes)
            if parent_fraction >= 0.95 and _is_descendant(f.path, parent.path):
                covered = True
                break
        if covered:
            suppressed += 1
        else:
            selected.append(f)

    safe = sum(f.estimated_reclaimable_bytes for f in selected if f.disposition == "probably_safe_cleanup")
    manual = sum(f.estimated_reclaimable_bytes for f in selected if f.disposition == "manual_review")

    return {
        "path_candidates_nonoverlap_bytes": safe + manual,
        "probably_safe_path_bytes": safe,
        "manual_review_path_bytes": manual,
        "duplicate_potential_bytes_separate": duplicate_bytes,
        "application_potential_bytes_separate": application_bytes,
        "platform_potential_bytes_separate": platform_bytes,
        "selected_path_candidates": len(selected),
        "suppressed_overlapping_path_findings": suppressed,
        "actionable_findings_total": len(rows),
        "note": (
            "Path candidate totals suppress descendant findings covered by a full-reclaim parent. "
            "Duplicate, application and platform potentials are shown separately because they can overlap path candidates and are not additive."
        ),
    }
