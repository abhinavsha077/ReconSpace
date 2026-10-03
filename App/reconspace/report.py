from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .classify import CATEGORY_GROUPS, resolve_category_group
from .models import Finding, ScanReport


DISPOSITION_LABELS: dict[str, str] = {
    "probably_safe_cleanup": "Probably Safe Cleanup",
    "manual_review": "Manual Review",
    "intentional_tooling": "Developer / Cyber Tooling",
    "do_not_touch": "Protected / Do Not Touch",
    "informational": "Informational",
}


def format_bytes(value: int | None) -> str:
    if value is None:
        return "Unknown"
    size = float(value)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if abs(size) < 1024.0 or unit == units[-1]:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} B"
        size /= 1024.0
    return f"{size:.1f} PB"


def report_json(report: ScanReport, pretty: bool = True) -> str:
    return json.dumps(report.to_dict(), indent=2 if pretty else None, ensure_ascii=False)


def write_json(report: ScanReport, destination: str) -> Path:
    """Explicit export only; normal scanning does not write reports automatically."""
    path = Path(destination).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report_json(report, pretty=True), encoding="utf-8")
    return path


def report_markdown(report: ScanReport | dict[str, Any], max_items: int = 40) -> str:
    lines: list[str] = []
    if isinstance(report, dict):
        s_raw = report.get("stats") or {}
        reclaim = report.get("reclaim_summary") or {}
        health = report.get("audit_health") or {}
        profile = report.get("profile", "")
        version = report.get("version", "")
        raw_findings = report.get("findings") or []
    else:
        s_raw = report.stats
        reclaim = report.reclaim_summary or {}
        health = report.audit_health or {}
        profile = report.profile
        version = report.version
        raw_findings = report.findings or []

    def _stat(key: str, default=0):
        if isinstance(s_raw, dict):
            return s_raw.get(key, default)
        return getattr(s_raw, key, default)

    root = _stat("root", "")
    total_fs = _stat("filesystem_total_bytes", 0)
    used_fs = _stat("filesystem_used_bytes", 0)
    free_fs = _stat("filesystem_free_bytes", 0)
    files_seen = _stat("files_seen", 0)
    directories_seen = _stat("directories_seen", 0)
    bytes_seen = _stat("bytes_seen", 0)
    duration_seconds = _stat("duration_seconds", 0.0)

    findings_list: list[Finding] = []
    for f in raw_findings:
        if isinstance(f, Finding):
            findings_list.append(f)
        elif isinstance(f, dict):
            findings_list.append(Finding(
                title=f.get("title", ""),
                path=f.get("path", ""),
                size_bytes=int(f.get("size_bytes") or 0),
                category=f.get("category", "other"),
                disposition=f.get("disposition", "manual_review"),
                risk=f.get("risk", "medium"),
                confidence=f.get("confidence", "medium"),
                why_it_exists=f.get("why_it_exists", ""),
                recommendation=f.get("recommendation", ""),
                removal_risk=f.get("removal_risk", ""),
                estimated_reclaimable_bytes=int(f.get("estimated_reclaimable_bytes") or 0),
                age_days=f.get("age_days"),
                related_to=f.get("related_to") or [],
                category_group=f.get("category_group", ""),
                evidence=f.get("evidence") or {},
                priority_score=float(f.get("priority_score") or 0.0),
            ))

    used_pct = f" ({int(used_fs / total_fs * 100)}%)" if total_fs and used_fs else ""
    free_pct = (free_fs / total_fs * 100) if total_fs else None
    storage_state = "unknown" if free_pct is None else "critical" if free_pct < 5 else "low" if free_pct < 10 else "watch" if free_pct < 15 else "healthy"
    safe_rows = [f for f in findings_list if f.disposition == "probably_safe_cleanup" and f.estimated_reclaimable_bytes > 0]
    review_rows = [f for f in findings_list if f.disposition == "manual_review" and f.estimated_reclaimable_bytes > 0]
    protected_rows = [f for f in findings_list if f.disposition in {"intentional_tooling", "do_not_touch"}]
    next_step = (
        f"Review the {len(safe_rows)} probably-safe candidate(s) first, confirm no active work, then use each owning tool's supported cleanup workflow."
        if safe_rows else
        f"Review the {len(review_rows)} manual candidate(s) for ownership, current use, backups and retention before approving anything."
        if review_rows else
        "No direct path cleanup candidate needs action. Review application and platform opportunities separately if more space is needed."
    )

    lines += [
        "# ReconSpace Storage Intelligence Report",
        "",
        "> **100% READ-ONLY AUDIT** · Zero mutations executed. All findings require manual review and explicit approval.",
        "",
        "## System Storage Overview",
        "",
        f"- **Scan Root:** `{root}`",
        f"- **Scan Profile:** {profile} | **ReconSpace Version:** v{version}",
        f"- **Volume Capacity:** {format_bytes(used_fs)} used of {format_bytes(total_fs)}{used_pct} | **{format_bytes(free_fs)} free**",
        f"- **Files Traversed:** {files_seen:,} files across {directories_seen:,} directories ({format_bytes(bytes_seen)}) in {duration_seconds:.1f}s",
        f"- **Audit Coverage Quality:** **{health.get('coverage_grade', 'unknown')}** ({health.get('coverage_score', 'n/a')}/100)",
        "",
        "## What This Audit Means",
        "",
        f"- **Storage state:** **{storage_state.upper()}**" + (f" ({free_pct:.1f}% free)" if free_pct is not None else ""),
        f"- **Probably-safe candidates:** {len(safe_rows)} | **Manual-review candidates:** {len(review_rows)} | **Protected/tooling findings:** {len(protected_rows)}",
        f"- **Recommended next move:** {next_step}",
        f"- **Scope:** File/folder sizes, duplicates and path candidates are limited to `{root}`. Installed apps, processes, startup entries, services, scheduled tasks, WSL/Docker, trust and Windows platform evidence describe the wider host.",
        "- **Meaning of coverage:** The score measures evidence completeness. It is not a cleanliness, security or malware score.",
        "",
        "## Reclaimable Space Summary",
        "",
        f"- **Conservative Non-Overlapping Path Candidates:** **{format_bytes(int(reclaim.get('path_candidates_nonoverlap_bytes') or 0))}**",
        f"  - Probably-safe cleanup candidates: **{format_bytes(int(reclaim.get('probably_safe_path_bytes') or 0))}**",
        f"  - Manual-review candidates: **{format_bytes(int(reclaim.get('manual_review_path_bytes') or 0))}**",
        f"- **Exact Duplicate Potential (Separate / Non-additive):** **{format_bytes(int(reclaim.get('duplicate_potential_bytes_separate') or 0))}**",
        f"- **Application Potential (Separate / Non-additive):** **{format_bytes(int(reclaim.get('application_potential_bytes_separate') or 0))}**",
        f"- **Platform Potential (Separate / Non-additive):** **{format_bytes(int(reclaim.get('platform_potential_bytes_separate') or 0))}**",
        "",
        "> *Note: Path candidates, duplicates, and applications can overlap. Categories are intentionally not added together to avoid double-counting.*",
        "",
        "---",
        "",
        "## Audit Depth and Limitations",
        "",
    ]

    depth_domains = health.get("depth_domains") or []
    if depth_domains:
        for domain in depth_domains:
            status = str(domain.get("status") or "unknown").replace("_", " ").upper()
            limitations = ", ".join(str(x).replace("_", " ") for x in (domain.get("limitations") or [])[:6])
            lines.append(
                f"- **{domain.get('title', 'Evidence domain')}: {status}** — "
                f"{domain.get('checks_succeeded', 0)}/{domain.get('checks_requested', 0)} applicable checks succeeded"
                + (f"; limited/unavailable: {limitations}" if limitations else "")
            )
    else:
        lines.append("- Domain-level depth data is unavailable in this report version; inspect raw collector results.")

    lines += [
        "",
        "## Recommended Review Workflow",
        "",
        "1. Read coverage limitations before trusting a zero or missing category.",
        "2. Review probably-safe candidates first; 'probably safe' still requires confirmation that no related job or application is active.",
        "3. Review manual candidates for ownership, current use, backups, offline requirements and evidence-retention needs.",
        "4. Keep development, cybersecurity, VM, container and forensic data unless its owner confirms it is obsolete.",
        "5. Export an approval plan. ReconSpace performs no cleanup or system modification.",
        "",
        "---",
        "",
        "## Findings Managed by Category",
        "",
    ]

    # Group findings by category group
    grouped: dict[str, list[Finding]] = {}
    for f in findings_list:
        cg = getattr(f, "category_group", "") or resolve_category_group(f.category)
        grouped.setdefault(cg, []).append(f)

    if not findings_list:
        lines += ["*No actionable findings were identified for this scan root.*", ""]
    else:
        ordered_keys = [k for k in CATEGORY_GROUPS if k in grouped]
        for k in grouped:
            if k not in ordered_keys:
                ordered_keys.append(k)

        items_shown = 0
        for group_key in ordered_keys:
            if items_shown >= max_items:
                break
            group_findings = grouped[group_key]
            meta = CATEGORY_GROUPS.get(group_key, {
                "title": group_key.replace("_", " ").title(),
                "icon": "📁",
                "summary": "Storage items identified in this category.",
            })
            total_size = sum(f.size_bytes for f in group_findings)
            reclaim_size = sum(f.estimated_reclaimable_bytes for f in group_findings)

            lines += [
                f"### {meta.get('title', group_key)}",
                "",
                f"*{meta.get('summary', '')}*",
                "",
                f"> **Category Total:** {format_bytes(total_size)} observed | **{format_bytes(reclaim_size)} estimated reclaimable** across {len(group_findings)} item(s)",
                "",
            ]

            for f in group_findings:
                if items_shown >= max_items:
                    break
                items_shown += 1
                disp_label = DISPOSITION_LABELS.get(f.disposition, f.disposition)
                lines += [
                    f"#### {f.title} — {format_bytes(f.size_bytes)} [{disp_label}]",
                    f"- **Path:** `{f.path}`",
                    f"- **Estimated Reclaimable:** **{format_bytes(f.estimated_reclaimable_bytes)}** (Observed: {format_bytes(f.size_bytes)})",
                    f"- **Status / Risk:** `{disp_label}` | Risk: `{f.risk}` | Priority Score: `{f.priority_score:.1f}`",
                    f"- **Why it exists:** {f.why_it_exists}",
                    f"- **Recommended action:** {f.recommendation}",
                    f"- **Risk if removed:** {f.removal_risk}",
                    "",
                ]

    top_files = (report.get("top_files") or []) if isinstance(report, dict) else (report.top_files or [])
    top_dirs = (report.get("top_directories") or []) if isinstance(report, dict) else (report.top_directories or [])
    ext_summary = (report.get("extension_summary") or []) if isinstance(report, dict) else (report.extension_summary or [])
    artifacts = (report.get("project_artifacts") or []) if isinstance(report, dict) else (report.project_artifacts or [])
    duplicates = (report.get("duplicates") or []) if isinstance(report, dict) else (report.duplicates or [])
    apps = (report.get("applications") or []) if isinstance(report, dict) else (report.applications or [])

    def _val(obj, key, default=None):
        if isinstance(obj, dict):
            return obj.get(key, default)
        return getattr(obj, key, default)

    lines += ["---", "", "## Largest Files", ""]
    for x in top_files[:max_items]:
        sz = _val(x, "size_bytes", 0)
        alloc = _val(x, "allocated_bytes")
        allocated = f"; allocated {format_bytes(alloc)}" if alloc is not None and alloc != sz else ""
        flags = []
        if _val(x, "is_sparse"): flags.append("sparse")
        if _val(x, "is_compressed"): flags.append("compressed")
        if _val(x, "is_reparse"): flags.append("reparse")
        if _val(x, "is_offline"): flags.append("offline/cloud")
        suffix = ("; " + ", ".join(flags)) if flags else ""
        lines.append(f"- {format_bytes(sz)} logical{allocated}{suffix} — `{_val(x, 'path', '')}`")

    lines += ["", "## Largest Directories", ""]
    for x in top_dirs[:max_items]:
        lines.append(f"- {format_bytes(_val(x, 'size_bytes', 0))} recursive / {format_bytes(_val(x, 'direct_size_bytes', 0))} direct — `{_val(x, 'path', '')}`")

    lines += ["", "## Storage by Extension", ""]
    for x in ext_summary[:20]:
        lines.append(f"- {format_bytes(_val(x, 'bytes', 0))} across {int(_val(x, 'files', 0)):,} files — `{_val(x, 'extension', '')}`")

    if artifacts:
        lines += ["", "## Development / Project Artifacts", ""]
        for x in artifacts[:max_items]:
            lines.append(f"- {format_bytes(_val(x, 'size_bytes', 0))} — **{_val(x, 'artifact_type', '')}** — `{_val(x, 'path', '')}`")

    if duplicates:
        lines += ["", "## Exact Duplicate Groups", ""]
        for d in duplicates[:max_items]:
            paths = _val(d, "paths") or []
            sha = _val(d, "sha256", "")
            basis = _val(d, "reclaimable_basis", "")
            lines.append(f"- {format_bytes(_val(d, 'reclaimable_bytes', 0))} potential — {len(paths)} paths / {_val(d, 'distinct_file_instances', 0)} distinct file instances — SHA-256 `{sha[:16]}…` ({basis})")

    if apps:
        lines += ["", "## Installed Applications by Estimated Size", ""]
        for a in apps[:max_items]:
            framework = "; framework/runtime" if _val(a, "is_framework") else ""
            lines.append(f"- {format_bytes(_val(a, 'estimated_size_bytes', 0))} — **{_val(a, 'name', '')}** {_val(a, 'version', '')} — {_val(a, 'classification', '')}{framework}")

    startup_rows = (report.get("startup") or []) if isinstance(report, dict) else (report.startup or [])
    service_rows = (report.get("services") or []) if isinstance(report, dict) else (report.services or [])
    task_rows = (report.get("scheduled_tasks") or []) if isinstance(report, dict) else (report.scheduled_tasks or [])
    rule_pack_info = (report.get("rule_pack_info") or {}) if isinstance(report, dict) else (report.rule_pack_info or {})
    notes = (report.get("notes") or []) if isinstance(report, dict) else (report.notes or [])

    startup_review = [x for x in startup_rows if _val(x, "risk_hint")]
    service_review = [x for x in service_rows if _val(x, "risk_hint")]
    task_review = [x for x in task_rows if _val(x, "risk_hint")]
    if startup_review or service_review or task_review:
        lines += ["", "## Persistence Review Signals", "",
                  f"- Startup items flagged for review: **{len(startup_review)}** / {len(startup_rows)}",
                  f"- Services flagged for review: **{len(service_review)}** / {len(service_rows)}",
                  f"- Scheduled tasks flagged for review: **{len(task_review)}** / {len(task_rows)}"]
        for kind, rows, name_attr in (("Startup", startup_review, "name"), ("Service", service_review, "display_name"), ("Task", task_review, "task_name")):
            for row in rows[:10]:
                lines.append(f"- {kind}: **{_val(row, name_attr, '')}** — {_val(row, 'risk_hint', '')}: {_val(row, 'reason', '')}")

    lines += ["", "## Rule Intelligence", "",
              f"- Rule packs/rules/matches: **{len(rule_pack_info.get('packs') or [])} / {rule_pack_info.get('rules_loaded', 0)} / {rule_pack_info.get('matches', 0)}**",
              f"- Custom code execution capability: **{bool(rule_pack_info.get('custom_code_execution', False))}**"]

    if notes:
        lines += ["", "## Safety & Accuracy Notes", ""]
        lines.extend(f"- {n}" for n in notes)
    return "\n".join(lines)
