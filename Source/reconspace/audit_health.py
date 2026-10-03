from __future__ import annotations

"""Coverage and evidence-quality summary for a ReconSpace audit."""

from typing import Any, Iterable

from .models import CollectorResult, ScanStats


_DEPTH_DOMAINS: tuple[tuple[str, str, str, tuple[str, ...]], ...] = (
    ("storage_map", "Storage map", "Filesystem traversal, volumes, disks, partitions and NTFS evidence.",
     ("filesystem_traversal", "platform_info", "computer_system", "operating_system", "logical_disks", "partitions", "physical_disks", "storage_volumes", "physical_disk_reliability", "storage_pools", "ntfs_info", "usn_journal")),
    ("recovery_system", "Windows storage & recovery", "Pagefile, hibernation capability, restore/VSS, component store and reserved-storage evidence.",
     ("pagefile_usage", "restore_points", "shadow_copies", "shadow_storage", "vss_shadowstorage_text", "power_capabilities", "component_store_analysis", "reserved_storage_state", "compact_os_state", "dedup_status", "bitlocker_status")),
    ("apps_toolchains", "Applications & toolchains", "Installed apps, packages, drivers, SDKs, runtimes and package-manager locations.",
     ("uninstall_registry", "appx_packages", "driver_store_inventory", "dotnet_", "python_launchers", "npm_cache_location", "pip_cache_location", "conda_info", "uv_cache_location", "project_context_summary")),
    ("virtualization", "VMs, WSL & containers", "Hyper-V, WSL and Docker inventory and storage signals.",
     ("hyperv_", "wsl_", "docker_")),
    ("persistence", "Startup & background persistence", "Startup entries, services and scheduled tasks.",
     ("hkcu run", "hklm run", "startup_folder:", "startup_commands_extended", "services", "scheduled_tasks")),
    ("activity_ownership", "Activity & ownership", "Running processes, execution metadata and application-to-data correlation.",
     ("active_processes", "prefetch_metadata", "application_ownership_graph")),
    ("trust_permissions", "Trust & permissions", "Authenticode state and selected path owner/ACL evidence.",
     ("binary_trust_batch_", "path_security_batch_")),
    ("rules_duplicates", "Rules & duplicate proof", "Metadata rule intelligence and exact-duplicate hashing policy/results.",
     ("rule_pack_engine", "duplicate_hash_errors", "duplicate_hash_policy")),
)


def _build_depth_domains(stats: ScanStats, rows: list[CollectorResult]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = [{
        "name": "filesystem_traversal",
        "ok": not stats.scan_cancelled,
        "applicable": True,
        "error": "The filesystem traversal was cancelled." if stats.scan_cancelled else "",
    }]
    evidence.extend({"name": row.name, "ok": row.ok, "applicable": row.applicable, "error": row.error or ""} for row in rows)
    domains: list[dict[str, Any]] = []
    for domain_id, title, description, patterns in _DEPTH_DOMAINS:
        matched = [row for row in evidence if any(pattern in str(row["name"]).lower() for pattern in patterns)]
        applicable = [row for row in matched if row["applicable"] is not False]
        unavailable = [row for row in matched if row["applicable"] is False]
        succeeded = [row for row in applicable if row["ok"]]
        failed = [row for row in applicable if not row["ok"]]
        if applicable and len(succeeded) == len(applicable):
            status = "complete"
        elif succeeded:
            status = "partial"
        elif applicable:
            status = "blocked"
        else:
            status = "not_available"
        domains.append({
            "id": domain_id,
            "title": title,
            "description": description,
            "status": status,
            "checks_succeeded": len(succeeded),
            "checks_requested": len(applicable),
            "checks_not_available": len(unavailable),
            "successful_evidence": [str(row["name"]) for row in succeeded[:8]],
            "limitations": [str(row["name"]) for row in failed[:8]] + [str(row["name"]) for row in unavailable[:8]],
        })
    return domains


def build_audit_health(
    stats: ScanStats,
    collectors: Iterable[CollectorResult],
    *,
    profile: str,
    excluded_paths: Iterable[str] = (),
    duplicate_scan_enabled: bool = False,
    process_count: int = 0,
    process_requested: bool = False,
    process_applicable: bool = True,
    signature_targets: int = 0,
    signature_records: int = 0,
    signature_requested: bool = False,
    signature_applicable: bool = True,
    acl_targets: int = 0,
    acl_records: int = 0,
    acl_requested: bool = False,
    acl_applicable: bool = True,
) -> dict[str, Any]:
    rows = list(collectors)
    exclusions = list(excluded_paths)
    score = 100.0
    issues: list[dict[str, Any]] = []
    strengths: list[str] = []

    if stats.scan_cancelled:
        score -= 55
        issues.append({"severity": "critical", "area": "filesystem", "message": "The filesystem traversal was cancelled before completion."})
    if exclusions:
        penalty = min(25, 5 + len(exclusions) * 2)
        score -= penalty
        issues.append({"severity": "high", "area": "filesystem", "message": f"{len(exclusions)} path(s) were explicitly excluded; those areas have no coverage."})
    if stats.access_denied:
        ratio = stats.access_denied / max(1, stats.directories_seen)
        penalty = min(25, 4 + ratio * 100)
        score -= penalty
        issues.append({"severity": "medium" if ratio < 0.05 else "high", "area": "filesystem", "message": f"Access was denied for {stats.access_denied} location(s)."})
    else:
        strengths.append("No access-denied locations were recorded during traversal.")
    if stats.stat_errors:
        score -= min(15, 2 + stats.stat_errors / 50)
        issues.append({"severity": "medium", "area": "filesystem", "message": f"{stats.stat_errors} filesystem metadata/stat error(s) occurred."})
    if stats.reparse_points_skipped:
        issues.append({"severity": "informational", "area": "filesystem", "message": f"{stats.reparse_points_skipped} reparse directory/junction(s) were intentionally not followed to avoid loops or aliased trees."})
    if stats.cloud_or_offline_files:
        issues.append({"severity": "informational", "area": "cloud files", "message": f"{stats.cloud_or_offline_files} cloud/offline/reparse file(s) were metadata-inventoried but not content-hashed."})
    if stats.metadata_candidate_files_omitted:
        score -= min(8, 2 + stats.metadata_candidate_files_omitted / max(1, stats.metadata_candidate_files_seen) * 8)
        issues.append({
            "severity": "medium",
            "area": "file-rule metadata retention",
            "message": (
                f"The bounded file-candidate pool omitted {stats.metadata_candidate_files_omitted} of "
                f"{stats.metadata_candidate_files_seen} eligible large files; file-rule and some classification coverage is partial for omitted candidates."
            ),
        })

    operational = [row for row in rows if row.name not in {"filesystem_errors", "explicit_exclusions", "duplicate_hash_errors", "duplicate_hash_policy", "reclaim_summary", "project_context_summary"}]
    not_applicable = [row for row in operational if row.applicable is False]
    requested = [row for row in operational if row.applicable is not False]
    succeeded = [row for row in requested if row.ok]
    failed = [row for row in requested if not row.ok]
    if requested:
        success_rate = len(succeeded) / len(requested)
        score -= (1.0 - success_rate) * 25
        if failed:
            issues.append({
                "severity": "medium" if success_rate >= 0.6 else "high",
                "area": "collectors",
                "message": f"{len(failed)} of {len(operational)} optional/platform collectors did not return complete data.",
                "failed_collectors": [row.name for row in failed[:30]],
            })
        else:
            strengths.append("All applicable requested optional/platform collectors completed successfully.")
    else:
        success_rate = None
    if not_applicable:
        strengths.append(f"{len(not_applicable)} optional collector(s) were correctly treated as not applicable/unavailable rather than failed coverage.")

    if duplicate_scan_enabled:
        strengths.append("Exact duplicate verification was enabled with staged content hashing.")
        if stats.duplicate_hash_policy_skipped_files:
            issues.append({"severity": "informational", "area": "duplicates", "message": f"{stats.duplicate_hash_policy_skipped_files} candidate file(s) were skipped by size/state/cloud hashing policy."})
    else:
        score -= 4
        issues.append({"severity": "informational", "area": "duplicates", "message": "Exact duplicate hashing was disabled for this profile/scan."})

    if profile in {"deep", "forensics"}:
        if not process_requested:
            issues.append({"severity": "informational", "area": "processes", "message": "Active-process context was not requested for this scan."})
        elif not process_applicable:
            issues.append({"severity": "informational", "area": "processes", "message": "Active-process collection was not applicable or available on this host."})
        elif process_count:
            strengths.append(f"Active-process context was captured for {process_count} process(es).")
        else:
            score -= 3
            issues.append({"severity": "informational", "area": "processes", "message": "The applicable active-process collector returned no process records."})

        if not signature_requested:
            issues.append({"severity": "informational", "area": "binary trust", "message": "Local Authenticode collection was not requested for this scan."})
        elif not signature_applicable:
            issues.append({"severity": "informational", "area": "binary trust", "message": "Local Authenticode collection was not applicable or available on this host."})
        elif signature_targets:
            coverage = signature_records / max(1, signature_targets)
            if coverage < 0.8:
                score -= min(8, (1 - coverage) * 10)
                issues.append({"severity": "medium", "area": "binary trust", "message": f"Signature metadata was returned for {signature_records} of {signature_targets} selected target(s)."})
            else:
                strengths.append(f"Local Authenticode metadata covered {signature_records} selected persistence binary target(s).")
        else:
            strengths.append("No eligible persistence binary targets were selected for Authenticode inspection.")

        if not acl_requested:
            issues.append({"severity": "informational", "area": "permissions", "message": "Owner/ACL collection was not requested for this scan."})
        elif not acl_applicable:
            issues.append({"severity": "informational", "area": "permissions", "message": "Owner/ACL collection was not applicable or available on this host."})
        elif acl_targets:
            coverage = acl_records / max(1, acl_targets)
            if coverage < 0.8:
                score -= min(8, (1 - coverage) * 10)
                issues.append({"severity": "medium", "area": "permissions", "message": f"Owner/ACL metadata was returned for {acl_records} of {acl_targets} selected path(s)."})
            else:
                strengths.append(f"Owner/ACL metadata covered {acl_records} selected high-value path(s).")
        else:
            strengths.append("No eligible high-value paths were selected for owner/ACL inspection.")

    score = round(max(0.0, min(100.0, score)), 1)
    grade = "high" if score >= 85 else "moderate" if score >= 65 else "limited" if score >= 40 else "incomplete"
    return {
        "coverage_score": score,
        "coverage_grade": grade,
        "profile": profile,
        "collector_success_rate": round(success_rate, 3) if success_rate is not None else None,
        "collectors_requested": len(requested),
        "collectors_succeeded": len(succeeded),
        "collectors_failed": len(failed),
        "collectors_not_applicable": len(not_applicable),
        "issues": issues,
        "strengths": strengths,
        "depth_domains": _build_depth_domains(stats, rows),
        "interpretation": "This is a scan coverage/evidence-quality indicator, not a system health, security, malware, or cleanliness score.",
    }
