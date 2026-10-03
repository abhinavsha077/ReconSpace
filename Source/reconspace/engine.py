from __future__ import annotations

import ntpath
import os
from dataclasses import dataclass
from typing import Callable

from . import __version__
from .audit_health import build_audit_health
from .classify import (
    build_findings,
    classify_applications,
    classify_services_and_tasks,
    classify_startup,
    normalize_findings,
)
from .duplicates import find_duplicate_groups
from .insights import discover_project_artifacts
from .models import CollectorResult, ScanReport
from .ownership import build_application_footprints, protect_active_process_paths
from .reclaim import build_reclaim_summary
from .rules import apply_keep_policy, evaluate_rule_packs, load_rule_packs
from .scanner import ScanCancelled, ScanConfig, scan_filesystem
from .security_insights import build_binary_and_acl_findings, build_protection_findings, build_storage_health_findings
from .system_insights import build_system_findings
from .windows_collectors import (
    basic_platform_info,
    collect_binary_trust,
    collect_installed_applications,
    collect_optional_system_inventory,
    collect_path_security as collect_path_security_records,
    collect_prefetch_metadata,
    collect_processes as collect_process_records,
    collect_scheduled_tasks,
    collect_services,
    collect_startup_items,
)

ProgressCallback = Callable[[dict], None]
CancelCallback = Callable[[], bool]

PROFILE_DEFAULTS = {
    "quick": {
        "duplicate_min_mb": 256,
        "scan_duplicates": False,
        "deep_windows_inventory": False,
        "top_files": 150,
        "top_directories": 180,
        "interesting_file_min_mb": 64,
        "artifact_min_mb": 100,
        "duplicate_max_mb": 4096,
        "collect_processes": False,
        "verify_signatures": False,
        "collect_path_security": False,
        "collect_prefetch": False,
        "signature_hashes": False,
    },
    "standard": {
        "duplicate_min_mb": 128,
        "scan_duplicates": True,
        "deep_windows_inventory": True,
        "top_files": 300,
        "top_directories": 300,
        "interesting_file_min_mb": 24,
        "artifact_min_mb": 60,
        "duplicate_max_mb": 8192,
        "collect_processes": True,
        "verify_signatures": True,
        "collect_path_security": False,
        "collect_prefetch": True,
        "signature_hashes": False,
    },
    "deep": {
        "duplicate_min_mb": 64,
        "scan_duplicates": True,
        "deep_windows_inventory": True,
        "top_files": 500,
        "top_directories": 500,
        "interesting_file_min_mb": 12,
        "artifact_min_mb": 40,
        "duplicate_max_mb": 32768,
        "collect_processes": True,
        "verify_signatures": True,
        "collect_path_security": True,
        "collect_prefetch": True,
        "signature_hashes": False,
    },
    "forensics": {
        "duplicate_min_mb": 32,
        "scan_duplicates": True,
        "deep_windows_inventory": True,
        "top_files": 800,
        "top_directories": 800,
        "interesting_file_min_mb": 8,
        "artifact_min_mb": 25,
        "duplicate_max_mb": 131072,
        "collect_processes": True,
        "verify_signatures": True,
        "collect_path_security": True,
        "collect_prefetch": True,
        "signature_hashes": True,
    },
}


@dataclass(slots=True)
class AuditConfig:
    root: str = "C:\\"
    profile: str = "deep"
    duplicate_min_mb: int | None = None
    scan_duplicates: bool | None = None
    deep_windows_inventory: bool | None = None
    top_files: int | None = None
    top_directories: int | None = None
    excluded_paths: tuple[str, ...] = ()
    duplicate_max_mb: int | None = None
    hash_stateful_files: bool = False
    rule_pack_paths: tuple[str, ...] = ()
    use_builtin_rules: bool = True
    keep_paths: tuple[str, ...] = ()
    collect_processes: bool | None = None
    verify_signatures: bool | None = None
    collect_path_security: bool | None = None
    collect_prefetch: bool | None = None
    signature_hashes: bool | None = None


def _effective(config: AuditConfig) -> dict:
    profile = config.profile if config.profile in PROFILE_DEFAULTS else "deep"
    values = dict(PROFILE_DEFAULTS[profile])
    for name in (
        "duplicate_min_mb", "duplicate_max_mb", "scan_duplicates",
        "deep_windows_inventory", "top_files", "top_directories",
        "collect_processes", "verify_signatures", "collect_path_security",
        "collect_prefetch", "signature_hashes",
    ):
        value = getattr(config, name)
        if value is not None:
            values[name] = value
    values["profile"] = profile
    return values


def _norm(path: str) -> str:
    cleaned = str(path or "").strip().strip('"').strip("'").strip()
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    return os.path.normcase(os.path.normpath(os.path.abspath(os.path.expandvars(os.path.expanduser(cleaned)))))


def _trust_targets(startup, services, scheduled_tasks, processes, include_processes: bool) -> tuple[list[str], dict[str, set[str]]]:
    source_map: dict[str, set[str]] = {}

    def add(path: str, source: str) -> None:
        if not path:
            return
        expanded = os.path.expandvars(os.path.expanduser(path.strip().strip('"')))
        if not expanded:
            return
        if not (os.path.isabs(expanded) or ntpath.isabs(expanded)):
            return
        key = _norm(expanded)
        source_map.setdefault(key, set()).add(source)

    for row in startup:
        add(row.target_path, "startup")
    for row in services:
        add(row.target_path, "service")
    for row in scheduled_tasks:
        for path in row.target_paths:
            add(path, "scheduled_task")
    if include_processes:
        for row in list(processes)[:60]:
            add(row.executable_path, "active_process")
    return list(source_map), source_map


def _acl_targets(inventory, findings, applications, limit: int = 60) -> list[str]:
    candidates: list[str] = []
    candidates.extend(row.path for row in inventory.top_directories[:25])
    candidates.extend(row.path for row in findings[:25] if row.path)
    candidates.extend(app.install_location for app in applications[:20] if app.install_location)
    output: list[str] = []
    seen: set[str] = set()
    for path in candidates:
        key = _norm(path)
        if key in seen:
            continue
        seen.add(key)
        output.append(path)
        if len(output) >= limit:
            break
    return output


def _collector_data(collectors: list[CollectorResult], name: str, default):
    row = next((item for item in collectors if item.name == name), None)
    return row.data if row and row.ok else default


def run_audit(
    config: AuditConfig,
    progress: ProgressCallback | None = None,
    cancel: CancelCallback | None = None,
) -> ScanReport:
    def check_cancel() -> None:
        if cancel and cancel():
            raise ScanCancelled("Audit cancelled by user")

    def emit(payload: dict) -> None:
        check_cancel()
        if progress:
            progress(payload)
        check_cancel()

    check_cancel()
    eff = _effective(config)
    # Rule packs are validated before traversal so their file-size requirements
    # can shape the bounded metadata-candidate retention threshold. This keeps
    # arbitrary file-extension rules useful without retaining every small file
    # on a multi-million-file system.
    packs = load_rule_packs(config.rule_pack_paths, include_builtin=config.use_builtin_rules)
    profile_candidate_min = max(1, int(eff["interesting_file_min_mb"])) * 1024 * 1024
    file_rule_mins = [
        int(rule.get("min_size_bytes") or 0)
        for pack in packs for rule in pack.rules
        if rule.get("scope") == "file"
    ]
    retention_floor = 1024 * 1024
    requested_file_rule_min = min(file_rule_mins) if file_rule_mins else profile_candidate_min
    metadata_candidate_min = min(profile_candidate_min, max(retention_floor, requested_file_rule_min))
    file_rule_floor_applied = bool(file_rule_mins and requested_file_rule_min < retention_floor)
    emit({"phase": "starting", "root": config.root, "profile": eff["profile"]})
    inventory = scan_filesystem(
        ScanConfig(
            root=config.root,
            top_files=int(eff["top_files"]),
            top_directories=int(eff["top_directories"]),
            duplicate_min_bytes=max(1, int(eff["duplicate_min_mb"])) * 1024 * 1024,
            duplicate_max_bytes=max(1, int(eff["duplicate_max_mb"])) * 1024 * 1024,
            hash_stateful_files=bool(config.hash_stateful_files),
            interesting_file_min_bytes=metadata_candidate_min,
            excluded_paths=config.excluded_paths,
        ),
        progress=emit,
        cancel=cancel,
    )
    check_cancel()

    duplicate_errors: list[str] = []
    duplicates = []
    if eff["scan_duplicates"]:
        emit({"phase": "duplicate_hashing", "groups": len(inventory.duplicate_candidates)})
        duplicates, duplicate_errors = find_duplicate_groups(inventory.duplicate_candidates, progress=emit, cancel=cancel)
        check_cancel()

    emit({"phase": "project_context"})
    project_artifacts = discover_project_artifacts(
        inventory,
        min_size_bytes=int(eff["artifact_min_mb"]) * 1024 * 1024,
    )
    check_cancel()

    emit({"phase": "applications"})
    apps, app_results = collect_installed_applications(inventory.directory_sizes)
    check_cancel()
    classify_applications(apps)

    emit({"phase": "startup"})
    startup, startup_results = collect_startup_items()
    check_cancel()
    classify_startup(startup)

    services = []
    scheduled_tasks = []
    processes = []
    binary_trust = []
    path_security = []
    process_result: CollectorResult | None = None
    trust_results: list[CollectorResult] = []
    acl_results: list[CollectorResult] = []
    collectors: list[CollectorResult] = []
    collectors.extend(app_results)
    collectors.extend(startup_results)
    collectors.append(CollectorResult(name="platform_info", ok=True, data=basic_platform_info()))

    if eff["deep_windows_inventory"]:
        emit({"phase": "windows_deep_inventory", "detail": "Auditing Windows background services..."})
        services, service_result = collect_services()
        check_cancel()
        emit({"phase": "windows_deep_inventory", "detail": "Auditing scheduled tasks..."})
        scheduled_tasks, task_result = collect_scheduled_tasks()
        check_cancel()
        collectors.extend([service_result, task_result])
        classify_services_and_tasks(services, scheduled_tasks)
        collectors.extend(
            collect_optional_system_inventory(
                root=config.root,
                profile=eff["profile"],
                cancel=cancel,
                progress=emit,
                installed_apps=apps,
                directory_sizes=inventory.directory_sizes,
            )
        )
        check_cancel()

    if eff["collect_processes"]:
        emit({"phase": "process_context", "detail": "Analyzing active processes and ownership..."})
        processes, process_result = collect_process_records(include_owner=eff["profile"] in {"deep", "forensics"})
        check_cancel()
        collectors.append(process_result)

    prefetch_result = CollectorResult(name="prefetch_metadata", ok=False, error="Not requested by scan profile")
    if eff["collect_prefetch"]:
        emit({"phase": "execution_metadata", "detail": "Reading prefetch execution metadata..."})
        prefetch_result = collect_prefetch_metadata()
        check_cancel()
        collectors.append(prefetch_result)

    emit({"phase": "rule_intelligence", "detail": "Evaluating rule packs and heuristics..."})
    rule_findings, rule_pack_info = evaluate_rule_packs(inventory, packs)
    check_cancel()
    rule_pack_info["file_candidate_retention"] = {
        "effective_min_bytes": metadata_candidate_min,
        "profile_default_min_bytes": profile_candidate_min,
        "lowest_file_rule_min_bytes": requested_file_rule_min if file_rule_mins else None,
        "minimum_floor_bytes": retention_floor,
        "floor_applied": file_rule_floor_applied,
        "eligible_files_seen": inventory.stats.metadata_candidate_files_seen,
        "files_retained": inventory.stats.metadata_candidate_files_retained,
        "files_omitted_by_bound": inventory.stats.metadata_candidate_files_omitted,
        "retention_bound": 10000,
    }

    emit({"phase": "classification", "detail": "Normalizing storage findings..."})
    findings = normalize_findings(
        build_findings(inventory, duplicates, apps, project_artifacts)
        + build_system_findings(collectors)
        + build_storage_health_findings(collectors)
        + build_protection_findings(collectors)
        + rule_findings
    )
    check_cancel()

    signature_targets: list[str] = []
    source_map: dict[str, set[str]] = {}
    if eff["verify_signatures"]:
        signature_targets, source_map = _trust_targets(
            startup, services, scheduled_tasks, processes,
            include_processes=eff["profile"] == "forensics",
        )
        emit({"phase": "binary_trust", "detail": f"Verifying code signatures for {len(signature_targets)} binaries..."})
        binary_trust, trust_results = collect_binary_trust(
            signature_targets,
            include_hashes=bool(eff["signature_hashes"]),
            cancel=cancel,
            progress=emit,
        )
        check_cancel()
        for row in binary_trust:
            row.source_kinds = sorted(source_map.get(_norm(row.path), set()))
        collectors.extend(trust_results)

    acl_targets: list[str] = []
    if eff["collect_path_security"]:
        acl_targets = _acl_targets(inventory, findings, apps)
        emit({"phase": "ownership_permissions", "detail": f"Auditing security permissions on {len(acl_targets)} paths..."})
        path_security, acl_results = collect_path_security_records(acl_targets, cancel=cancel, progress=emit)
        check_cancel()
        collectors.extend(acl_results)

    process_applicable = bool(process_result.applicable) if process_result is not None else False
    signature_applicable = (
        bool(eff["verify_signatures"])
        and (not trust_results or any(row.applicable for row in trust_results))
    )
    acl_applicable = (
        bool(eff["collect_path_security"])
        and (not acl_results or any(row.applicable for row in acl_results))
    )

    findings = normalize_findings(findings + build_binary_and_acl_findings(binary_trust, path_security))
    check_cancel()

    emit({"phase": "ownership_graph", "detail": "Building application footprint and ownership graph..."})
    prefetch_rows = prefetch_result.data if prefetch_result.ok and isinstance(prefetch_result.data, list) else []
    application_footprints = build_application_footprints(
        apps,
        inventory.directory_sizes,
        processes=processes,
        startup=startup,
        services=services,
        scheduled_tasks=scheduled_tasks,
        prefetch_rows=prefetch_rows,
        cancel=cancel,
    )
    check_cancel()
    active_policy = protect_active_process_paths(findings, processes)
    keep_policy = apply_keep_policy(findings, config.keep_paths)
    findings = normalize_findings(findings)
    reclaim_summary = build_reclaim_summary(findings)

    rule_pack_info["keep_policy"] = keep_policy
    rule_pack_info["active_process_protection"] = active_policy
    collectors.extend([
        CollectorResult(name="rule_pack_engine", ok=True, data=rule_pack_info),
        CollectorResult(name="application_ownership_graph", ok=True, data={
            "applications": len(application_footprints),
            "with_active_processes": sum(bool(row.active_processes) for row in application_footprints),
            "with_related_data_paths": sum(bool(row.related_paths) for row in application_footprints),
        }),
        CollectorResult(name="binary_trust_summary", ok=True, data={
            "requested": bool(eff["verify_signatures"]),
            "applicable": signature_applicable,
            "targets": len(signature_targets),
            "records": len(binary_trust),
            "hashes_enabled": bool(eff["signature_hashes"]),
            "online_reputation_queries": False,
        }),
        CollectorResult(name="path_security_summary", ok=True, data={
            "requested": bool(eff["collect_path_security"]),
            "applicable": acl_applicable,
            "targets": len(acl_targets),
            "records": len(path_security),
            "broad_write_signals": sum(row.broad_write_detected for row in path_security),
        }),
    ])

    notes = [
        "READ-ONLY audit engine: ReconSpace has no delete, uninstall, registry-write, service-change, task-change, compression, move, permission-change or cleanup-execution endpoint.",
        "Declarative rule packs inspect scan metadata only. They cannot execute code, commands or cleanup actions.",
        "Keep/protected paths remain visible for analysis, but matching reclaimable amounts are zeroed and safe-clean labels are downgraded.",
        "Reparse directories/junctions are not followed. Reparse regular files are counted from metadata but are not content-read by duplicate hashing, avoiding cloud-placeholder hydration and linked-tree loops.",
        "Directory sizes are logical namespace totals. NTFS hard-link aliases can make logical directory totals exceed uniquely allocated physical storage; hard-link alias metrics are reported separately.",
        "Exact duplicate analysis uses stable staged hashing, accounts for hard-linked aliases, rejects files that change during hashing, and skips stateful VM/forensics/dump formats by default.",
        "Reclaim summaries are deliberately non-additive: path-scoped candidates suppress covered descendants, while duplicate/application/platform potentials are reported separately because they can overlap.",
        "Installed-application sizes are estimates from Windows uninstall metadata with scanned install-directory size as a fallback when available.",
        "Application ownership/usage evidence is conservative. No observed process, prefetch or persistence evidence does not prove an application is unused.",
        "Authenticode, hashes and ACL summaries are local evidence signals only; they are not malware verdicts and do not change files or permissions.",
        "Development/cybersecurity/VM artifacts are context-classified separately; size alone never makes them junk.",
        "Access-denied paths are reported rather than bypassed or permission-modified. Running manually elevated can improve visibility without changing ACLs.",
        "Age uses filesystem timestamps as a heuristic; it does not prove that data is unused.",
    ]
    if file_rule_floor_applied:
        notes.append(
            "At least one file rule requested a threshold below 1 MiB. ReconSpace applied a 1 MiB bounded-retention floor to avoid retaining millions of small-file records; such a rule may have incomplete coverage below that floor."
        )
    if inventory.stats.metadata_candidate_files_omitted:
        notes.append(
            f"The bounded large-file metadata pool retained {inventory.stats.metadata_candidate_files_retained:,} of {inventory.stats.metadata_candidate_files_seen:,} eligible files; {inventory.stats.metadata_candidate_files_omitted:,} smaller eligible candidates were omitted from file-rule/classification analysis."
        )
    if inventory.excluded_paths:
        notes.append(f"This scan explicitly excluded {len(inventory.excluded_paths)} path(s); it is not a complete-root inventory for those locations.")
    if inventory.errors:
        notes.append(f"Filesystem scan recorded {len(inventory.errors)} representative access/stat errors (capped).")
    if duplicate_errors:
        notes.append(f"Duplicate hashing recorded {len(duplicate_errors)} representative read/change errors (capped).")

    collectors.append(CollectorResult(
        name="filesystem_errors",
        ok=not bool(inventory.errors),
        data=inventory.errors,
        error="Some filesystem entries could not be read." if inventory.errors else "",
    ))
    collectors.append(CollectorResult(name="explicit_exclusions", ok=True, data=inventory.excluded_paths))
    collectors.append(CollectorResult(
        name="duplicate_hash_errors",
        ok=not bool(duplicate_errors),
        data=duplicate_errors,
        error="Some duplicate candidates changed or could not be read." if duplicate_errors else "",
    ))
    collectors.append(CollectorResult(
        name="duplicate_hash_policy",
        ok=True,
        data={
            "min_bytes": max(1, int(eff["duplicate_min_mb"])) * 1024 * 1024,
            "max_bytes": max(1, int(eff["duplicate_max_mb"])) * 1024 * 1024,
            "hash_stateful_files": bool(config.hash_stateful_files),
            "policy_skipped_files": inventory.stats.duplicate_hash_policy_skipped_files,
            "policy_skipped_bytes": inventory.stats.duplicate_hash_policy_skipped_bytes,
            "cloud_or_offline_files_not_hashed": inventory.stats.cloud_or_offline_files,
        },
    ))
    collectors.append(CollectorResult(name="reclaim_summary", ok=True, data=reclaim_summary))
    collectors.append(CollectorResult(
        name="project_context_summary",
        ok=True,
        data={"directories_with_manifests": len(inventory.project_markers), "semantic_artifacts": len(project_artifacts)},
    ))

    audit_health = build_audit_health(
        inventory.stats,
        collectors,
        profile=eff["profile"],
        excluded_paths=inventory.excluded_paths,
        duplicate_scan_enabled=bool(eff["scan_duplicates"]),
        process_count=len(processes),
        process_requested=bool(eff["collect_processes"]),
        process_applicable=process_applicable,
        signature_targets=len(signature_targets),
        signature_records=len(binary_trust),
        signature_requested=bool(eff["verify_signatures"]),
        signature_applicable=signature_applicable,
        acl_targets=len(acl_targets),
        acl_records=len(path_security),
        acl_requested=bool(eff["collect_path_security"]),
        acl_applicable=acl_applicable,
    )
    check_cancel()
    collectors.append(CollectorResult(name="audit_health", ok=True, data=audit_health))

    emit({"phase": "done", "findings": len(findings), "duplicates": len(duplicates)})
    return ScanReport(
        version=__version__,
        profile=eff["profile"],
        stats=inventory.stats,
        top_files=inventory.top_files,
        top_directories=inventory.top_directories,
        extension_summary=inventory.extension_summary,
        age_summary=inventory.age_summary,
        project_artifacts=project_artifacts,
        findings=findings,
        duplicates=duplicates,
        applications=apps,
        startup=startup,
        services=services,
        scheduled_tasks=scheduled_tasks,
        collectors=collectors,
        notes=notes,
        reclaim_summary=reclaim_summary,
        processes=processes,
        binary_trust=binary_trust,
        path_security=path_security,
        application_footprints=application_footprints,
        rule_pack_info=rule_pack_info,
        audit_health=audit_health,
    )
