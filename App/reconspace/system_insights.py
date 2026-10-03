from __future__ import annotations

import os
import re
from typing import Any

from .classify import score_finding
from .models import CollectorResult, Finding


def _collector_map(collectors: list[CollectorResult]) -> dict[str, CollectorResult]:
    return {c.name: c for c in collectors}


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _human_bytes(value: Any) -> int | None:
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value or "").strip()
    if not text:
        return None
    # Docker examples include forms like "11.63 MB (70%)".
    m = re.search(r"(?i)([0-9]+(?:\.[0-9]+)?)\s*(B|kB|KB|MB|GB|TB|KiB|MiB|GiB|TiB)", text)
    if not m:
        return None
    num = float(m.group(1))
    unit = m.group(2).lower()
    mult = {
        "b": 1,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
        "tb": 1000**4,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
    }[unit]
    return int(num * mult)


def _docker_value(row: dict[str, Any], *names: str) -> Any:
    lower = {str(k).casefold(): v for k, v in row.items()}
    for name in names:
        if name.casefold() in lower:
            return lower[name.casefold()]
    return None


def _append(findings: list[Finding], f: Finding) -> None:
    f.priority_score = score_finding(f)
    findings.append(f)


def build_system_findings(collectors: list[CollectorResult]) -> list[Finding]:
    """Convert read-only Windows collector evidence into conservative findings."""
    by_name = _collector_map(collectors)
    findings: list[Finding] = []

    wsl = by_name.get("wsl_registry")
    if wsl and wsl.ok:
        for distro in _as_list(wsl.data):
            if not isinstance(distro, dict):
                continue
            path = str(distro.get("vhdx") or distro.get("base_path") or "WSL")
            logical = distro.get("vhdx_logical_bytes")
            allocated = distro.get("vhdx_allocated_bytes")
            size = int(allocated if isinstance(allocated, int) else logical if isinstance(logical, int) else 0)
            name = str(distro.get("name") or "unnamed distro")
            _append(findings, Finding(
                title=f"WSL distro backing storage: {name}",
                path=path,
                size_bytes=size,
                category="WSL / virtualization",
                disposition="intentional_tooling",
                risk="critical",
                confidence="high",
                why_it_exists="WSL stores the Linux distribution filesystem in managed backing storage, commonly an ext4.vhdx virtual disk.",
                recommendation="Inspect storage from inside the distro and through WSL/Docker ownership first. Retire a distro only through its supported management workflow; never delete the backing VHDX as a cleanup shortcut.",
                removal_risk="Direct removal can destroy the Linux distro, containers, package caches, source trees, credentials and lab state.",
                related_to=["WSL", "Docker", "development", "cybersecurity", "virtualization"],
                estimated_reclaimable_bytes=0,
                evidence={
                    "scope_type": "platform",
                    "distro": name,
                    "wsl_version": distro.get("version"),
                    "logical_bytes": logical,
                    "allocated_bytes": allocated,
                },
            ))

    docker = by_name.get("docker_system_df")
    if docker and docker.ok and isinstance(docker.data, list):
        for row in docker.data:
            if not isinstance(row, dict):
                continue
            dtype = str(_docker_value(row, "Type") or "Docker objects")
            total_size = _human_bytes(_docker_value(row, "Size")) or 0
            reclaim = _human_bytes(_docker_value(row, "Reclaimable")) or 0
            low = dtype.casefold()
            if "volume" in low:
                disposition = "intentional_tooling"
                risk = "critical"
                estimate = 0
                recommendation = "Inspect every volume's owning containers/projects and data contents. Volumes can contain unique databases and application state; do not treat Docker's unused status as proof that the data is disposable."
            elif "build" in low:
                disposition = "manual_review"
                risk = "low"
                estimate = reclaim
                recommendation = "Review build-cache ownership and current development needs in Docker Desktop/CLI. Reclaim only through Docker's supported object/cache management after approval."
            elif "image" in low:
                disposition = "manual_review"
                risk = "medium"
                estimate = reclaim
                recommendation = "Review tags, active containers, offline/reproducibility needs and image ownership. Remove only specifically approved unused images through Docker's supported management workflow."
            else:
                disposition = "manual_review"
                risk = "high"
                estimate = reclaim
                recommendation = "Inspect the reported Docker objects and their owners. Stopped/unused does not mean unimportant; preserve any container state or project dependencies before supported removal."
            _append(findings, Finding(
                title=f"Docker storage: {dtype}",
                path="Docker daemon storage",
                size_bytes=total_size,
                category="Docker storage",
                disposition=disposition,  # type: ignore[arg-type]
                risk=risk,  # type: ignore[arg-type]
                confidence="high",
                why_it_exists="Docker retains images, containers, volumes and build cache so development and container workloads can be reproduced or resumed.",
                recommendation=recommendation,
                removal_risk="Removing the wrong Docker object can break environments, require large re-downloads/rebuilds, or permanently destroy state stored in containers/volumes.",
                related_to=["Docker", "containers", "development", "cybersecurity"],
                estimated_reclaimable_bytes=estimate,
                evidence={"scope_type": "platform", "docker_report": row, "docker_reported_reclaimable_bytes": reclaim},
            ))

    shadow = by_name.get("shadow_storage")
    if shadow and shadow.ok:
        rows = [r for r in _as_list(shadow.data) if isinstance(r, dict)]
        used = sum(int(r.get("UsedSpace") or 0) for r in rows)
        allocated = sum(int(r.get("AllocatedSpace") or 0) for r in rows)
        maximum = sum(int(r.get("MaxSpace") or 0) for r in rows if isinstance(r.get("MaxSpace"), (int, float)))
        if used or allocated:
            _append(findings, Finding(
                title="Volume Shadow Copy / restore storage",
                path="VSS shadow storage",
                size_bytes=used or allocated,
                category="System restore / VSS",
                disposition="manual_review",
                risk="critical",
                confidence="high",
                why_it_exists="Windows Volume Shadow Copy storage can contain restore points, snapshots and backup-related differential data that is not visible as ordinary files in a folder scan.",
                recommendation="Review System Protection, backup software and restore requirements. Manage retention/limits only through supported Windows or backup-product controls; do not delete System Volume Information manually.",
                removal_risk="Reducing or deleting shadow-copy storage can permanently remove restore points, snapshots and backup recovery options.",
                related_to=["Windows", "VSS", "restore points", "backups"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "platform", "used_bytes": used, "allocated_bytes": allocated, "max_bytes": maximum, "associations": rows},
            ))

    component = by_name.get("component_store_analysis")
    if component and component.ok and isinstance(component.data, dict):
        actual = component.data.get("actual_size_bytes")
        cleanup = component.data.get("cleanup_recommended")
        if isinstance(actual, int) or cleanup is True:
            _append(findings, Finding(
                title="Windows component store servicing analysis",
                path=os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "WinSxS"),
                size_bytes=int(actual or 0),
                category="Windows component store",
                disposition="manual_review" if cleanup else "informational",
                risk="high",
                confidence="high",
                why_it_exists="The component store keeps Windows servicing payloads, shared components, disabled-feature payloads and update history. Folder scanners can overstate its physical cost because of hard links.",
                recommendation=(
                    "Windows reports component-store cleanup as recommended. If you choose to reclaim servicing data, use Windows-supported servicing/Storage cleanup only; never manually delete WinSxS."
                    if cleanup else
                    "No manual folder cleanup is appropriate. Use this servicing analysis rather than raw WinSxS folder size when judging component-store pressure."
                ),
                removal_risk="Manual WinSxS changes can break Windows Update, optional features, repair and system servicing.",
                related_to=["Windows", "updates", "servicing"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "platform", **component.data},
            ))

    pagefile = by_name.get("pagefile_usage")
    if pagefile and pagefile.ok:
        for row in _as_list(pagefile.data):
            if not isinstance(row, dict):
                continue
            mb = row.get("AllocatedBaseSize")
            if not isinstance(mb, (int, float)):
                continue
            _append(findings, Finding(
                title="Windows pagefile allocation",
                path=str(row.get("Name") or "pagefile.sys"),
                size_bytes=int(mb) * 1024 * 1024,
                category="System-managed virtual memory",
                disposition="do_not_touch",
                risk="critical",
                confidence="high",
                why_it_exists="Windows uses the pagefile as virtual-memory backing and for some crash-dump configurations.",
                recommendation="Do not delete it directly. Change virtual-memory policy only intentionally after considering workload, RAM, crash-dump and application requirements.",
                removal_risk="Incorrect paging configuration can cause application failures, memory pressure and loss of crash-dump capability.",
                related_to=["Windows", "memory", "crash dumps"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "platform", **row},
            ))

    dedup = by_name.get("dedup_status")
    if dedup and dedup.ok:
        saved = 0
        for row in _as_list(dedup.data):
            if isinstance(row, dict) and isinstance(row.get("SavedSpace"), (int, float)):
                saved += int(row.get("SavedSpace") or 0)
        if saved:
            _append(findings, Finding(
                title="Windows Data Deduplication savings detected",
                path="Windows Data Deduplication",
                size_bytes=saved,
                category="Filesystem optimization",
                disposition="informational",
                risk="high",
                confidence="high",
                why_it_exists="Windows Data Deduplication is already reducing physical storage by sharing duplicate chunks.",
                recommendation="Treat ordinary logical folder/file totals with extra caution on this volume; do not assume deleting a logical-size duplicate will reclaim the same physical amount.",
                removal_risk="Changing deduplication policy without understanding the volume/workload can affect capacity and performance.",
                related_to=["Windows", "deduplication", "storage"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "platform", "saved_bytes": saved, "status": dedup.data},
            ))

    orphaned = by_name.get("orphaned_app_data")
    if orphaned and orphaned.ok and isinstance(orphaned.data, list):
        for item in orphaned.data[:15]:
            if not isinstance(item, dict):
                continue
            sz = int(item.get("size_bytes") or 0)
            if sz < 5 * 1024 * 1024:
                continue
            name = str(item.get("name") or "Application data")
            path = str(item.get("path") or "")
            env_loc = str(item.get("location_env") or "AppData")
            _append(findings, Finding(
                title=f"Application leftover data: {name} ({env_loc})",
                path=path,
                size_bytes=sz,
                category="Application leftovers",
                category_group="app_leftovers",
                disposition="manual_review",
                risk="medium",
                confidence="medium",
                why_it_exists=f"Residual configuration, cache or data directory in %{env_loc}% where no matching installed application was detected.",
                recommendation="Review the contents of this folder. If the application has been uninstalled and its settings are no longer needed, it can be safely cleared.",
                removal_risk="Any saved preferences, local cache or offline data belonging to this software will be deleted.",
                related_to=["applications", "uninstaller", "leftovers", "cleanup"],
                estimated_reclaimable_bytes=sz,
                evidence={"scope_type": "application_leftover", "location_env": env_loc, **item},
            ))

    mem = by_name.get("system_memory_status")
    if mem and mem.ok and isinstance(mem.data, dict):
        load_pct = mem.data.get("memory_load_pct")
        total_phys = mem.data.get("total_physical_bytes") or 0
        if isinstance(load_pct, (int, float)) and load_pct >= 85 and total_phys > 0:
            total_gb = total_phys / (1024**3)
            used_gb = (mem.data.get("used_physical_bytes") or 0) / (1024**3)
            _append(findings, Finding(
                title=f"High system memory load ({load_pct}% of {total_gb:.1f} GB RAM)",
                path="RAM",
                size_bytes=int(mem.data.get("used_physical_bytes") or 0),
                category="System maintenance",
                category_group="system_maintenance",
                disposition="informational",
                risk="medium",
                confidence="high",
                why_it_exists=f"{used_gb:.1f} GB of {total_gb:.1f} GB installed physical RAM is currently committed or in working sets.",
                recommendation="Inspect top memory-consuming processes in the Performance tab. Consider closing unused background apps or trimming working sets.",
                removal_risk="Stopping active processes can cause loss of unsaved application work.",
                related_to=["performance", "memory", "ram", "maintenance"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "hardware_memory", **mem.data},
            ))

    wu = by_name.get("windows_update_cache")
    if wu and wu.ok and isinstance(wu.data, dict):
        dl_bytes = wu.data.get("software_distribution_download_bytes") or 0
        if dl_bytes > 500 * 1024 * 1024:
            dl_mb = dl_bytes / (1024 * 1024)
            _append(findings, Finding(
                title=f"Windows Update download cache ({dl_mb:.0f} MB)",
                path=os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "SoftwareDistribution", "Download"),
                size_bytes=dl_bytes,
                category="System maintenance",
                category_group="system_maintenance",
                disposition="manual_review",
                risk="low",
                confidence="high",
                why_it_exists="Windows Update stages downloaded installation payloads in SoftwareDistribution\\Download.",
                recommendation="If updates are fully installed and the PC is functioning normally, update staging files can be safely purged via Windows Disk Cleanup or PowerShell inspection recipes.",
                removal_risk="Future updates may re-download needed installation packages.",
                related_to=["windows_update", "maintenance", "cleanup"],
                estimated_reclaimable_bytes=dl_bytes,
                evidence={"scope_type": "windows_update_cache", **wu.data},
            ))

    winget_upg = by_name.get("winget_catalog_correlation")
    if winget_upg and winget_upg.ok and isinstance(winget_upg.data, dict):
        upg_count = winget_upg.data.get("upgrades_available_count") or 0
        if upg_count > 0:
            _append(findings, Finding(
                title=f"Software updates available via WinGet ({upg_count} package(s))",
                path="WinGet Package Manager",
                size_bytes=0,
                category="Application leftovers",
                category_group="app_leftovers",
                disposition="informational",
                risk="low",
                confidence="high",
                why_it_exists=f"WinGet detected newer release versions for {upg_count} installed applications.",
                recommendation="Review out-of-date packages in the Applications Hub and run winget upgrade commands.",
                removal_risk="Software upgrades can introduce UI or configuration changes.",
                related_to=["winget", "applications", "updates", "maintenance"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "winget_catalog", "upgrades_count": upg_count},
            ))

    cs_analysis = by_name.get("component_store_analysis")
    if cs_analysis and cs_analysis.ok and isinstance(cs_analysis.data, dict):
        if cs_analysis.data.get("cleanup_recommended"):
            reclaim_est = int(cs_analysis.data.get("backups_disabled_features_bytes") or 0)
            _append(findings, Finding(
                title="Windows Component Store (WinSxS) cleanup recommended",
                path="C:\\Windows\\WinSxS",
                size_bytes=int(cs_analysis.data.get("actual_size_bytes") or 0),
                category="System maintenance",
                category_group="system_maintenance",
                disposition="manual_review",
                risk="low",
                confidence="high",
                why_it_exists="DISM component store analysis reports that superseded Windows update packages can be reclaimed.",
                recommendation="Run Windows Disk Cleanup (cleanmgr.exe) to safely reclaim superseded components.",
                removal_risk="Superseded component backups will be removed; previous update rollbacks will not be possible.",
                related_to=["dism", "winsxs", "servicing", "maintenance"],
                estimated_reclaimable_bytes=reclaim_est,
                evidence={"scope_type": "component_store", **cs_analysis.data},
            ))

    return findings
