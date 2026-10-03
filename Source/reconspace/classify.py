from __future__ import annotations

import math
import os
import re
import time
from collections import defaultdict
from pathlib import Path

from .models import ApplicationRecord, DuplicateGroup, Finding, ProjectArtifactRecord, ScheduledTaskRecord, ServiceRecord, StartupRecord
from .scanner import ScanInventory
from .storage_basis import directory_reclaim_evidence, file_reclaim_basis
from .commandline import absolute_target_exists, extract_windows_executable, has_unquoted_service_path_risk, looks_user_writable_windows_path

MB = 1024 * 1024
GB = 1024 * MB

DEV_SECURITY_APP_TOKENS = (
    "wireshark", "burp", "portswigger", "kali", "nmap", "metasploit", "ghidra",
    "ida", "virtualbox", "vmware", "docker", "podman", "wsl", "ubuntu", "debian",
    "android studio", "visual studio", "visual studio code", "vscode", "jetbrains",
    "pycharm", "intellij", "webstorm", "clion", "goland", "rider", "python",
    "anaconda", "miniconda", "miniforge", "node.js", "node ", "jdk", "java development kit",
    "git", "cmake", "mingw", "msys2", "windows sdk", "dotnet sdk", ".net sdk",
    "postman", "insomnia", "fiddler", "charles", "mitmproxy", "sysinternals",
    "autopsy", "volatility", "ftk", "sleuth", "radare", "cutter", "ollydbg",
    "x64dbg", "hyper-v", "qemu", "vagrant", "terraform", "kubectl", "kubernetes",
    "powershell", "gitkraken", "sourcetree", "unity", "unreal engine", "godot",
)

SIDE_BY_SIDE_RUNTIME_TOKENS = (
    "microsoft visual c++", ".net", "windows sdk", "java", "jdk", "python",
    "node.js", "directx", "runtime", "redistributable", "sdk", "targeting pack",
)

VM_EXTENSIONS = {".vhd", ".vhdx", ".avhdx", ".vdi", ".vmdk", ".qcow2", ".ova", ".ovf", ".vmem", ".vmsn", ".vmss", ".sav"}
SECURITY_DATA_EXTENSIONS = {".pcap", ".pcapng", ".e01", ".aff4", ".raw", ".dd", ".ad1"}
ARCHIVE_EXTENSIONS = {".iso", ".img", ".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".xz", ".zst"}
INSTALLER_EXTENSIONS = {".msi", ".msix", ".appx", ".exe", ".apk", ".aab"}
BACKUP_EXTENSIONS = {".bak", ".backup", ".old"}

CATEGORY_GROUPS: dict[str, dict[str, str]] = {
    "system_temp": {
        "title": "System & Temporary Files",
        "icon": "🧹",
        "summary": "Temporary files, Windows update caches, and crash diagnostics. These are regenerable working files generally safe for routine cleanup.",
        "description": "Temporary files, Windows update caches, and crash diagnostics. These are regenerable working files generally safe for routine cleanup.",
    },
    "dev_build": {
        "title": "Developer & Build Artifacts",
        "icon": "⚡",
        "summary": "Project build artifacts, dependency directories (such as node_modules), package manager caches, and compiled bytecode. Can be rebuilt when needed.",
        "description": "Project build artifacts, dependency directories (such as node_modules), package manager caches, and compiled bytecode. Can be rebuilt when needed.",
    },
    "ai_ml": {
        "title": "AI & Machine Learning Models",
        "icon": "🧠",
        "summary": "Downloaded AI model weights, model snapshots, and machine-learning caches. Large files that require significant network bandwidth to re-download.",
        "description": "Downloaded AI model weights, model snapshots, and machine-learning caches. Large files that require significant network bandwidth to re-download.",
    },
    "browser_app": {
        "title": "Browser & Application Caches",
        "icon": "🌐",
        "summary": "Web browser caches, GPU shader caches, and desktop app workspaces. Cleaning frees space while preserving user accounts and passwords.",
        "description": "Web browser caches, GPU shader caches, and desktop app workspaces. Cleaning frees space while preserving user accounts and passwords.",
    },
    "apps_installers": {
        "title": "Applications & Package Caches",
        "icon": "📦",
        "summary": "Installer caches, packaged Store application state, and runtime libraries. Best reviewed and managed through official application settings or uninstallers.",
        "description": "Installer caches, packaged Store application state, and runtime libraries. Best reviewed and managed through official application settings or uninstallers.",
    },
    "virtualization": {
        "title": "Virtualization & Containers",
        "icon": "🐳",
        "summary": "Virtual machine disk images, emulator snapshots, and container layers. Stateful files that should only be deleted if no longer needed.",
        "description": "Virtual machine disk images, emulator snapshots, and container layers. Stateful files that should only be deleted if no longer needed.",
    },
    "diagnostics": {
        "title": "System & Security Diagnostics",
        "icon": "📊",
        "summary": "Storage health signals, permission anomalies, and diagnostic reports requiring administrative review.",
        "description": "Storage health signals, permission anomalies, and diagnostic reports requiring administrative review.",
    },
    "app_leftovers": {
        "title": "Application Leftovers & Residual Data",
        "icon": "🧩",
        "summary": "Orphaned AppData and ProgramData folders left behind by uninstalled software. Ready for approved cleanup.",
        "description": "Orphaned AppData and ProgramData folders left behind by uninstalled software. Ready for approved cleanup.",
    },
    "privacy_permissions": {
        "title": "Privacy & Hardware Permissions",
        "icon": "🛡️",
        "summary": "Audits hardware access (webcam, microphone, location) and browser privacy footprint without altering settings.",
        "description": "Audits hardware access (webcam, microphone, location) and browser privacy footprint without altering settings.",
    },
    "system_maintenance": {
        "title": "System Maintenance & Speed",
        "icon": "⚡",
        "summary": "Windows maintenance opportunities such as DNS cache flushing, component store health, and memory optimization.",
        "description": "Windows maintenance opportunities such as DNS cache flushing, component store health, and memory optimization.",
    },
}


def resolve_category_group(category: str) -> str:
    cat = (category or "").lower()
    if any(k in cat for k in ("leftover", "orphan", "uninstalled")):
        return "app_leftovers"
    if any(k in cat for k in ("privacy", "consent", "webcam", "microphone", "permission")):
        return "privacy_permissions"
    if any(k in cat for k in ("maintenance", "dns", "flush", "sfc", "ram", "memory pressure")):
        return "system_maintenance"
    if any(k in cat for k in ("ai", "ml", "model", "huggingface", "torch", "ollama", "comfyui")):
        return "ai_ml"
    if any(k in cat for k in ("virtual", "vm", "emulator", "container", "wsl", "docker", "hyper-v")):
        return "virtualization"
    if any(k in cat for k in ("pip", "npm", "yarn", "pnpm", "cargo", "gradle", "nuget", "maven", "node_modules", "rust_target", "python_venv", "developer", "build", "ide", "package manager")):
        return "dev_build"
    if any(k in cat for k in ("browser", "electron", "spotify", "discord", "slack", "teams", "shader", "d3d", "glcache", "dxcache")):
        return "browser_app"
    if any(k in cat for k in ("installer", "application", "store", "msix", "appx", "runtime", "download", "steam", "epic")):
        return "apps_installers"
    if any(k in cat for k in ("temp", "cache", "crash", "windows managed", "dump", "log", "report", "wer", "distribution", "livekernel", "recycle", "prefetch", "delivery_optimization", "upgrade_residue")):
        return "system_temp"
    return "diagnostics"


def _norm(path: str) -> str:
    cleaned = str(path or "").strip().strip('"').strip("'").strip()
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    return os.path.normcase(os.path.normpath(os.path.abspath(os.path.expandvars(os.path.expanduser(cleaned)))))


def _winish(path: str) -> str:
    return _norm(path).replace("/", "\\").lower()


def _age_days(ts: float | None) -> float | None:
    if ts is None:
        return None
    return max(0.0, (time.time() - ts) / 86400.0)


def _folder_lookup(inventory: ScanInventory) -> dict[str, tuple[str, int]]:
    return {_norm(path): (path, size) for path, size in inventory.directory_sizes.items()}


def _priority(f: Finding) -> float:
    size_component = min(45.0, math.log2(max(1.0, f.estimated_reclaimable_bytes / MB) + 1.0) * 4.5)
    disposition_component = {
        "probably_safe_cleanup": 28.0,
        "manual_review": 17.0,
        "intentional_tooling": 5.0,
        "informational": 1.0,
        "do_not_touch": 0.0,
    }[f.disposition]
    confidence_component = {"high": 12.0, "medium": 7.0, "low": 2.0}[f.confidence]
    risk_component = {"low": 10.0, "medium": 5.0, "high": 1.0, "critical": 0.0}[f.risk]
    age_component = 0.0
    if f.age_days is not None:
        if f.age_days >= 365:
            age_component = 8.0
        elif f.age_days >= 90:
            age_component = 5.0
        elif f.age_days >= 30:
            age_component = 2.0
    return round(min(100.0, size_component + disposition_component + confidence_component + risk_component + age_component), 1)


def _add_folder_finding(
    findings: list[Finding], lookup: dict[str, tuple[str, int]], path: str, *,
    title: str, category: str, disposition: str, risk: str, confidence: str,
    why: str, recommendation: str, removal_risk: str, related_to: list[str],
    reclaim_fraction: float = 1.0, min_size: int = 25 * MB,
    age_days: float | None = None, evidence: dict | None = None,
) -> None:
    item = lookup.get(_norm(path))
    if not item:
        return
    actual_path, size = item
    if size < min_size:
        return
    finding = Finding(
        title=title,
        path=actual_path,
        size_bytes=size,
        category=category,
        disposition=disposition,  # type: ignore[arg-type]
        risk=risk,  # type: ignore[arg-type]
        confidence=confidence,  # type: ignore[arg-type]
        why_it_exists=why,
        recommendation=recommendation,
        removal_risk=removal_risk,
        related_to=related_to,
        estimated_reclaimable_bytes=max(0, int(size * reclaim_fraction)),
        age_days=age_days,
        evidence={"scope_type": "folder", **directory_reclaim_evidence(), **(evidence or {})},
    )
    finding.priority_score = _priority(finding)
    findings.append(finding)


def _find_dirs_ending(inventory: ScanInventory, suffixes: tuple[str, ...], min_size: int = 25 * MB) -> list[tuple[str, int]]:
    wanted = tuple(s.replace("/", "\\").lower().strip("\\") for s in suffixes)
    out: list[tuple[str, int]] = []
    for path, size in inventory.directory_sizes.items():
        if size < min_size:
            continue
        w = _winish(path).strip("\\")
        if any(w.endswith(s) for s in wanted):
            out.append((path, size))
    out.sort(key=lambda x: x[1], reverse=True)
    return out


def _app_token_match(blob: str, token: str) -> bool:
    """Match product/tool tokens without substring traps such as Git -> Logitech."""
    t = token.strip().lower()
    if not t:
        return False
    # Tokens containing punctuation/spaces are product phrases and can be matched
    # directly. Short plain words require alphanumeric boundaries.
    if any(ch in t for ch in " .+-/"):
        return t in blob
    return re.search(rf"(?<![a-z0-9]){re.escape(t)}(?![a-z0-9])", blob) is not None


def classify_applications(apps: list[ApplicationRecord]) -> None:
    for app in apps:
        blob = f"{app.name} {app.publisher}".lower()
        if app.is_framework:
            app.classification = "Packaged framework/runtime - may be shared by Store apps"
            app.note = "Do not remove based only on size; packaged frameworks can satisfy dependencies for multiple apps."
        elif any(_app_token_match(blob, token) for token in DEV_SECURITY_APP_TOKENS):
            app.classification = "Likely intentional cybersecurity/development tooling"
            app.note = "Large or uncommon does not imply unnecessary. Review against active projects, labs, SDKs and VMs."
        elif any(_app_token_match(blob, token) for token in SIDE_BY_SIDE_RUNTIME_TOKENS):
            app.classification = "Runtime/SDK - side-by-side versions may be required"
            app.note = "Do not remove a version based only on age or apparent duplication."
        elif app.publisher.lower().startswith("microsoft"):
            app.classification = "Microsoft/Windows-related application"
            app.note = "Prefer Apps & Features or vendor-supported removal if you later decide it is unnecessary."
        else:
            app.classification = "Installed application - review usage manually"
            app.note = "Reported size can be missing or inaccurate; removal should use the normal uninstaller."


def _is_protected_windows_application(app: ApplicationRecord) -> bool:
    name = app.name.casefold().strip()
    microsoft_published = app.publisher.casefold().startswith("microsoft")
    return app.is_framework or (microsoft_published and (name == "microsoft edge" or "microsoft edge webview2" in name))


def _persistence_reasons(command: str, target: str = "") -> list[str]:
    cmd = command.lower()
    reasons: list[str] = []
    if any(token in cmd for token in ("\\temp\\", "/temp/", "\\downloads\\", "/downloads/")):
        reasons.append("launch target appears to be under a temporary/download location")
    if any(token in cmd for token in ("powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32")):
        reasons.append("script/interpreter-style persistence action")
    if "-enc" in cmd or "-encodedcommand" in cmd:
        reasons.append("encoded PowerShell-style argument detected")
    if target and looks_user_writable_windows_path(target):
        reasons.append("binary/script target is in a user-writable location")
    exists = absolute_target_exists(target) if target else None
    if exists is False:
        reasons.append("absolute target path is currently missing")
    return reasons


def classify_startup(items: list[StartupRecord]) -> None:
    """Attach conservative persistence hints; this is not malware detection."""
    for item in items:
        target = extract_windows_executable(item.command)
        item.target_path = target
        item.target_exists = absolute_target_exists(target)
        reasons = _persistence_reasons(item.command, target)
        item.risk_hint = "review" if reasons else ""
        item.reason = "; ".join(dict.fromkeys(reasons))


def classify_services_and_tasks(services: list[ServiceRecord], tasks: list[ScheduledTaskRecord]) -> None:
    """Conservative persistence review hints for services/tasks; never a malware verdict."""
    for svc in services:
        target = extract_windows_executable(svc.path_name)
        svc.target_path = target
        svc.target_exists = absolute_target_exists(target)
        reasons = _persistence_reasons(svc.path_name, target)
        if has_unquoted_service_path_risk(svc.path_name):
            reasons.append("unquoted service executable path contains spaces; review service path quoting")
        svc.risk_hint = "review" if reasons else ""
        svc.reason = "; ".join(dict.fromkeys(reasons))

    for task in tasks:
        reasons: list[str] = []
        targets: list[str] = []
        for action in task.actions:
            target = extract_windows_executable(action)
            if target:
                targets.append(target)
            reasons.extend(_persistence_reasons(action, target))
        task.target_paths = list(dict.fromkeys(targets))
        microsoft_builtin = task.task_path.casefold().startswith("\\microsoft\\windows\\")
        if microsoft_builtin:
            reasons = [reason for reason in reasons if reason != "script/interpreter-style persistence action"]
        elif task.hidden:
            reasons.append("scheduled task is marked Hidden")
        task.risk_hint = "review" if reasons else ""
        task.reason = "; ".join(dict.fromkeys(reasons))


def score_finding(finding: Finding) -> float:
    return _priority(finding)


def _artifact_finding(artifact: ProjectArtifactRecord) -> Finding:
    kind = artifact.artifact_type
    age = artifact.age_days
    evidence = {
        **directory_reclaim_evidence(),
        "artifact_type": kind,
        "project_root": artifact.project_root,
        "project_markers": artifact.project_markers,
        "rebuildable": artifact.rebuildable,
        "scope_type": "folder",
    }

    safe_cache_types = {
        "Gradle cache", "Cargo package cache", "Go module cache", "npm cache", "Yarn cache",
        "pip cache", "Conda package cache", "Python generated cache", "Application/browser cache",
        "JetBrains IDE caches", "Unreal Derived Data Cache",
    }
    manual_shared_types = {"Maven local repository", "NuGet global packages", "pnpm shared store"}
    high_state_types = {"Android emulator data", "Android SDK system images", "Virtual machine library", "Conda environments", "VS Code extensions"}

    if kind in safe_cache_types:
        f = Finding(
            title=kind,
            path=artifact.path,
            size_bytes=artifact.size_bytes,
            category="Development/application cache",
            disposition="probably_safe_cleanup",
            risk="low" if kind not in {"Gradle cache", "Go module cache"} else "medium",
            confidence="high",
            why_it_exists="This directory stores generated or downloaded cache data used to accelerate development/application workflows.",
            recommendation="If the space is meaningful, prune it using the owning tool/application's supported cache workflow after confirming no install/build is active.",
            removal_risk="The data is generally regenerable, but later builds/installs may be slower, require network access, or fail offline.",
            related_to=artifact.related_to,
            estimated_reclaimable_bytes=artifact.size_bytes,
            evidence=evidence,
            age_days=age,
        )
    elif kind in manual_shared_types:
        f = Finding(
            title=kind,
            path=artifact.path,
            size_bytes=artifact.size_bytes,
            category="Shared development storage",
            disposition="manual_review",
            risk="medium",
            confidence="high",
            why_it_exists="This is shared package/dependency storage that can serve multiple projects or contain locally produced artifacts.",
            recommendation="Inspect ownership and use the package manager's supported maintenance commands. Do not treat the whole directory as disposable cache.",
            removal_risk="Private, unpublished or offline dependencies can be lost; active projects may need to restore data.",
            related_to=artifact.related_to,
            estimated_reclaimable_bytes=artifact.size_bytes if artifact.rebuildable else 0,
            evidence=evidence,
            age_days=age,
        )
    elif kind in high_state_types:
        f = Finding(
            title=kind,
            path=artifact.path,
            size_bytes=artifact.size_bytes,
            category="Virtualization/emulation",
            disposition="intentional_tooling",
            risk="high",
            confidence="high",
            why_it_exists="This directory holds SDK/emulator/virtual-machine state associated with development or cybersecurity workflows.",
            recommendation="Review the owning VM/emulator/SDK manager and retire only images/devices you know are no longer needed. Never delete backing disks blindly.",
            removal_risk="Removal can destroy VM state, emulator apps/data, snapshots, lab evidence or SDK components.",
            related_to=artifact.related_to,
            estimated_reclaimable_bytes=0,
            evidence=evidence,
            age_days=age,
        )
    else:
        rebuildable = artifact.rebuildable
        f = Finding(
            title=kind,
            path=artifact.path,
            size_bytes=artifact.size_bytes,
            category="Project/development artifact",
            disposition="intentional_tooling",
            risk="medium" if rebuildable else "high",
            confidence="high" if artifact.project_markers else "medium",
            why_it_exists="This directory is associated with a development project, environment, dependency tree or generated build output.",
            recommendation=(
                "This appears reproducible from project/tool metadata, but it is intentional development data. Review project activity, lock/manifests and offline requirements before reclaiming it through the owning tool."
                if rebuildable else
                "Review against active projects/toolchains. Do not remove it merely because it is large."
            ),
            removal_risk="Removing it may break a development environment, require a full dependency restore/rebuild, lose local state, or make offline work impossible.",
            related_to=artifact.related_to,
            estimated_reclaimable_bytes=0,
            evidence=evidence,
            age_days=age,
        )
    f.priority_score = _priority(f)
    return f


def build_findings(
    inventory: ScanInventory,
    duplicates: list[DuplicateGroup],
    apps: list[ApplicationRecord],
    project_artifacts: list[ProjectArtifactRecord] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    lookup = _folder_lookup(inventory)

    user = os.environ.get("USERPROFILE", "")
    local = os.environ.get("LOCALAPPDATA", "")
    roaming = os.environ.get("APPDATA", "")
    scan_root = inventory.stats.root
    scan_drive = os.path.splitdrive(scan_root)[0] or os.environ.get("SystemDrive", "C:")
    default_windows = os.path.join(scan_drive + os.sep if scan_drive else scan_root, "Windows")
    windows_dir = os.environ.get("SystemRoot", default_windows)
    programdata = os.environ.get("PROGRAMDATA", os.path.join(scan_drive + os.sep if scan_drive else scan_root, "ProgramData"))
    program_files = os.environ.get("ProgramFiles", os.path.join(scan_drive + os.sep if scan_drive else scan_root, "Program Files"))
    temp = os.environ.get("TEMP", "") or os.environ.get("TMP", "")

    # High-confidence regenerable / system-supported cleanup targets.
    if temp:
        _add_folder_finding(
            findings, lookup, temp,
            title="User temporary files", category="Temporary files",
            disposition="probably_safe_cleanup", risk="low", confidence="high",
            why="Applications and installers use the user TEMP directory for short-lived working files.",
            recommendation="Review for active installers/processes, then use Windows Storage/Temporary files or remove only stale contents after explicit approval.",
            removal_risk="Open files may be in use; active installers can fail if their temporary payload is removed.",
            related_to=["Windows", "installers", "application caches"],
        )

    _add_folder_finding(
        findings, lookup, os.path.join(windows_dir, "Temp"),
        title="Windows temporary files", category="Temporary files",
        disposition="probably_safe_cleanup", risk="medium", confidence="high",
        why="Windows and elevated applications place temporary working data here.",
        recommendation="Prefer Windows Storage/Temporary files or Disk Cleanup rather than deleting the directory itself.",
        removal_risk="Some files may be in use; forcing locked-file removal can disrupt active work.",
        related_to=["Windows"],
    )

    if local:
        local_rules = [
            (r"CrashDumps", "Application crash dumps", "Crash dumps", "probably_safe_cleanup", "low", 1.0,
             "Application failures can create user-mode dump files here.", "Keep recent dumps if debugging; stale dumps are normally only diagnostic evidence.", "Deleting them removes post-crash debugging evidence.", ["debugging", "development"]),
            (r"D3DSCache", "Direct3D shader cache", "GPU shader cache", "probably_safe_cleanup", "low", 1.0,
             "Direct3D caches compiled shaders to speed rendering.", "Regenerable; use Windows/application-supported cache cleanup if space is meaningful.", "Games/apps may stutter temporarily while shaders rebuild.", ["gaming", "GPU"]),
            (r"NVIDIA\DXCache", "NVIDIA DirectX shader cache", "GPU shader cache", "probably_safe_cleanup", "low", 1.0,
             "The NVIDIA driver caches compiled graphics shaders.", "Regenerable; close GPU-heavy apps before any later cleanup.", "First launches may rebuild shaders and temporarily stutter.", ["gaming", "GPU"]),
            (r"NVIDIA\GLCache", "NVIDIA OpenGL shader cache", "GPU shader cache", "probably_safe_cleanup", "low", 1.0,
             "The NVIDIA driver caches OpenGL shader data.", "Regenerable; close GPU-heavy apps before any later cleanup.", "Applications may rebuild cache data on next launch.", ["gaming", "GPU"]),
            (r"AMD\DxCache", "AMD DirectX shader cache", "GPU shader cache", "probably_safe_cleanup", "low", 1.0,
             "AMD graphics software caches compiled shader data.", "Regenerable; use driver/Windows-supported cache cleanup where available.", "Applications may rebuild cache data and temporarily stutter.", ["gaming", "GPU"]),
        ]
        for rel, title, cat, disp, risk, fraction, why, rec, removal_risk, related in local_rules:
            _add_folder_finding(
                findings, lookup, os.path.join(local, *rel.split("\\")),
                title=title, category=cat, disposition=disp, risk=risk, confidence="high",
                why=why, recommendation=rec, removal_risk=removal_risk, related_to=related,
                reclaim_fraction=fraction,
            )

        # Browser profile roots are surfaced as manual-review containers, while
        # cache subdirectories are separately detected below.
        for rel, title, browser in [
            (r"Google\Chrome\User Data", "Chrome profile data", "Chrome"),
            (r"Microsoft\Edge\User Data", "Edge profile data", "Edge"),
            (r"BraveSoftware\Brave-Browser\User Data", "Brave profile data", "Brave"),
        ]:
            _add_folder_finding(
                findings, lookup, os.path.join(local, *rel.split("\\")),
                title=title, category="Browser profile", disposition="manual_review", risk="high", confidence="high",
                why=f"{browser} profile storage mixes caches with cookies, sessions, extensions, databases and local user state.",
                recommendation="Inspect cache subdirectories; do not remove the entire profile directory as a cleanup shortcut.",
                removal_risk="Whole-profile removal can destroy sessions, extensions, unsynced local data and browser configuration.",
                related_to=["browser"], reclaim_fraction=0.0,
            )

        _add_folder_finding(
            findings, lookup, os.path.join(local, "Packages"),
            title="Microsoft Store app data", category="Application data",
            disposition="manual_review", risk="high", confidence="high",
            why="Packaged Microsoft Store/MSIX applications keep per-user state, caches and databases under this managed application-data root.",
            recommendation="Review individual package ownership and use the app/Windows reset or uninstall workflow. Do not delete the Packages root wholesale.",
            removal_risk="Manual removal can erase app state, offline data and settings or leave packaged apps inconsistent.",
            related_to=["Windows", "MSIX", "applications"], reclaim_fraction=0.0,
        )

    if roaming:
        for rel, title, disp, risk, fraction, why, rec, removal_risk in [
            (r"Code\Cache", "VS Code web cache", "probably_safe_cleanup", "low", 1.0, "VS Code caches renderer/web resources here.", "Close VS Code and use application-supported cache troubleshooting/cleanup if the footprint is meaningful.", "The cache regenerates; first launch may be slower."),
            (r"Code\CachedData", "VS Code cached application data", "probably_safe_cleanup", "low", 1.0, "VS Code keeps versioned cached application resources here.", "Close VS Code before any later cleanup; cache data should regenerate.", "VS Code may rebuild/re-download cache data."),
            (r"Code\Code Cache", "VS Code compiled code cache", "probably_safe_cleanup", "low", 1.0, "Electron/V8 compiled code cache improves VS Code startup/runtime performance.", "Close VS Code before any later cleanup.", "The cache will rebuild and may temporarily slow startup."),
            (r"Code\GPUCache", "VS Code GPU cache", "probably_safe_cleanup", "low", 1.0, "Electron GPU cache stores regenerable graphics data.", "Close VS Code before any later cleanup.", "The cache will regenerate."),
            (r"Code\User\workspaceStorage", "VS Code workspace storage", "manual_review", "medium", 0.0, "Extensions and VS Code store per-workspace state here; some entries are caches while others are useful extension/workspace data.", "Review individual workspace/extension ownership rather than deleting the whole directory.", "Whole-directory removal can reset extension state and workspace-specific data."),
        ]:
            _add_folder_finding(
                findings, lookup, os.path.join(roaming, *rel.split("\\")),
                title=title, category="IDE data", disposition=disp, risk=risk, confidence="high",
                why=why, recommendation=rec, removal_risk=removal_risk, related_to=["VS Code", "development", "IDE"],
                reclaim_fraction=fraction,
            )

    if programdata:
        _add_folder_finding(
            findings, lookup, os.path.join(programdata, "Package Cache"),
            title="Installer package cache", category="Installer cache",
            disposition="do_not_touch", risk="high", confidence="high",
            why="Installers keep payloads here for repair, modify, update and uninstall operations.",
            recommendation="Do not manually delete it. Reclaim application space through supported uninstall/maintenance workflows.",
            removal_risk="Manual deletion can break repair, uninstall and update operations.",
            related_to=["installers", "applications"], reclaim_fraction=0.0,
        )

    # Windows-managed cleanup candidates.
    managed_windows_rules = [
        (os.path.join(windows_dir, "SoftwareDistribution", "Download"), "Windows Update download cache", "Windows Update stages downloaded update payloads here.", "Prefer Windows Settings > Storage > Temporary files or supported Windows Update cleanup.", "medium"),
        (os.path.join(programdata, "Microsoft", "Windows", "DeliveryOptimization", "Cache"), "Delivery Optimization cache", "Windows Delivery Optimization caches update/app content for local delivery.", "Use Windows Storage/Delivery Optimization settings for cleanup.", "low"),
        (os.path.join(windows_dir, "Minidump"), "Windows minidumps", "Windows records small crash dumps here after bugchecks.", "Keep if troubleshooting BSODs; otherwise old dumps are diagnostic cleanup candidates.", "low"),
        (os.path.join(programdata, "Microsoft", "Windows", "WER", "ReportArchive"), "Windows Error Reporting archive", "Windows Error Reporting retains crash/error reports for diagnostics.", "Review diagnostic need; Windows Storage/Disk Cleanup is preferred.", "low"),
        (os.path.join(programdata, "Microsoft", "Windows", "WER", "ReportQueue"), "Windows Error Reporting queue", "Windows Error Reporting queues reports that may be uploaded/processed.", "Review recent crash investigation needs before any cleanup.", "medium"),
        (os.path.join(scan_drive + os.sep if scan_drive else scan_root, "Windows.old"), "Previous Windows installation", "Windows can retain a prior installation after an upgrade for rollback/recovery.", "If rollback is no longer needed, use Windows Storage > Temporary files to remove Previous Windows installation(s).", "medium"),
        (os.path.join(scan_drive + os.sep if scan_drive else scan_root, "$WINDOWS.~BT"), "Windows upgrade staging data", "Windows Setup can retain feature-upgrade staging files here.", "Review through Windows Storage/Temporary files rather than deleting the folder directly.", "medium"),
        (os.path.join(windows_dir, "LiveKernelReports"), "Windows live-kernel reports", "Windows can store kernel/device crash diagnostics here.", "Keep while investigating crashes; otherwise review through supported Windows diagnostic cleanup workflows.", "medium"),
    ]
    for path, title, why, rec, risk in managed_windows_rules:
        _add_folder_finding(
            findings, lookup, path,
            title=title, category="Windows managed cleanup", disposition="probably_safe_cleanup" if "Minidump" not in title else "manual_review",
            risk=risk, confidence="high", why=why, recommendation=rec,
            removal_risk="Premature cleanup can remove rollback, update or diagnostic data; use the supported Windows workflow.",
            related_to=["Windows", "updates" if "Update" in title or "Delivery" in title else "diagnostics"],
        )

    # Recycle Bin can be large; supported Empty Recycle Bin is the correct flow.
    for path, size in _find_dirs_ending(inventory, ("$Recycle.Bin",), min_size=25 * MB)[:4]:
        f = Finding(
            title="Recycle Bin contents", path=path, size_bytes=size, category="Recycle Bin",
            disposition="probably_safe_cleanup", risk="low", confidence="high",
            why_it_exists="Deleted items remain here until the Recycle Bin is emptied, allowing recovery.",
            recommendation="Review the Recycle Bin first; empty it only after confirming nothing needs restoring.",
            removal_risk="Emptying permanently removes the easy restore copy of those files.",
            related_to=["Windows", "user files"], estimated_reclaimable_bytes=size, evidence={"scope_type": "folder"},
        )
        f.priority_score = _priority(f)
        findings.append(f)

    # Cache-only browser/application subdirectories, not full profiles.
    for path, size in _find_dirs_ending(inventory, ("Cache", "cache2", "Code Cache", "GPUCache", "Service Worker\\CacheStorage"), min_size=80 * MB)[:100]:
        w = _winish(path)
        if not any(token in w for token in ("chrome", "edge", "brave", "mozilla", "firefox", "discord", "slack", "spotify", "teams")):
            continue
        f = Finding(
            title="Large application/browser cache", path=path, size_bytes=size, category="Application/browser cache",
            disposition="probably_safe_cleanup", risk="low", confidence="medium",
            why_it_exists="Applications cache web resources, compiled code or GPU data to improve startup and browsing performance.",
            recommendation="Close the owning application and prefer its built-in cache/privacy controls. The cache should regenerate.",
            removal_risk="Sessions are normally outside cache folders, but misidentifying a profile database as cache can lose state; verify the exact path.",
            related_to=["browser", "application cache"], estimated_reclaimable_bytes=size, evidence={"scope_type": "folder"},
        )
        f.priority_score = _priority(f)
        findings.append(f)

    # Game-launcher transient storage.
    game_rules = [
        ("steamapps\\shadercache", "Steam shader cache", "Steam stores per-game shader caches to reduce runtime compilation stutter."),
        ("steamapps\\downloading", "Steam partial downloads", "Steam stores in-progress/paused game download data here."),
        ("epicgameslauncher\\saved\\webcache", "Epic Games Launcher web cache", "Epic's launcher caches web UI resources here."),
    ]
    for suffix, title, why in game_rules:
        for path, size in _find_dirs_ending(inventory, (suffix,), min_size=80 * MB)[:20]:
            partial = "partial" in title.lower()
            f = Finding(
                title=title, path=path, size_bytes=size, category="Gaming/launcher storage",
                disposition="manual_review" if partial else "probably_safe_cleanup",
                risk="medium" if partial else "low", confidence="high",
                why_it_exists=why,
                recommendation="Use the game launcher/client's own storage or cache management. Confirm no download/update is active.",
                removal_risk="Partial downloads can represent bandwidth/time already spent; shader caches will rebuild and may cause temporary stutter.",
                related_to=["gaming"], estimated_reclaimable_bytes=size, evidence={"scope_type": "folder"},
            )
            f.priority_score = _priority(f)
            findings.append(f)

    # System-critical storage: visibility without deletion suggestions.
    critical_dirs = [
        (os.path.join(windows_dir, "Installer"), "Windows Installer cache", "Windows Installer caches MSI/MSP packages required to patch, repair and uninstall software."),
        (os.path.join(windows_dir, "WinSxS"), "Windows component store", "The component store supports Windows servicing, updates, optional features and repair."),
        (os.path.join(windows_dir, "System32"), "Windows System32", "Core Windows binaries, libraries, services and configuration live here."),
        (os.path.join(windows_dir, "System32", "DriverStore"), "Windows Driver Store", "Windows keeps trusted driver packages here for device installation, rollback and servicing."),
        (os.path.join(program_files, "WindowsApps"), "Microsoft Store application store", "Protected packaged-app files are managed by Windows/MSIX servicing."),
        (os.path.join(scan_drive + os.sep if scan_drive else scan_root, "System Volume Information"), "System Volume Information", "Windows stores restore, indexing and filesystem metadata here."),
        (os.path.join(programdata, "Microsoft", "Windows Defender"), "Microsoft Defender data", "Microsoft Defender keeps security intelligence, scan history, quarantine and operational data under this managed tree."),
    ]
    for path, title, why in critical_dirs:
        _add_folder_finding(
            findings, lookup, path,
            title=title, category="System-critical storage", disposition="do_not_touch",
            risk="critical", confidence="high", why=why,
            recommendation="Do not manually delete, move, compress or change permissions on this location. Use Windows/vendor-supported management only.",
            removal_risk="Manual changes can damage Windows servicing, applications, recovery, drivers or system stability.",
            related_to=["Windows", "system"], reclaim_fraction=0.0, min_size=1,
        )

    # Large managed diagnostic/index stores deserve visibility, but are not direct-delete targets.
    for path, title, why, recommendation, related in [
        (os.path.join(programdata, "Microsoft", "Search", "Data"), "Windows Search index data", "Windows Search maintains index databases here for fast file/content search.", "If the index is unexpectedly large or unhealthy, use Windows Indexing Options/Search settings to change indexed locations or rebuild the index; do not delete the database tree manually.", ["Windows", "search"]),
        (os.path.join(windows_dir, "System32", "winevt", "Logs"), "Windows Event Log store", "Windows Event Log channels, including security and operational evidence, are stored here.", "Review channel retention and maximum sizes in Event Viewer/Group Policy. Do not bulk-delete EVTX files, especially on security or forensic systems.", ["Windows", "logs", "cybersecurity", "forensics"]),
    ]:
        _add_folder_finding(
            findings, lookup, path, title=title, category="Managed Windows data",
            disposition="manual_review", risk="high", confidence="high", why=why,
            recommendation=recommendation,
            removal_risk="Manual deletion can destroy diagnostic/security evidence or leave a Windows-managed database inconsistent.",
            related_to=related, reclaim_fraction=0.0, min_size=100 * MB,
        )

    # Semantic project/developer artifacts. Discover here as a backward-compatible
    # fallback when callers do not precompute project context.
    if project_artifacts is None:
        from .insights import discover_project_artifacts
        project_artifacts = discover_project_artifacts(inventory)
    for artifact in project_artifacts:
        findings.append(_artifact_finding(artifact))
        # Preserve the primary "intentional tooling" classification, but surface a
        # separate stale/reproducible review opportunity when evidence is strong.
        # This prevents development trees from being mislabeled as junk while still
        # making old dependency/build footprints manageable.
        if artifact.rebuildable and artifact.project_markers and (artifact.age_days or 0) >= 90:
            stale = Finding(
                title=f"Dormant reproducible development data: {artifact.artifact_type}",
                path=artifact.path, size_bytes=artifact.size_bytes, category="Development storage review",
                disposition="manual_review", risk="medium", confidence="high",
                why_it_exists="This is intentional project/development data, but nearby manifests/lock metadata indicate it is reproducible and its directory timestamp is old enough to merit review.",
                recommendation="Confirm the project is inactive, the manifests/lockfiles are preserved, and dependencies can be restored before reclaiming through the owning tool or project workflow.",
                removal_risk="The next use may require a complete restore/rebuild, network access, unavailable package versions, native toolchains, or locally patched dependencies.",
                related_to=artifact.related_to + ["intentional development tooling"],
                estimated_reclaimable_bytes=artifact.size_bytes, age_days=artifact.age_days,
                evidence={"scope_type": "folder", "project_root": artifact.project_root, "project_markers": artifact.project_markers, "rebuildable": True, "stale_threshold_days": 90},
            )
            stale.priority_score = _priority(stale)
            findings.append(stale)

    # Large interesting files: age and type provide context.
    for rec in inventory.interesting_files:
        ext = rec.extension.lower()
        age = _age_days(rec.modified_ts)
        win = _winish(rec.path)
        physical_reclaim, physical_evidence = file_reclaim_basis(rec)

        if ext in VM_EXTENSIONS:
            owner = "WSL/Docker virtual disk" if ("wsl" in win or "docker" in win or "ext4.vhdx" in win) else "Virtual machine disk/image"
            f = Finding(
                title=owner, path=rec.path, size_bytes=rec.size_bytes, category="Virtualization",
                disposition="intentional_tooling", risk="high", confidence="high",
                why_it_exists="Virtualization, WSL, Docker or emulator software stores guest filesystems/state in large disk images.",
                recommendation="Inspect the owning distro/VM/container platform. Retire data through that platform; never delete an active backing disk directly.",
                removal_risk="Direct deletion can destroy a VM, WSL distro, containers, images, volumes, lab state or development data.",
                related_to=["virtualization", "WSL", "Docker", "cybersecurity", "development"],
                estimated_reclaimable_bytes=0, age_days=age,
                evidence={"extension": ext, "scope_type": "file", **physical_evidence},
            )
        elif ext in SECURITY_DATA_EXTENSIONS:
            f = Finding(
                title="Large cybersecurity/forensics artifact", path=rec.path, size_bytes=rec.size_bytes,
                category="Cybersecurity/forensics data", disposition="intentional_tooling", risk="high", confidence="high",
                why_it_exists="Packet captures, forensic images and raw evidence can be intentionally very large.",
                recommendation="Review against active investigations, labs, CTFs and retention requirements; archive externally if appropriate rather than treating it as junk.",
                removal_risk="Removal can destroy unique evidence, captures or lab artifacts.",
                related_to=["cybersecurity", "forensics", "packet capture"], estimated_reclaimable_bytes=0,
                age_days=age, evidence={"extension": ext, "scope_type": "file", **physical_evidence},
            )
        elif ext in ARCHIVE_EXTENSIONS and (age or 0) >= 45:
            f = Finding(
                title="Large old archive/disk image", path=rec.path, size_bytes=rec.size_bytes,
                category="Archives/install media", disposition="manual_review", risk="medium", confidence="medium",
                why_it_exists="Archives and disk images often accumulate as downloads, installers, backups, VM media or project handoffs.",
                recommendation="Verify whether it is still needed, unique, or already extracted/installed. Consider external archival for intentional long-term media.",
                removal_risk="The file may be the only installer, backup, evidence set or offline recovery image.",
                related_to=["installers", "backups", "VMs", "development"], estimated_reclaimable_bytes=physical_reclaim,
                age_days=age, evidence={"extension": ext, "scope_type": "file", **physical_evidence},
            )
        elif ext in INSTALLER_EXTENSIONS and (age or 0) >= 60 and any(token in win for token in ("\\downloads\\", "\\desktop\\", "\\temp\\")):
            f = Finding(
                title="Old large installer/package", path=rec.path, size_bytes=rec.size_bytes,
                category="Installers/downloads", disposition="manual_review", risk="low", confidence="medium",
                why_it_exists="Standalone installers/packages commonly remain after software installation or testing.",
                recommendation="Confirm the application is installed and the file is not needed for offline reinstall, lab reproduction or deployment before removing it.",
                removal_risk="You may lose an offline installer or a specific version needed for reproducibility.",
                related_to=["installers", "development"], estimated_reclaimable_bytes=physical_reclaim,
                age_days=age, evidence={"extension": ext, "scope_type": "file", **physical_evidence},
            )
        elif ext in {".dmp", ".mdmp"}:
            f = Finding(
                title="Large crash dump", path=rec.path, size_bytes=rec.size_bytes,
                category="Crash dumps", disposition="manual_review", risk="medium", confidence="high",
                why_it_exists="Crash dumps capture process/system memory for debugging failures.",
                recommendation="Keep if debugging or investigating an incident; otherwise old dumps can be cleanup candidates after approval.",
                removal_risk="Deleting the dump removes potentially unique debugging or incident-response evidence.",
                related_to=["debugging", "cybersecurity", "development"], estimated_reclaimable_bytes=physical_reclaim,
                age_days=age, evidence={"scope_type": "file", **physical_evidence},
            )
        elif ext == ".evtx" and (age or 0) >= 30:
            managed_event_log = "\\windows\\system32\\winevt\\logs\\" in win
            f = Finding(
                title="Windows Event Log / EVTX evidence", path=rec.path, size_bytes=rec.size_bytes,
                category="Windows event logs", disposition="manual_review", risk="high", confidence="high",
                why_it_exists="EVTX files contain Windows event/audit records and can be important for troubleshooting, incident response, SIEM ingestion, audit trails and forensics.",
                recommendation=(
                    "This appears to be the live Windows Event Log store. Do not delete individual files; manage retention/maximum sizes through Event Viewer, Group Policy or supported logging controls."
                    if managed_event_log else
                    "This appears to be an exported/copied EVTX. Confirm incident/audit retention, SIEM ingestion and backup requirements before considering archival or removal."
                ),
                removal_risk="Deleting event logs can destroy security/audit/diagnostic evidence and, for managed live logs, bypass supported log-retention workflows.",
                related_to=["Windows", "event logs", "SIEM", "cybersecurity", "forensics"],
                estimated_reclaimable_bytes=0 if managed_event_log else physical_reclaim,
                age_days=age, evidence={"scope_type": "file", "managed_live_event_log": managed_event_log, **physical_evidence},
            )
        elif ext in {".log", ".etl"} and (age or 0) >= 30:
            f = Finding(
                title="Large old log/trace", path=rec.path, size_bytes=rec.size_bytes,
                category="Logs/traces", disposition="manual_review", risk="medium", confidence="medium",
                why_it_exists="Applications and Windows components produce logs/traces for diagnostics and auditing.",
                recommendation="Identify the owner and retention need; prefer supported log rotation/retention controls.",
                removal_risk="Logs may be needed for troubleshooting, security investigations, audits or compliance.",
                related_to=["logs", "SIEM", "cybersecurity", "development"], estimated_reclaimable_bytes=physical_reclaim,
                age_days=age, evidence={"scope_type": "file", **physical_evidence},
            )
        elif ext in BACKUP_EXTENSIONS and (age or 0) >= 60:
            f = Finding(
                title="Large old backup-like file", path=rec.path, size_bytes=rec.size_bytes,
                category="Backups", disposition="manual_review", risk="high", confidence="low",
                why_it_exists="Applications/users often create .bak/.backup/.old copies during migrations, editing or upgrades.",
                recommendation="Identify the producer and verify a newer good copy/backup exists before considering removal.",
                removal_risk="It may be the only recoverable copy of important data.",
                related_to=["backups"], estimated_reclaimable_bytes=physical_reclaim,
                age_days=age, evidence={"scope_type": "file", **physical_evidence},
            )
        else:
            continue
        f.priority_score = _priority(f)
        findings.append(f)

    # System-managed files are checked explicitly and via top files.
    critical_system_names = {
        "pagefile.sys": ("Windows paging file", "Virtual-memory backing store managed by Windows.", "Do not manually delete or resize it; review Virtual Memory settings only if you intentionally want to change paging behavior."),
        "swapfile.sys": ("Windows swap file", "Windows-managed swap backing used by the OS/app model.", "Do not manually delete it."),
        "hiberfil.sys": ("Hibernation/Fast Startup file", "Windows stores hibernation/Fast Startup state here.", "Do not delete directly. Its size is only reclaimable by intentionally changing hibernation/Fast Startup configuration after reviewing the tradeoff."),
        "memory.dmp": ("Windows kernel memory dump", "Windows may create this after a bugcheck for debugging.", "Keep while diagnosing crashes/incidents; otherwise review it as diagnostic data."),
    }
    candidate_by_norm = {_norm(x.path): x for x in inventory.top_files}
    root = inventory.stats.root
    volume_root = scan_drive + os.sep if scan_drive else root
    candidates = [
        os.path.join(volume_root, "pagefile.sys"), os.path.join(volume_root, "swapfile.sys"), os.path.join(volume_root, "hiberfil.sys"),
        os.path.join(windows_dir, "MEMORY.DMP"),
    ]
    seen: set[str] = set()
    for system_path in candidates:
        rec = candidate_by_norm.get(_norm(system_path))
        size: int | None = rec.size_bytes if rec else None
        if size is None:
            try:
                if os.path.isfile(system_path):
                    size = os.path.getsize(system_path)
            except OSError:
                size = None
        if size is None:
            continue
        seen.add(_norm(system_path))
        name = os.path.basename(system_path).lower()
        title, why, recommendation = critical_system_names[name]
        is_dump = name == "memory.dmp"
        if rec is not None:
            system_reclaim, system_basis = file_reclaim_basis(rec)
        else:
            system_reclaim, system_basis = size, {
                "logical_size_bytes": size,
                "allocated_size_bytes": None,
                "reclaim_basis": "logical_size_fallback",
                "reclaim_estimate_caveat": "Allocated size was unavailable for this direct system-file probe.",
            }
        f = Finding(
            title=title, path=system_path, size_bytes=size,
            category="Crash dumps" if is_dump else "System-managed file",
            disposition="manual_review" if is_dump else "do_not_touch",
            risk="medium" if is_dump else "critical", confidence="high",
            why_it_exists=why, recommendation=recommendation,
            removal_risk="Incorrect handling can affect system features/stability or destroy crash-debugging evidence.",
            related_to=["Windows", "system", "debugging"], estimated_reclaimable_bytes=system_reclaim if is_dump else 0,
            evidence={"scope_type": "file", **system_basis},
        )
        f.priority_score = _priority(f)
        findings.append(f)

    # Conservative orphan/leftover reconnaissance. "Unmatched" is not the same as
    # orphaned: portable apps, launchers and vendor data may have no uninstall entry.
    def app_tokens() -> set[str]:
        out: set[str] = set()
        stop = {"microsoft", "corporation", "inc", "ltd", "software", "windows", "application", "app"}
        for app in apps:
            for token in re.findall(r"[a-z0-9]{4,}", f"{app.name} {app.publisher}".lower()):
                if token not in stop:
                    out.add(token)
        return out

    installed_tokens = app_tokens()
    protected_names = {
        "microsoft", "packages", "temp", "google", "mozilla", "nvidia", "amd", "docker",
        "programs", "crashdumps", "connecteddevicesplatform", "comms", "d3dscache",
    }
    for base in (local, roaming, programdata):
        if not base:
            continue
        base_n = _norm(base)
        for path, size in inventory.directory_sizes.items():
            if size < 750 * MB or _norm(path) == base_n:
                continue
            try:
                if _norm(os.path.dirname(path)) != base_n:
                    continue
            except OSError:
                continue
            name = os.path.basename(path).lower()
            if name in protected_names:
                continue
            tokens = set(re.findall(r"[a-z0-9]{4,}", name))
            if tokens & installed_tokens:
                continue
            age = _age_days(inventory.directory_mtimes.get(path))
            f = Finding(
                title="Large application-data folder with no obvious installed-app match",
                path=path, size_bytes=size, category="Potential leftover/orphaned data",
                disposition="manual_review", risk="high", confidence="low",
                why_it_exists="Large per-user/vendor data can remain after an uninstall, belong to a portable application, or use a vendor/product name that does not match Windows uninstall metadata.",
                recommendation="Identify the owning product by folder contents, nearby logs/configuration and recent activity. Treat this only as an orphan candidate, never proof that the folder is disposable.",
                removal_risk="The directory can contain unique application databases, game saves, projects, authentication state or portable-app data.",
                related_to=["applications", "AppData", "orphan analysis"],
                estimated_reclaimable_bytes=0, age_days=age,
                evidence={"installed_app_name_match": False, "heuristic": "direct application-data child name token comparison"},
            )
            f.priority_score = _priority(f)
            findings.append(f)

    # Exact duplicates: verified content but path-level semantics still require review.
    for group in duplicates:
        f = Finding(
            title=f"Exact duplicate large files ({len(group.paths)} paths)",
            path=group.paths[0], size_bytes=group.total_logical_bytes,
            category="Duplicates", disposition="manual_review", risk="medium", confidence="high",
            why_it_exists="Files with identical size and full SHA-256 content were found at multiple paths.",
            recommendation="Determine which path is authoritative and whether copies are referenced by projects, VMs, installers, backups or applications. Hard-linked aliases are already excluded from reclaimable-space estimates.",
            removal_risk="Byte-identical content can still be required at a specific path. Removing the wrong instance can break workflows or backup assumptions.",
            related_to=["duplicates", "backups", "VMs", "development"],
            estimated_reclaimable_bytes=group.reclaimable_bytes,
            evidence={
                "sha256": group.sha256,
                "paths": group.paths,
                "size_each": group.size_bytes_each,
                "distinct_file_instances": group.distinct_file_instances,
                "hardlink_sets": group.hardlink_sets,
                "allocated_bytes_total": group.allocated_bytes_total,
                "reclaimable_basis": group.reclaimable_basis,
                "note": group.note,
            },
        )
        f.priority_score = _priority(f)
        findings.append(f)

    # Large applications are review targets; dev/security/runtime tooling stays separate.
    for app in apps:
        if not app.estimated_size_bytes or app.estimated_size_bytes < 1024 * MB:
            continue
        protected = _is_protected_windows_application(app)
        intentional = app.classification.startswith("Likely intentional") or "side-by-side" in app.classification.lower()
        f = Finding(
            title=f"Large installed application: {app.name}",
            path=app.install_location or "Installed applications registry",
            size_bytes=app.estimated_size_bytes,
            category="Installed applications",
            disposition="do_not_touch" if protected else "intentional_tooling" if intentional else "manual_review",
            risk="medium", confidence="medium",
            why_it_exists="This installed application has a reported or measured footprint large enough to materially affect storage.",
            recommendation=(
                "Treat this as a shared or Windows-integrated component. Do not count its reported size as ordinary cleanup potential or delete its files manually."
                if protected else "Likely development/cybersecurity/runtime tooling. Review current projects, labs and dependencies; do not remove based on size alone."
                if intentional else
                "Check actual usage. If later approved for removal, use Windows Installed Apps or the vendor uninstaller rather than deleting program files."
            ),
            removal_risk=(
                "Removal or manual file deletion can break Windows features or applications that depend on the shared browser runtime."
                if protected else "Removal can break projects, labs, SDK/runtime dependencies or workflows."
                if intentional else
                "Uninstalling can remove application data, integrations or shared components; verify dependencies and backups first."
            ),
            related_to=["applications"] + (["Windows", "shared runtime"] if protected else ["development", "cybersecurity"] if intentional else []),
            estimated_reclaimable_bytes=0 if protected or intentional else app.estimated_size_bytes,
            evidence={"scope_type": "application", "version": app.version, "publisher": app.publisher or "(missing)", "scope": app.scope, "architecture": app.architecture, "size_is_estimate": True},
        )
        f.priority_score = _priority(f)
        findings.append(f)

    # Multiple installed versions: informative review only.
    by_name: dict[str, list[ApplicationRecord]] = defaultdict(list)
    for app in apps:
        base = re.sub(r"\b\d+(?:\.\d+){0,4}\b", "", app.name.lower())
        base = re.sub(r"\s+", " ", base).strip(" -_()")
        if base:
            by_name[base].append(app)
    for variants in by_name.values():
        versions = {a.version for a in variants if a.version}
        if len(variants) < 2 or len(versions) < 2:
            continue
        names_blob = " ".join(a.name.lower() for a in variants)
        side_by_side = any(t in names_blob for t in SIDE_BY_SIDE_RUNTIME_TOKENS) or any(t in names_blob for t in DEV_SECURITY_APP_TOKENS)
        size = sum(a.estimated_size_bytes or 0 for a in variants)
        f = Finding(
            title=f"Multiple installed versions: {variants[0].name}",
            path=variants[0].install_location or "Installed applications registry",
            size_bytes=size, category="Installed applications",
            disposition="intentional_tooling" if side_by_side else "manual_review",
            risk="medium", confidence="medium",
            why_it_exists="Multiple versions can accumulate through upgrades or exist intentionally for side-by-side SDK/runtime/toolchain compatibility.",
            recommendation="Check project/runtime dependencies and vendor guidance. If a version is truly unused, remove it only through its supported uninstaller.",
            removal_risk="Older projects or applications may depend on a specific side-by-side runtime/SDK version.",
            related_to=["applications", "runtimes", "SDKs", "development"], estimated_reclaimable_bytes=0,
            evidence={"versions": sorted(versions), "applications": [a.name for a in variants]},
        )
        f.priority_score = _priority(f)
        findings.append(f)

    return normalize_findings(findings)


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    """Deduplicate and rank findings without changing their safety semantics."""
    unique: dict[tuple[str, str], Finding] = {}
    for f in findings:
        if not f.priority_score:
            f.priority_score = _priority(f)
        if not f.category_group:
            f.category_group = resolve_category_group(f.category)
        key = (f.title, _norm(f.path))
        old = unique.get(key)
        if old is None or f.size_bytes > old.size_bytes:
            unique[key] = f

    ranked = list(unique.values())
    disposition_rank = {
        "probably_safe_cleanup": 0,
        "manual_review": 1,
        "intentional_tooling": 2,
        "do_not_touch": 3,
        "informational": 4,
    }
    ranked.sort(key=lambda f: (disposition_rank[f.disposition], -f.priority_score, -f.estimated_reclaimable_bytes, -f.size_bytes))
    return ranked
