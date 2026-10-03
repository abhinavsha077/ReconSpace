from __future__ import annotations

import json
import locale
import os
import platform
import re
import subprocess
from pathlib import Path
from typing import Any, Callable

from .models import (
    ApplicationRecord,
    BinaryTrustRecord,
    CollectorResult,
    PathSecurityRecord,
    ProcessRecord,
    ScheduledTaskRecord,
    ServiceRecord,
    StartupRecord,
)
from .sizeutil import allocated_size
from .ntfs import collect_ntfs_mft_status

IS_WINDOWS = os.name == "nt"


def _decode_console_bytes(value: bytes | None) -> str:
    data = value or b""
    if not data:
        return ""
    if data.startswith(b"\xff\xfe") or data.startswith(b"\xfe\xff"):
        try:
            return data.decode("utf-16").replace("\x00", "").strip()
        except UnicodeError:
            pass
    # Older wsl.exe and some Windows tools can emit UTF-16LE without a BOM.
    if len(data) >= 8 and data.count(b"\x00") > len(data) // 8:
        try:
            return data.decode("utf-16-le", errors="replace").replace("\x00", "").strip()
        except UnicodeError:
            pass
    for enc in ("utf-8", locale.getpreferredencoding(False), "cp1252"):
        try:
            return data.decode(enc).replace("\x00", "").strip()
        except (UnicodeError, LookupError):
            continue
    return data.decode("utf-8", errors="replace").replace("\x00", "").strip()


def _run_read_only(command: list[str], timeout: int = 45) -> CollectorResult:
    """Run a fixed inventory-only command and capture output. No shell is used."""
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=False,
            timeout=timeout,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        stdout = _decode_console_bytes(proc.stdout)
        stderr = _decode_console_bytes(proc.stderr)
        return CollectorResult(
            name=" ".join(command[:2]),
            ok=proc.returncode == 0,
            data=stdout,
            error=stderr if proc.returncode else "",
        )
    except FileNotFoundError as exc:
        return CollectorResult(
            name=" ".join(command[:2]), ok=False,
            error=f"Optional inventory command is not installed or not on PATH: {type(exc).__name__}: {exc}",
            applicable=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return CollectorResult(name=" ".join(command[:2]), ok=False, error=f"{type(exc).__name__}: {exc}")


def _powershell_json(script: str, name: str, timeout: int = 45) -> CollectorResult:
    if not IS_WINDOWS:
        return CollectorResult(name=name, ok=False, error="Windows-only collector", applicable=False)
    # Process-local output encoding only; no system setting or profile is changed.
    prefix = "$OutputEncoding=[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false);"
    result = _run_read_only([
        "powershell.exe",
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command", prefix + script,
    ], timeout=timeout)
    result.name = name
    if not result.ok or not result.data:
        return result
    try:
        result.data = json.loads(result.data)
    except json.JSONDecodeError as exc:
        result.ok = False
        result.error = f"JSONDecodeError: {exc}"
    return result


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _norm(path: str) -> str:
    cleaned = str(path or "").strip().strip('"').strip("'").strip()
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    return os.path.normcase(os.path.normpath(os.path.abspath(os.path.expandvars(os.path.expanduser(cleaned)))))


def collect_installed_applications(directory_sizes: dict[str, int] | None = None) -> tuple[list[ApplicationRecord], list[CollectorResult]]:
    if not IS_WINDOWS:
        return [], [CollectorResult(name="installed_applications", ok=False, error="Windows-only collector", applicable=False)]

    try:
        import winreg
    except ImportError as exc:
        return [], [CollectorResult(name="installed_applications", ok=False, error=str(exc))]

    apps: list[ApplicationRecord] = []
    seen: set[tuple[str, str, str, str]] = set()
    results: list[CollectorResult] = []
    scanned_size_lookup = {_norm(path): size for path, size in (directory_sizes or {}).items()}

    roots = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "machine", "64-bit", winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "machine", "32-bit", winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", "user", "native", 0),
    ]

    for hive, key_path, scope, arch, view_flag in roots:
        before = len(apps)
        try:
            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ | view_flag) as parent:
                count = winreg.QueryInfoKey(parent)[0]
                for i in range(count):
                    try:
                        subname = winreg.EnumKey(parent, i)
                        with winreg.OpenKey(parent, subname, 0, winreg.KEY_READ | view_flag) as key:
                            def q(name: str, default=""):
                                try:
                                    return winreg.QueryValueEx(key, name)[0]
                                except OSError:
                                    return default

                            name = str(q("DisplayName", "")).strip()
                            if not name:
                                continue
                            version = str(q("DisplayVersion", "")).strip()
                            publisher = str(q("Publisher", "")).strip()
                            install_location = os.path.expandvars(str(q("InstallLocation", "")).strip())
                            install_date = str(q("InstallDate", "")).strip()
                            estimated_kb = q("EstimatedSize", 0)
                            estimated_size = int(estimated_kb) * 1024 if isinstance(estimated_kb, int) and estimated_kb > 0 else None

                            dedupe_key = (name.casefold(), version.casefold(), install_location.casefold(), arch.casefold())
                            if dedupe_key in seen:
                                continue
                            seen.add(dedupe_key)

                            if estimated_size is None and install_location and scanned_size_lookup:
                                estimated_size = scanned_size_lookup.get(_norm(install_location))

                            apps.append(ApplicationRecord(
                                name=name,
                                version=version,
                                publisher=publisher,
                                estimated_size_bytes=estimated_size,
                                install_location=install_location,
                                install_date=install_date,
                                scope=scope,
                                architecture=arch,
                                package_type="Win32/MSI",
                            ))
                    except OSError:
                        continue
            results.append(CollectorResult(name=f"uninstall_registry_{scope}_{arch}", ok=True, data={"added": len(apps) - before}))
        except FileNotFoundError as exc:
            results.append(CollectorResult(name=f"uninstall_registry_{scope}_{arch}", ok=False, error=f"Registry view/key is absent: {exc}", applicable=False))
        except OSError as exc:
            results.append(CollectorResult(name=f"uninstall_registry_{scope}_{arch}", ok=False, error=f"{type(exc).__name__}: {exc}"))

    appx_result = _powershell_json(
        "Get-AppxPackage | Select-Object Name,Version,Publisher,InstallLocation,PackageFullName,IsFramework,Architecture | ConvertTo-Json -Depth 3 -Compress",
        "appx_packages_current_user",
        timeout=75,
    )
    results.append(appx_result)
    if appx_result.ok:
        for item in _as_list(appx_result.data):
            if not isinstance(item, dict):
                continue
            name = str(item.get("Name") or "").strip()
            location = str(item.get("InstallLocation") or "").strip()
            version = str(item.get("Version") or "").strip()
            publisher = str(item.get("Publisher") or "").strip()
            architecture = str(item.get("Architecture") or "AppX/MSIX")
            is_framework = bool(item.get("IsFramework"))
            if not name:
                continue
            dedupe_key = (name.casefold(), version.casefold(), location.casefold(), architecture.casefold())
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            estimated_size = scanned_size_lookup.get(_norm(location)) if location else None
            apps.append(ApplicationRecord(
                name=name,
                version=version,
                publisher=publisher,
                estimated_size_bytes=estimated_size,
                install_location=location,
                scope="user/AppX",
                architecture=architecture or "AppX/MSIX",
                note="Packaged Windows application; size can be unavailable when WindowsApps is not readable.",
                package_type="AppX/MSIX",
                is_framework=is_framework,
            ))

    apps.sort(key=lambda a: a.estimated_size_bytes or -1, reverse=True)
    return apps, results


def collect_startup_items() -> tuple[list[StartupRecord], list[CollectorResult]]:
    if not IS_WINDOWS:
        return [], [CollectorResult(name="startup_items", ok=False, error="Windows-only collector", applicable=False)]

    items: list[StartupRecord] = []
    results: list[CollectorResult] = []
    try:
        import winreg
        run_keys = [
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Run", 0),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run 64", winreg.KEY_WOW64_64KEY),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Run 32", winreg.KEY_WOW64_32KEY),
        ]
        for hive, path, source, flag in run_keys:
            try:
                with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | flag) as key:
                    value_count = winreg.QueryInfoKey(key)[1]
                    for i in range(value_count):
                        name, value, _ = winreg.EnumValue(key, i)
                        items.append(StartupRecord(source=source, name=name, command=str(value)))
                results.append(CollectorResult(name=source, ok=True))
            except FileNotFoundError as exc:
                results.append(CollectorResult(name=source, ok=False, error=f"Startup registry key is absent: {exc}", applicable=False))
            except OSError as exc:
                results.append(CollectorResult(name=source, ok=False, error=f"{type(exc).__name__}: {exc}"))
    except ImportError as exc:
        results.append(CollectorResult(name="startup_registry", ok=False, error=str(exc)))

    startup_envs = [
        ("APPDATA", "Microsoft/Windows/Start Menu/Programs/Startup"),
        ("PROGRAMDATA", "Microsoft/Windows/Start Menu/Programs/StartUp"),
    ]
    for env_name, suffix in startup_envs:
        base = os.environ.get(env_name, "").strip()
        if not base:
            continue
        folder = Path(base) / suffix
        try:
            if folder.exists():
                for child in folder.iterdir():
                    items.append(StartupRecord(source=str(folder), name=child.name, command=str(child)))
            results.append(CollectorResult(name=f"startup_folder:{folder}", ok=True))
        except OSError as exc:
            results.append(CollectorResult(name=f"startup_folder:{folder}", ok=False, error=str(exc)))
    return items, results


def collect_services() -> tuple[list[ServiceRecord], CollectorResult]:
    script = (
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,State,StartMode,PathName,StartName,ProcessId,Description | ConvertTo-Json -Depth 3 -Compress"
    )
    result = _powershell_json(script, "services", timeout=90)
    services: list[ServiceRecord] = []
    if result.ok:
        for item in _as_list(result.data):
            if not isinstance(item, dict):
                continue
            pid = item.get("ProcessId")
            services.append(ServiceRecord(
                name=str(item.get("Name") or ""),
                display_name=str(item.get("DisplayName") or ""),
                state=str(item.get("State") or ""),
                start_mode=str(item.get("StartMode") or ""),
                path_name=str(item.get("PathName") or ""),
                start_name=str(item.get("StartName") or ""),
                process_id=int(pid) if isinstance(pid, (int, float)) else None,
                description=str(item.get("Description") or ""),
            ))
    return services, result


def collect_scheduled_tasks() -> tuple[list[ScheduledTaskRecord], CollectorResult]:
    script = (
        "$t=Get-ScheduledTask | ForEach-Object { "
        "$task=$_;$info=$null;try{$info=$task|Get-ScheduledTaskInfo -ErrorAction Stop}catch{};"
        "[PSCustomObject]@{TaskName=$task.TaskName;TaskPath=$task.TaskPath;State=[string]$task.State;Author=$task.Author;"
        "Actions=@($task.Actions|ForEach-Object{ if($_.Execute){(($_.Execute)+' '+($_.Arguments)).Trim()}elseif($_.ClassId){'COM:'+([string]$_.ClassId)}else{[string]$_.CimClass.CimClassName}});"
        "Triggers=@($task.Triggers|ForEach-Object{(([string]$_.CimClass.CimClassName)+' Start='+([string]$_.StartBoundary)+' Enabled='+([string]$_.Enabled)).Trim()});"
        "Hidden=[bool]$task.Settings.Hidden;UserId=[string]$task.Principal.UserId;RunLevel=[string]$task.Principal.RunLevel;"
        "LastRunTime=if($info){[string]$info.LastRunTime}else{''};NextRunTime=if($info){[string]$info.NextRunTime}else{''};"
        "LastTaskResult=if($info){[int64]$info.LastTaskResult}else{$null}}};"
        "$t | ConvertTo-Json -Depth 6 -Compress"
    )
    result = _powershell_json(script, "scheduled_tasks", timeout=150)
    tasks: list[ScheduledTaskRecord] = []
    if result.ok:
        for item in _as_list(result.data):
            if not isinstance(item, dict):
                continue
            actions = item.get("Actions") or []
            triggers = item.get("Triggers") or []
            if not isinstance(actions, list):
                actions = [str(actions)]
            if not isinstance(triggers, list):
                triggers = [str(triggers)]
            task_result = item.get("LastTaskResult")
            tasks.append(ScheduledTaskRecord(
                task_name=str(item.get("TaskName") or ""),
                task_path=str(item.get("TaskPath") or ""),
                state=str(item.get("State") or ""),
                author=str(item.get("Author") or ""),
                actions=[str(x) for x in actions],
                triggers=[str(x) for x in triggers],
                hidden=bool(item.get("Hidden")),
                user_id=str(item.get("UserId") or ""),
                run_level=str(item.get("RunLevel") or ""),
                last_run_time=str(item.get("LastRunTime") or ""),
                next_run_time=str(item.get("NextRunTime") or ""),
                last_task_result=int(task_result) if isinstance(task_result, (int, float)) else None,
            ))
    return tasks, result



def collect_processes(include_owner: bool = True) -> tuple[list[ProcessRecord], CollectorResult]:
    """Inventory active processes without opening handles or changing state."""
    owner_index = (
        "$owners=@{};try{& tasklist.exe /V /FO CSV /NH 2>$null|ConvertFrom-Csv -Header ImageName,PID,SessionName,SessionNumber,MemoryUsage,Status,UserName,CPUTime,WindowTitle|ForEach-Object{if($_.PID -match '^\\d+$' -and $_.UserName -and $_.UserName -ne 'N/A'){$owners[[int]$_.PID]=[string]$_.UserName}}}catch{};"
        if include_owner else "$owners=@{};"
    )
    script = (
        owner_index + "$rows=Get-CimInstance Win32_Process | ForEach-Object {$owner=[string]$owners[[int]$_.ProcessId];"
        "[PSCustomObject]@{ProcessId=$_.ProcessId;Name=$_.Name;ExecutablePath=$_.ExecutablePath;"
        "CommandLine=$_.CommandLine;WorkingSetSize=$_.WorkingSetSize;CreationDate=$_.CreationDate;Owner=$owner}};"
        "$rows | ConvertTo-Json -Depth 3 -Compress"
    )
    result = _powershell_json(script, "active_processes", timeout=60)
    records: list[ProcessRecord] = []
    if result.ok:
        for item in _as_list(result.data):
            if not isinstance(item, dict):
                continue
            pid = item.get("ProcessId")
            working = item.get("WorkingSetSize")
            records.append(ProcessRecord(
                pid=int(pid) if isinstance(pid, (int, float)) else 0,
                name=str(item.get("Name") or ""),
                executable_path=str(item.get("ExecutablePath") or ""),
                command_line=str(item.get("CommandLine") or ""),
                owner=str(item.get("Owner") or ""),
                working_set_bytes=int(working) if isinstance(working, (int, float)) else None,
                creation_date=str(item.get("CreationDate") or ""),
            ))
    records.sort(key=lambda row: row.working_set_bytes or 0, reverse=True)
    return records, result


def _ps_single_quote(value: str) -> str:
    return str(value).replace("'", "''")


def _is_user_writable_location(path: str) -> bool:
    text = _norm(path).replace("/", "\\").casefold()
    candidates = [
        os.environ.get("USERPROFILE", ""), os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("APPDATA", ""), os.environ.get("TEMP", ""),
    ]
    for candidate in candidates:
        if candidate and text.startswith(_norm(candidate).replace("/", "\\").casefold().rstrip("\\") + "\\"):
            return True
    return any(token in text for token in ("\\users\\public\\", "\\downloads\\", "\\temp\\"))


def collect_binary_trust(
    paths: list[str],
    batch_size: int = 40,
    include_hashes: bool = False,
    cancel: Callable[[], bool] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[BinaryTrustRecord], list[CollectorResult]]:
    """Read Authenticode/certificate metadata for selected persistence binaries.

    Hashing is optional because it adds I/O. No online reputation service is
    contacted; all data is local.
    """
    unique: list[str] = []
    seen: set[str] = set()
    records: list[BinaryTrustRecord] = []
    results: list[CollectorResult] = []

    for path in paths:
        expanded = os.path.expandvars(os.path.expanduser(str(path or "").strip()))
        if not expanded:
            continue
        key = _norm(expanded)
        if key in seen:
            continue
        seen.add(key)
        drive = os.path.splitdrive(expanded)[0]
        if drive and drive.endswith(":") and len(drive) == 2 and not os.path.exists(drive + "\\"):
            records.append(BinaryTrustRecord(
                path=expanded,
                exists=False,
                signature_status="Missing",
                is_user_writable_location=_is_user_writable_location(expanded),
                note="Drive letter is offline or unavailable; verification skipped.",
            ))
            continue
        unique.append(expanded)
    if not IS_WINDOWS:
        return records, [CollectorResult(name="binary_trust", ok=False, error="Windows-only collector", applicable=False)]

    total_batches = (len(unique) + max(1, batch_size) - 1) // max(1, batch_size)
    for batch_index in range(0, len(unique), max(1, batch_size)):
        if cancel and cancel():
            break
        batch_num = batch_index // max(1, batch_size) + 1
        if progress:
            progress({
                "phase": "binary_trust",
                "batch": batch_num,
                "total_batches": total_batches,
                "count": len(unique),
                "detail": f"Verifying code signatures (batch {batch_num} of {total_batches})...",
            })
        batch = unique[batch_index:batch_index + max(1, batch_size)]
        literal = ",".join("'" + _ps_single_quote(path) + "'" for path in batch)
        hash_expression = (
            "$hash='';try{$hash=(Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash}catch{};"
            if include_hashes else "$hash='';"
        )
        script = (
            f"$paths=@({literal});$rows=foreach($p in $paths){{"
            "$exists=Test-Path -LiteralPath $p -PathType Leaf;"
            "$status='Missing';$subject='';$issuer='';$thumb='';$size=$null;$mtime='';"
            "if($exists){try{$item=Get-Item -LiteralPath $p -Force -ErrorAction Stop;$size=[int64]$item.Length;$mtime=[string]$item.LastWriteTimeUtc}catch{};"
            "try{$sig=Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop;$status=[string]$sig.Status;"
            "if($sig.SignerCertificate){$subject=[string]$sig.SignerCertificate.Subject;$issuer=[string]$sig.SignerCertificate.Issuer;$thumb=[string]$sig.SignerCertificate.Thumbprint}}catch{$status='Error'}};"
            + hash_expression +
            "[PSCustomObject]@{Path=$p;Exists=[bool]$exists;SignatureStatus=$status;SignerSubject=$subject;SignerIssuer=$issuer;CertificateThumbprint=$thumb;Sha256=$hash;SizeBytes=$size;ModifiedTime=$mtime}};"
            "$rows|ConvertTo-Json -Depth 4 -Compress"
        )
        result = _powershell_json(script, f"binary_trust_batch_{batch_num}", timeout=180 if include_hashes else 90)
        results.append(result)
        if not result.ok:
            continue
        for item in _as_list(result.data):
            if not isinstance(item, dict):
                continue
            size = item.get("SizeBytes")
            records.append(BinaryTrustRecord(
                path=str(item.get("Path") or ""),
                exists=bool(item.get("Exists")) if item.get("Exists") is not None else None,
                signature_status=str(item.get("SignatureStatus") or ""),
                signer_subject=str(item.get("SignerSubject") or ""),
                signer_issuer=str(item.get("SignerIssuer") or ""),
                certificate_thumbprint=str(item.get("CertificateThumbprint") or ""),
                sha256=str(item.get("Sha256") or ""),
                size_bytes=int(size) if isinstance(size, (int, float)) else None,
                modified_time=str(item.get("ModifiedTime") or ""),
                is_user_writable_location=_is_user_writable_location(str(item.get("Path") or "")),
                note="Local signature metadata only; signature status does not by itself establish trust or maliciousness.",
            ))
    records.sort(key=lambda row: (row.signature_status.casefold() in {"valid", "notsigned"}, row.path.casefold()))
    return records, results


def collect_path_security(
    paths: list[str],
    batch_size: int = 30,
    cancel: Callable[[], bool] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
) -> tuple[list[PathSecurityRecord], list[CollectorResult]]:
    """Summarize owner and ACL risk indicators for selected high-value paths."""
    unique: list[str] = []
    seen: set[str] = set()
    records: list[PathSecurityRecord] = []
    results: list[CollectorResult] = []

    for path in paths:
        expanded = os.path.expandvars(os.path.expanduser(str(path or "").strip()))
        if not expanded:
            continue
        key = _norm(expanded)
        if key not in seen:
            seen.add(key)
            unique.append(expanded)
        drive = os.path.splitdrive(expanded)[0]
        if drive and drive.endswith(":") and len(drive) == 2 and not os.path.exists(drive + "\\"):
            records.append(PathSecurityRecord(
                path=expanded,
                owner="",
                access_rule_count=0,
                error="Drive letter is offline or unavailable",
            ))
            continue
        unique.append(expanded)
    if not IS_WINDOWS:
        return records, [CollectorResult(name="path_security", ok=False, error="Windows-only collector", applicable=False)]

    total_batches = (len(unique) + max(1, batch_size) - 1) // max(1, batch_size)
    for batch_index in range(0, len(unique), max(1, batch_size)):
        if cancel and cancel():
            break
        batch_num = batch_index // max(1, batch_size) + 1
        if progress:
            progress({
                "phase": "ownership_permissions",
                "batch": batch_num,
                "total_batches": total_batches,
                "count": len(unique),
                "detail": f"Checking path access controls (batch {batch_num} of {total_batches})...",
            })
        batch = unique[batch_index:batch_index + max(1, batch_size)]
        literal = ",".join("'" + _ps_single_quote(path) + "'" for path in batch)
        script = (
            f"$paths=@({literal});$rows=foreach($p in $paths){{"
            "$owner='';$count=0;$explicit=0;$deny=0;$broad=@();$protected=$null;$err='';"
            "try{$acl=Get-Acl -LiteralPath $p -ErrorAction Stop;$owner=[string]$acl.Owner;$protected=[bool]$acl.AreAccessRulesProtected;"
            "$rules=@($acl.Access);$count=$rules.Count;foreach($r in $rules){if(-not $r.IsInherited){$explicit++};if([string]$r.AccessControlType -eq 'Deny'){$deny++};"
            "$id=[string]$r.IdentityReference;$rights=[string]$r.FileSystemRights;"
            "if($id -match '(Everyone|Authenticated Users|BUILTIN\\\\Users)$' -and $rights -match '(Write|Modify|FullControl|CreateFiles|AppendData)'){$broad+=($id+': '+$rights)}}}"
            "}catch{$err=$_.Exception.Message};"
            "[PSCustomObject]@{Path=$p;Owner=$owner;AccessRuleCount=$count;ExplicitRuleCount=$explicit;DenyRuleCount=$deny;BroadWrite=@($broad);ProtectedAcl=$protected;Error=$err}};"
            "$rows|ConvertTo-Json -Depth 5 -Compress"
        )
        result = _powershell_json(script, f"path_security_batch_{batch_num}", timeout=120)
        results.append(result)
        if not result.ok:
            continue
        for item in _as_list(result.data):
            if not isinstance(item, dict):
                continue
            broad = item.get("BroadWrite") or []
            if not isinstance(broad, list):
                broad = [str(broad)] if broad else []
            records.append(PathSecurityRecord(
                path=str(item.get("Path") or ""),
                owner=str(item.get("Owner") or ""),
                access_rule_count=int(item.get("AccessRuleCount") or 0),
                explicit_rule_count=int(item.get("ExplicitRuleCount") or 0),
                deny_rule_count=int(item.get("DenyRuleCount") or 0),
                broad_write_detected=bool(broad),
                broad_write_identities=[str(x) for x in broad],
                protected_acl=bool(item.get("ProtectedAcl")) if item.get("ProtectedAcl") is not None else None,
                error=str(item.get("Error") or ""),
            ))
    records.sort(key=lambda row: (not row.broad_write_detected, row.path.casefold()))
    return records, results


def collect_prefetch_metadata(limit: int = 5000) -> CollectorResult:
    """Read only prefetch filenames, sizes and timestamps; never parse process memory."""
    if not IS_WINDOWS:
        return CollectorResult(name="prefetch_metadata", ok=False, error="Windows-only collector", applicable=False)
    folder = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "Prefetch"
    rows: list[dict[str, Any]] = []
    try:
        with os.scandir(folder) as entries:
            for entry in entries:
                if len(rows) >= max(1, limit):
                    break
                if not entry.name.casefold().endswith(".pf"):
                    continue
                try:
                    stat = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                image_name = entry.name.split("-", 1)[0]
                rows.append({
                    "name": entry.name,
                    "image_name": image_name,
                    "path": entry.path,
                    "size_bytes": int(stat.st_size),
                    "modified_time": str(getattr(stat, "st_mtime", "")),
                    "modified_ts": float(getattr(stat, "st_mtime", 0.0) or 0.0),
                })
        rows.sort(key=lambda row: row.get("modified_ts", 0), reverse=True)
        return CollectorResult(name="prefetch_metadata", ok=True, data=rows)
    except OSError as exc:
        return CollectorResult(name="prefetch_metadata", ok=False, error=f"{type(exc).__name__}: {exc}")

def _collect_wsl_registry() -> CollectorResult:
    if not IS_WINDOWS:
        return CollectorResult(name="wsl_registry", ok=False, error="Windows-only collector", applicable=False)
    try:
        import winreg
        base = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
        distros: list[dict[str, Any]] = []
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, base, 0, winreg.KEY_READ) as parent:
            for i in range(winreg.QueryInfoKey(parent)[0]):
                try:
                    sub = winreg.EnumKey(parent, i)
                    with winreg.OpenKey(parent, sub, 0, winreg.KEY_READ) as key:
                        def q(name: str, default=""):
                            try:
                                return winreg.QueryValueEx(key, name)[0]
                            except OSError:
                                return default
                        base_path = os.path.expandvars(str(q("BasePath", "")))
                        vhdx = os.path.join(base_path, "ext4.vhdx") if base_path else ""
                        logical = None
                        allocated = None
                        if vhdx:
                            try:
                                logical = os.path.getsize(vhdx)
                                allocated = allocated_size(vhdx, logical)
                            except OSError:
                                pass
                        distros.append({
                            "id": sub,
                            "name": str(q("DistributionName", "")),
                            "version": q("Version", ""),
                            "base_path": base_path,
                            "vhdx": vhdx,
                            "vhdx_logical_bytes": logical,
                            "vhdx_allocated_bytes": allocated,
                        })
                except OSError:
                    continue
        return CollectorResult(name="wsl_registry", ok=True, data=distros)
    except FileNotFoundError as exc:
        return CollectorResult(name="wsl_registry", ok=False, error=f"WSL distro registry key is absent: {exc}", applicable=False)
    except OSError as exc:
        return CollectorResult(name="wsl_registry", ok=False, error=f"{type(exc).__name__}: {exc}")


def collect_system_memory_status() -> CollectorResult:
    """Collect physical and committed RAM usage via Win32 API without modifying state."""
    if not IS_WINDOWS:
        return CollectorResult(name="system_memory_status", ok=False, error="Windows-only collector", applicable=False)
    try:
        import ctypes

        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        stat = MEMORYSTATUSEX()
        stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
            total_phys = int(stat.ullTotalPhys)
            avail_phys = int(stat.ullAvailPhys)
            if total_phys <= 0:
                return CollectorResult(name="system_memory_status", ok=False, error="Non-positive physical memory reported")
            load_pct = max(0, min(100, int(stat.dwMemoryLoad)))
            return CollectorResult(name="system_memory_status", ok=True, data={
                "memory_load_pct": load_pct,
                "total_physical_bytes": total_phys,
                "available_physical_bytes": max(0, avail_phys),
                "used_physical_bytes": max(0, total_phys - avail_phys),
                "total_pagefile_bytes": max(0, int(stat.ullTotalPageFile)),
                "available_pagefile_bytes": max(0, int(stat.ullAvailPageFile)),
            })
    except Exception as exc:
        return CollectorResult(name="system_memory_status", ok=False, error=str(exc))
    return CollectorResult(name="system_memory_status", ok=False, error="Failed to query GlobalMemoryStatusEx")


def collect_privacy_consent_store() -> CollectorResult:
    """Audit Windows app permissions (camera, microphone, location) from ConsentStore without changes."""
    if not IS_WINDOWS:
        return CollectorResult(name="privacy_consent_store", ok=False, error="Windows-only collector", applicable=False)
    try:
        import winreg
        base = r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore"
        capabilities = ["webcam", "microphone", "location", "userNotificationListener"]
        results: dict[str, list[dict[str, str]]] = {c: [] for c in capabilities}
        for cap in capabilities:
            for hive, hive_name in [(winreg.HKEY_CURRENT_USER, "user"), (winreg.HKEY_LOCAL_MACHINE, "system")]:
                try:
                    with winreg.OpenKey(hive, f"{base}\\{cap}") as key:
                        sub_count = winreg.QueryInfoKey(key)[0]
                        for i in range(sub_count):
                            sub_name = winreg.EnumKey(key, i)
                            if sub_name == "NonPackaged":
                                try:
                                    with winreg.OpenKey(key, sub_name) as np_key:
                                        np_count = winreg.QueryInfoKey(np_key)[0]
                                        for j in range(np_count):
                                            np_sub = winreg.EnumKey(np_key, j)
                                            try:
                                                with winreg.OpenKey(np_key, np_sub) as entry_key:
                                                    val, _ = winreg.QueryValueEx(entry_key, "Value")
                                                    if str(val).lower() in ("allow", "1"):
                                                        results[cap].append({
                                                            "name": np_sub.replace("#", "/"),
                                                            "type": "desktop",
                                                            "scope": hive_name,
                                                            "capability": cap,
                                                        })
                                            except OSError:
                                                pass
                                except OSError:
                                    pass
                                continue
                            try:
                                with winreg.OpenKey(key, sub_name) as entry_key:
                                    val, _ = winreg.QueryValueEx(entry_key, "Value")
                                    if str(val).lower() in ("allow", "1"):
                                        results[cap].append({
                                            "name": sub_name,
                                            "type": "packaged",
                                            "scope": hive_name,
                                            "capability": cap,
                                        })
                            except OSError:
                                pass
                except OSError:
                    pass
        return CollectorResult(name="privacy_consent_store", ok=True, data=results)
    except Exception as exc:
        return CollectorResult(name="privacy_consent_store", ok=False, error=str(exc))


def collect_browser_privacy_footprints() -> CollectorResult:
    """Read file sizes of browser history, cookie stores, and session databases without opening locks."""
    if not IS_WINDOWS:
        return CollectorResult(name="browser_privacy_footprints", ok=False, error="Windows-only collector", applicable=False)
    try:
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        app_data = os.environ.get("APPDATA", "")
        browsers = [
            {"name": "Google Chrome", "path": os.path.join(local_app_data, "Google", "Chrome", "User Data", "Default")},
            {"name": "Microsoft Edge", "path": os.path.join(local_app_data, "Microsoft", "Edge", "User Data", "Default")},
            {"name": "Brave Browser", "path": os.path.join(local_app_data, "BraveSoftware", "Brave-Browser", "User Data", "Default")},
        ]
        results: list[dict[str, Any]] = []
        for b in browsers:
            p = b["path"]
            if os.path.isdir(p):
                items: dict[str, int] = {}
                for target in ["History", "Cookies", "Network/Cookies", "Web Data", "Login Data", "Top Sites", "Shortcuts"]:
                    tp = os.path.join(p, target.replace("/", os.sep))
                    if os.path.isfile(tp):
                        try:
                            items[target] = os.path.getsize(tp)
                        except OSError:
                            pass
                total = sum(items.values())
                if items:
                    results.append({"browser": b["name"], "profile_path": p, "data_files": items, "total_bytes": total})

        ff_profiles = os.path.join(app_data, "Mozilla", "Firefox", "Profiles")
        if os.path.isdir(ff_profiles):
            for entry in os.scandir(ff_profiles):
                if entry.is_dir():
                    items = {}
                    for target in ["places.sqlite", "cookies.sqlite", "formhistory.sqlite", "favicons.sqlite"]:
                        tp = os.path.join(entry.path, target)
                        if os.path.isfile(tp):
                            try:
                                items[target] = os.path.getsize(tp)
                            except OSError:
                                pass
                    total = sum(items.values())
                    if items:
                        results.append({"browser": f"Mozilla Firefox ({entry.name})", "profile_path": entry.path, "data_files": items, "total_bytes": total})
        return CollectorResult(name="browser_privacy_footprints", ok=True, data=results)
    except Exception as exc:
        return CollectorResult(name="browser_privacy_footprints", ok=False, error=str(exc))


def collect_orphaned_app_data(installed_apps: list[ApplicationRecord] | None = None, directory_sizes: dict[str, int] | None = None) -> CollectorResult:
    """Detect leftover application data in AppData/ProgramData for uninstalled software (inspired by BCUninstaller heuristics)."""
    if not IS_WINDOWS:
        return CollectorResult(name="orphaned_app_data", ok=False, error="Windows-only collector", applicable=False)
    try:
        import time
        app_tokens: set[str] = set()

        def _add_tokens_from_text(text: str) -> None:
            if not text:
                return
            cleaned = re.sub(r"[^a-zA-Z0-9]+", " ", str(text).lower())
            for word in cleaned.split():
                if len(word) >= 3 or word in {"7z", "go", "db", "sh", "ai", "py"}:
                    app_tokens.add(word)

        if installed_apps:
            for a in installed_apps:
                for val in (a.name, a.publisher, os.path.basename(a.install_location or "")):
                    _add_tokens_from_text(val)

        if not app_tokens:
            import winreg
            for hive in [winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE]:
                for flags in [0, winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY]:
                    try:
                        with winreg.OpenKey(hive, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_READ | flags) as parent:
                            for i in range(winreg.QueryInfoKey(parent)[0]):
                                try:
                                    sub = winreg.EnumKey(parent, i)
                                    with winreg.OpenKey(parent, sub, 0, winreg.KEY_READ | flags) as k:
                                        def q(v: str) -> str:
                                            try:
                                                return str(winreg.QueryValueEx(k, v)[0])
                                            except Exception:
                                                return ""
                                        for val in [q("DisplayName"), q("Publisher"), q("InstallLocation")]:
                                            _add_tokens_from_text(val)
                                except OSError:
                                    pass
                    except OSError:
                        pass

        system_ignores = {
            "microsoft", "windows", "temp", "packages", "connecteddevicesplatform",
            "d3dscache", "directxshadercache", "publishers", "crashdumps", "google",
            "bravesoftware", "mozilla", "chromium", "pip", "npm", "yarn", "pnpm", "system",
            "usoprivate", "usoshared", "package cache", "microsoft help", "comms",
            "elevateddiagnostics", "programs", "system32", "virtualstore", "cryptneturlcache",
            "identitycrl", "nativeimagestore", "systemcerts", "assembly", "nuget",
            ".nuget", "code", "vscode", ".vscode", "docker", "git", "github", "golang",
            "go", "cargo", "rustup", "android", ".android", "gradle", "m2", ".m2",
            "chocolatey", "scoop", "winget", "pypoetry", "virtualenvs", "fathom",
            "fathomvideo", "openai", "chatgpt"
        }

        def bounded_dir_size(path: str, max_files: int = 800) -> int:
            if directory_sizes and path in directory_sizes:
                return directory_sizes[path]
            norm_p = _norm(path)
            if directory_sizes and norm_p in directory_sizes:
                return directory_sizes[norm_p]
            total = 0
            count = 0
            for root, _, files in os.walk(path):
                for f in files:
                    count += 1
                    if count > max_files:
                        return total
                    try:
                        total += os.path.getsize(os.path.join(root, f))
                    except OSError:
                        pass
            return total

        now = time.time()
        leftovers: list[dict[str, Any]] = []
        for env_name in ["LOCALAPPDATA", "APPDATA", "PROGRAMDATA"]:
            base = os.environ.get(env_name, "")
            if not base or not os.path.isdir(base):
                continue
            try:
                for entry in os.scandir(base):
                    if entry.is_dir():
                        name_lower = entry.name.lower()
                        if name_lower in system_ignores or any(name_lower.startswith(x) for x in ["microsoft", "windows", "system", "cache", "."]):
                            continue
                        # If modified within the last 14 days, it is actively in use, not an abandoned leftover
                        mtime = getattr(entry.stat(), "st_mtime", 0.0)
                        if (now - mtime) < 14 * 86400:
                            continue
                        name_words = [w for w in re.sub(r"[^a-zA-Z0-9]+", " ", name_lower).split() if len(w) >= 3 or w in {"7z", "go", "db", "sh", "ai", "py"}]
                        matched = any(w in app_tokens for w in name_words) or any(t in name_lower for t in app_tokens if len(t) >= 4)
                        if not matched and len(name_words) > 0:
                            sz = bounded_dir_size(entry.path)
                            if sz > 2 * 1024 * 1024:
                                leftovers.append({
                                    "name": entry.name,
                                    "path": entry.path,
                                    "location_env": env_name,
                                    "size_bytes": sz,
                                    "modified_ts": float(mtime),
                                })
            except OSError:
                pass

        leftovers.sort(key=lambda x: x["size_bytes"], reverse=True)
        return CollectorResult(name="orphaned_app_data", ok=True, data=leftovers[:50])
    except Exception as exc:
        return CollectorResult(name="orphaned_app_data", ok=False, error=str(exc))


def _named(command: list[str], name: str, timeout: int) -> CollectorResult:
    result = _run_read_only(command, timeout=timeout)
    result.name = name
    return result


def _collect_docker_df() -> CollectorResult:
    # JSON-lines format gives a machine-readable summary without invoking prune or
    # any other mutating Docker operation. Fallback preserves raw text if an older
    # Docker CLI lacks this format.
    result = _run_read_only(["docker.exe", "system", "df", "--format", "json"], timeout=75)
    result.name = "docker_system_df"
    if result.ok and result.data:
        rows: list[dict[str, Any]] = []
        try:
            for line in str(result.data).splitlines():
                line = line.strip()
                if line:
                    parsed = json.loads(line)
                    if isinstance(parsed, dict):
                        rows.append(parsed)
            result.data = rows
            return result
        except json.JSONDecodeError:
            pass
    fallback = _run_read_only(["docker.exe", "system", "df", "-v"], timeout=75)
    fallback.name = "docker_system_df"
    return fallback



def _collect_json_lines(command: list[str], name: str, timeout: int = 75) -> CollectorResult:
    result = _run_read_only(command, timeout=timeout)
    result.name = name
    if not result.ok or not result.data:
        return result
    rows: list[Any] = []
    try:
        for line in str(result.data).splitlines():
            line = line.strip()
            if line:
                rows.append(json.loads(line))
        result.data = rows
    except json.JSONDecodeError:
        # Preserve the raw output and mark the collector as successful. Docker
        # versions differ in format support; the evidence is still useful.
        result.data = {"raw": result.data, "parse_warning": "Output was not JSON-lines."}
    return result

def _parse_dism_bytes(text: str, label: str) -> int | None:
    # DISM /English prints e.g. "Windows Explorer Reported Size of Component Store : 12.34 GB".
    m = re.search(rf"(?im)^\s*{re.escape(label)}\s*:\s*([0-9.,]+)\s*(bytes|kb|mb|gb|tb)\s*$", text)
    if not m:
        return None
    value = float(m.group(1).replace(",", ""))
    unit = m.group(2).lower()
    mult = {"bytes": 1, "kb": 1024, "mb": 1024**2, "gb": 1024**3, "tb": 1024**4}[unit]
    return int(value * mult)


def _collect_component_store() -> CollectorResult:
    raw = _named(
        ["dism.exe", "/Online", "/Cleanup-Image", "/AnalyzeComponentStore", "/English"],
        "component_store_analysis",
        180,
    )
    if not raw.ok or not isinstance(raw.data, str):
        return raw
    text = raw.data
    cleanup = re.search(r"(?im)^\s*Component Store Cleanup Recommended\s*:\s*(Yes|No)\s*$", text)
    explorer_reported = _parse_dism_bytes(text, "Windows Explorer Reported Size of Component Store")
    actual_size = _parse_dism_bytes(text, "Actual Size of Component Store")
    hardlink_savings = max(0, (explorer_reported or 0) - (actual_size or 0)) if (explorer_reported and actual_size) else 0
    raw.data = {
        "cleanup_recommended": cleanup.group(1).lower() == "yes" if cleanup else None,
        "explorer_reported_bytes": explorer_reported,
        "actual_size_bytes": actual_size,
        "shared_with_windows_bytes": _parse_dism_bytes(text, "Shared with Windows"),
        "backups_disabled_features_bytes": _parse_dism_bytes(text, "Backups and Disabled Features"),
        "cache_temp_bytes": _parse_dism_bytes(text, "Cache and Temporary Data"),
        "hardlink_dedup_savings_bytes": hardlink_savings,
        "cleanup_recipe": "cleanmgr.exe",
        "raw": text,
    }
    return raw


def collect_winget_catalog_correlation(installed_apps: list[ApplicationRecord] | None = None) -> CollectorResult:
    """Correlate installed software against winget packages to detect available upgrades."""
    if not IS_WINDOWS:
        return CollectorResult(name="winget_catalog_correlation", ok=False, error="Windows-only collector", applicable=False)
    try:
        proc = subprocess.run(
            ["winget.exe", "list", "--accept-source-agreements"],
            capture_output=True,
            text=True,
            timeout=40,
            shell=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode != 0 and not proc.stdout:
            return CollectorResult(
                name="winget_catalog_correlation",
                ok=False,
                error=f"winget returned code {proc.returncode}: {proc.stderr[:200]}",
            )
        lines = proc.stdout.splitlines()
        header_idx = next((i for i, l in enumerate(lines[:15]) if "Name" in l and "Id" in l and "Version" in l), -1)
        if header_idx == -1:
            return CollectorResult(name="winget_catalog_correlation", ok=False, error="Header row not found in winget output")

        h = lines[header_idx]
        id_idx = h.find("Id")
        ver_idx = h.find("Version")
        avail_idx = h.find("Available")
        src_idx = h.find("Source")

        pkgs: list[dict[str, Any]] = []
        for line in lines[header_idx + 2:]:
            if not line.strip() or line.startswith("-") or line.startswith("<"):
                continue
            name = line[:id_idx].strip()
            pkg_id = line[id_idx:ver_idx].strip() if ver_idx != -1 else ""
            ver = line[ver_idx:avail_idx].strip() if avail_idx != -1 else line[ver_idx:].strip()
            avail = line[avail_idx:src_idx].strip() if src_idx != -1 and avail_idx != -1 else (line[avail_idx:].strip() if avail_idx != -1 else "")
            src = line[src_idx:].strip() if src_idx != -1 else ""
            if pkg_id or name:
                has_up = bool(avail and avail != ver and not avail.startswith("<"))
                pkgs.append({
                    "name": name,
                    "id": pkg_id,
                    "version": ver,
                    "available_version": avail,
                    "source": src,
                    "has_update": has_up,
                    "upgrade_command": f'winget upgrade --id "{pkg_id}"' if pkg_id else "",
                })

        upgrades = [p for p in pkgs if p["has_update"]]
        return CollectorResult(
            name="winget_catalog_correlation",
            ok=True,
            data={
                "total_tracked": len(pkgs),
                "upgrades_available_count": len(upgrades),
                "upgrades": upgrades,
                "packages": pkgs[:250],
            },
        )
    except FileNotFoundError:
        return CollectorResult(
            name="winget_catalog_correlation",
            ok=False,
            error="winget.exe not found on system PATH",
            applicable=False,
        )
    except Exception as exc:
        return CollectorResult(name="winget_catalog_correlation", ok=False, error=f"{type(exc).__name__}: {exc}")


def collect_browser_extensions() -> CollectorResult:
    """Inspect installed browser extensions across Chrome, Edge, Brave, and Firefox."""
    if not IS_WINDOWS:
        return CollectorResult(name="browser_extensions", ok=False, error="Windows-only collector", applicable=False)

    import glob
    results: list[dict[str, Any]] = []
    local = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")

    chromium_browsers = [
        ("Google Chrome", os.path.join(local, "Google", "Chrome", "User Data")),
        ("Microsoft Edge", os.path.join(local, "Microsoft", "Edge", "User Data")),
        ("Brave", os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data")),
    ]

    for b_name, b_root in chromium_browsers:
        if not os.path.isdir(b_root):
            continue
        try:
            pattern = os.path.join(b_root, "*", "Extensions", "*", "*", "manifest.json")
            for mf in glob.glob(pattern):
                try:
                    with open(mf, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    ext_dir = os.path.dirname(mf)
                    version_str = os.path.basename(ext_dir)
                    ext_id = os.path.basename(os.path.dirname(ext_dir))
                    profile = os.path.basename(os.path.dirname(os.path.dirname(os.path.dirname(ext_dir))))

                    raw_name = data.get("name", ext_id)
                    name = raw_name
                    if isinstance(raw_name, str) and raw_name.startswith("__MSG_"):
                        key = raw_name[6:-2] if raw_name.endswith("__") else raw_name[6:]
                        def_loc = data.get("default_locale", "en")
                        loc_file = os.path.join(ext_dir, "_locales", def_loc, "messages.json")
                        if not os.path.exists(loc_file):
                            loc_file = os.path.join(ext_dir, "_locales", "en", "messages.json")
                        if os.path.exists(loc_file):
                            try:
                                with open(loc_file, "r", encoding="utf-8", errors="ignore") as lf:
                                    loc_data = json.load(lf)
                                if isinstance(loc_data, dict):
                                    match_k = next((k for k in loc_data if k.casefold() == key.casefold()), None)
                                    if match_k and isinstance(loc_data[match_k], dict) and "message" in loc_data[match_k]:
                                        name = loc_data[match_k]["message"]
                            except Exception:
                                pass

                    perms = list(data.get("permissions", []) or [])
                    perms.extend(data.get("optional_permissions", []) or [])
                    perms.extend(data.get("host_permissions", []) or [])
                    clean_perms = [str(p) for p in perms if isinstance(p, str)]

                    has_broad_web = any(p in {"<all_urls>", "*://*/*", "https://*/*", "http://*/*"} for p in clean_perms)
                    has_intercept = any(p in {"webRequest", "webRequestBlocking", "debugger", "nativeMessaging", "proxy"} for p in clean_perms)
                    risk = "high" if (has_broad_web or has_intercept) else "medium" if any(p in {"cookies", "tabs", "clipboardRead"} for p in clean_perms) else "low"

                    results.append({
                        "browser": b_name,
                        "profile": profile,
                        "id": ext_id,
                        "name": str(name),
                        "version": str(data.get("version", version_str)),
                        "description": str(data.get("description", "")),
                        "permissions": clean_perms,
                        "risk_level": risk,
                        "has_broad_web": has_broad_web,
                        "has_native_messaging": "nativeMessaging" in clean_perms,
                    })
                except Exception:
                    continue
        except Exception:
            continue

    # Firefox
    ff_root = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff_root):
        try:
            for ef in glob.glob(os.path.join(ff_root, "*", "extensions.json")):
                profile = os.path.basename(os.path.dirname(ef))
                try:
                    with open(ef, "r", encoding="utf-8", errors="ignore") as f:
                        fdata = json.load(f)
                    for addon in fdata.get("addons", []):
                        if addon.get("type") not in ("extension", None):
                            continue
                        raw_perms = addon.get("permissions") or []
                        clean_perms = [str(p) for p in raw_perms if isinstance(p, str)]
                        has_broad_web = any(p in {"<all_urls>", "*://*/*"} for p in clean_perms)
                        has_intercept = any(p in {"webRequest", "webRequestBlocking", "nativeMessaging"} for p in clean_perms)
                        risk = "high" if (has_broad_web or has_intercept) else "medium" if any(p in {"cookies", "tabs", "clipboardRead"} for p in clean_perms) else "low"
                        name = addon.get("defaultLocale", {}).get("name") or addon.get("name") or addon.get("id")
                        results.append({
                            "browser": "Firefox",
                            "profile": profile,
                            "id": str(addon.get("id", "")),
                            "name": str(name),
                            "version": str(addon.get("version", "")),
                            "description": str(addon.get("defaultLocale", {}).get("description", "")),
                            "permissions": clean_perms,
                            "risk_level": risk,
                            "has_broad_web": has_broad_web,
                            "has_native_messaging": "nativeMessaging" in clean_perms,
                        })
                except Exception:
                    continue
        except Exception:
            pass

    return CollectorResult(
        name="browser_extensions",
        ok=True,
        data=results,
    )


def collect_extended_persistence() -> CollectorResult:
    """Audit deep persistence: context menu shell extensions, AppInit_DLLs, Winlogon, and BHOs."""
    if not IS_WINDOWS:
        return CollectorResult(name="extended_persistence", ok=False, error="Windows-only collector", applicable=False)

    import winreg
    records: list[dict[str, Any]] = []

    def _resolve_clsid(clsid: str) -> str:
        if not clsid:
            return ""
        for sub_path in (f"CLSID\\{clsid}\\InprocServer32", f"Wow6432Node\\CLSID\\{clsid}\\InprocServer32"):
            try:
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, sub_path) as k:
                    val, _ = winreg.QueryValueEx(k, "")
                    if val:
                        return str(val)
            except OSError:
                continue
        return ""

    # 1. Shell Context Menu Handlers
    for root_key_name, path in (
        ("HKCR", "*\\shellex\\ContextMenuHandlers"),
        ("HKCR", "Directory\\shellex\\ContextMenuHandlers"),
        ("HKCR", "Folder\\shellex\\ContextMenuHandlers"),
    ):
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, path) as k:
                for i in range(winreg.QueryInfoKey(k)[0]):
                    handler_name = winreg.EnumKey(k, i)
                    clsid = ""
                    try:
                        with winreg.OpenKey(k, handler_name) as sk:
                            clsid, _ = winreg.QueryValueEx(sk, "")
                    except OSError:
                        pass
                    if not clsid and handler_name.startswith("{"):
                        clsid = handler_name
                    dll_path = _resolve_clsid(clsid)
                    clean_dll = dll_path.strip().strip('"\'') if dll_path else ""
                    expanded_dll = os.path.expandvars(clean_dll) if clean_dll else ""
                    if expanded_dll and not os.path.isabs(expanded_dll):
                        cand = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", expanded_dll)
                        if os.path.exists(cand):
                            expanded_dll = cand
                    exists = os.path.exists(expanded_dll) if expanded_dll else None
                    in_user_dir = any(u in dll_path.lower() for u in ("appdata", "temp", "users\\")) if dll_path else False
                    records.append({
                        "category": "ContextMenuHandler",
                        "scope": f"{root_key_name}\\{path}",
                        "name": handler_name,
                        "clsid": clsid,
                        "target_path": dll_path,
                        "target_exists": exists,
                        "is_user_writable": in_user_dir,
                    })
        except OSError:
            pass

    # 2. AppInit_DLLs
    for is_wow in (False, True):
        p = "Software\\Wow6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" if is_wow else "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, p) as k:
                val, _ = winreg.QueryValueEx(k, "AppInit_DLLs")
                if val and str(val).strip():
                    records.append({
                        "category": "AppInit_DLLs",
                        "scope": f"HKLM\\{p}",
                        "name": "AppInit_DLLs",
                        "clsid": "",
                        "target_path": str(val).strip(),
                        "target_exists": None,
                        "is_user_writable": True,
                    })
        except OSError:
            pass

    # 3. Winlogon Userinit & Shell
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon") as k:
            for val_name in ("Userinit", "Shell"):
                try:
                    val, _ = winreg.QueryValueEx(k, val_name)
                    records.append({
                        "category": "Winlogon",
                        "scope": "HKLM\\...\\Winlogon",
                        "name": val_name,
                        "clsid": "",
                        "target_path": str(val).strip(),
                        "target_exists": True,
                        "is_user_writable": False,
                    })
                except OSError:
                    pass
    except OSError:
        pass

    # 4. Browser Helper Objects (BHOs)
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Browser Helper Objects") as k:
            for i in range(winreg.QueryInfoKey(k)[0]):
                bho_clsid = winreg.EnumKey(k, i)
                dll_path = _resolve_clsid(bho_clsid)
                clean_bho = dll_path.strip().strip('"\'') if dll_path else ""
                expanded_bho = os.path.expandvars(clean_bho) if clean_bho else ""
                if expanded_bho and not os.path.isabs(expanded_bho):
                    cand = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", expanded_bho)
                    if os.path.exists(cand):
                        expanded_bho = cand
                exists = os.path.exists(expanded_bho) if expanded_bho else None
                records.append({
                    "category": "BrowserHelperObject",
                    "scope": "HKLM\\...\\Browser Helper Objects",
                    "name": bho_clsid,
                    "clsid": bho_clsid,
                    "target_path": dll_path,
                    "target_exists": exists,
                    "is_user_writable": any(u in dll_path.lower() for u in ("appdata", "temp")) if dll_path else False,
                })
    except OSError:
        pass

    return CollectorResult(
        name="extended_persistence",
        ok=True,
        data=records,
    )


def collect_alternate_data_streams(root: str | None = None) -> CollectorResult:
    """Audit Alternate Data Streams (ADS) detecting Zone.Identifier and large hidden NTFS streams."""
    if not IS_WINDOWS:
        return CollectorResult(name="alternate_data_streams", ok=False, error="Windows-only collector", applicable=False)

    import ctypes
    from ctypes import wintypes

    class WIN32_FIND_STREAM_DATA(ctypes.Structure):
        _fields_ = [
            ("StreamSize", ctypes.c_int64),
            ("cStreamName", ctypes.c_wchar * 296),
        ]

    kernel32 = ctypes.windll.kernel32
    find_first = getattr(kernel32, "FindFirstStreamW", None)
    find_next = getattr(kernel32, "FindNextStreamW", None)
    find_close = getattr(kernel32, "FindClose", None)
    if not (find_first and find_next and find_close):
        return CollectorResult(name="alternate_data_streams", ok=False, error="FindFirstStreamW API unavailable", applicable=False)

    find_first.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    find_first.restype = wintypes.HANDLE
    find_next.argtypes = [wintypes.HANDLE, ctypes.c_void_p]
    find_next.restype = wintypes.BOOL
    find_close.argtypes = [wintypes.HANDLE]
    find_close.restype = wintypes.BOOL

    def _find_streams(filepath: str) -> list[tuple[str, int]]:
        data = WIN32_FIND_STREAM_DATA()
        h = find_first(filepath, 0, ctypes.byref(data), 0)
        if h == -1 or h == 0:
            return []
        streams: list[tuple[str, int]] = []
        try:
            streams.append((data.cStreamName, int(data.StreamSize)))
            while find_next(h, ctypes.byref(data)):
                streams.append((data.cStreamName, int(data.StreamSize)))
        finally:
            find_close(h)
        return streams

    candidate_dirs: list[str] = []
    user_prof = os.environ.get("USERPROFILE", "")
    if user_prof:
        for sub in ("Downloads", "Desktop"):
            p = os.path.join(user_prof, sub)
            if os.path.isdir(p):
                candidate_dirs.append(p)
    if root and os.path.isdir(root) and root not in candidate_dirs:
        candidate_dirs.append(root)

    streams_found: list[dict[str, Any]] = []
    zone_count = 0
    total_stream_bytes = 0

    for d in candidate_dirs:
        try:
            for dirpath, _, filenames in os.walk(d):
                for f in filenames[:100]:
                    fp = os.path.join(dirpath, f)
                    try:
                        s_list = _find_streams(fp)
                        for s_name, s_size in s_list:
                            if s_name != "::$DATA":
                                is_zone = ":Zone.Identifier" in s_name
                                if is_zone:
                                    zone_count += 1
                                total_stream_bytes += s_size
                                streams_found.append({
                                    "file_path": fp,
                                    "file_name": f,
                                    "stream_name": s_name,
                                    "size_bytes": s_size,
                                    "is_zone_identifier": is_zone,
                                })
                    except Exception:
                        continue
                break  # Top directory only
        except Exception:
            continue

    return CollectorResult(
        name="alternate_data_streams",
        ok=True,
        data={
            "scanned_directories": candidate_dirs,
            "total_streams": len(streams_found),
            "zone_identifier_streams": zone_count,
            "total_stream_bytes": total_stream_bytes,
            "streams": streams_found[:100],
        },
    )


def collect_windows_update_cache() -> CollectorResult:
    """Audit Windows Update SoftwareDistribution cache and Delivery Optimization cache."""
    if not IS_WINDOWS:
        return CollectorResult(name="windows_update_cache", ok=False, error="Windows-only collector", applicable=False)

    sys_root = os.environ.get("SystemRoot", "C:\\Windows")
    sd_dl = os.path.join(sys_root, "SoftwareDistribution", "Download")
    sd_ds = os.path.join(sys_root, "SoftwareDistribution", "DataStore")
    do_cache = r"C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Cache"

    def _dir_metrics(path: str) -> tuple[int, int]:
        if not os.path.isdir(path):
            return 0, 0
        total = 0
        count = 0
        try:
            for r, _, files in os.walk(path):
                for f in files:
                    count += 1
                    try:
                        total += os.path.getsize(os.path.join(r, f))
                    except OSError:
                        pass
        except OSError:
            pass
        return total, count

    dl_bytes, dl_count = _dir_metrics(sd_dl)
    ds_bytes, ds_count = _dir_metrics(sd_ds)
    do_bytes, do_count = _dir_metrics(do_cache)

    services: dict[str, str] = {}
    for svc in ("wuauserv", "bits", "dosvc"):
        try:
            p = subprocess.run(
                ["sc.exe", "query", svc],
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            m = re.search(r"STATE\s+:\s+\d+\s+([A-Z_]+)", p.stdout)
            services[svc] = m.group(1) if m else "UNKNOWN"
        except Exception:
            services[svc] = "UNKNOWN"

    recipe = 'Get-ChildItem "$env:SystemRoot\\SoftwareDistribution\\Download" -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum'

    return CollectorResult(
        name="windows_update_cache",
        ok=True,
        data={
            "software_distribution_download_bytes": dl_bytes,
            "software_distribution_download_files": dl_count,
            "software_distribution_datastore_bytes": ds_bytes,
            "software_distribution_datastore_files": ds_count,
            "delivery_optimization_cache_bytes": do_bytes,
            "delivery_optimization_cache_files": do_count,
            "services_state": services,
            "purge_recipe": recipe,
        },
    )



def _drive_for_root(root: str) -> str:
    cleaned = str(root or "").strip().strip('"').strip("'").strip()
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    drive = os.path.splitdrive(os.path.abspath(cleaned))[0]
    if drive:
        return drive
    # Defensive Windows fallback for paths normalized by another environment.
    m = re.match(r"^[A-Za-z]:", cleaned)
    return m.group(0) if m else cleaned


def collect_optional_system_inventory(
    root: str = "C:\\",
    profile: str = "deep",
    cancel: Callable[[], bool] | None = None,
    progress: Callable[[dict[str, Any]], None] | None = None,
    installed_apps: list[ApplicationRecord] | None = None,
    directory_sizes: dict[str, int] | None = None,
) -> list[CollectorResult]:
    if not IS_WINDOWS:
        return [CollectorResult(name="system_inventory", ok=False, error="Windows-only collector", applicable=False)]

    collectors: list[CollectorResult] = []
    drive = _drive_for_root(root)

    ps = {
        "computer_system": (
            "Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory,HypervisorPresent | ConvertTo-Json -Compress"
        ),
        "operating_system": (
            "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,LastBootUpTime,FreePhysicalMemory | ConvertTo-Json -Compress"
        ),
        "logical_disks": (
            "Get-CimInstance Win32_LogicalDisk -Filter \"DriveType=3\" | Select-Object DeviceID,VolumeName,Size,FreeSpace,FileSystem | ConvertTo-Json -Compress"
        ),
        "partitions": (
            "Get-Partition -ErrorAction Stop | Select-Object DiskNumber,PartitionNumber,DriveLetter,Type,GptType,Size,IsBoot,IsSystem,IsHidden,IsReadOnly | ConvertTo-Json -Compress"
        ),
        "pagefile_usage": (
            "Get-CimInstance Win32_PageFileUsage | Select-Object Name,AllocatedBaseSize,CurrentUsage,PeakUsage,TempPageFile | ConvertTo-Json -Compress"
        ),
        "restore_points": (
            "Get-ComputerRestorePoint | Select-Object SequenceNumber,Description,CreationTime,RestorePointType | ConvertTo-Json -Compress"
        ),
        "shadow_copies": (
            "Get-CimInstance Win32_ShadowCopy | Select-Object ID,InstallDate,DeviceObject,VolumeName,State,ClientAccessible | ConvertTo-Json -Compress"
        ),
        "shadow_storage": (
            "Get-CimInstance Win32_ShadowStorage | Select-Object UsedSpace,AllocatedSpace,MaxSpace | ConvertTo-Json -Compress"
        ),
        "third_party_drivers": (
            "Get-CimInstance Win32_PnPSignedDriver | Where-Object {$_.DriverProviderName -and $_.DriverProviderName -notmatch '^Microsoft'} | "
            "Select-Object DeviceName,DriverProviderName,DriverVersion,DriverDate,InfName | ConvertTo-Json -Depth 3 -Compress"
        ),
        "startup_commands_extended": (
            "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User | ConvertTo-Json -Depth 3 -Compress"
        ),
        "defender_status": (
            "$cs=Get-MpComputerStatus -ErrorAction Stop | Select-Object AntivirusEnabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,TamperProtection,AntivirusSignatureAge,AntivirusSignatureLastUpdated,EngineVersion,ProductVersion; "
            "$td=@(); try{$td=@(Get-MpThreatDetection -ErrorAction Stop | Select-Object -First 10 ThreatID,ThreatName,SeverityID,InitialDetectionTime,RemediationTime,ThreatStatusID)}catch{}; "
            "[PSCustomObject]@{Status=$cs;Threats=$td} | ConvertTo-Json -Depth 4 -Compress"
        ),
    }
    if profile in {"deep", "forensics"}:
        ps.update({
            "physical_disks": (
                "Get-PhysicalDisk -ErrorAction Stop | Select-Object FriendlyName,MediaType,BusType,HealthStatus,OperationalStatus,Size | ConvertTo-Json -Compress"
            ),
            "storage_volumes": (
                "Get-Volume -ErrorAction Stop | Select-Object DriveLetter,FileSystemLabel,FileSystem,HealthStatus,Size,SizeRemaining | ConvertTo-Json -Compress"
            ),
            "hyperv_vms": (
                "Get-VM -ErrorAction Stop | Select-Object Name,State,Generation,Path,ConfigurationLocation,SnapshotFileLocation,SmartPagingFilePath | ConvertTo-Json -Compress"
            ),
            "dedup_status": (
                "Get-DedupStatus -ErrorAction Stop | Select-Object Volume,SavingsRate,SavedSpace,OptimizedFilesCount,InPolicyFilesCount | ConvertTo-Json -Compress"
            ),
            "physical_disk_reliability": (
                "$rows=Get-PhysicalDisk -ErrorAction Stop | ForEach-Object {$disk=$_;$rel=$null;try{$rel=$disk|Get-StorageReliabilityCounter -ErrorAction Stop}catch{};"
                "[PSCustomObject]@{FriendlyName=$disk.FriendlyName;SerialNumber=$disk.SerialNumber;UniqueId=$disk.UniqueId;HealthStatus=[string]$disk.HealthStatus;"
                "OperationalStatus=@($disk.OperationalStatus|ForEach-Object{[string]$_});MediaType=[string]$disk.MediaType;BusType=[string]$disk.BusType;Size=[int64]$disk.Size;"
                "Temperature=if($rel){$rel.Temperature}else{$null};TemperatureMax=if($rel){$rel.TemperatureMax}else{$null};Wear=if($rel){$rel.Wear}else{$null};"
                "PowerOnHours=if($rel){$rel.PowerOnHours}else{$null};ReadErrorsTotal=if($rel){$rel.ReadErrorsTotal}else{$null};WriteErrorsTotal=if($rel){$rel.WriteErrorsTotal}else{$null};"
                "ReadLatencyMax=if($rel){$rel.ReadLatencyMax}else{$null};WriteLatencyMax=if($rel){$rel.WriteLatencyMax}else{$null}}};$rows|ConvertTo-Json -Depth 5 -Compress"
            ),
            "storage_pools": (
                "Get-StoragePool -ErrorAction Stop | Select-Object FriendlyName,HealthStatus,OperationalStatus,IsPrimordial,Size,AllocatedSize | ConvertTo-Json -Depth 4 -Compress"
            ),
            "bitlocker_status": (
                "Get-BitLockerVolume -ErrorAction Stop | Select-Object MountPoint,VolumeStatus,ProtectionStatus,EncryptionMethod,EncryptionPercentage,LockStatus,AutoUnlockEnabled | ConvertTo-Json -Depth 4 -Compress"
            ),
            "hyperv_disks": (
                "$rows=Get-VMHardDiskDrive -VMName * -ErrorAction Stop | ForEach-Object {$d=$_;$v=$null;try{$v=Get-VHD -Path $d.Path -ErrorAction Stop}catch{};"
                "[PSCustomObject]@{VMName=$d.VMName;ControllerType=[string]$d.ControllerType;ControllerNumber=$d.ControllerNumber;ControllerLocation=$d.ControllerLocation;Path=$d.Path;"
                "VhdType=if($v){[string]$v.VhdType}else{''};VhdFormat=if($v){[string]$v.VhdFormat}else{''};FileSize=if($v){[int64]$v.FileSize}else{$null};"
                "Size=if($v){[int64]$v.Size}else{$null};MinimumSize=if($v){[int64]$v.MinimumSize}else{$null};ParentPath=if($v){[string]$v.ParentPath}else{''};FragmentationPercentage=if($v){$v.FragmentationPercentage}else{$null}}};"
                "$rows|ConvertTo-Json -Depth 5 -Compress"
            ),
        })
    optional_feature_collectors = {
        "restore_points", "hyperv_vms", "hyperv_disks", "dedup_status",
        "bitlocker_status", "storage_pools", "physical_disk_reliability",
        "defender_status",
    }

    command_collectors = (
        ("system_memory_status", lambda: collect_system_memory_status()),
        ("privacy_consent_store", lambda: collect_privacy_consent_store()),
        ("browser_privacy_footprints", lambda: collect_browser_privacy_footprints()),
        ("orphaned_app_data", lambda: collect_orphaned_app_data(installed_apps=installed_apps, directory_sizes=directory_sizes)),
        ("winget_upgrade_summary", lambda: _named(["winget.exe", "upgrade", "--include-unknown"], "winget_upgrade_summary", 45)),
        ("wsl_registry", lambda: _collect_wsl_registry()),
        ("wsl_list", lambda: _named(["wsl.exe", "--list", "--verbose"], "wsl_list", 35)),
        ("wsl_status", lambda: _named(["wsl.exe", "--status"], "wsl_status", 35)),
        ("docker_system_df", lambda: _collect_docker_df()),
        ("docker_containers", lambda: _collect_json_lines(["docker.exe", "ps", "-a", "--size", "--format", "json"], "docker_containers", 75)),
        ("docker_images", lambda: _collect_json_lines(["docker.exe", "image", "ls", "--digests", "--format", "json"], "docker_images", 75)),
        ("docker_volumes", lambda: _collect_json_lines(["docker.exe", "volume", "ls", "--format", "json"], "docker_volumes", 60)),
        ("docker_buildx_disk_usage", lambda: _named(["docker.exe", "buildx", "du", "--verbose"], "docker_buildx_disk_usage", 120)),
        ("driver_store_inventory", lambda: _named(["pnputil.exe", "/enum-drivers", "/files", "/format", "CSV"], "driver_store_inventory", 120)),
        ("dotnet_sdks", lambda: _named(["dotnet.exe", "--list-sdks"], "dotnet_sdks", 45)),
        ("dotnet_runtimes", lambda: _named(["dotnet.exe", "--list-runtimes"], "dotnet_runtimes", 45)),
        ("python_launchers", lambda: _named(["py.exe", "-0p"], "python_launchers", 45)),
        ("npm_cache_location", lambda: _named(["npm.cmd", "config", "get", "cache"], "npm_cache_location", 45)),
        ("pip_cache_location", lambda: _named(["pip.exe", "cache", "dir"], "pip_cache_location", 45)),
        ("conda_info", lambda: _named(["conda.exe", "info", "--json"], "conda_info", 75)),
        ("uv_cache_location", lambda: _named(["uv.exe", "cache", "dir"], "uv_cache_location", 45)),
        ("vss_shadowstorage_text", lambda: _named(["vssadmin.exe", "list", "shadowstorage"], "vss_shadowstorage_text", 40)),
        ("power_capabilities", lambda: _named(["powercfg.exe", "/a"], "power_capabilities", 30)),
        ("component_store_analysis", lambda: _collect_component_store()),
        ("reserved_storage_state", lambda: _named(["dism.exe", "/Online", "/Get-ReservedStorageState", "/English"], "reserved_storage_state", 60)),
        ("compact_os_state", lambda: _named(["compact.exe", "/CompactOS:query"], "compact_os_state", 45)),
        ("ntfs_mft_status", lambda: collect_ntfs_mft_status(root)),
        ("winget_catalog_correlation", lambda: collect_winget_catalog_correlation(installed_apps=installed_apps)),
        ("browser_extensions", lambda: collect_browser_extensions()),
        ("extended_persistence", lambda: collect_extended_persistence()),
        ("alternate_data_streams", lambda: collect_alternate_data_streams(root=root)),
        ("windows_update_cache", lambda: collect_windows_update_cache()),
    )

    has_drive_collectors = bool(drive and re.match(r"^[A-Za-z]:$", drive))
    total_collectors = len(ps) + len(command_collectors) + (2 if has_drive_collectors else 0) + (4 if profile == "forensics" else 0)
    current_idx = 0

    for name, script in ps.items():
        if cancel and cancel():
            return collectors
        current_idx += 1
        if progress:
            progress({
                "phase": "windows_deep_inventory",
                "item": name,
                "done": current_idx,
                "total": total_collectors,
                "detail": f"Checking {name.replace('_', ' ')}...",
            })
        result = _powershell_json(script, name, timeout=150 if name in {"third_party_drivers", "hyperv_vms", "hyperv_disks", "physical_disk_reliability"} else 75)
        error_text = str(result.error or "").casefold()
        if name in optional_feature_collectors and not result.ok and any(token in error_text for token in (
            "commandnotfoundexception", "is not recognized", "not recognized as the name", "no msft_", "not supported",
        )):
            result.applicable = False
            result.error = "Optional Windows feature/cmdlet is unavailable: " + str(result.error or "")
        collectors.append(result)

    for name, collect in command_collectors:
        if cancel and cancel():
            return collectors
        current_idx += 1
        if progress:
            progress({
                "phase": "windows_deep_inventory",
                "item": name,
                "done": current_idx,
                "total": total_collectors,
                "detail": f"Checking {name.replace('_', ' ')}...",
            })
        collectors.append(collect())

    if has_drive_collectors:
        if cancel and cancel():
            return collectors
        current_idx += 1
        if progress:
            progress({
                "phase": "windows_deep_inventory",
                "item": "ntfs_info",
                "done": current_idx,
                "total": total_collectors,
                "detail": f"Checking NTFS metadata on {drive}...",
            })
        collectors.append(_named(["fsutil.exe", "fsinfo", "ntfsinfo", drive], "ntfs_info", 45))
        if cancel and cancel():
            return collectors
        current_idx += 1
        if progress:
            progress({
                "phase": "windows_deep_inventory",
                "item": "usn_journal",
                "done": current_idx,
                "total": total_collectors,
                "detail": f"Checking USN journal on {drive}...",
            })
        collectors.append(_named(["fsutil.exe", "usn", "queryjournal", drive], "usn_journal", 45))

    if profile == "forensics":
        forensics_collectors = (
            ("vss_shadows", lambda: _named(["vssadmin.exe", "list", "shadows"], "vss_shadows", 60)),
            ("virtualbox_vms", lambda: _named(["VBoxManage.exe", "list", "vms"], "virtualbox_vms", 45)),
            ("virtualbox_disks", lambda: _named(["VBoxManage.exe", "list", "hdds"], "virtualbox_disks", 60)),
            ("appx_packages_all_users", lambda: _powershell_json(
                "Get-AppxPackage -AllUsers -ErrorAction Stop | Select-Object Name,Version,Publisher,InstallLocation,PackageFullName,IsFramework,Architecture | ConvertTo-Json -Depth 3 -Compress",
                "appx_packages_all_users",
                timeout=120,
            )),
        )
        for name, collect in forensics_collectors:
            if cancel and cancel():
                return collectors
            current_idx += 1
            if progress:
                progress({
                    "phase": "windows_deep_inventory",
                    "item": name,
                    "done": current_idx,
                    "total": total_collectors,
                    "detail": f"Checking {name.replace('_', ' ')}...",
                })
            collectors.append(collect())

    return collectors


def basic_platform_info() -> dict[str, str]:
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "windows": str(IS_WINDOWS),
    }
