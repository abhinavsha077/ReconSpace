from __future__ import annotations

"""Conservative evidence findings from local signature, ACL and disk-health data."""

from typing import Any, Iterable

from .models import BinaryTrustRecord, CollectorResult, Finding, PathSecurityRecord


def build_binary_and_acl_findings(
    trust: Iterable[BinaryTrustRecord],
    permissions: Iterable[PathSecurityRecord],
) -> list[Finding]:
    findings: list[Finding] = []
    concerning_signature = {"hashmismatch", "nottrusted", "unknownerror", "notsupportedfileformat"}
    for row in trust:
        status = row.signature_status.casefold().replace(" ", "")
        persistence = bool(row.source_kinds)
        if row.exists is False:
            findings.append(Finding(
                title="Persistence binary target is missing",
                path=row.path,
                size_bytes=0,
                category="Persistence and binary trust",
                disposition="manual_review",
                risk="medium",
                confidence="high",
                why_it_exists="A startup, service or scheduled-task entry points to a file that was not present when signature metadata was collected.",
                recommendation="Review the owning startup/service/task registration and application state. A missing path can be an incomplete uninstall, a temporarily unavailable location, or stale persistence.",
                removal_risk="Changing persistence registrations can affect application startup or system behavior; this report does not modify them.",
                related_to=["startup", "services", "scheduled tasks"],
                estimated_reclaimable_bytes=0,
                evidence={"signature_status": row.signature_status, "source_kinds": row.source_kinds, "scope_type": "persistence"},
            ))
        elif persistence and status in concerning_signature:
            findings.append(Finding(
                title=f"Persistence binary signature requires review: {row.signature_status or 'unknown'}",
                path=row.path,
                size_bytes=row.size_bytes or 0,
                category="Persistence and binary trust",
                disposition="manual_review",
                risk="high",
                confidence="medium",
                why_it_exists="Local Authenticode inspection returned a status that is not a valid signature for a selected persistence target.",
                recommendation="Verify the publisher, expected installation path, file origin and application ownership. Signature status is one signal and is not a malware verdict.",
                removal_risk="Deleting or disabling a legitimate unsigned or locally built binary can break software, development workflows or security tooling.",
                related_to=["startup", "services", "scheduled tasks", "code signing"],
                estimated_reclaimable_bytes=0,
                evidence={"signature_status": row.signature_status, "signer_subject": row.signer_subject, "sha256": row.sha256, "source_kinds": row.source_kinds, "user_writable_location": row.is_user_writable_location, "scope_type": "persistence"},
            ))
        elif persistence and status == "notsigned" and row.is_user_writable_location:
            findings.append(Finding(
                title="Unsigned persistence binary in a user-writable location",
                path=row.path,
                size_bytes=row.size_bytes or 0,
                category="Persistence and binary trust",
                disposition="manual_review",
                risk="high",
                confidence="medium",
                why_it_exists="The selected startup/service/task target is unsigned and is located under a user-writable path. Legitimate portable, development and security tools can also match this pattern.",
                recommendation="Confirm the software owner, expected path, hash and installation source. Do not infer malware from this heuristic alone.",
                removal_risk="The target may be a legitimate local tool, script host, portable application or lab component.",
                related_to=["startup", "services", "scheduled tasks", "cybersecurity"],
                estimated_reclaimable_bytes=0,
                evidence={"signature_status": row.signature_status, "sha256": row.sha256, "source_kinds": row.source_kinds, "scope_type": "persistence"},
            ))

    for row in permissions:
        if not row.broad_write_detected:
            continue
        findings.append(Finding(
            title="Broad write permissions on a high-value path",
            path=row.path,
            size_bytes=0,
            category="Ownership and permissions",
            disposition="manual_review",
            risk="high",
            confidence="medium",
            why_it_exists="ACL metadata indicates that a broad identity such as Users, Authenticated Users or Everyone may have write/modify rights on a selected high-value path.",
            recommendation="Review the effective ACL, inherited permissions and application requirements. ReconSpace does not change permissions and this summary can contain benign intentional configurations.",
            removal_risk="Permission changes can break applications, services, build systems or shared workflows and can lock users out of data.",
            related_to=["permissions", "security", "ownership"],
            estimated_reclaimable_bytes=0,
            evidence={"owner": row.owner, "broad_write_identities": row.broad_write_identities, "protected_acl": row.protected_acl, "scope_type": "permissions"},
        ))
    return findings


def build_storage_health_findings(collectors: Iterable[CollectorResult]) -> list[Finding]:
    findings: list[Finding] = []
    lookup = {row.name: row for row in collectors}
    reliability = lookup.get("physical_disk_reliability")
    if reliability and reliability.ok:
        rows = reliability.data if isinstance(reliability.data, list) else [reliability.data]
        for row in rows:
            if not isinstance(row, dict):
                continue
            health = str(row.get("HealthStatus") or "").casefold()
            operational = " ".join(str(x) for x in (row.get("OperationalStatus") or [])).casefold()
            read_errors = row.get("ReadErrorsTotal")
            write_errors = row.get("WriteErrorsTotal")
            concerning = health not in {"", "healthy"} or any(x in operational for x in ("degraded", "lost", "error", "failed"))
            if isinstance(read_errors, (int, float)) and read_errors > 0:
                concerning = True
            if isinstance(write_errors, (int, float)) and write_errors > 0:
                concerning = True
            if not concerning:
                continue
            name = str(row.get("FriendlyName") or row.get("SerialNumber") or "Physical disk")
            findings.append(Finding(
                title=f"Storage reliability/health signal: {name}",
                path=name,
                size_bytes=int(row.get("Size") or 0),
                category="Storage hardware health",
                disposition="manual_review",
                risk="critical",
                confidence="medium",
                why_it_exists="Windows storage reliability metadata reported a non-healthy status or non-zero error counter for a physical disk.",
                recommendation="Prioritize backup verification and inspect the device with the manufacturer/Windows storage diagnostics. Error counters and health fields vary by controller and may be unavailable or vendor-specific.",
                removal_risk="This is not a cleanup candidate. Ignoring a genuine storage-device problem can lead to data loss.",
                related_to=["storage health", "hardware", "backup"],
                estimated_reclaimable_bytes=0,
                evidence={**row, "scope_type": "hardware"},
            ))
    return findings


def build_protection_findings(collectors: Iterable[CollectorResult]) -> list[Finding]:
    findings: list[Finding] = []
    lookup = {row.name: row for row in collectors}
    defender = lookup.get("defender_status")
    if defender and defender.ok and isinstance(defender.data, dict):
        status = defender.data.get("Status") or {}
        if isinstance(status, dict):
            rt_enabled = status.get("RealTimeProtectionEnabled")
            if rt_enabled is False:
                findings.append(Finding(
                    title="Windows Defender Real-Time Protection is disabled",
                    path="Windows Defender",
                    size_bytes=0,
                    category="Security and protection",
                    category_group="privacy_permissions",
                    disposition="manual_review",
                    risk="critical",
                    confidence="high",
                    why_it_exists="Real-time malicious code scanning is turned off in Windows Defender.",
                    recommendation="Verify whether a third-party antivirus is protecting the PC, or re-enable Real-Time Protection in Windows Security.",
                    removal_risk="Workstation is vulnerable to malware execution while real-time inspection is disabled.",
                    related_to=["antivirus", "defender", "protection", "security"],
                    estimated_reclaimable_bytes=0,
                    evidence={"scope_type": "security_antivirus", **status},
                ))
            sig_age = status.get("AntivirusSignatureAge")
            if isinstance(sig_age, (int, float)) and sig_age > 7:
                findings.append(Finding(
                    title=f"Windows Defender signatures are outdated ({int(sig_age)} days old)",
                    path="Windows Defender",
                    size_bytes=0,
                    category="Security and protection",
                    category_group="privacy_permissions",
                    disposition="manual_review",
                    risk="high",
                    confidence="high",
                    why_it_exists=f"Antivirus definitions were last updated {int(sig_age)} days ago.",
                    recommendation="Update virus & threat protection definitions via Windows Update or Windows Security.",
                    removal_risk="Outdated definitions may not detect recently discovered malware variants.",
                    related_to=["antivirus", "defender", "protection", "security"],
                    estimated_reclaimable_bytes=0,
                    evidence={"scope_type": "security_antivirus", **status},
                ))
        threats = defender.data.get("Threats") or []
        if isinstance(threats, list) and threats:
            for t in threats[:5]:
                if not isinstance(t, dict):
                    continue
                tname = str(t.get("ThreatName") or f"Threat #{t.get('ThreatID')}")
                findings.append(Finding(
                    title=f"Windows Defender threat recorded: {tname}",
                    path="Windows Defender",
                    size_bytes=0,
                    category="Security and protection",
                    category_group="privacy_permissions",
                    disposition="manual_review",
                    risk="high",
                    confidence="high",
                    why_it_exists=f"A threat detection event was recorded by Windows Defender: {tname}.",
                    recommendation="Review the detection status in Windows Security Protection history to confirm complete remediation.",
                    removal_risk="Unresolved threats pose risk to workstation integrity.",
                    related_to=["antivirus", "defender", "threats", "security"],
                    estimated_reclaimable_bytes=0,
                    evidence={"scope_type": "security_threat", **t},
                ))

    privacy = lookup.get("privacy_consent_store")
    if privacy and privacy.ok and isinstance(privacy.data, dict):
        webcam = privacy.data.get("webcam") or []
        mic = privacy.data.get("microphone") or []
        if len(webcam) > 0 or len(mic) > 0:
            findings.append(Finding(
                title=f"Hardware privacy permissions active ({len(webcam)} camera, {len(mic)} microphone)",
                path="CapabilityAccessManager",
                size_bytes=0,
                category="Privacy and permissions",
                category_group="privacy_permissions",
                disposition="informational",
                risk="low",
                confidence="high",
                why_it_exists=f"Windows ConsentStore grants camera access to {len(webcam)} apps and microphone access to {len(mic)} apps.",
                recommendation="Review the apps with camera/mic access in the Protection tab to verify that only trusted software has access.",
                removal_risk="No changes are made by ReconSpace; revoke permissions manually in Windows Settings if desired.",
                related_to=["privacy", "permissions", "camera", "microphone"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "privacy_hardware", "webcam_count": len(webcam), "mic_count": len(mic)},
            ))

    exts = lookup.get("browser_extensions")
    if exts and exts.ok and isinstance(exts.data, list):
        high_risk_exts = [x for x in exts.data if isinstance(x, dict) and x.get("risk_level") == "high"]
        if high_risk_exts:
            sample_names = ", ".join(str(x.get("name") or "Extension") for x in high_risk_exts[:3])
            findings.append(Finding(
                title=f"Browser extensions with elevated web permissions ({len(high_risk_exts)} detected)",
                path="Browser Extensions",
                size_bytes=0,
                category="Privacy and permissions",
                category_group="privacy_permissions",
                disposition="informational",
                risk="medium",
                confidence="high",
                why_it_exists=f"{len(high_risk_exts)} extension(s) have broad permissions (e.g. all URLs, webRequest, or native messaging): {sample_names}.",
                recommendation="Review installed browser extensions in the Applications or Protection tab to verify that third-party extensions remain trusted.",
                removal_risk="No changes are made by ReconSpace; disable unwanted extensions in browser settings.",
                related_to=["browser", "privacy", "extensions", "permissions"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "browser_extensions", "high_risk_count": len(high_risk_exts), "samples": high_risk_exts[:10]},
            ))

    persist = lookup.get("extended_persistence")
    if persist and persist.ok and isinstance(persist.data, list):
        concerning_persist = [
            x for x in persist.data
            if isinstance(x, dict) and (x.get("is_user_writable") or x.get("target_exists") is False or x.get("category") == "AppInit_DLLs")
        ]
        for cp in concerning_persist[:5]:
            p_cat = cp.get("category")
            p_name = cp.get("name")
            p_path = cp.get("target_path") or p_name
            findings.append(Finding(
                title=f"Extended persistence entry requires review: {p_name} ({p_cat})",
                path=str(p_path),
                size_bytes=0,
                category="Security and protection",
                category_group="privacy_permissions",
                disposition="manual_review",
                risk="high" if cp.get("is_user_writable") else "medium",
                confidence="high",
                why_it_exists=f"A shell extension or persistence hook ({p_cat}) points to a user-writable path or non-standard library: {p_path}.",
                recommendation="Verify the target binary publisher and expected installation origin.",
                removal_risk="Do not modify without understanding the registering application.",
                related_to=["persistence", "autoruns", "shellex", "security"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "extended_persistence", **cp},
            ))

    ads = lookup.get("alternate_data_streams")
    if ads and ads.ok and isinstance(ads.data, dict):
        zone_cnt = ads.data.get("zone_identifier_streams") or 0
        total_cnt = ads.data.get("total_streams") or 0
        hidden_cnt = total_cnt - zone_cnt
        if hidden_cnt > 0:
            findings.append(Finding(
                title=f"Hidden Alternate Data Streams detected ({hidden_cnt} stream(s))",
                path="NTFS Alternate Data Streams",
                size_bytes=int(ads.data.get("total_stream_bytes") or 0),
                category="Security and protection",
                category_group="privacy_permissions",
                disposition="manual_review",
                risk="medium",
                confidence="high",
                why_it_exists=f"{hidden_cnt} file(s) contain NTFS alternate streams beyond standard Zone.Identifier download markers.",
                recommendation="Inspect stream names and contents using PowerShell Get-Item -Stream *.",
                removal_risk="Alternate data streams can store metadata required by some applications.",
                related_to=["security", "ntfs", "ads", "streams"],
                estimated_reclaimable_bytes=0,
                evidence={"scope_type": "alternate_data_streams", **ads.data},
            ))

    return findings
