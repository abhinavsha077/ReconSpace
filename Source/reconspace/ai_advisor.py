from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any

from .privacy import redact_report
from .report import format_bytes


@dataclass(slots=True)
class AIProviderConfig:
    provider: str = "openai"  # "openai", "anthropic", "gemini", "ollama", "heuristic", "mock"
    api_key: str = ""
    model: str = ""
    endpoint: str = ""
    temperature: float = 0.2
    timeout_seconds: float = 60.0

    def resolve_endpoint(self) -> str:
        if self.endpoint:
            return self.endpoint
        p = self.provider.lower()
        if p == "openai":
            return "https://api.openai.com/v1/chat/completions"
        if p == "anthropic":
            return "https://api.anthropic.com/v1/messages"
        if p == "gemini":
            model = self.model or "gemini-1.5-flash"
            return f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
        if p == "ollama":
            return "http://localhost:11434/api/generate"
        return ""

    def resolve_model(self) -> str:
        if self.model:
            return self.model
        p = self.provider.lower()
        if p == "openai":
            return "gpt-4o"
        if p == "anthropic":
            return "claude-3-5-sonnet-20241022"
        if p == "gemini":
            return "gemini-1.5-flash"
        if p == "ollama":
            return "llama3:latest"
        return "reconspace-heuristic"

    def resolve_api_key(self) -> str:
        if self.api_key:
            return self.api_key
        p = self.provider.lower()
        if p == "openai":
            return os.environ.get("OPENAI_API_KEY", "") or os.environ.get("RECONSPACE_AI_KEY", "")
        if p == "anthropic":
            return os.environ.get("ANTHROPIC_API_KEY", "") or os.environ.get("RECONSPACE_AI_KEY", "")
        if p == "gemini":
            return os.environ.get("GEMINI_API_KEY", "") or os.environ.get("RECONSPACE_AI_KEY", "")
        return os.environ.get("RECONSPACE_AI_KEY", "")


@dataclass(slots=True)
class AIRecommendation:
    id: str
    category: str  # "critical_action", "quick_win", "safety_warning", "explainer"
    title: str
    impact_reclaim_bytes: int = 0
    safety_rating: str = "high_safety"  # "high_safety", "requires_manual_review", "do_not_touch"
    summary: str = ""
    technical_detail: str = ""
    suggested_action: str = ""
    affected_paths: list[str] = field(default_factory=list)


@dataclass(slots=True)
class AIReviewResult:
    ok: bool
    provider: str
    model: str
    summary_verdict: str
    overall_score: int  # 0 - 100
    recommendations: list[AIRecommendation] = field(default_factory=list)
    critical_actions: list[AIRecommendation] = field(default_factory=list)
    quick_wins: list[AIRecommendation] = field(default_factory=list)
    safety_warnings: list[AIRecommendation] = field(default_factory=list)
    explainers: list[AIRecommendation] = field(default_factory=list)
    total_potential_reclaim_bytes: int = 0
    raw_response: str = ""
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    sanitization_summary: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


SYSTEM_PROMPT = """You are the ReconSpace AI Audit Advisor, an elite Windows systems architecture and cybersecurity auditor.
Your mission is to provide an evidence-based, transparent, and strictly safe audit review of a Windows system reconnaissance report.

Core Directives:
1. SAFETY INVARIANT: Never recommend destructive deletion of Windows system files, driver stores, or development workspaces (Docker, WSL, Python venvs, node_modules, Git repositories).
2. DISTINGUISH WITH PRECISION:
   - "critical_action": Urgent posture improvements (e.g. disabled Defender real-time protection, stale AV signatures >14 days, massive crash dumps >2 GB, unsigned persistence executables in writable paths).
   - "quick_win": Zero-risk disposable cleanup (e.g. Windows Temp, Delivery Optimization cache, WER reports, browser cache compaction, reduced hibernation switch).
   - "safety_warning": Explicit warnings of intentional tooling and sensitive environments to NEVER delete.
   - "explainer": Architectural explanations of Windows storage mechanics (e.g. Component Store WinSxS hardlinks, reduced vs full hiberfil.sys, Fast Startup, Delivery Optimization P2P).
3. STRUCTURED OUTPUT: You MUST return ONLY valid JSON matching the exact schema specified below with no surrounding conversation.

Output JSON Schema:
{
  "overall_score": <integer from 0 to 100 representing system health & storage efficiency>,
  "summary_verdict": "<concise 2-sentence executive summary of the system status>",
  "critical_actions": [
    {
      "id": "AIR-C01",
      "title": "<short title>",
      "impact_reclaim_bytes": <estimated integer bytes reclaimed or 0>,
      "safety_rating": "high_safety" | "requires_manual_review" | "do_not_touch",
      "summary": "<clear summary>",
      "technical_detail": "<technical rationale>",
      "suggested_action": "<exact copyable PowerShell / command recipe>",
      "affected_paths": ["<path1>", ...]
    }
  ],
  "quick_wins": [
    {
      "id": "AIR-Q01",
      "title": "<short title>",
      "impact_reclaim_bytes": <integer bytes>,
      "safety_rating": "high_safety",
      "summary": "<summary>",
      "technical_detail": "<detail>",
      "suggested_action": "<recipe>",
      "affected_paths": ["<path1>"]
    }
  ],
  "safety_warnings": [
    {
      "id": "AIR-S01",
      "title": "<short title>",
      "impact_reclaim_bytes": 0,
      "safety_rating": "do_not_touch",
      "summary": "<what NOT to delete and why>",
      "technical_detail": "<technical risk explanation>",
      "suggested_action": "<safeguard advice>",
      "affected_paths": ["<path1>"]
    }
  ],
  "explainers": [
    {
      "id": "AIR-E01",
      "title": "<concept title>",
      "impact_reclaim_bytes": 0,
      "safety_rating": "high_safety",
      "summary": "<educational concept summary>",
      "technical_detail": "<deep architectural context>",
      "suggested_action": "<inspection command>",
      "affected_paths": []
    }
  ]
}
"""


def _extract_collector(collectors: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for c in collectors:
        if isinstance(c, dict) and c.get("name") == name and c.get("ok"):
            return c.get("data")
    return None


def build_condensed_audit_context(report: dict[str, Any]) -> dict[str, Any]:
    """Extract and condense high-signal telemetry from a ReconSpace report for LLM ingestion."""
    stats = report.get("stats") or {}
    reclaim = report.get("reclaim_summary") or {}
    collectors = report.get("collectors") or []
    findings = report.get("findings") or []
    applications = report.get("applications") or []
    startup = report.get("startup") or []

    # Storage & volume
    total_bytes = stats.get("filesystem_total_bytes") or 0
    free_bytes = stats.get("filesystem_free_bytes") or 0
    used_bytes = stats.get("filesystem_used_bytes") or 0
    free_pct = round((free_bytes / total_bytes * 100), 1) if total_bytes > 0 else 0

    # Memory collector
    mem = _extract_collector(collectors, "system_memory_status") or {}
    # Defender collector
    def_data = _extract_collector(collectors, "defender_status") or {}
    # Hibernation & pagefile collector
    hiber_data = _extract_collector(collectors, "hibernation_pagefile_intelligence") or {}
    # Delivery optimization collector
    do_data = _extract_collector(collectors, "delivery_optimization_status") or {}
    # Battery collector
    bat_data = _extract_collector(collectors, "battery_power_health") or {}
    # Crash dumps collector
    dumps_data = _extract_collector(collectors, "crash_dumps_inventory") or {}
    # Recycle bin collector
    rb_data = _extract_collector(collectors, "recycle_bin_metrics") or {}
    # Orphaned app data
    orphans = _extract_collector(collectors, "orphaned_app_data") or {}
    # Network adapters
    net_data = _extract_collector(collectors, "network_adapters_telemetry") or {}
    # Windows update cache
    wu_data = _extract_collector(collectors, "windows_update_cache") or {}

    # Top findings condensed (max 15)
    top_findings = []
    for f in findings[:15]:
        if isinstance(f, dict):
            top_findings.append({
                "title": f.get("title", ""),
                "size_bytes": f.get("size_bytes", 0),
                "category": f.get("category", ""),
                "disposition": f.get("disposition", ""),
                "risk": f.get("risk", ""),
                "path": f.get("path", "")[:120],
                "why_it_exists": f.get("why_it_exists", "")[:160],
            })

    # High-risk startup or unsigned persistence targets
    risky_startup = [
        {"name": s.get("name"), "command": str(s.get("command"))[:100], "reason": s.get("reason")}
        for s in startup[:10] if isinstance(s, dict) and s.get("risk_hint")
    ]

    context = {
        "scan_root": stats.get("root", "C:\\"),
        "scan_profile": report.get("profile", "deep"),
        "storage": {
            "total_bytes": total_bytes,
            "free_bytes": free_bytes,
            "used_bytes": used_bytes,
            "free_percentage": free_pct,
            "reclaim_candidates_total_bytes": reclaim.get("reclaim_candidates_total_bytes", 0),
            "safe_cleanup_bytes": reclaim.get("safe_cleanup_bytes", 0),
            "manual_review_bytes": reclaim.get("manual_review_bytes", 0),
            "duplicate_reclaim_bytes": reclaim.get("duplicate_reclaim_bytes", 0),
        },
        "performance": {
            "ram_load_pct": mem.get("memory_load_pct"),
            "total_ram_bytes": mem.get("total_physical_bytes"),
            "avail_ram_bytes": mem.get("available_physical_bytes"),
            "total_pagefile_bytes": mem.get("total_pagefile_bytes"),
            "top_processes_count": len(report.get("processes") or []),
            "startup_items_count": len(startup),
            "risky_startup_items": risky_startup,
        },
        "protection": {
            "defender_realtime": (def_data.get("Status") or {}).get("RealTimeProtectionEnabled"),
            "defender_signature_age_days": (def_data.get("Status") or {}).get("AntivirusSignatureAge"),
            "active_threats_count": len(def_data.get("Threats") or []),
        },
        "windows_internals": {
            "hibernation": {
                "exists": hiber_data.get("hiberfil_exists", False),
                "size_bytes": hiber_data.get("hiberfil_bytes", 0),
                "mode": hiber_data.get("hiber_file_type", "unknown"),
                "potential_reduced_savings_bytes": hiber_data.get("potential_reduced_savings_bytes", 0),
            },
            "pagefile_bytes": hiber_data.get("pagefile_bytes", 0),
            "swapfile_bytes": hiber_data.get("swapfile_bytes", 0),
            "delivery_optimization": {
                "cache_size_bytes": do_data.get("cache_size_bytes", 0),
                "bytes_uploaded_to_peers": do_data.get("bytes_uploaded_to_peers", 0),
                "download_mode": do_data.get("download_mode", "Default"),
            },
            "crash_dumps": {
                "count": dumps_data.get("total_dumps_count", 0),
                "size_bytes": dumps_data.get("total_size_bytes", 0),
            },
            "recycle_bin": {
                "count": rb_data.get("item_count", 0),
                "size_bytes": rb_data.get("total_size_bytes", 0),
            },
            "orphaned_appdata": {
                "count": len(orphans.get("orphaned_directories", [])) if isinstance(orphans, dict) else 0,
                "reclaimable_bytes": orphans.get("total_reclaimable_bytes", 0) if isinstance(orphans, dict) else 0,
            },
            "battery": bat_data,
            "network": {
                "active_adapters": net_data.get("active_adapters_count", 0),
                "total_adapters": net_data.get("total_adapters_count", 0),
            },
            "windows_update": {
                "download_bytes": wu_data.get("software_distribution_download_bytes", 0),
                "datastore_bytes": wu_data.get("software_distribution_datastore_bytes", 0),
            },
        },
        "top_findings": top_findings,
        "installed_applications_count": len(applications),
    }
    return context


def build_advisor_prompt(report: dict[str, Any], redact: bool = True) -> tuple[str, str, dict[str, Any]]:
    """Build system and user prompts, optionally applying automatic report redaction."""
    sanitization_summary = {"redacted": False, "rules_applied": 0}
    working_report = report
    if redact:
        redacted = redact_report(report)
        working_report = redacted
        sanitization_summary = {
            "redacted": True,
            "rules_applied": (redacted.get("privacy_redaction_summary") or {}).get("replacement_rules_applied", 0),
        }

    condensed = build_condensed_audit_context(working_report)
    user_prompt = (
        "Here is the sanitized Windows reconnaissance audit data. Analyze the telemetry and return your structured recommendations JSON:\n\n"
        f"```json\n{json.dumps(condensed, indent=2, ensure_ascii=False)}\n```"
    )
    return SYSTEM_PROMPT, user_prompt, sanitization_summary


def _clean_json_text(text: str) -> str:
    """Strip markdown code fences and whitespace from LLM text."""
    s = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", s)
    if match:
        return match.group(1).strip()
    return s


def generate_heuristic_review(report: dict[str, Any]) -> AIReviewResult:
    """Deterministic, offline, zero-network rule-based AI review fallback."""
    condensed = build_condensed_audit_context(report)
    storage = condensed["storage"]
    perf = condensed["performance"]
    prot = condensed["protection"]
    internals = condensed["windows_internals"]

    crit: list[AIRecommendation] = []
    quick: list[AIRecommendation] = []
    warns: list[AIRecommendation] = []
    expls: list[AIRecommendation] = []

    # Score starting point
    score = 95

    # 1. Protection checks
    if prot.get("defender_realtime") is False:
        score -= 25
        crit.append(AIRecommendation(
            id="AIR-C01",
            category="critical_action",
            title="Microsoft Defender Real-Time Protection is Disabled",
            impact_reclaim_bytes=0,
            safety_rating="high_safety",
            summary="Real-time antivirus scanning is currently inactive, exposing the system to zero-day file execution threats.",
            technical_detail="Get-MpComputerStatus reports RealTimeProtectionEnabled=False. Active persistence targets or downloaded executables will not be inspected on access.",
            suggested_action="Set-MpPreference -DisableRealtimeMonitoring $false",
            affected_paths=["C:\\Windows\\System32\\SecurityHealthSystray.exe"],
        ))

    sig_age = prot.get("defender_signature_age_days")
    if sig_age is not None and sig_age > 7:
        score -= 10
        crit.append(AIRecommendation(
            id="AIR-C02",
            category="critical_action",
            title=f"Antivirus Signatures Outdated ({sig_age} Days Old)",
            impact_reclaim_bytes=0,
            safety_rating="high_safety",
            summary="Defender definition updates have fallen behind official Microsoft telemetry.",
            technical_detail=f"Signatures are {sig_age} days old. Modern ransomware strains evade definitions older than 48 hours.",
            suggested_action='Update-MpSignature; "Signatures updated"',
            affected_paths=[],
        ))

    # 2. Crash dumps check
    dumps = internals.get("crash_dumps", {})
    dump_bytes = dumps.get("size_bytes", 0)
    dump_count = dumps.get("count", 0)
    if dump_bytes > 500 * 1024 * 1024:
        score -= 5
        crit.append(AIRecommendation(
            id="AIR-C03",
            category="critical_action",
            title=f"Substantial Crash Dump Storage ({format_bytes(dump_bytes)})",
            impact_reclaim_bytes=dump_bytes,
            safety_rating="high_safety",
            summary=f"Discovered {dump_count} memory or user crash dumps holding {format_bytes(dump_bytes)} of dead data.",
            technical_detail="Crash dumps (MEMORY.DMP and %LocalAppData%\\CrashDumps) preserve state at failure time and are not required once diagnosis is concluded.",
            suggested_action="Get-ChildItem -Path '$env:LOCALAPPDATA\\CrashDumps', '$env:SystemRoot\\Minidump' -Filter *.dmp -ErrorAction SilentlyContinue | Select-Object FullName, Length",
            affected_paths=["%LOCALAPPDATA%\\CrashDumps", "%SystemRoot%\\MEMORY.DMP"],
        ))
    elif dump_bytes > 0:
        quick.append(AIRecommendation(
            id="AIR-Q01",
            category="quick_win",
            title=f"Purge Windows Error Reporting Crash Dumps ({format_bytes(dump_bytes)})",
            impact_reclaim_bytes=dump_bytes,
            safety_rating="high_safety",
            summary=f"{dump_count} localized crash dumps can be safely reclaimed.",
            technical_detail="Dumps in %LocalAppData%\\CrashDumps are purely forensic snapshots.",
            suggested_action="Get-ChildItem -Path '$env:LOCALAPPDATA\\CrashDumps' -Filter *.dmp -ErrorAction SilentlyContinue | Select-Object FullName, Length",
            affected_paths=["%LOCALAPPDATA%\\CrashDumps"],
        ))

    # 3. Hibernation Sizing Intelligence (Dism++ style)
    hiber = internals.get("hibernation", {})
    hiber_bytes = hiber.get("size_bytes", 0)
    hiber_mode = hiber.get("mode", "unknown")
    pot_savings = hiber.get("potential_reduced_savings_bytes", 0)
    if hiber.get("exists") and hiber_mode == "full" and pot_savings > 1024 * 1024 * 1024:
        quick.append(AIRecommendation(
            id="AIR-Q02",
            category="quick_win",
            title=f"Switch Hibernation to Reduced Mode (Save {format_bytes(pot_savings)})",
            impact_reclaim_bytes=pot_savings,
            safety_rating="high_safety",
            summary=f"Full hibernation file uses {format_bytes(hiber_bytes)}. Switching to reduced keeps Fast Startup while saving ~50% disk space.",
            technical_detail="Windows reduced hibernation stores only the kernel context necessary for Fast Startup, freeing 50% of the RAM-equivalent file size on C:\\.",
            suggested_action="powercfg.exe /hibernate /type reduced",
            affected_paths=["C:\\hiberfil.sys"],
        ))

    # 4. Delivery Optimization Cache (Glances / Dism++ style)
    do_data = internals.get("delivery_optimization", {})
    do_bytes = do_data.get("cache_size_bytes", 0)
    do_uploads = do_data.get("bytes_uploaded_to_peers", 0)
    if do_bytes > 500 * 1024 * 1024:
        quick.append(AIRecommendation(
            id="AIR-Q03",
            category="quick_win",
            title=f"Clear Delivery Optimization Cache ({format_bytes(do_bytes)})",
            impact_reclaim_bytes=do_bytes,
            safety_rating="high_safety",
            summary=f"Windows Update peer cache contains {format_bytes(do_bytes)} of downloaded packages.",
            technical_detail="Delivery Optimization stores cumulative updates for local/internet sharing. Once updates are installed, this cache is safe to purge.",
            suggested_action="Delete-DeliveryOptimizationCache",
            affected_paths=["C:\\Windows\\ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache"],
        ))
    if do_uploads > 1024 * 1024 * 1024:
        quick.append(AIRecommendation(
            id="AIR-Q04",
            category="quick_win",
            title=f"Restrict P2P Delivery Uploads ({format_bytes(do_uploads)} Uploaded)",
            impact_reclaim_bytes=0,
            safety_rating="high_safety",
            summary="Delivery Optimization is uploading updates to external peers, consuming background upload bandwidth.",
            technical_detail="DODownloadMode allows P2P peering across the Internet. Restricting it to LAN or HTTP-only prevents background ISP data leakage.",
            suggested_action="Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeliveryOptimization' -Name DODownloadMode -Value 1 -Type DWord",
            affected_paths=[],
        ))

    # 5. Recycle Bin (PrivaZer style)
    rb = internals.get("recycle_bin", {})
    rb_bytes = rb.get("size_bytes", 0)
    rb_items = rb.get("count", 0)
    if rb_bytes > 200 * 1024 * 1024:
        quick.append(AIRecommendation(
            id="AIR-Q05",
            category="quick_win",
            title=f"Empty Recycle Bin ({format_bytes(rb_bytes)}, {rb_items} Items)",
            impact_reclaim_bytes=rb_bytes,
            safety_rating="high_safety",
            summary=f"The Recycle Bin is currently holding {rb_items} deleted files consuming {format_bytes(rb_bytes)}.",
            technical_detail="Files in $Recycle.Bin occupy disk blocks on the respective volume until explicitly purged.",
            suggested_action="Get-ChildItem -Path 'C:\\$Recycle.Bin' -Force -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum",
            affected_paths=["C:\\$Recycle.Bin"],
        ))

    # 6. Orphaned AppData leftovers (BCUninstaller style)
    orph = internals.get("orphaned_appdata", {})
    orph_bytes = orph.get("reclaimable_bytes", 0)
    orph_count = orph.get("count", 0)
    if orph_count > 0:
        quick.append(AIRecommendation(
            id="AIR-Q06",
            category="quick_win",
            title=f"Review Orphaned AppData Leftovers ({orph_count} Folders, {format_bytes(orph_bytes)})",
            impact_reclaim_bytes=orph_bytes,
            safety_rating="requires_manual_review",
            summary=f"BCUninstaller token heuristics identified {orph_count} residual folders left behind by uninstalled software.",
            technical_detail="These directories in %LocalAppData% or %AppData% have no corresponding registered uninstaller or running process, and have been untouched for over 14 days.",
            suggested_action="# Review paths in ReconSpace Applications Hub before safe manual removal",
            affected_paths=[],
        ))

    # 7. Safety Warnings (Developer workspace guards)
    warns.append(AIRecommendation(
        id="AIR-S01",
        category="safety_warning",
        title="Developer Workspaces & Package Caches Protected",
        impact_reclaim_bytes=0,
        safety_rating="do_not_touch",
        summary="ReconSpace strictly protects WSL distros, Docker images, Python virtual environments, and node_modules from automated deletion.",
        technical_detail="Conventional cleaners corrupt build tooling by treating node_modules or .venv as temporary caches. These are essential project dependencies and must only be pruned via language package managers (e.g. `npm prune`, `pip cache purge`).",
        suggested_action="# Do not run blanket cleaners on developer project folders",
        affected_paths=[],
    ))
    warns.append(AIRecommendation(
        id="AIR-S02",
        category="safety_warning",
        title="Windows Servicing Component Store (WinSxS) Invariant",
        impact_reclaim_bytes=0,
        safety_rating="do_not_touch",
        summary="Never delete files directly from C:\\Windows\\WinSxS.",
        technical_detail="WinSxS utilizes NTFS hardlinks. Direct deletion corrupts the Windows component store and prevents future security updates. Use only official DISM tooling.",
        suggested_action="dism.exe /Online /Cleanup-Image /AnalyzeComponentStore",
        affected_paths=["C:\\Windows\\WinSxS"],
    ))

    # 8. Explainers
    expls.append(AIRecommendation(
        id="AIR-E01",
        category="explainer",
        title="NTFS Hardlinks & The WinSxS Size Illusion",
        impact_reclaim_bytes=0,
        safety_rating="high_safety",
        summary="Why Windows Explorer reports WinSxS as 10-20 GB when actual unique disk allocation is far smaller.",
        technical_detail="Files in C:\\Windows\\System32 are hardlink pointers sharing the same MFT record as C:\\Windows\\WinSxS. Standard file traversals sum every pointer, creating double-counting illusions. ReconSpace deduplicates hardlinks cryptographically to display true allocated bytes.",
        suggested_action="fsutil.exe hardlink list C:\\Windows\\System32\\ntdll.dll",
        affected_paths=["C:\\Windows\\WinSxS", "C:\\Windows\\System32"],
    ))
    expls.append(AIRecommendation(
        id="AIR-E02",
        category="explainer",
        title="Windows Memory Pressure vs Working Set Allocation",
        impact_reclaim_bytes=0,
        safety_rating="high_safety",
        summary="Understanding physical RAM utilization and committed pagefile dynamics on modern Windows 10/11.",
        technical_detail="Windows aggressively caches standby memory to accelerate app launching. High standby memory is normal and healthy; high committed pagefile pressure is what causes disk thrashing.",
        suggested_action="Get-CimInstance Win32_PageFileUsage",
        affected_paths=[],
    ))

    # Calculate wellness score
    free_pct = storage.get("free_percentage", 100)
    if free_pct < 10:
        score -= 20
    elif free_pct < 20:
        score -= 10

    ram_load = perf.get("ram_load_pct")
    if ram_load and ram_load > 85:
        score -= 10

    score = max(10, min(100, score))
    total_reclaim = sum(r.impact_reclaim_bytes for r in (crit + quick))

    verdict = (
        f"System health score is {score}/100 with {format_bytes(total_reclaim)} in safe, actionable reclamation opportunities. "
        f"Storage free space is {free_pct}% with {len(crit)} critical action(s) and {len(quick)} quick win(s) identified."
    )

    all_recs = crit + quick + warns + expls

    return AIReviewResult(
        ok=True,
        provider="heuristic",
        model="reconspace-heuristic-advisor-v1",
        summary_verdict=verdict,
        overall_score=score,
        recommendations=all_recs,
        critical_actions=crit,
        quick_wins=quick,
        safety_warnings=warns,
        explainers=expls,
        total_potential_reclaim_bytes=total_reclaim,
        raw_response="",
        sanitization_summary={"redacted": True, "rules_applied": 0, "offline_heuristic": True},
    )


def _parse_ai_json_response(
    data: dict[str, Any],
    provider: str,
    model: str,
    raw_text: str,
    sanitization_summary: dict[str, Any],
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
) -> AIReviewResult:
    """Parse structured JSON from an LLM into an AIReviewResult."""
    score = int(data.get("overall_score") or 85)
    score = max(0, min(100, score))
    verdict = str(data.get("summary_verdict") or "Audit review completed successfully.")

    def parse_items(items_raw: Any, category: str) -> list[AIRecommendation]:
        if not isinstance(items_raw, list):
            return []
        recs = []
        for idx, item in enumerate(items_raw, 1):
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or f"AIR-{category[:1].upper()}{idx:02d}")
            title = str(item.get("title") or "Recommendation")
            impact = int(item.get("impact_reclaim_bytes") or 0)
            safety = str(item.get("safety_rating") or "high_safety")
            if safety not in {"high_safety", "requires_manual_review", "do_not_touch"}:
                safety = "high_safety"
            summary = str(item.get("summary") or "")
            technical = str(item.get("technical_detail") or "")
            suggested = str(item.get("suggested_action") or "")
            paths = [str(p) for p in (item.get("affected_paths") or []) if isinstance(p, str)]
            recs.append(AIRecommendation(
                id=item_id,
                category=category,
                title=title,
                impact_reclaim_bytes=impact,
                safety_rating=safety,
                summary=summary,
                technical_detail=technical,
                suggested_action=suggested,
                affected_paths=paths,
            ))
        return recs

    crit = parse_items(data.get("critical_actions"), "critical_action")
    quick = parse_items(data.get("quick_wins"), "quick_win")
    warns = parse_items(data.get("safety_warnings"), "safety_warning")
    expls = parse_items(data.get("explainers"), "explainer")

    all_recs = crit + quick + warns + expls
    total_reclaim = sum(r.impact_reclaim_bytes for r in (crit + quick))

    return AIReviewResult(
        ok=True,
        provider=provider,
        model=model,
        summary_verdict=verdict,
        overall_score=score,
        recommendations=all_recs,
        critical_actions=crit,
        quick_wins=quick,
        safety_warnings=warns,
        explainers=expls,
        total_potential_reclaim_bytes=total_reclaim,
        raw_response=raw_text,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        sanitization_summary=sanitization_summary,
    )


def query_ai_advisor(report: dict[str, Any], config: AIProviderConfig | None = None, redact: bool = True) -> AIReviewResult:
    """Query the configured AI provider with a sanitized audit report and parse structured recommendations."""
    cfg = config or AIProviderConfig()
    provider = cfg.provider.lower()

    if provider in {"heuristic", "mock", "offline"}:
        return generate_heuristic_review(report)

    system_prompt, user_prompt, sanitization_summary = build_advisor_prompt(report, redact=redact)
    api_key = cfg.resolve_api_key()
    model = cfg.resolve_model()
    endpoint = cfg.resolve_endpoint()

    if not api_key and provider in {"openai", "anthropic", "gemini"}:
        # Graceful fallback: return heuristic review with a helpful explanation
        heuristic = generate_heuristic_review(report)
        heuristic.sanitization_summary["note"] = f"No API key provided for {provider}; falling back to built-in heuristic advisor."
        return heuristic

    try:
        if provider == "openai":
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {api_key}",
            }
            body = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": cfg.temperature,
                "response_format": {"type": "json_object"},
            }
            req = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
            choice = (resp_data.get("choices") or [{}])[0]
            raw_text = choice.get("message", {}).get("content", "")
            usage = resp_data.get("usage") or {}
            parsed_json = json.loads(_clean_json_text(raw_text))
            return _parse_ai_json_response(
                parsed_json,
                provider=provider,
                model=model,
                raw_text=raw_text,
                sanitization_summary=sanitization_summary,
                prompt_tokens=usage.get("prompt_tokens"),
                completion_tokens=usage.get("completion_tokens"),
            )

        elif provider == "anthropic":
            headers = {
                "Content-Type": "application/json",
                "x-api-key": api_key,
                "anthropic-version": "2023-06-01",
            }
            body = {
                "model": model,
                "max_tokens": 4096,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "temperature": cfg.temperature,
            }
            req = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
            content_blocks = resp_data.get("content") or []
            raw_text = "".join(b.get("text", "") for b in content_blocks if b.get("type") == "text")
            usage = resp_data.get("usage") or {}
            parsed_json = json.loads(_clean_json_text(raw_text))
            return _parse_ai_json_response(
                parsed_json,
                provider=provider,
                model=model,
                raw_text=raw_text,
                sanitization_summary=sanitization_summary,
                prompt_tokens=usage.get("input_tokens"),
                completion_tokens=usage.get("output_tokens"),
            )

        elif provider == "gemini":
            headers = {"Content-Type": "application/json"}
            url = f"{endpoint}?key={api_key}" if "?" not in endpoint else f"{endpoint}&key={api_key}"
            body = {
                "contents": [
                    {
                        "parts": [
                            {"text": f"{system_prompt}\n\n{user_prompt}"}
                        ]
                    }
                ],
                "generationConfig": {
                    "temperature": cfg.temperature,
                    "responseMimeType": "application/json",
                },
            }
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
            candidates = resp_data.get("candidates") or []
            parts = ((candidates[0] if candidates else {}).get("content") or {}).get("parts") or []
            raw_text = parts[0].get("text", "") if parts else ""
            meta = resp_data.get("usageMetadata") or {}
            parsed_json = json.loads(_clean_json_text(raw_text))
            return _parse_ai_json_response(
                parsed_json,
                provider=provider,
                model=model,
                raw_text=raw_text,
                sanitization_summary=sanitization_summary,
                prompt_tokens=meta.get("promptTokenCount"),
                completion_tokens=meta.get("candidatesTokenCount"),
            )

        elif provider == "ollama":
            headers = {"Content-Type": "application/json"}
            body = {
                "model": model,
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "stream": False,
                "format": "json",
            }
            req = urllib.request.Request(endpoint, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
            with urllib.request.urlopen(req, timeout=cfg.timeout_seconds) as resp:
                resp_data = json.loads(resp.read().decode("utf-8"))
            raw_text = resp_data.get("response", "")
            parsed_json = json.loads(_clean_json_text(raw_text))
            return _parse_ai_json_response(
                parsed_json,
                provider=provider,
                model=model,
                raw_text=raw_text,
                sanitization_summary=sanitization_summary,
                prompt_tokens=resp_data.get("prompt_eval_count"),
                completion_tokens=resp_data.get("eval_count"),
            )

        else:
            return AIReviewResult(
                ok=False,
                provider=provider,
                model=model,
                summary_verdict="Unsupported AI provider",
                overall_score=0,
                error=f"Unsupported AI provider: {provider}",
            )

    except urllib.error.HTTPError as exc:
        err_body = ""
        try:
            err_body = exc.read().decode("utf-8", "replace")[:300]
        except Exception:
            pass
        return AIReviewResult(
            ok=False,
            provider=provider,
            model=model,
            summary_verdict="AI provider HTTP request failed",
            overall_score=0,
            error=f"HTTP {exc.code} {exc.reason}: {err_body}",
        )
    except urllib.error.URLError as exc:
        return AIReviewResult(
            ok=False,
            provider=provider,
            model=model,
            summary_verdict="AI provider network connection failed",
            overall_score=0,
            error=f"Network error: {exc.reason}",
        )
    except json.JSONDecodeError as exc:
        return AIReviewResult(
            ok=False,
            provider=provider,
            model=model,
            summary_verdict="Failed to parse structured JSON from AI response",
            overall_score=0,
            error=f"JSON decode error: {exc}",
        )
    except Exception as exc:
        return AIReviewResult(
            ok=False,
            provider=provider,
            model=model,
            summary_verdict="Unexpected error during AI review",
            overall_score=0,
            error=f"{type(exc).__name__}: {exc}",
        )


def render_ai_review_markdown(result: AIReviewResult) -> str:
    """Format AI recommendations into structured Markdown."""
    lines = [
        "# ReconSpace AI Audit Advisor - Executive Review",
        "",
        f"**System Wellness Score:** `{result.overall_score}/100`  ",
        f"**AI Engine:** `{result.provider}` (`{result.model}`)  ",
        f"**Total Reclaimable Potential:** `{format_bytes(result.total_potential_reclaim_bytes)}`  ",
        f"**Privacy Sanitization:** `{'Applied (PII Redacted)' if result.sanitization_summary.get('redacted') else 'None'}`  ",
        "",
        "## Executive Summary",
        "",
        f"> {result.summary_verdict}",
        "",
    ]

    if result.critical_actions:
        lines.extend([
            "## [CRITICAL] Critical Actions (Immediate Attention)",
            "",
        ])
        for c in result.critical_actions:
            lines.extend([
                f"### [{c.id}] {c.title}",
                f"- **Safety Rating:** `{c.safety_rating}` | **Potential Reclaim:** `{format_bytes(c.impact_reclaim_bytes)}`",
                f"- **Summary:** {c.summary}",
                f"- **Technical Rationale:** {c.technical_detail}",
            ])
            if c.suggested_action:
                lines.extend([
                    "- **PowerShell Action Recipe:**",
                    "  ```powershell",
                    f"  {c.suggested_action}",
                    "  ```",
                ])
            if c.affected_paths:
                lines.append(f"- **Affected Targets:** `{', '.join(c.affected_paths)}`")
            lines.append("")

    if result.quick_wins:
        lines.extend([
            "## [QUICK WIN] Quick Wins (Safe High-Yield Optimizations)",
            "",
        ])
        for q in result.quick_wins:
            lines.extend([
                f"### [{q.id}] {q.title}",
                f"- **Safety Rating:** `{q.safety_rating}` | **Estimated Reclaim:** `{format_bytes(q.impact_reclaim_bytes)}`",
                f"- **Summary:** {q.summary}",
                f"- **Technical Rationale:** {q.technical_detail}",
            ])
            if q.suggested_action:
                lines.extend([
                    "- **PowerShell Action Recipe:**",
                    "  ```powershell",
                    f"  {q.suggested_action}",
                    "  ```",
                ])
            if q.affected_paths:
                lines.append(f"- **Affected Targets:** `{', '.join(q.affected_paths)}`")
            lines.append("")

    if result.safety_warnings:
        lines.extend([
            "## [SAFETY] Safety Warnings (What NOT to Touch)",
            "",
        ])
        for s in result.safety_warnings:
            lines.extend([
                f"### [{s.id}] {s.title}",
                f"- **Safety Rating:** `{s.safety_rating}`",
                f"- **Protection Scope:** {s.summary}",
                f"- **Technical Invariant:** {s.technical_detail}",
            ])
            if s.affected_paths:
                lines.append(f"- **Protected Paths:** `{', '.join(s.affected_paths)}`")
            lines.append("")

    if result.explainers:
        lines.extend([
            "## [EXPLAINER] Windows Architecture & Maintenance Explainers",
            "",
        ])
        for e in result.explainers:
            lines.extend([
                f"### [{e.id}] {e.title}",
                f"- **Concept:** {e.summary}",
                f"- **Architecture Deep Dive:** {e.technical_detail}",
            ])
            if e.suggested_action:
                lines.extend([
                    "- **Verification Command:**",
                    "  ```powershell",
                    f"  {e.suggested_action}",
                    "  ```",
                ])
            lines.append("")

    lines.extend([
        "---",
        "*Report generated by ReconSpace AI Audit Advisor. Zero-telemetry local audit architecture.*",
    ])
    return "\n".join(lines) + "\n"


def ai_review_to_json(result: AIReviewResult) -> dict[str, Any]:
    """Serialize AIReviewResult to JSON-compatible dictionary."""
    return result.to_dict()
