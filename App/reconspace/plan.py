from __future__ import annotations

import hashlib
import json
from typing import Any


def _bytes(n: int | None) -> str:
    if n is None:
        return "Unknown"
    v = float(n)
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    for unit in units:
        if abs(v) < 1024 or unit == units[-1]:
            return f"{v:.1f} {unit}" if unit != "B" else f"{int(v)} B"
        v /= 1024
    return f"{v:.1f} PB"


def compute_manifest_hash(items: list[dict[str, Any]]) -> str:
    """Compute a deterministic SHA-256 manifest hash across plan action items."""
    canonical_tokens: list[str] = []
    for it in sorted((x for x in (items or []) if isinstance(x, dict)), key=lambda x: str(x.get("id", ""))):
        canonical_tokens.append(
            f"{it.get('id')}:{it.get('path')}:{it.get('disposition')}:{it.get('estimated_reclaimable_bytes')}"
        )
    raw_payload = "|".join(canonical_tokens).encode("utf-8")
    return hashlib.sha256(raw_payload).hexdigest()


def verify_plan_manifest(plan: dict[str, Any]) -> tuple[bool, str]:
    """Verify that an approval plan manifest has not been modified or tampered with."""
    if not isinstance(plan, dict):
        return False, "Plan manifest must be a dictionary object"
    expected = plan.get("manifest_sha256")
    if not expected:
        sig = str(plan.get("manifest_signature") or "")
        if sig.startswith("sha256:"):
            expected = sig[7:]
    if not expected:
        return False, "Plan manifest is unsigned (missing manifest_sha256)"
    items = plan.get("items") or []
    computed = compute_manifest_hash(items)
    if computed != expected:
        return False, f"Manifest integrity failure: calculated {computed} does not match expected {expected}"
    return True, "Manifest signature verified"


def build_plan(report: dict[str, Any]) -> dict[str, Any]:
    findings = list(report.get("findings") or [])
    actionable = [
        f for f in findings
        if f.get("disposition") in {"probably_safe_cleanup", "manual_review"}
        and int(f.get("estimated_reclaimable_bytes") or 0) > 0
    ]
    actionable.sort(key=lambda f: (float(f.get("priority_score") or 0), int(f.get("estimated_reclaimable_bytes") or 0)), reverse=True)

    items = []
    for idx, f in enumerate(actionable, 1):
        items.append({
            "id": f"RS-{idx:04d}",
            "approval_status": "PENDING_REVIEW",
            "title": f.get("title", ""),
            "path": f.get("path", ""),
            "category": f.get("category", ""),
            "disposition": f.get("disposition", ""),
            "risk": f.get("risk", ""),
            "confidence": f.get("confidence", ""),
            "priority_score": f.get("priority_score", 0),
            "observed_size_bytes": int(f.get("size_bytes") or 0),
            "estimated_reclaimable_bytes": int(f.get("estimated_reclaimable_bytes") or 0),
            "why_it_exists": f.get("why_it_exists", ""),
            "recommended_management": f.get("recommendation", ""),
            "risk_if_removed": f.get("removal_risk", ""),
            "related_to": f.get("related_to") or [],
            "evidence": f.get("evidence") or {},
            "execution": "NONE - PLAN ONLY",
        })

    manifest_hash = compute_manifest_hash(items)

    return {
        "reconspace_version": report.get("version", "unknown"),
        "scan_profile": report.get("profile", "unknown"),
        "scan_root": (report.get("stats") or {}).get("root", ""),
        "scan_finished_at": (report.get("stats") or {}).get("finished_at", ""),
        "mode": "PLAN_ONLY_NO_EXECUTION",
        "manifest_sha256": manifest_hash,
        "manifest_signature": f"sha256:{manifest_hash}",
        "scope_note": (
            "File/folder candidates are limited to the selected scan root. Installed applications, processes, persistence, "
            "virtualization and Windows platform evidence can describe the wider host and are kept as separate estimates."
        ),
        "audit_coverage": {
            "score": (report.get("audit_health") or {}).get("coverage_score"),
            "grade": (report.get("audit_health") or {}).get("coverage_grade"),
            "depth_domains": (report.get("audit_health") or {}).get("depth_domains") or [],
            "issues": (report.get("audit_health") or {}).get("issues") or [],
        },
        "summary": {
            "items_pending_review": len(items),
            "probably_safe_estimated_bytes_raw": sum(i["estimated_reclaimable_bytes"] for i in items if i["disposition"] == "probably_safe_cleanup"),
            "manual_review_estimated_bytes_raw": sum(i["estimated_reclaimable_bytes"] for i in items if i["disposition"] == "manual_review"),
            "conservative_path_candidates_bytes": int((report.get("reclaim_summary") or {}).get("path_candidates_nonoverlap_bytes") or 0),
            "probably_safe_path_bytes": int((report.get("reclaim_summary") or {}).get("probably_safe_path_bytes") or 0),
            "manual_review_path_bytes": int((report.get("reclaim_summary") or {}).get("manual_review_path_bytes") or 0),
            "duplicate_potential_bytes_separate": int((report.get("reclaim_summary") or {}).get("duplicate_potential_bytes_separate") or 0),
            "application_potential_bytes_separate": int((report.get("reclaim_summary") or {}).get("application_potential_bytes_separate") or 0),
            "platform_potential_bytes_separate": int((report.get("reclaim_summary") or {}).get("platform_potential_bytes_separate") or 0),
        },
        "guardrails": [
            "No filesystem/application/system action is executed by this plan.",
            "Every item remains pending review until a human confirms ownership, current use, backups and the recommended supported management workflow.",
            "DO NOT TOUCH and INTENTIONAL TOOLING findings are intentionally excluded from the actionable total.",
            "Estimated reclaimable bytes are triage estimates, not guarantees.",
            "Conservative path totals suppress covered descendants. Duplicate, application and platform potentials are separate alternatives and MUST NOT be added to path totals without manual overlap review.",
        ],
        "items": items,
    }


def plan_json(report: dict[str, Any], pretty: bool = True) -> str:
    return json.dumps(build_plan(report), indent=2 if pretty else None, ensure_ascii=False)


def plan_markdown(report: dict[str, Any], max_items: int = 100) -> str:
    plan = build_plan(report)
    s = plan["summary"]
    lines = [
        "# ReconSpace Review / Approval Plan",
        "",
        "**Mode: PLAN ONLY — NO EXECUTION**",
        "",
        f"- Scan root: `{plan['scan_root']}`",
        f"- Scan profile: **{plan['scan_profile']}**",
        f"- Scan finished: {plan['scan_finished_at'] or 'Unknown'}",
        f"- Items pending review: **{s['items_pending_review']}**",
        f"- Audit evidence quality: **{plan['audit_coverage']['grade'] or 'unknown'} ({plan['audit_coverage']['score'] if plan['audit_coverage']['score'] is not None else 'n/a'}/100)**",
        f"- Scope: {plan['scope_note']}",
        f"- Conservative non-overlapping path candidates: **{_bytes(s['conservative_path_candidates_bytes'])}**",
        f"  - Probably-safe path candidates: **{_bytes(s['probably_safe_path_bytes'])}**",
        f"  - Manual-review path candidates: **{_bytes(s['manual_review_path_bytes'])}**",
        f"- Exact-duplicate potential (separate / non-additive): **{_bytes(s['duplicate_potential_bytes_separate'])}**",
        f"- Application potential (separate / non-additive): **{_bytes(s['application_potential_bytes_separate'])}**",
        f"- Platform potential such as Docker cache/images (separate / non-additive): **{_bytes(s['platform_potential_bytes_separate'])}**",
        "",
        "## Guardrails",
        "",
    ]
    lines.extend(f"- {x}" for x in plan["guardrails"])
    lines += ["", "## Audit depth", ""]
    for domain in plan["audit_coverage"]["depth_domains"]:
        status = str(domain.get("status") or "unknown").replace("_", " ").upper()
        limitations = ", ".join(str(x).replace("_", " ") for x in (domain.get("limitations") or [])[:6])
        lines.append(
            f"- **{domain.get('title', 'Evidence domain')}: {status}** — "
            f"{domain.get('checks_succeeded', 0)}/{domain.get('checks_requested', 0)} applicable checks succeeded"
            + (f"; limited/unavailable: {limitations}" if limitations else "")
        )
    lines += ["", "## Ranked pending items", ""]
    for item in plan["items"][:max_items]:
        lines += [
            f"### [ ] {item['id']} — {item['title']}",
            f"- Approval: **{item['approval_status']}**",
            f"- Path: `{item['path']}`",
            f"- Observed / estimated reclaimable: **{_bytes(item['observed_size_bytes'])} / {_bytes(item['estimated_reclaimable_bytes'])}**",
            f"- Disposition: **{item['disposition']}** | Risk: **{item['risk']}** | Confidence: **{item['confidence']}** | Priority: **{float(item['priority_score'] or 0):.1f}**",
            f"- Why it exists: {item['why_it_exists']}",
            f"- Recommended management: {item['recommended_management']}",
            f"- Risk if removed: {item['risk_if_removed']}",
            "- Execution: **NONE**",
            "",
        ]
    return "\n".join(lines)
