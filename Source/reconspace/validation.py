from __future__ import annotations

from typing import Any


def _validate_list(report: dict[str, Any], key: str, errors: list[str], warnings: list[str], *, required: bool = False) -> list[Any]:
    if key not in report:
        (errors if required else warnings).append(f"{key} is missing")
        return []
    value = report[key]
    if not isinstance(value, list):
        errors.append(f"{key} must be a list")
        return []
    return value


def validate_report(report: Any) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(report, dict):
        return {"ok": False, "errors": ["Top-level report must be a JSON object."], "warnings": []}

    stats = report.get("stats")
    if not isinstance(stats, dict):
        errors.append("stats must be an object")
    else:
        if not isinstance(stats.get("root"), str):
            warnings.append("stats.root is missing or is not a string")
        for key in ("files_seen", "directories_seen", "bytes_seen"):
            if key in stats and not isinstance(stats[key], int):
                errors.append(f"stats.{key} must be an integer")
        total = stats.get("filesystem_total_bytes")
        used = stats.get("filesystem_used_bytes")
        free = stats.get("filesystem_free_bytes")
        for key, value in (("filesystem_total_bytes", total), ("filesystem_used_bytes", used), ("filesystem_free_bytes", free)):
            if value is not None and (not isinstance(value, int) or value < 0):
                errors.append(f"stats.{key} must be a non-negative integer or null")
        if isinstance(total, int) and total > 0:
            tolerance = max(1024 ** 3, int(total * 0.02))
            if isinstance(used, int) and used > total + tolerance:
                warnings.append("stats.filesystem_used_bytes is materially greater than total capacity")
            if isinstance(free, int) and free > total + tolerance:
                warnings.append("stats.filesystem_free_bytes is materially greater than total capacity")
            if isinstance(used, int) and isinstance(free, int) and abs((used + free) - total) > tolerance:
                warnings.append("filesystem total/used/free counters are materially inconsistent")

    required_lists = ("findings", "top_files", "top_directories", "duplicates", "applications", "collectors")
    for key in required_lists:
        _validate_list(report, key, errors, warnings, required=True)
    optional_lists = (
        "startup", "services", "scheduled_tasks", "project_artifacts", "processes",
        "binary_trust", "path_security", "application_footprints",
    )
    for key in optional_lists:
        if key in report:
            _validate_list(report, key, errors, warnings)

    for i, row in enumerate(report.get("collectors") or []):
        if not isinstance(row, dict):
            errors.append(f"collectors[{i}] must be an object")
            continue
        if not isinstance(row.get("name"), str):
            errors.append(f"collectors[{i}].name must be a string")
        if not isinstance(row.get("ok"), bool):
            errors.append(f"collectors[{i}].ok must be a boolean")
        if "applicable" in row and not isinstance(row.get("applicable"), bool):
            errors.append(f"collectors[{i}].applicable must be a boolean")

    dispositions = {"probably_safe_cleanup", "manual_review", "intentional_tooling", "do_not_touch", "informational"}
    risks = {"low", "medium", "high", "critical"}
    confidences = {"low", "medium", "high"}
    for i, finding in enumerate(report.get("findings") or []):
        if not isinstance(finding, dict):
            errors.append(f"findings[{i}] must be an object")
            continue
        for key in ("title", "path", "category", "disposition", "risk", "confidence"):
            if key not in finding:
                errors.append(f"findings[{i}].{key} is missing")
        if finding.get("disposition") not in dispositions:
            errors.append(f"findings[{i}].disposition is invalid")
        if finding.get("risk") not in risks:
            errors.append(f"findings[{i}].risk is invalid")
        if finding.get("confidence") not in confidences:
            errors.append(f"findings[{i}].confidence is invalid")
        for key in ("size_bytes", "estimated_reclaimable_bytes"):
            val = finding.get(key, 0)
            if not isinstance(val, int) or val < 0:
                errors.append(f"findings[{i}].{key} must be a non-negative integer")

    for i, row in enumerate(report.get("processes") or []):
        if not isinstance(row, dict):
            errors.append(f"processes[{i}] must be an object")
        elif not isinstance(row.get("pid"), int):
            errors.append(f"processes[{i}].pid must be an integer")

    for i, row in enumerate(report.get("binary_trust") or []):
        if not isinstance(row, dict):
            errors.append(f"binary_trust[{i}] must be an object")
        elif not isinstance(row.get("path"), str):
            errors.append(f"binary_trust[{i}].path must be a string")

    for i, row in enumerate(report.get("path_security") or []):
        if not isinstance(row, dict):
            errors.append(f"path_security[{i}] must be an object")
        elif "broad_write_detected" in row and not isinstance(row.get("broad_write_detected"), bool):
            errors.append(f"path_security[{i}].broad_write_detected must be a boolean")

    schema = report.get("schema_version")
    if schema is None:
        warnings.append("schema_version missing; this may be a legacy report")
    elif not isinstance(schema, int) or schema < 1:
        errors.append("schema_version must be a positive integer")
    elif schema >= 4:
        for key in ("rule_pack_info", "audit_health"):
            if key not in report:
                warnings.append(f"schema {schema} report is missing {key}")
            elif not isinstance(report[key], dict):
                errors.append(f"{key} must be an object")

    if report.get("reclaim_summary"):
        rs = report["reclaim_summary"]
        if not isinstance(rs, dict):
            errors.append("reclaim_summary must be an object")
        else:
            for key in ("path_candidates_nonoverlap_bytes", "duplicate_potential_bytes_separate", "application_potential_bytes_separate", "platform_potential_bytes_separate"):
                if key in rs and (not isinstance(rs[key], int) or rs[key] < 0):
                    errors.append(f"reclaim_summary.{key} must be a non-negative integer")

    health = report.get("audit_health")
    if isinstance(health, dict) and "coverage_score" in health:
        score = health.get("coverage_score")
        if not isinstance(score, (int, float)) or not 0 <= score <= 100:
            errors.append("audit_health.coverage_score must be between 0 and 100")

    rule_info = report.get("rule_pack_info")
    if isinstance(rule_info, dict) and rule_info.get("custom_code_execution") not in {None, False}:
        errors.append("rule_pack_info.custom_code_execution must be false")

    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        "schema_version": schema,
        "reconspace_version": report.get("version"),
    }
