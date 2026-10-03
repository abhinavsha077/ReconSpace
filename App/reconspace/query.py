from __future__ import annotations

"""Small report query language for interactive and CLI analysis.

The language is intentionally data-only. It evaluates exported JSON fields and
never invokes commands or alters the source report.
"""

import csv
import io
import json
import re
import shlex
from dataclasses import dataclass
from typing import Any, Iterable


SECTION_ALIASES = {
    "findings": "findings",
    "files": "top_files",
    "top_files": "top_files",
    "directories": "top_directories",
    "dirs": "top_directories",
    "top_directories": "top_directories",
    "applications": "applications",
    "apps": "applications",
    "duplicates": "duplicates",
    "projects": "project_artifacts",
    "project_artifacts": "project_artifacts",
    "startup": "startup",
    "services": "services",
    "tasks": "scheduled_tasks",
    "scheduled_tasks": "scheduled_tasks",
    "processes": "processes",
    "trust": "binary_trust",
    "binary_trust": "binary_trust",
    "permissions": "path_security",
    "path_security": "path_security",
    "footprints": "application_footprints",
    "application_footprints": "application_footprints",
    "collectors": "collectors",
}

FIELD_ALIASES = {
    "size": "size_bytes",
    "reclaim": "estimated_reclaimable_bytes",
    "reclaimable": "estimated_reclaimable_bytes",
    "age": "age_days",
    "risk": "risk",
    "confidence": "confidence",
    "disposition": "disposition",
    "category": "category",
    "path": "path",
    "name": "name",
    "title": "title",
    "publisher": "publisher",
    "version": "version",
    "related": "related_to",
    "status": "signature_status",
    "owner": "owner",
    "pid": "pid",
    "working_set": "working_set_bytes",
    "data": "related_data_bytes",
    "installed": "installed_size_bytes",
}

DEFAULT_COLUMNS = {
    "findings": ["disposition", "risk", "size_bytes", "estimated_reclaimable_bytes", "title", "path"],
    "top_files": ["size_bytes", "allocated_bytes", "extension", "path"],
    "top_directories": ["size_bytes", "direct_size_bytes", "path"],
    "applications": ["estimated_size_bytes", "name", "version", "publisher", "install_location", "classification"],
    "duplicates": ["reclaimable_bytes", "size_bytes_each", "distinct_file_instances", "sha256", "paths"],
    "project_artifacts": ["size_bytes", "artifact_type", "age_days", "project_root", "path"],
    "startup": ["risk_hint", "name", "source", "target_path", "command"],
    "services": ["risk_hint", "state", "start_mode", "display_name", "target_path"],
    "scheduled_tasks": ["risk_hint", "state", "task_path", "task_name", "actions"],
    "processes": ["pid", "working_set_bytes", "name", "owner", "executable_path"],
    "binary_trust": ["signature_status", "signer_subject", "sha256", "source_kinds", "path"],
    "path_security": ["owner", "broad_write_detected", "deny_rule_count", "protected_acl", "path"],
    "application_footprints": ["installed_size_bytes", "related_data_bytes", "ownership_confidence", "name", "active_processes", "related_paths"],
    "collectors": ["ok", "applicable", "name", "error"],
}

MAX_QUERY_REGEX_LENGTH = 512

_BYTE_UNITS = {
    "b": 1,
    "kb": 1000,
    "mb": 1000**2,
    "gb": 1000**3,
    "tb": 1000**4,
    "kib": 1024,
    "mib": 1024**2,
    "gib": 1024**3,
    "tib": 1024**4,
}
_AGE_UNITS = {"d": 1.0, "day": 1.0, "days": 1.0, "w": 7.0, "week": 7.0, "weeks": 7.0, "mo": 30.4375, "month": 30.4375, "months": 30.4375, "y": 365.25, "year": 365.25, "years": 365.25}


@dataclass(slots=True)
class Condition:
    field: str
    operator: str
    raw_value: str


@dataclass(slots=True)
class QueryPlan:
    groups: list[list[Condition]]
    free_text_groups: list[list[str]]
    source: str


def _split_groups(expression: str) -> list[list[str]]:
    # POSIX shlex otherwise consumes Windows backslashes (for example
    # C:\Users becomes C:Users). Doubling them before tokenization preserves the
    # literal path while retaining useful quote handling for values with spaces.
    tokens = shlex.split((expression or "").replace("\\", "\\\\"), posix=True)
    groups: list[list[str]] = [[]]
    for token in tokens:
        if token.casefold() in {"or", "|", "||"}:
            if groups[-1]:
                groups.append([])
            continue
        groups[-1].append(token)
    return [g for g in groups if g] or [[]]


def parse_query(expression: str) -> QueryPlan:
    parsed_groups: list[list[Condition]] = []
    free_groups: list[list[str]] = []
    pattern = re.compile(r"^([A-Za-z_][A-Za-z0-9_.-]*)(>=|<=|!=|=|>|<|:|~)(.*)$")
    for group in _split_groups(expression):
        conditions: list[Condition] = []
        free: list[str] = []
        for token in group:
            match = pattern.match(token)
            if not match:
                free.append(token)
                continue
            field, operator, value = match.groups()
            if not value:
                raise ValueError(f"query condition has no value: {token}")
            conditions.append(Condition(FIELD_ALIASES.get(field.casefold(), field), operator, value))
        parsed_groups.append(conditions)
        free_groups.append(free)
    return QueryPlan(parsed_groups, free_groups, expression)


def _get_nested(row: dict[str, Any], field: str) -> Any:
    current: Any = row
    for part in field.split("."):
        if not isinstance(current, dict):
            return None
        if part in current:
            current = current[part]
            continue
        # Case-insensitive fallback makes hand-written queries less brittle.
        match = next((k for k in current if str(k).casefold() == part.casefold()), None)
        if match is None:
            return None
        current = current[match]
    return current


def _parse_number(text: str, field: str) -> float | None:
    value = text.strip().replace(",", "")
    match = re.fullmatch(r"([-+]?[0-9]*\.?[0-9]+)\s*([A-Za-z]+)?", value)
    if not match:
        return None
    number = float(match.group(1))
    unit = (match.group(2) or "").casefold()
    field_l = field.casefold()
    if unit in _BYTE_UNITS or any(x in field_l for x in ("bytes", "size", "reclaim", "working_set", "data", "installed")):
        if not unit:
            return number
        if unit not in _BYTE_UNITS:
            return None
        return number * _BYTE_UNITS[unit]
    if unit in _AGE_UNITS or "age" in field_l or field_l.endswith("days"):
        if not unit:
            return number
        if unit not in _AGE_UNITS:
            return None
        return number * _AGE_UNITS[unit]
    return number if not unit else None


def _flatten_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        return " ".join(f"{k} {_flatten_text(v)}" for k, v in value.items())
    if isinstance(value, list):
        return " ".join(_flatten_text(x) for x in value)
    return str(value)


def _compare(actual: Any, condition: Condition) -> bool:
    operator = condition.operator
    wanted = condition.raw_value
    if operator in {">", ">=", "<", "<="}:
        left_num = float(actual) if isinstance(actual, (int, float)) else _parse_number(str(actual or ""), condition.field)
        right_num = _parse_number(wanted, condition.field)
        if left_num is None or right_num is None:
            return False
        return {">": left_num > right_num, ">=": left_num >= right_num, "<": left_num < right_num, "<=": left_num <= right_num}[operator]

    if isinstance(actual, bool):
        actual_text = "true" if actual else "false"
    else:
        actual_text = _flatten_text(actual)
    left = actual_text.casefold()
    right = wanted.casefold()
    if operator == ":":
        return right in left
    if operator == "~":
        if len(wanted) > MAX_QUERY_REGEX_LENGTH:
            raise ValueError(f"query regex exceeds {MAX_QUERY_REGEX_LENGTH} characters")
        try:
            return bool(re.search(wanted, actual_text, re.IGNORECASE))
        except re.error as exc:
            raise ValueError(f"invalid query regex {wanted!r}: {exc}") from exc
    if operator == "=":
        left_num = _parse_number(actual_text, condition.field)
        right_num = _parse_number(wanted, condition.field)
        if left_num is not None and right_num is not None:
            return left_num == right_num
        return left == right
    if operator == "!=":
        left_num = _parse_number(actual_text, condition.field)
        right_num = _parse_number(wanted, condition.field)
        if left_num is not None and right_num is not None:
            return left_num != right_num
        return left != right
    return False


def row_matches(row: dict[str, Any], plan: QueryPlan) -> bool:
    text = _flatten_text(row).casefold()
    for conditions, free in zip(plan.groups, plan.free_text_groups):
        if all(_compare(_get_nested(row, cond.field), cond) for cond in conditions) and all(term.casefold() in text for term in free):
            return True
    return False


def query_report(report: dict[str, Any], section: str, expression: str = "", limit: int = 1000, sort: str = "") -> dict[str, Any]:
    canonical = SECTION_ALIASES.get(section.casefold())
    if not canonical:
        raise ValueError(f"unknown section {section!r}; choose from {', '.join(sorted(set(SECTION_ALIASES.values())))}")
    rows = report.get(canonical) or []
    if not isinstance(rows, list):
        raise ValueError(f"report section {canonical} is not a list")
    materialized = [x for x in rows if isinstance(x, dict)]
    plan = parse_query(expression)
    matched = [row for row in materialized if row_matches(row, plan)] if expression.strip() else materialized

    if sort:
        descending = sort.startswith("-")
        field = FIELD_ALIASES.get(sort.lstrip("+-").casefold(), sort.lstrip("+-"))
        def key(row: dict[str, Any]) -> tuple[int, Any]:
            value = _get_nested(row, field)
            if isinstance(value, bool):
                return 0, int(value)
            if isinstance(value, (int, float)):
                return 0, float(value)
            if isinstance(value, str):
                return 1, value.casefold()
            if value is None:
                return 3, ""
            return 2, _flatten_text(value).casefold()
        matched.sort(key=key, reverse=descending)
        # Keep missing values last for both ascending and descending sorts.
        matched.sort(key=lambda row: _get_nested(row, field) is None)
    output = matched[: max(0, int(limit))]
    return {
        "section": canonical,
        "query": expression,
        "matched": len(matched),
        "returned": len(output),
        "total": len(materialized),
        "rows": output,
    }


def _display_value(value: Any, max_len: int = 80) -> str:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    elif value is None:
        text = ""
    else:
        text = str(value)
    text = text.replace("\r", " ").replace("\n", " ")
    return text if len(text) <= max_len else text[: max_len - 1] + "…"


def query_to_table(result: dict[str, Any], columns: Iterable[str] | None = None) -> str:
    section = str(result.get("section") or "")
    rows = result.get("rows") or []
    cols = list(columns or DEFAULT_COLUMNS.get(section) or [])
    if not cols and rows:
        cols = list(rows[0])[:8]
    if not rows:
        return f"No matching rows in {section}."
    rendered = [[_display_value(_get_nested(row, col)) for col in cols] for row in rows]
    widths = [len(col) for col in cols]
    for row in rendered:
        for i, value in enumerate(row):
            widths[i] = min(80, max(widths[i], len(value)))
    header = " | ".join(col.ljust(widths[i]) for i, col in enumerate(cols))
    divider = "-+-".join("-" * width for width in widths)
    lines = [f"{result['matched']} matched / {result['total']} total; showing {result['returned']}", header, divider]
    for row in rendered:
        lines.append(" | ".join(value.ljust(widths[i]) for i, value in enumerate(row)))
    return "\n".join(lines)


def query_to_csv(result: dict[str, Any], columns: Iterable[str] | None = None) -> str:
    section = str(result.get("section") or "")
    rows = result.get("rows") or []
    cols = list(columns or DEFAULT_COLUMNS.get(section) or [])
    if not cols and rows:
        cols = list(rows[0])
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=cols)
    writer.writeheader()
    for row in rows:
        writer.writerow({col: _display_value(_get_nested(row, col), max_len=100000) for col in cols})
    return stream.getvalue()
