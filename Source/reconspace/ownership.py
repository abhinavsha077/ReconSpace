from __future__ import annotations

"""Conservative application/process/storage ownership inference.

The output is an evidence graph, not a claim that an application is unused or
that related data is removable. Strong path ancestry is preferred over fuzzy
name matching, and every inferred relation carries a confidence explanation.
"""

import os
import re
from typing import Any, Iterable

from .models import (
    ApplicationFootprintRecord,
    ApplicationRecord,
    Finding,
    ProcessRecord,
    ScheduledTaskRecord,
    ServiceRecord,
    StartupRecord,
)

_STOP_TOKENS = {
    "microsoft", "corporation", "inc", "ltd", "limited", "software", "windows",
    "application", "applications", "program", "programs", "company", "technology",
    "technologies", "system", "systems", "client", "service", "services", "update",
    "updater", "helper", "runtime", "framework", "package", "packages", "desktop",
}


def _norm(path: str) -> str:
    cleaned = str(path or "").strip().strip('"').strip("'").strip()
    if not cleaned:
        return ""
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    return os.path.normcase(os.path.normpath(os.path.abspath(os.path.expandvars(os.path.expanduser(cleaned)))))


def _is_descendant_or_same(norm_child: str, norm_parent: str) -> bool:
    if not norm_child or not norm_parent:
        return False
    if norm_child == norm_parent:
        return True
    prefix = norm_parent if norm_parent.endswith(("\\", "/")) else (norm_parent + "/" if "/" in norm_parent else norm_parent + "\\")
    return norm_child.startswith(prefix)


def _under(path: str, ancestor: str) -> bool:
    if not path or not ancestor:
        return False
    return _is_descendant_or_same(_norm(path), _norm(ancestor))


def _tokens(*values: str) -> set[str]:
    output: set[str] = set()
    for value in values:
        for token in re.findall(r"[a-z0-9]{4,}", str(value).casefold()):
            if token not in _STOP_TOKENS:
                output.add(token)
    return output


def _path_segments(path: str) -> set[str]:
    return {part.casefold() for part in re.split(r"[\\/]+", str(path)) if len(part) >= 4}


def _strong_token_match(tokens: set[str], path: str) -> bool:
    if not tokens or not path:
        return False
    segments = _path_segments(path)
    return bool(tokens & segments)


def _target_matches(install_location: str, tokens: set[str], target: str) -> tuple[bool, str]:
    if not target:
        return False, ""
    target_norm = _norm(target)
    if install_location and _is_descendant_or_same(target_norm, _norm(install_location)):
        return True, "install-location ancestry"
    if _strong_token_match(tokens, target_norm):
        return True, "exact path-segment token"
    return False, ""


def _nonoverlap_total(paths: list[tuple[str, int]]) -> tuple[int, list[str]]:
    selected: list[tuple[str, str, int]] = []
    norm_items = [(_norm(p), p, max(0, int(size))) for p, size in paths]
    norm_items.sort(key=lambda x: (len(x[0]), -x[2]))
    for norm_p, orig_p, size in norm_items:
        if any(_is_descendant_or_same(norm_p, existing_norm) for _, existing_norm, _ in selected):
            continue
        selected.append((orig_p, norm_p, size))
    return sum(size for _, _, size in selected), [orig_p for orig_p, _, _ in selected]


def build_application_footprints(
    applications: Iterable[ApplicationRecord],
    directory_sizes: dict[str, int],
    processes: Iterable[ProcessRecord] = (),
    startup: Iterable[StartupRecord] = (),
    services: Iterable[ServiceRecord] = (),
    scheduled_tasks: Iterable[ScheduledTaskRecord] = (),
    prefetch_rows: Iterable[dict[str, Any]] = (),
    max_related_paths: int = 30,
    cancel: Callable[[], bool] | None = None,
) -> list[ApplicationFootprintRecord]:
    from collections import defaultdict
    process_list = list(processes)
    startup_list = list(startup)
    service_list = list(services)
    task_list = list(scheduled_tasks)
    prefetch_list = [x for x in prefetch_rows if isinstance(x, dict)]
    footprints: list[ApplicationFootprintRecord] = []

    data_roots = [_norm(os.environ.get(name, "")) for name in ("LOCALAPPDATA", "APPDATA", "PROGRAMDATA")]
    data_roots = [root for root in data_roots if root]

    # Pre-filter and index candidate directories under data roots.
    # An audit of a large drive can discover >100k directories. Building this
    # inverted token index once reduces candidate matching across hundreds of
    # applications from minutes down to milliseconds.
    token_to_dir_candidates: dict[str, list[tuple[str, str, int]]] = defaultdict(list)
    for path, raw_size in directory_sizes.items():
        size = int(raw_size)
        if size <= 0:
            continue
        normalized = _norm(path)
        if not normalized:
            continue
        if any(_is_descendant_or_same(normalized, root) for root in data_roots):
            cand = (path, normalized, size)
            for seg in _path_segments(normalized):
                token_to_dir_candidates[seg].append(cand)

    for app in applications:
        if cancel and cancel():
            break
        install = _norm(app.install_location) if app.install_location else ""
        tokens = _tokens(app.name, app.publisher, os.path.basename(app.install_location or ""))
        active: list[str] = []
        startup_names: list[str] = []
        service_names: list[str] = []
        task_names: list[str] = []
        execution: list[str] = []
        relation_methods: set[str] = set()

        for proc in process_list:
            matched, method = _target_matches(install, tokens, proc.executable_path)
            if matched:
                active.append(f"{proc.name} (PID {proc.pid})")
                relation_methods.add(method)

        for item in startup_list:
            target = item.target_path or item.command
            matched, method = _target_matches(install, tokens, target)
            if matched:
                startup_names.append(item.name)
                relation_methods.add(method)

        for item in service_list:
            target = item.target_path or item.path_name
            matched, method = _target_matches(install, tokens, target)
            if matched:
                service_names.append(item.display_name or item.name)
                relation_methods.add(method)

        for item in task_list:
            targets = item.actions or []
            if any(_target_matches(install, tokens, action)[0] for action in targets):
                task_names.append((item.task_path or "") + item.task_name)
                relation_methods.add("scheduled-task action")

        exe_tokens = {os.path.splitext(os.path.basename(proc.executable_path))[0].casefold() for proc in process_list if proc.executable_path and _target_matches(install, tokens, proc.executable_path)[0]}
        for row in prefetch_list:
            image = str(row.get("image_name") or row.get("name") or "")
            stem = os.path.splitext(image)[0].casefold()
            if (exe_tokens and stem in exe_tokens) or (tokens and stem in tokens):
                execution.append(f"Prefetch metadata: {image} ({row.get('modified_time') or 'time unavailable'})")

        related_candidates: list[tuple[str, int]] = []
        seen_cands: set[str] = set()
        for tok in tokens:
            for orig_path, norm_path, size in token_to_dir_candidates.get(tok, ()):
                if norm_path in seen_cands:
                    continue
                seen_cands.add(norm_path)
                if install and _is_descendant_or_same(norm_path, install):
                    continue
                related_candidates.append((orig_path, size))

        related_candidates.sort(key=lambda x: x[1], reverse=True)
        related_total, related_paths = _nonoverlap_total(related_candidates[: max_related_paths * 3])
        related_paths = related_paths[:max_related_paths]
        if related_paths:
            relation_methods.add("application-data path token")

        strong_evidence = bool(install and (active or startup_names or service_names or task_names))
        medium_evidence = bool(relation_methods or execution or related_paths)
        confidence = "high" if strong_evidence else "medium" if medium_evidence else "low"
        if active:
            note = "Active process evidence was observed during this scan. This indicates current execution, not long-term usage frequency."
        elif execution:
            note = "Historical execution metadata was observed. Prefetch presence is not a definitive usage-frequency or recency measure."
        elif startup_names or service_names or task_names:
            note = "Persistence/integration evidence was observed, but this does not prove the software is actively used."
        elif related_paths:
            note = "Related data paths were inferred from exact product/vendor path segments; ownership should still be verified manually."
        else:
            note = "No process, persistence, prefetch or related-data evidence was observed in the available collectors. Absence of evidence does not prove the application is unused."

        footprints.append(ApplicationFootprintRecord(
            name=app.name,
            version=app.version,
            publisher=app.publisher,
            install_location=app.install_location,
            installed_size_bytes=app.estimated_size_bytes,
            related_data_bytes=related_total,
            related_paths=related_paths,
            active_processes=sorted(set(active)),
            startup_items=sorted(set(startup_names)),
            services=sorted(set(service_names)),
            scheduled_tasks=sorted(set(task_names)),
            execution_evidence=sorted(set(execution)),
            ownership_confidence=confidence,
            review_note=note + (f" Relation methods: {', '.join(sorted(relation_methods))}." if relation_methods else ""),
        ))

    footprints.sort(key=lambda row: ((row.installed_size_bytes or 0) + row.related_data_bytes), reverse=True)
    return footprints


def protect_active_process_paths(findings: list[Finding], processes: Iterable[ProcessRecord]) -> dict[str, Any]:
    """Downgrade candidates that contain a currently running executable.

    It is not sufficient to prove that a general cache is in use, but it is a
    strong reason not to count an application/program directory as reclaimable.
    """
    process_list = [(p, _norm(p.executable_path)) for p in processes if p.executable_path]
    affected = 0
    before_bytes = 0
    for finding in findings:
        finding_norm = _norm(finding.path)
        matches = [p for p, p_norm in process_list if _is_descendant_or_same(p_norm, finding_norm)]
        if not matches:
            continue
        affected += 1
        before_bytes += max(0, int(finding.estimated_reclaimable_bytes))
        finding.evidence = dict(finding.evidence or {})
        finding.evidence["active_processes_within_path"] = [
            {"pid": p.pid, "name": p.name, "executable_path": p.executable_path} for p in matches[:20]
        ]
        finding.evidence["reclaimable_before_active_process_protection"] = int(finding.estimated_reclaimable_bytes)
        finding.estimated_reclaimable_bytes = 0
        if finding.disposition == "probably_safe_cleanup":
            finding.disposition = "manual_review"
        if finding.risk == "low":
            finding.risk = "medium"
        finding.recommendation = finding.recommendation.rstrip() + " A currently running executable is located within this path; treat it as active application scope and verify the owning process before any later action."
    return {
        "affected_findings": affected,
        "protected_reclaimable_bytes": before_bytes,
        "policy": "Candidates containing a currently running executable are not counted as reclaimable.",
    }
