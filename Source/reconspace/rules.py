from __future__ import annotations

"""Declarative, read-only finding rules.

Rule packs can add recognition intelligence, but they cannot execute code or
perform cleanup. Custom packs are JSON documents validated against a narrow
schema. They only inspect metadata already gathered by the filesystem scanner.
"""

import json
import ntpath
import os
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import Finding
from .scanner import ScanInventory
from .storage_basis import directory_reclaim_evidence, file_reclaim_basis

MiB = 1024 * 1024
GiB = 1024 * MiB
MAX_RULE_PACK_BYTES = 2 * MiB
MAX_RULES_PER_PACK = 500
MAX_REGEX_LENGTH = 512
MAX_MATCHES_PER_RULE = 200
_FORBIDDEN_RULE_KEYS = {"command", "script", "shell", "executable", "action", "execute", "cleanup_action", "delete_action", "uninstall_action"}

_ALLOWED_SCOPES = {"directory", "file"}
_ALLOWED_DISPOSITIONS = {
    "probably_safe_cleanup", "manual_review", "intentional_tooling",
    "do_not_touch", "informational",
}
_ALLOWED_RISKS = {"low", "medium", "high", "critical"}
_ALLOWED_CONFIDENCES = {"low", "medium", "high"}


BUILTIN_RULE_PACK: dict[str, Any] = {
    "schema_version": 1,
    "name": "ReconSpace intelligence rules",
    "version": "2026.08",
    "description": "Conservative metadata-only rules for modern developer, AI, browser, package and build storage.",
    "rules": [
        {
            "id": "web-build-cache",
            "title": "Rebuildable web-development cache",
            "scope": "directory",
            "match": {"segments_any": [".next", ".nuxt", ".turbo", ".parcel-cache", ".vite", ".cache"]},
            "require_ancestor_marker_any": ["package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json"],
            "min_size_bytes": 256 * MiB,
            "category": "Developer build/cache data",
            "disposition": "manual_review",
            "risk": "low",
            "confidence": "high",
            "why_it_exists": "Web build tools retain transformed assets, dependency graphs and incremental-build state to make subsequent builds faster.",
            "recommendation": "Confirm the owning project is reproducible and inactive. Prefer the framework or package-manager documented cache command when later approved.",
            "removal_risk": "The next build can be slow and local-only generated state can be lost if the directory also contains custom output.",
            "related_to": ["development", "Node.js", "build cache"],
            "reclaim_fraction": 1.0,
        },
        {
            "id": "python-tool-cache",
            "title": "Python analysis/test cache",
            "scope": "directory",
            "match": {"segments_any": [".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox", ".nox", "__pycache__"]},
            "require_ancestor_marker_any": ["pyproject.toml", "requirements.txt", "poetry.lock", "pipfile"],
            "min_size_bytes": 64 * MiB,
            "category": "Developer build/cache data",
            "disposition": "manual_review",
            "risk": "low",
            "confidence": "high",
            "why_it_exists": "Python tools cache bytecode, test state, type-analysis data or isolated test environments.",
            "recommendation": "Review the project and tool configuration. Rebuildable caches are usually regenerated; isolated environments can require dependency reinstallation.",
            "removal_risk": "The next run can be slower, and .tox/.nox environments may contain expensive or locally patched dependencies.",
            "related_to": ["development", "Python", "testing"],
            "reclaim_fraction": 1.0,
        },
        {
            "id": "ml-model-cache",
            "title": "Machine-learning model/cache storage",
            "scope": "directory",
            "match": {"path_contains_any": ["huggingface\\hub", "huggingface/hub", "torch\\hub", "torch/hub", "ollama\\models", "ollama/models", ".cache\\huggingface", ".cache/huggingface"]},
            "min_size_bytes": 512 * MiB,
            "category": "AI/ML model and package data",
            "disposition": "intentional_tooling",
            "risk": "medium",
            "confidence": "high",
            "why_it_exists": "AI/ML tools retain model weights, snapshots and downloaded assets locally. These files can be very large and may be expensive to download again.",
            "recommendation": "Review model names, project references, offline requirements and download cost. Manage models with the owning tool rather than removing opaque files directly.",
            "removal_risk": "Projects can stop working offline, model revisions can become unavailable, and large downloads may be required again.",
            "related_to": ["development", "AI/ML", "models"],
            "reclaim_fraction": 0.0,
        },
        {
            "id": "browser-automation-cache",
            "title": "Browser automation binaries/cache",
            "scope": "directory",
            "match": {"path_contains_any": ["ms-playwright", "playwright\\browsers", "playwright/browsers", "cypress\\cache", "cypress/cache", "puppeteer"]},
            "min_size_bytes": 256 * MiB,
            "category": "Developer tool downloads",
            "disposition": "manual_review",
            "risk": "low",
            "confidence": "medium",
            "why_it_exists": "Browser automation frameworks download versioned Chromium, Firefox or WebKit builds for tests and scraping.",
            "recommendation": "Check active test projects and pinned browser versions. Prefer the framework's supported install/cache management workflow when later approved.",
            "removal_risk": "Automated tests can fail until matching browser binaries are downloaded again.",
            "related_to": ["development", "testing", "browser automation"],
            "reclaim_fraction": 1.0,
        },
        {
            "id": "terraform-provider-cache",
            "title": "Terraform provider/plugin storage",
            "scope": "directory",
            "match": {"segments_any": [".terraform"]},
            "require_ancestor_marker_any": [".terraform.lock.hcl", "terraform.tf", "main.tf"],
            "min_size_bytes": 256 * MiB,
            "category": "Infrastructure tooling",
            "disposition": "intentional_tooling",
            "risk": "medium",
            "confidence": "high",
            "why_it_exists": "Terraform downloads provider plugins and stores local working state under project directories.",
            "recommendation": "Distinguish downloaded providers from state files and local workspaces. Never treat the entire directory as disposable without checking the project and backend configuration.",
            "removal_risk": "Local state or workspace metadata can be lost, potentially affecting infrastructure management.",
            "related_to": ["development", "infrastructure", "Terraform"],
            "reclaim_fraction": 0.0,
        },
        {
            "id": "android-build-cache",
            "title": "Android/Gradle build output",
            "scope": "directory",
            "match": {"segments_any": [".gradle", "build", ".cxx"]},
            "require_ancestor_marker_any": ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts"],
            "min_size_bytes": 512 * MiB,
            "category": "Developer build/cache data",
            "disposition": "manual_review",
            "risk": "low",
            "confidence": "medium",
            "why_it_exists": "Gradle and Android tooling retain dependency, compilation, native-build and incremental state.",
            "recommendation": "Confirm the owning project and distinguish global dependency caches from project build output. Use Gradle/Android Studio supported workflows when later approved.",
            "removal_risk": "Builds can become slow and dependencies may need to be downloaded again; custom artifacts can be lost if mixed into build folders.",
            "related_to": ["development", "Android", "Gradle"],
            "reclaim_fraction": 1.0,
        },
        {
            "id": "partial-download",
            "title": "Large partial or interrupted download",
            "scope": "file",
            "match": {"extensions": [".crdownload", ".part", ".partial", ".download", ".tmp"]},
            "min_size_bytes": 256 * MiB,
            "min_age_days": 14,
            "category": "Partial downloads / temporary files",
            "disposition": "manual_review",
            "risk": "low",
            "confidence": "medium",
            "why_it_exists": "Browsers, launchers and download clients use temporary extensions while data is incomplete or being verified.",
            "recommendation": "Verify the associated download is no longer active and that the file is not a resumable transfer you still need.",
            "removal_risk": "Removing it can discard resumable progress or interrupt an active updater/download.",
            "related_to": ["downloads", "temporary data"],
            "reclaim_fraction": 1.0,
        },
        {
            "id": "large-core-dump",
            "title": "Large diagnostic/core dump",
            "scope": "file",
            "match": {"extensions": [".dmp", ".mdmp", ".core", ".etl"]},
            "min_size_bytes": 256 * MiB,
            "min_age_days": 30,
            "category": "Diagnostics and crash data",
            "disposition": "manual_review",
            "risk": "medium",
            "confidence": "high",
            "why_it_exists": "Crash and trace captures preserve process memory or event data for debugging and incident analysis.",
            "recommendation": "Confirm the investigation, debugging or support case is complete and that no evidentiary retention requirement applies.",
            "removal_risk": "Unique forensic/debugging evidence can be permanently lost and the file can contain sensitive memory contents.",
            "related_to": ["diagnostics", "cybersecurity", "forensics"],
            "reclaim_fraction": 0.0,
        },
    ],
}


@dataclass(slots=True)
class LoadedRulePack:
    name: str
    version: str
    description: str
    source: str
    rules: list[dict[str, Any]]
    warnings: list[str]


def _windowsish(path: str) -> bool:
    text = str(path or "")
    return bool(ntpath.splitdrive(text)[0] or text.startswith("\\") or "\\" in text)


def _norm(path: str) -> str:
    cleaned = str(path or "").strip().strip('"').strip("'").strip()
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    expanded = os.path.expandvars(os.path.expanduser(cleaned))
    if _windowsish(expanded):
        return ntpath.normcase(ntpath.normpath(expanded))
    return os.path.normcase(os.path.normpath(os.path.abspath(expanded)))


def _basename(path: str) -> str:
    return ntpath.basename(path) if _windowsish(path) else os.path.basename(path)


def _path_text(path: str) -> str:
    return _norm(path).replace("/", "\\").casefold()


def _segments(path: str) -> set[str]:
    return {x.casefold() for x in re.split(r"[\\/]+", str(path)) if x}


def _under(path: str, ancestor: str) -> bool:
    try:
        path_n, ancestor_n = _norm(path), _norm(ancestor)
        pathmod = ntpath if _windowsish(path_n) or _windowsish(ancestor_n) else os.path
        return pathmod.commonpath([path_n, ancestor_n]) == ancestor_n
    except (ValueError, OSError):
        return False


def _age_days(timestamp: float | None) -> float | None:
    if not timestamp:
        return None
    return max(0.0, (time.time() - float(timestamp)) / 86400.0)


def _validate_string_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ValueError(f"{field_name} must be a list of strings")
    return [x for x in (s.strip() for s in value) if x]


def validate_rule_pack(data: Any, source: str = "<memory>") -> LoadedRulePack:
    if not isinstance(data, dict):
        raise ValueError("rule pack must be a JSON object")
    if int(data.get("schema_version", 0)) != 1:
        raise ValueError("rule pack schema_version must be 1")
    name = str(data.get("name") or "Unnamed rule pack").strip()
    version = str(data.get("version") or "").strip()
    description = str(data.get("description") or "").strip()
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise ValueError("rule pack rules must be a list")
    if len(raw_rules) > MAX_RULES_PER_PACK:
        raise ValueError(f"rule pack exceeds {MAX_RULES_PER_PACK} rules")

    rules: list[dict[str, Any]] = []
    warnings: list[str] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_rules):
        if not isinstance(raw, dict):
            raise ValueError(f"rules[{index}] must be an object")
        rule = dict(raw)
        forbidden = {str(key).casefold() for key in rule} & _FORBIDDEN_RULE_KEYS
        if forbidden:
            raise ValueError(f"rules[{index}] contains forbidden execution/action fields: {', '.join(sorted(forbidden))}")
        rule_id = str(rule.get("id") or "").strip()
        if not rule_id or not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", rule_id):
            raise ValueError(f"rules[{index}].id is missing or invalid")
        if rule_id.casefold() in seen_ids:
            raise ValueError(f"duplicate rule id: {rule_id}")
        seen_ids.add(rule_id.casefold())

        scope = str(rule.get("scope") or "").strip().casefold()
        if scope not in _ALLOWED_SCOPES:
            raise ValueError(f"{rule_id}: scope must be directory or file")
        disposition = str(rule.get("disposition") or "manual_review")
        risk = str(rule.get("risk") or "medium")
        confidence = str(rule.get("confidence") or "medium")
        if disposition not in _ALLOWED_DISPOSITIONS:
            raise ValueError(f"{rule_id}: invalid disposition")
        if risk not in _ALLOWED_RISKS:
            raise ValueError(f"{rule_id}: invalid risk")
        if confidence not in _ALLOWED_CONFIDENCES:
            raise ValueError(f"{rule_id}: invalid confidence")
        raw_match = rule.get("match")
        if not isinstance(raw_match, dict) or not raw_match:
            raise ValueError(f"{rule_id}: match must be a non-empty object")
        # Never mutate the caller's JSON object during validation.
        match = dict(raw_match)
        supported_match = {"segments_any", "path_contains_any", "path_suffix_any", "extensions", "name_regex", "path_regex"}
        unknown = set(match) - supported_match
        if unknown:
            raise ValueError(f"{rule_id}: unsupported match fields: {', '.join(sorted(unknown))}")
        for field_name in ("segments_any", "path_contains_any", "path_suffix_any", "extensions"):
            if field_name in match:
                match[field_name] = _validate_string_list(match[field_name], f"{rule_id}.match.{field_name}")
        for field_name in ("name_regex", "path_regex"):
            if field_name in match:
                value = str(match[field_name])
                if len(value) > MAX_REGEX_LENGTH:
                    raise ValueError(f"{rule_id}.{field_name} exceeds {MAX_REGEX_LENGTH} characters")
                try:
                    re.compile(value, re.IGNORECASE)
                except re.error as exc:
                    raise ValueError(f"{rule_id}.{field_name} invalid regex: {exc}") from exc
                match[field_name] = value

        min_size = int(rule.get("min_size_bytes", 0) or 0)
        min_age = rule.get("min_age_days")
        if min_size < 0:
            raise ValueError(f"{rule_id}: min_size_bytes must be non-negative")
        if min_age is not None and float(min_age) < 0:
            raise ValueError(f"{rule_id}: min_age_days must be non-negative")
        fraction = float(rule.get("reclaim_fraction", 0.0) or 0.0)
        if fraction < 0.0 or fraction > 1.0:
            raise ValueError(f"{rule_id}: reclaim_fraction must be between 0 and 1")

        match_mode = str(rule.get("match_mode") or "any").casefold()
        if match_mode not in {"any", "all"}:
            raise ValueError(f"{rule_id}: match_mode must be any or all")

        normalized = {
            **rule,
            "id": rule_id,
            "scope": scope,
            "match": match,
            "match_mode": match_mode,
            "disposition": disposition,
            "risk": risk,
            "confidence": confidence,
            "min_size_bytes": min_size,
            "min_age_days": float(min_age) if min_age is not None else None,
            "reclaim_fraction": fraction,
            "related_to": _validate_string_list(rule.get("related_to"), f"{rule_id}.related_to"),
            "exclude_contains_any": _validate_string_list(rule.get("exclude_contains_any"), f"{rule_id}.exclude_contains_any"),
            "require_ancestor_marker_any": _validate_string_list(rule.get("require_ancestor_marker_any"), f"{rule_id}.require_ancestor_marker_any"),
            "max_matches": min(MAX_MATCHES_PER_RULE, max(1, int(rule.get("max_matches", MAX_MATCHES_PER_RULE) or MAX_MATCHES_PER_RULE))),
        }
        for required in ("title", "category", "why_it_exists", "recommendation", "removal_risk"):
            if not str(normalized.get(required) or "").strip():
                raise ValueError(f"{rule_id}: {required} is required")
            normalized[required] = str(normalized[required]).strip()
        if normalized["disposition"] in {"intentional_tooling", "do_not_touch", "informational"} and fraction > 0:
            warnings.append(f"{rule_id}: reclaim_fraction ignored for {normalized['disposition']}")
            normalized["reclaim_fraction"] = 0.0
        rules.append(normalized)

    return LoadedRulePack(name=name, version=version, description=description, source=source, rules=rules, warnings=warnings)


def load_rule_packs(paths: Iterable[str] = (), include_builtin: bool = True) -> list[LoadedRulePack]:
    packs: list[LoadedRulePack] = []
    if include_builtin:
        packs.append(validate_rule_pack(BUILTIN_RULE_PACK, source="builtin"))
    for raw_path in paths:
        path = Path(raw_path).expanduser().resolve()
        size = path.stat().st_size
        if size > MAX_RULE_PACK_BYTES:
            raise ValueError(f"rule pack is larger than {MAX_RULE_PACK_BYTES} bytes: {path}")
        data = json.loads(path.read_text(encoding="utf-8"))
        packs.append(validate_rule_pack(data, source=str(path)))
    return packs


def _ancestor_markers(path: str, marker_lookup: dict[str, set[str]]) -> set[str]:
    """Return the nearest project-marker set by walking path parents.

    The previous implementation compared every candidate with every project
    root. Parent walking is bounded by path depth and is materially faster on
    workstations with many repositories.
    """
    current = _norm(path)
    pathmod = ntpath if _windowsish(current) else os.path
    while current:
        values = marker_lookup.get(current)
        if values is not None:
            return values
        parent = pathmod.dirname(current)
        if not parent or parent == current:
            break
        current = parent
    return set()


def _matches(
    rule: dict[str, Any],
    path: str,
    extension: str,
    marker_lookup: dict[str, set[str]],
    marker_cache: dict[str, set[str]],
) -> bool:
    match = rule["match"]
    text = _path_text(path)
    name = _basename(path)
    segments = _segments(path)

    checks: list[bool] = []
    if match.get("segments_any"):
        checks.append(bool(segments & {x.casefold() for x in match["segments_any"]}))
    if match.get("path_contains_any"):
        checks.append(any(x.replace("/", "\\").casefold() in text for x in match["path_contains_any"]))
    if match.get("path_suffix_any"):
        checks.append(any(text.endswith(x.replace("/", "\\").casefold()) for x in match["path_suffix_any"]))
    if match.get("extensions"):
        checks.append(extension.casefold() in {x.casefold() if x.startswith(".") else "." + x.casefold() for x in match["extensions"]})
    if match.get("name_regex"):
        checks.append(bool(re.search(match["name_regex"], name, re.IGNORECASE)))
    if match.get("path_regex"):
        checks.append(bool(re.search(match["path_regex"], path, re.IGNORECASE)))
    if not checks:
        return False
    match_mode = rule.get("match_mode", "any")
    if (all(checks) if match_mode == "all" else any(checks)) is False:
        return False
    if any(x.replace("/", "\\").casefold() in text for x in rule.get("exclude_contains_any", [])):
        return False
    required = {x.casefold() for x in rule.get("require_ancestor_marker_any", [])}
    if required:
        key = _norm(path)
        observed = marker_cache.get(key)
        if observed is None:
            observed = _ancestor_markers(path, marker_lookup)
            marker_cache[key] = observed
        if not (observed & required):
            return False
    return True


def evaluate_rule_packs(inventory: ScanInventory, packs: list[LoadedRulePack]) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    pack_summaries: list[dict[str, Any]] = []
    now = time.time()
    total_rules = 0
    total_matches = 0

    # Pure segment/extension rules use narrow inverted indexes. The complete
    # directory candidate set is intentionally *not* materialized: a C: scan can
    # contain millions of directories, and duplicating the scanner's directory
    # map into tuples would trade CPU for a large avoidable memory spike.
    file_candidates: list[tuple[str, int, float | None, str, Any | None]] = [
        (record.path, int(record.size_bytes), _age_days(record.modified_ts), record.extension, record)
        for record in inventory.interesting_files
    ]
    needed_directory_segments: set[str] = set()
    needed_file_extensions: set[str] = set()
    for pack in packs:
        for rule in pack.rules:
            fields = {key for key, value in rule["match"].items() if value}
            if rule["scope"] == "directory" and fields == {"segments_any"}:
                needed_directory_segments.update(x.casefold() for x in rule["match"]["segments_any"])
            if rule["scope"] == "file" and fields == {"extensions"}:
                needed_file_extensions.update(
                    x.casefold() if x.startswith(".") else "." + x.casefold()
                    for x in rule["match"]["extensions"]
                )

    directory_segment_index: dict[str, list[tuple[str, int, float | None, str, Any | None]]] = {
        key: [] for key in needed_directory_segments
    }
    for path, raw_size in inventory.directory_sizes.items():
        matched_segments = _segments(path) & needed_directory_segments
        if not matched_segments:
            continue
        candidate = (path, int(raw_size), _age_days(inventory.directory_mtimes.get(path)), "", None)
        for segment in matched_segments:
            directory_segment_index[segment].append(candidate)
    file_extension_index: dict[str, list[tuple[str, int, float | None, str, Any | None]]] = {}
    for candidate in file_candidates:
        extension = candidate[3].casefold()
        if extension in needed_file_extensions:
            file_extension_index.setdefault(extension, []).append(candidate)

    marker_lookup = {
        _norm(path): {str(value).casefold() for value in values}
        for path, values in inventory.project_markers.items()
    }
    marker_cache: dict[str, set[str]] = {}

    for pack in packs:
        pack_matches = 0
        for rule in pack.rules:
            total_rules += 1
            match_fields = {key for key, value in rule["match"].items() if value}
            if rule["scope"] == "directory":
                candidates: Iterable[tuple[str, int, float | None, str, Any | None]] = (
                    (path, int(size), _age_days(inventory.directory_mtimes.get(path)), "", None)
                    for path, size in inventory.directory_sizes.items()
                )
                if match_fields == {"segments_any"}:
                    indexed_candidates: list[tuple[str, int, float | None, str, Any | None]] = []
                    seen_candidate_paths: set[str] = set()
                    for segment in rule["match"]["segments_any"]:
                        for candidate in directory_segment_index.get(segment.casefold(), []):
                            if candidate[0] not in seen_candidate_paths:
                                seen_candidate_paths.add(candidate[0])
                                indexed_candidates.append(candidate)
                    candidates = indexed_candidates
            else:
                candidates = file_candidates
                if match_fields == {"extensions"}:
                    candidates = []
                    seen_candidate_paths = set()
                    for extension in rule["match"]["extensions"]:
                        ext = extension.casefold() if extension.startswith(".") else "." + extension.casefold()
                        for candidate in file_extension_index.get(ext, []):
                            if candidate[0] not in seen_candidate_paths:
                                seen_candidate_paths.add(candidate[0])
                                candidates.append(candidate)

            matched: list[tuple[str, int, float | None, Any | None]] = []
            for path, size, age, extension, record in candidates:
                if size < rule["min_size_bytes"]:
                    continue
                if rule["min_age_days"] is not None and (age is None or age < rule["min_age_days"]):
                    continue
                if not _matches(rule, path, extension, marker_lookup, marker_cache):
                    continue
                matched.append((path, size, age, record))
            matched.sort(key=lambda x: x[1], reverse=True)

            selected: list[tuple[str, int, float | None, Any | None]] = []
            for item in matched:
                path = item[0]
                # One rule should not flood the report with a parent and all of its
                # descendants. The parent is the conservative storage scope.
                if any(_under(path, existing[0]) for existing in selected):
                    continue
                selected.append(item)
                if len(selected) >= rule["max_matches"]:
                    break

            for path, size, age, record in selected:
                if record is not None:
                    reclaim, storage_evidence = file_reclaim_basis(record, rule["reclaim_fraction"])
                else:
                    reclaim = int(size * rule["reclaim_fraction"])
                    storage_evidence = directory_reclaim_evidence()
                finding = Finding(
                    title=rule["title"],
                    path=path,
                    size_bytes=size,
                    category=rule["category"],
                    disposition=rule["disposition"],
                    risk=rule["risk"],
                    confidence=rule["confidence"],
                    why_it_exists=rule["why_it_exists"],
                    recommendation=rule["recommendation"],
                    removal_risk=rule["removal_risk"],
                    related_to=list(rule["related_to"]),
                    estimated_reclaimable_bytes=reclaim,
                    age_days=age,
                    evidence={
                        # Reclaim accounting distinguishes files from folders so
                        # it can suppress descendants covered by a full-reclaim
                        # parent. A generic "path" label caused rule findings to
                        # be omitted from the conservative path total entirely.
                        "scope_type": "file" if rule["scope"] == "file" else "folder",
                        "rule_pack": pack.name,
                        "rule_pack_version": pack.version,
                        "rule_id": rule["id"],
                        "rule_source": pack.source,
                        "metadata_only_rule": True,
                        **storage_evidence,
                    },
                )
                findings.append(finding)
                pack_matches += 1
                total_matches += 1
        pack_summaries.append({
            "name": pack.name,
            "version": pack.version,
            "source": pack.source,
            "rules": len(pack.rules),
            "matches": pack_matches,
            "warnings": pack.warnings,
        })

    return findings, {
        "engine": "declarative-json-metadata-only",
        "packs": pack_summaries,
        "rules_loaded": total_rules,
        "matches": total_matches,
        "custom_code_execution": False,
        "evaluated_at_epoch": now,
        "candidate_indexing": {
            "directory_candidates": len(inventory.directory_sizes),
            "file_candidates": len(file_candidates),
            "directory_segment_keys": len(directory_segment_index),
            "file_extension_keys": len(file_extension_index),
            "ancestor_marker_cache_entries": len(marker_cache),
        },
    }


def apply_keep_policy(findings: list[Finding], keep_paths: Iterable[str]) -> dict[str, Any]:
    normalized = [_norm(x) for x in keep_paths if str(x).strip()]
    affected = 0
    protected_bytes = 0
    for finding in findings:
        matched = next((keep for keep in normalized if _under(finding.path, keep)), "")
        if not matched:
            continue
        affected += 1
        protected_bytes += max(0, int(finding.estimated_reclaimable_bytes))
        finding.evidence = dict(finding.evidence or {})
        finding.evidence["protected_by_keep_path"] = matched
        finding.evidence["reclaimable_before_keep_policy"] = int(finding.estimated_reclaimable_bytes)
        finding.estimated_reclaimable_bytes = 0
        if finding.disposition == "probably_safe_cleanup":
            finding.disposition = "manual_review"
        if finding.risk == "low":
            finding.risk = "medium"
        suffix = " This path is covered by an explicit ReconSpace keep/protection rule, so no reclaimable amount is counted."
        if suffix.strip() not in finding.recommendation:
            finding.recommendation = finding.recommendation.rstrip() + suffix
    return {
        "keep_paths": normalized,
        "affected_findings": affected,
        "protected_reclaimable_bytes": protected_bytes,
        "policy": "Findings remain visible, but reclaimable bytes are zeroed and safe-clean labels are downgraded.",
    }
