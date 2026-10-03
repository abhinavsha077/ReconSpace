from __future__ import annotations

import heapq
import os
import shutil
import stat as statmod
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .models import AgeBucket, DirectoryRecord, ExtensionSummary, FileRecord, ScanStats
from .sizeutil import allocated_size

ProgressCallback = Callable[[dict], None]
CancelCallback = Callable[[], bool]


# Files in these classes can be enormous, actively changing, or represent unique
# lab/VM state. ReconSpace still inventories them, but standard/deep profiles do
# not content-hash them unless the user explicitly opts into stateful hashing.
STATEFUL_HASH_EXTENSIONS = {
    ".vhd", ".vhdx", ".avhdx", ".vdi", ".vmdk", ".qcow2", ".vmem", ".vmsn", ".vmss", ".sav",
    ".e01", ".aff4", ".raw", ".dd", ".ad1", ".dmp", ".mdmp",
}

PROJECT_MARKER_NAMES = {
    "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
    "pyproject.toml", "requirements.txt", "pipfile", "poetry.lock",
    "cargo.toml", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "settings.gradle", "settings.gradle.kts", "go.mod", "go.sum", "composer.json",
    "gemfile", "pubspec.yaml", "dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "compose.yml", "compose.yaml", "vagrantfile", ".gitmodules", "cmakelists.txt",
}
PROJECT_MARKER_EXTENSIONS = {".sln", ".csproj", ".fsproj", ".vbproj", ".vcxproj"}
PROJECT_MARKER_DIR_NAMES = {".git", "projectsettings"}

AGE_BUCKET_ORDER = ["<7d", "7-30d", "30-90d", "90-365d", "1-2y", ">2y", "unknown"]

# Windows file attribute values. They are defined here instead of depending on a
# particular Python build exposing every newer Cloud Files constant.
FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
FILE_ATTRIBUTE_OFFLINE = 0x00001000
FILE_ATTRIBUTE_SPARSE_FILE = 0x00000200
FILE_ATTRIBUTE_COMPRESSED = 0x00000800
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x00040000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x00400000


class ScanCancelled(RuntimeError):
    pass


@dataclass(slots=True)
class ScanConfig:
    root: str = "C:\\"
    top_files: int = 300
    top_directories: int = 300
    duplicate_min_bytes: int = 64 * 1024 * 1024
    duplicate_max_bytes: int | None = 32 * 1024 * 1024 * 1024
    hash_stateful_files: bool = False
    interesting_file_min_bytes: int = 16 * 1024 * 1024
    max_interesting_files: int = 10000
    progress_every_files: int = 4000
    max_errors: int = 500
    collect_project_markers: bool = True
    excluded_paths: tuple[str, ...] = ()


@dataclass(slots=True)
class ScanInventory:
    stats: ScanStats
    top_files: list[FileRecord]
    top_directories: list[DirectoryRecord]
    directory_sizes: dict[str, int]
    directory_direct_sizes: dict[str, int]
    directory_mtimes: dict[str, float | None]
    duplicate_candidates: dict[int, list[str]]
    interesting_files: list[FileRecord]
    extension_summary: list[ExtensionSummary]
    age_summary: list[AgeBucket]
    project_markers: dict[str, list[str]]
    excluded_paths: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _norm(path: str) -> str:
    cleaned = str(path or "").strip().strip('"').strip("'").strip()
    if len(cleaned) == 2 and cleaned[0].isalpha() and cleaned[1] == ":":
        cleaned += "\\"
    expanded = os.path.expandvars(os.path.expanduser(cleaned))
    return os.path.normcase(os.path.normpath(os.path.abspath(expanded)))


def _file_attributes(st: os.stat_result) -> int:
    return int(getattr(st, "st_file_attributes", 0) or 0)


def _has_attr(attrs: int, flag: int) -> bool:
    return bool(attrs & flag)


def _push_largest(heap: list, limit: int, key: int, serial: int, value) -> None:
    if limit <= 0:
        return
    item = (key, serial, value)
    if len(heap) < limit:
        heapq.heappush(heap, item)
    elif key > heap[0][0]:
        heapq.heapreplace(heap, item)


def _age_bucket(modified_ts: float | None) -> str:
    if not modified_ts:
        return "unknown"
    days = max(0.0, (time.time() - modified_ts) / 86400.0)
    if days < 7:
        return "<7d"
    if days < 30:
        return "7-30d"
    if days < 90:
        return "30-90d"
    if days < 365:
        return "90-365d"
    if days < 730:
        return "1-2y"
    return ">2y"


def _file_identity(st: os.stat_result) -> str:
    # st_ino/st_dev are usable on modern Python/Windows and let us identify NTFS
    # hard-link aliases. We do not use this to assign physical ownership to one
    # folder; directory sizes remain clearly labeled logical namespace sizes.
    ino = int(getattr(st, "st_ino", 0) or 0)
    dev = int(getattr(st, "st_dev", 0) or 0)
    return f"{dev}:{ino}" if ino else ""


def _hash_eligible(attrs: int, ext: str, size: int, config: ScanConfig) -> bool:
    # Opening a cloud placeholder for content can hydrate/download it. A read-only
    # audit must avoid causing that side effect, so metadata-only inventory is used.
    cloudish = any(_has_attr(attrs, f) for f in (
        FILE_ATTRIBUTE_REPARSE_POINT,
        FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_RECALL_ON_OPEN,
        FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    ))
    if cloudish:
        return False
    if config.duplicate_max_bytes is not None and size > config.duplicate_max_bytes:
        return False
    if not config.hash_stateful_files and ext in STATEFUL_HASH_EXTENSIONS:
        return False
    return True


def scan_filesystem(
    config: ScanConfig,
    progress: ProgressCallback | None = None,
    cancel: CancelCallback | None = None,
) -> ScanInventory:
    root = _norm(config.root)
    if not os.path.exists(root):
        raise FileNotFoundError(f"scan root does not exist: {root}")
    if not os.path.isdir(root):
        raise NotADirectoryError(f"scan root is not a directory: {root}")

    started_perf = time.perf_counter()
    stats = ScanStats(root=root, started_at=_now_iso())
    try:
        usage = shutil.disk_usage(root)
        stats.filesystem_total_bytes = int(usage.total)
        stats.filesystem_used_bytes = int(usage.used)
        stats.filesystem_free_bytes = int(usage.free)
    except OSError:
        pass

    direct_sizes: dict[str, int] = {root: 0}
    dir_mtimes: dict[str, float | None] = {root: None}
    parent_map: dict[str, str] = {}
    depth_map: dict[str, int] = {root: 0}
    duplicate_candidates: dict[int, list[str]] = defaultdict(list)
    interesting_heap: list[tuple[int, int, FileRecord]] = []
    extension_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    age_counts: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    project_markers: dict[str, list[str]] = defaultdict(list)
    top_file_heap: list[tuple[int, int, FileRecord]] = []
    errors: list[str] = []
    excluded_seen: list[str] = []
    hardlink_seen: set[str] = set()
    serial = 0

    excluded_list: list[str] = []
    for raw in config.excluded_paths:
        if not raw:
            continue
        ex = _norm(raw)
        try:
            common = os.path.commonpath([root, ex])
        except ValueError:
            common = ""
        if common != root or ex == root:
            raise ValueError(f"excluded path must be a strict descendant of scan root: {ex}")
        excluded_list.append(ex)
    excluded_norm = tuple(excluded_list)

    def is_excluded(path: str) -> bool:
        n = _norm(path)
        for ex in excluded_norm:
            try:
                if os.path.commonpath([n, ex]) == ex:
                    return True
            except ValueError:
                continue
        return False

    stack: list[str] = [root]
    last_progress = 0
    entries_since_cancel_check = 0

    while stack:
        if cancel and cancel():
            stats.scan_cancelled = True
            raise ScanCancelled("Scan cancelled by user")

        directory = stack.pop()
        if directory != root and is_excluded(directory):
            if len(excluded_seen) < config.max_errors:
                excluded_seen.append(directory)
            continue

        stats.directories_seen += 1
        try:
            try:
                dir_mtimes[directory] = os.stat(directory, follow_symlinks=False).st_mtime
            except OSError:
                pass

            with os.scandir(directory) as it:
                for entry in it:
                    entries_since_cancel_check += 1
                    if entries_since_cancel_check >= 512:
                        entries_since_cancel_check = 0
                        if cancel and cancel():
                            stats.scan_cancelled = True
                            raise ScanCancelled("Scan cancelled by user")
                    try:
                        st = entry.stat(follow_symlinks=False)
                        mode = st.st_mode
                        attrs = _file_attributes(st)
                        is_reparse = _has_attr(attrs, FILE_ATTRIBUTE_REPARSE_POINT)

                        if statmod.S_ISDIR(mode):
                            # Directory reparse points/junctions can cycle or alias a
                            # tree. Record coverage impact and never traverse them.
                            if is_reparse or entry.is_symlink():
                                stats.reparse_points_skipped += 1
                                continue
                            child = entry.path
                            if config.collect_project_markers and entry.name.lower() in PROJECT_MARKER_DIR_NAMES:
                                markers = project_markers[directory]
                                marker = entry.name + "/"
                                if marker not in markers and len(markers) < 24:
                                    markers.append(marker)
                            if is_excluded(child):
                                if len(excluded_seen) < config.max_errors:
                                    excluded_seen.append(child)
                                continue
                            if child not in direct_sizes:
                                direct_sizes[child] = 0
                                dir_mtimes[child] = float(st.st_mtime)
                                parent_map[child] = directory
                                depth_map[child] = depth_map.get(directory, 0) + 1
                                stack.append(child)
                            continue

                        # Symlinks/special devices are not opened or counted as file
                        # content. Reparse regular files (notably cloud placeholders)
                        # are counted by metadata but never content-hashed.
                        if not statmod.S_ISREG(mode):
                            if is_reparse or entry.is_symlink():
                                stats.reparse_points_skipped += 1
                            continue

                        size = int(st.st_size)
                        stats.files_seen += 1
                        stats.bytes_seen += size
                        direct_sizes[directory] = direct_sizes.get(directory, 0) + size

                        ext = Path(entry.name).suffix.lower()
                        identity = _file_identity(st)
                        link_count = max(1, int(getattr(st, "st_nlink", 1) or 1))
                        if link_count > 1 and identity:
                            if identity in hardlink_seen:
                                stats.hardlink_aliases_seen += 1
                                stats.hardlink_duplicate_logical_bytes += size
                            else:
                                hardlink_seen.add(identity)

                        offline = _has_attr(attrs, FILE_ATTRIBUTE_OFFLINE) or _has_attr(attrs, FILE_ATTRIBUTE_RECALL_ON_OPEN) or _has_attr(attrs, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS)
                        if offline:
                            stats.cloud_or_offline_files += 1
                        if is_reparse:
                            stats.reparse_files_counted += 1

                        eligible = _hash_eligible(attrs, ext, size, config)
                        blocks = getattr(st, "st_blocks", None)
                        stat_allocated = int(blocks) * 512 if isinstance(blocks, int) and blocks >= 0 else None
                        rec = FileRecord(
                            path=entry.path,
                            size_bytes=size,
                            modified_ts=float(st.st_mtime),
                            created_ts=float(getattr(st, "st_ctime", 0.0) or 0.0) or None,
                            extension=ext,
                            file_identity=identity,
                            link_count=link_count,
                            allocated_bytes=stat_allocated,
                            file_attributes=attrs,
                            is_reparse=is_reparse,
                            is_offline=offline,
                            is_sparse=_has_attr(attrs, FILE_ATTRIBUTE_SPARSE_FILE),
                            is_compressed=_has_attr(attrs, FILE_ATTRIBUTE_COMPRESSED),
                            content_hash_eligible=eligible,
                        )
                        serial += 1
                        _push_largest(top_file_heap, config.top_files, size, serial, rec)

                        ext_key = ext or "(no extension)"
                        extension_counts[ext_key][0] += 1
                        extension_counts[ext_key][1] += size
                        age_key = _age_bucket(rec.modified_ts)
                        age_counts[age_key][0] += 1
                        age_counts[age_key][1] += size

                        if size >= config.duplicate_min_bytes:
                            if eligible:
                                duplicate_candidates[size].append(entry.path)
                            else:
                                stats.duplicate_hash_policy_skipped_files += 1
                                stats.duplicate_hash_policy_skipped_bytes += size

                        # Retain a bounded set of *all* large files, not only a
                        # hard-coded extension allowlist. Declarative rule packs
                        # can match arbitrary extensions (for example
                        # .crdownload), and extension-gating here made otherwise
                        # valid file rules silently unreachable.
                        if size >= config.interesting_file_min_bytes:
                            stats.metadata_candidate_files_seen += 1
                            _push_largest(interesting_heap, config.max_interesting_files, size, serial, rec)

                        if config.collect_project_markers:
                            lower_name = entry.name.lower()
                            if lower_name in PROJECT_MARKER_NAMES or ext in PROJECT_MARKER_EXTENSIONS:
                                markers = project_markers[directory]
                                if entry.name not in markers and len(markers) < 24:
                                    markers.append(entry.name)

                        if progress and stats.files_seen - last_progress >= config.progress_every_files:
                            last_progress = stats.files_seen
                            progress({
                                "phase": "filesystem",
                                "path": directory,
                                "files_seen": stats.files_seen,
                                "directories_seen": stats.directories_seen,
                                "bytes_seen": stats.bytes_seen,
                                "access_denied": stats.access_denied,
                                "stat_errors": stats.stat_errors,
                            })
                    except PermissionError:
                        stats.access_denied += 1
                    except OSError as exc:
                        stats.stat_errors += 1
                        if len(errors) < config.max_errors:
                            errors.append(f"{entry.path}: {type(exc).__name__}: {exc}")
        except PermissionError:
            stats.access_denied += 1
            if len(errors) < config.max_errors:
                errors.append(f"{directory}: PermissionError")
        except OSError as exc:
            stats.stat_errors += 1
            if len(errors) < config.max_errors:
                errors.append(f"{directory}: {type(exc).__name__}: {exc}")

    # Bottom-up logical namespace aggregation. Hard links can cause the same NTFS
    # file instance to appear in multiple paths; we deliberately do not assign its
    # physical bytes to an arbitrary directory. The report exposes this caveat and
    # global hard-link alias metrics instead.
    aggregate_sizes = dict(direct_sizes)
    for directory in sorted(depth_map, key=depth_map.get, reverse=True):
        parent = parent_map.get(directory)
        if parent:
            aggregate_sizes[parent] = aggregate_sizes.get(parent, 0) + aggregate_sizes.get(directory, 0)

    top_dirs_heap: list[tuple[int, int, DirectoryRecord]] = []
    for directory, size in aggregate_sizes.items():
        serial += 1
        _push_largest(
            top_dirs_heap,
            config.top_directories,
            size,
            serial,
            DirectoryRecord(
                path=directory,
                size_bytes=size,
                direct_size_bytes=direct_sizes.get(directory, 0),
                modified_ts=dir_mtimes.get(directory),
            ),
        )

    top_files = [x[2] for x in sorted(top_file_heap, key=lambda x: x[0], reverse=True)]
    interesting_files = [x[2] for x in sorted(interesting_heap, key=lambda x: x[0], reverse=True)]
    stats.metadata_candidate_files_retained = len(interesting_files)
    stats.metadata_candidate_files_omitted = max(0, stats.metadata_candidate_files_seen - len(interesting_files))
    # Allocated-size calls are limited to retained evidence records.
    # GetCompressedFileSizeW is metadata-only and corrects sparse/compressed-file
    # distortion without a second content read of the whole drive.
    retained_records = {rec.path: rec for rec in [*top_files, *interesting_files]}
    for rec in retained_records.values():
        if rec.allocated_bytes is None:
            rec.allocated_bytes = allocated_size(rec.path, rec.size_bytes)
        if os.name != "nt" and rec.size_bytes > 0 and isinstance(rec.allocated_bytes, int) and rec.allocated_bytes < rec.size_bytes:
            rec.is_sparse = True
    top_directories = [x[2] for x in sorted(top_dirs_heap, key=lambda x: x[0], reverse=True)]
    duplicate_candidates = {k: v for k, v in duplicate_candidates.items() if len(v) > 1}

    ext_summary = [
        ExtensionSummary(extension=ext, files=vals[0], bytes=vals[1])
        for ext, vals in extension_counts.items()
    ]
    ext_summary.sort(key=lambda x: x.bytes, reverse=True)

    age_summary = [
        AgeBucket(bucket=bucket, files=age_counts[bucket][0], bytes=age_counts[bucket][1])
        for bucket in AGE_BUCKET_ORDER if bucket in age_counts
    ]

    stats.finished_at = _now_iso()
    stats.duration_seconds = round(time.perf_counter() - started_perf, 3)
    if stats.duration_seconds > 0:
        stats.scan_rate_files_per_second = round(stats.files_seen / stats.duration_seconds, 1)

    if progress:
        progress({
            "phase": "filesystem_done",
            "files_seen": stats.files_seen,
            "directories_seen": stats.directories_seen,
            "bytes_seen": stats.bytes_seen,
            "access_denied": stats.access_denied,
            "stat_errors": stats.stat_errors,
        })

    return ScanInventory(
        stats=stats,
        top_files=top_files,
        top_directories=top_directories,
        directory_sizes=aggregate_sizes,
        directory_direct_sizes=direct_sizes,
        directory_mtimes=dir_mtimes,
        duplicate_candidates=duplicate_candidates,
        interesting_files=interesting_files,
        extension_summary=ext_summary,
        age_summary=age_summary,
        project_markers=dict(project_markers),
        excluded_paths=excluded_seen,
        errors=errors,
    )
