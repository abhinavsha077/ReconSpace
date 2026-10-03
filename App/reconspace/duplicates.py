from __future__ import annotations

import hashlib
import os
from collections import defaultdict
from typing import Callable

from .models import DuplicateGroup
from .sizeutil import allocated_size

ProgressCallback = Callable[[dict], None]
CancelCallback = Callable[[], bool]

CHUNK = 1024 * 1024
FULL_CHUNK = 8 * 1024 * 1024


class DuplicateScanCancelled(RuntimeError):
    pass


class FileChangedDuringHash(OSError):
    pass


def _stat_signature(path: str) -> tuple[int, int, int, int]:
    st = os.stat(path, follow_symlinks=False)
    return (
        int(st.st_size),
        int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1_000_000_000))),
        int(getattr(st, "st_dev", 0) or 0),
        int(getattr(st, "st_ino", 0) or 0),
    )


def _quick_hash_raw(path: str, size: int) -> str:
    """Cheap content fingerprint: first, middle and last MiB."""
    h = hashlib.blake2b(digest_size=16)
    with open(path, "rb", buffering=0) as f:
        h.update(f.read(CHUNK))
        if size > CHUNK * 3:
            f.seek(max(0, (size // 2) - (CHUNK // 2)))
            h.update(f.read(CHUNK))
            f.seek(max(0, size - CHUNK))
            h.update(f.read(CHUNK))
        elif size > CHUNK:
            h.update(f.read())
    return h.hexdigest()


def _sha256_raw(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb", buffering=FULL_CHUNK) as f:
        while True:
            chunk = f.read(FULL_CHUNK)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _stable_hash(path: str, expected_size: int, full: bool) -> str:
    before = _stat_signature(path)
    if before[0] != expected_size:
        raise FileChangedDuringHash(f"size changed before hashing: expected {expected_size}, got {before[0]}")
    digest = _sha256_raw(path) if full else _quick_hash_raw(path, expected_size)
    after = _stat_signature(path)
    if after != before:
        raise FileChangedDuringHash("file metadata changed while hashing; duplicate result discarded")
    return digest


def _identity(path: str) -> tuple[int, int] | tuple[str, str]:
    st = os.stat(path, follow_symlinks=False)
    ino = int(getattr(st, "st_ino", 0) or 0)
    dev = int(getattr(st, "st_dev", 0) or 0)
    if ino:
        return dev, ino
    # Conservative fallback: without a stable file id, treat each pathname as a
    # distinct instance rather than undercounting potential duplicates.
    return "path", os.path.normcase(os.path.abspath(path))


def find_duplicate_groups(
    candidates: dict[int, list[str]],
    progress: ProgressCallback | None = None,
    cancel: CancelCallback | None = None,
) -> tuple[list[DuplicateGroup], list[str]]:
    """Verify exact duplicates without modifying files.

    Same-size paths are first collapsed by file identity, so NTFS hard-link aliases
    are content-hashed only once. Distinct instances are quick-fingerprinted and
    then fully SHA-256 hashed. Both hash stages reject files that change while read.
    """
    groups: list[DuplicateGroup] = []
    errors: list[str] = []
    candidate_total = sum(len(paths) for paths in candidates.values())
    done = 0

    for size, paths in sorted(candidates.items(), reverse=True):
        if cancel and cancel():
            raise DuplicateScanCancelled("Duplicate analysis cancelled by user")

        identities: dict[tuple, list[str]] = defaultdict(list)
        for path in paths:
            try:
                if cancel and cancel():
                    raise DuplicateScanCancelled("Duplicate analysis cancelled by user")
                if os.path.getsize(path) != size:
                    continue
                identities[_identity(path)].append(path)
            except DuplicateScanCancelled:
                raise
            except OSError as exc:
                if len(errors) < 500:
                    errors.append(f"{path}: {type(exc).__name__}: {exc}")
            finally:
                done += 1
                if progress:
                    progress({"phase": "duplicates", "done": done, "total": candidate_total, "path": path})

        # A same-size group consisting only of aliases to one file instance has no
        # duplicate data to reclaim and does not need any content read.
        if len(identities) < 2:
            continue

        representative_for_identity = {ident: sorted(alias_paths)[0] for ident, alias_paths in identities.items()}
        quick_groups: dict[str, list[tuple]] = defaultdict(list)
        for ident, path in representative_for_identity.items():
            try:
                if cancel and cancel():
                    raise DuplicateScanCancelled("Duplicate analysis cancelled by user")
                if progress:
                    progress({
                        "phase": "duplicate_hashing",
                        "stage": "quick_fingerprint",
                        "path": path,
                        "size_bytes": size,
                    })
                quick_groups[_stable_hash(path, size, full=False)].append(ident)
            except DuplicateScanCancelled:
                raise
            except OSError as exc:
                if len(errors) < 500:
                    errors.append(f"{path}: {type(exc).__name__}: {exc}")

        for quick_identities in quick_groups.values():
            if len(quick_identities) < 2:
                continue
            full_groups: dict[str, list[tuple]] = defaultdict(list)
            for ident in quick_identities:
                path = representative_for_identity[ident]
                try:
                    if cancel and cancel():
                        raise DuplicateScanCancelled("Duplicate analysis cancelled by user")
                    if progress:
                        progress({
                            "phase": "duplicate_hashing",
                            "stage": "sha256",
                            "path": path,
                            "size_bytes": size,
                        })
                    full_groups[_stable_hash(path, size, full=True)].append(ident)
                except DuplicateScanCancelled:
                    raise
                except OSError as exc:
                    if len(errors) < 500:
                        errors.append(f"{path}: {type(exc).__name__}: {exc}")

            for digest, dup_identities in full_groups.items():
                if len(dup_identities) < 2:
                    continue

                dup_paths: list[str] = []
                hardlink_sets: list[list[str]] = []
                allocated_instances: list[int] = []
                allocated_complete = True
                for ident in dup_identities:
                    aliases = sorted(identities[ident])
                    dup_paths.extend(aliases)
                    if len(aliases) > 1:
                        hardlink_sets.append(aliases)
                    value = allocated_size(representative_for_identity[ident], size)
                    if value is None:
                        allocated_complete = False
                    else:
                        allocated_instances.append(value)

                distinct_instances = len(dup_identities)
                if allocated_complete and len(allocated_instances) == distinct_instances:
                    allocated_total = sum(allocated_instances)
                    # Conservative: whichever instance a user keeps, claim no more
                    # than total physical allocation minus the largest instance.
                    reclaimable = max(0, allocated_total - max(allocated_instances))
                    reclaimable_basis = "allocated"
                else:
                    allocated_total = None
                    reclaimable = size * max(0, distinct_instances - 1)
                    reclaimable_basis = "logical"

                notes: list[str] = []
                if hardlink_sets:
                    notes.append(
                        "One or more matching paths are hard links to the same file instance; "
                        "those aliases are not counted as independently reclaimable data."
                    )
                if reclaimable_basis == "allocated":
                    notes.append("Reclaimable estimate uses physical allocated bytes to account for sparse/compressed files.")
                notes.append("Files were re-stat'ed before and after hashing; changing files were discarded.")

                groups.append(DuplicateGroup(
                    size_bytes_each=size,
                    total_logical_bytes=size * len(dup_paths),
                    reclaimable_bytes=reclaimable,
                    sha256=digest,
                    paths=sorted(dup_paths),
                    distinct_file_instances=distinct_instances,
                    hardlink_sets=hardlink_sets,
                    allocated_bytes_total=allocated_total,
                    reclaimable_basis=reclaimable_basis,
                    note=" ".join(notes),
                ))

    groups.sort(key=lambda x: (x.reclaimable_bytes, x.total_logical_bytes), reverse=True)
    return groups, errors
