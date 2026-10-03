from __future__ import annotations

import argparse
import hashlib
import os
import re
import tempfile
import zipfile
from pathlib import Path

from reconspace import __version__


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "RELEASE_MANIFEST.txt"
VERSION_FAMILY = ".".join(__version__.split(".")[:2])
DEFAULT_OUTPUT = ROOT / f"ReconSpace-v{VERSION_FAMILY}-complete.zip"
ROW = re.compile(r"([0-9a-f]{64})  (\d+)  (.+)")
IGNORED_DIRECTORIES = {"__pycache__", ".pytest_cache", ".playwright-cli", ".qa-venv", ".qa-temp", ".build-venv", "build", "dist", "output"}


def manifest_files() -> list[Path]:
    files: list[Path] = []
    seen: set[str] = set()
    for line in MANIFEST.read_text(encoding="utf-8").splitlines():
        match = ROW.fullmatch(line)
        if not match:
            continue
        expected_hash, expected_size, relative = match.groups()
        key = relative.replace("\\", "/").casefold()
        if key in seen:
            raise RuntimeError(f"release manifest contains duplicate path: {relative}")
        seen.add(key)
        path = ROOT / relative
        content = path.read_bytes()
        if len(content) != int(expected_size) or hashlib.sha256(content).hexdigest() != expected_hash:
            raise RuntimeError(f"release manifest mismatch: {relative}")
        files.append(path)
    return files


def discovered_release_files() -> set[Path]:
    discovered: set[Path] = set()
    for path in ROOT.rglob("*"):
        relative = path.relative_to(ROOT)
        # Extracted releases are runnable copies, not source inputs for a new release.
        if re.fullmatch(r"ReconSpace-v\d+\.\d+(?:\.\d+)?", relative.parts[0], re.IGNORECASE):
            continue
        if any(part in IGNORED_DIRECTORIES for part in relative.parts):
            continue
        if path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)()):
            raise RuntimeError(f"release tree contains a link/junction: {relative.as_posix()}")
        if not path.is_file() or path == MANIFEST:
            continue
        if path.name.casefold() == "prompt_history.md" or path.name.startswith(".reconspace-") or path.suffix.casefold() in {".pyc", ".pyo"}:
            continue
        if re.fullmatch(r"ReconSpace-v.+\.pyz", path.name, re.IGNORECASE) and path.name != f"ReconSpace-v{VERSION_FAMILY}.pyz":
            continue
        if re.fullmatch(r"ReconSpace-v.+-complete\.zip", path.name, re.IGNORECASE):
            continue
        discovered.add(path)
    return discovered


def verify_manifest_scope(files: list[Path], discovered: set[Path] | None = None) -> None:
    listed = set(files)
    unexpected = sorted((discovered if discovered is not None else discovered_release_files()) - listed)
    if unexpected:
        names = ", ".join(path.relative_to(ROOT).as_posix() for path in unexpected[:12])
        suffix = f" (+{len(unexpected) - 12} more)" if len(unexpected) > 12 else ""
        raise RuntimeError(f"release manifest omits shipped file(s): {names}{suffix}")


def build(output: Path) -> Path:
    target = output.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=".reconspace-release-", suffix=".zip", dir=target.parent)
    os.close(fd)
    temporary = Path(temporary_name)
    prefix = f"ReconSpace-v{VERSION_FAMILY}"
    try:
        files = manifest_files()
        verify_manifest_scope(files)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in [*files, MANIFEST]:
                archive.write(path, f"{prefix}/{path.relative_to(ROOT).as_posix()}")
        os.replace(temporary, target)
    finally:
        if temporary.exists():
            temporary.unlink()
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the complete ReconSpace release ZIP from the verified manifest")
    parser.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(f"Built ReconSpace {__version__} release: {build(args.output)}")


if __name__ == "__main__":
    main()
