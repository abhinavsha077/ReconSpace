from __future__ import annotations

import argparse
import hashlib
import os
import tempfile
from pathlib import Path

from build_release_zip import MANIFEST, ROOT, discovered_release_files
from reconspace import __version__


def render_manifest() -> str:
    lines = [
        f"ReconSpace {__version__} release source manifest",
        "Algorithm: SHA-256",
        "Scope: every shipped source/package file except RELEASE_MANIFEST.txt itself and the outer complete ZIP",
        "Format: SHA256  SIZE_BYTES  RELATIVE_PATH",
        "",
    ]
    for path in sorted(discovered_release_files(), key=lambda item: item.relative_to(ROOT).as_posix().casefold()):
        content = path.read_bytes()
        relative = path.relative_to(ROOT).as_posix()
        lines.append(f"{hashlib.sha256(content).hexdigest()}  {len(content)}  {relative}")
    return "\n".join(lines) + "\n"


def update() -> Path:
    content = render_manifest()
    fd, temporary_name = tempfile.mkstemp(prefix=".reconspace-manifest-", suffix=".txt", dir=ROOT)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, MANIFEST)
    finally:
        if temporary.exists():
            temporary.unlink()
    return MANIFEST


def main() -> None:
    parser = argparse.ArgumentParser(description="Atomically update or verify the ReconSpace release manifest")
    parser.add_argument("--check", action="store_true", help="Verify that the manifest exactly matches the current release tree")
    args = parser.parse_args()
    expected = render_manifest()
    if args.check:
        actual = MANIFEST.read_text(encoding="utf-8") if MANIFEST.is_file() else ""
        if actual != expected:
            raise SystemExit("Release manifest is stale; rebuild the portable PYZ, then run update_release_manifest.py")
        print(f"Release manifest is current: {MANIFEST}")
        return
    print(f"Updated ReconSpace {__version__} release manifest: {update()}")


if __name__ == "__main__":
    main()
