from __future__ import annotations

import argparse
import os
import shutil
import tempfile
import zipapp
from pathlib import Path

from reconspace import __version__


ROOT = Path(__file__).resolve().parent
DEFAULT_OUTPUT = ROOT / f"ReconSpace-v{'.'.join(__version__.split('.')[:2])}.pyz"


def build(output: Path) -> Path:
    target = output.expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="reconspace-zipapp-") as temp_dir:
        staging = Path(temp_dir)
        shutil.copytree(
            ROOT / "reconspace",
            staging / "reconspace",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        (staging / "__main__.py").write_text(
            "from reconspace.cli import main\n\nif __name__ == '__main__':\n    main()\n",
            encoding="utf-8",
        )
        fd, temporary_name = tempfile.mkstemp(prefix=".reconspace-", suffix=".pyz", dir=target.parent)
        os.close(fd)
        temporary = Path(temporary_name)
        try:
            zipapp.create_archive(staging, temporary, compressed=True)
            os.replace(temporary, target)
        finally:
            if temporary.exists():
                temporary.unlink()
    return target


def main() -> None:
    parser = argparse.ArgumentParser(description="Build the dependency-free ReconSpace Python zip application")
    parser.add_argument("output", nargs="?", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    destination = build(args.output)
    print(f"Built ReconSpace {__version__}: {destination}")


if __name__ == "__main__":
    main()
