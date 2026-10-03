from __future__ import annotations

import os
import time
from pathlib import Path

from .models import ProjectArtifactRecord
from .scanner import ScanInventory

MB = 1024 * 1024


def _norm(path: str) -> str:
    return os.path.normcase(os.path.normpath(path))


def _segments(path: str) -> list[str]:
    return [p.lower() for p in path.replace("\\", "/").split("/") if p]


def _age_days(ts: float | None) -> float | None:
    if not ts:
        return None
    return max(0.0, (time.time() - ts) / 86400.0)


def _nearest_project_root(path: str, inventory: ScanInventory, max_up: int = 8) -> tuple[str, list[str]]:
    current = os.path.dirname(path)
    for _ in range(max_up + 1):
        markers = inventory.project_markers.get(current)
        if markers:
            return current, sorted(markers)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return "", []


def _artifact_type(path: str, inventory: ScanInventory) -> tuple[str, bool, list[str]] | None:
    seg = _segments(path)
    if not seg:
        return None
    tail = seg[-1]
    last2 = "/".join(seg[-2:]) if len(seg) >= 2 else tail
    last3 = "/".join(seg[-3:]) if len(seg) >= 3 else last2

    # Project-local dependency/build artifacts.
    if tail == "node_modules":
        return "Node.js dependencies", True, ["Node.js", "development"]
    if tail in {".venv", "venv", ".tox"}:
        return "Python environment", True, ["Python", "development"]
    if tail in {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}:
        return "Python generated cache", True, ["Python", "development"]
    if tail in {".next", ".nuxt", ".turbo", ".parcel-cache", ".angular", ".vite"}:
        return "Web build cache/output", True, ["web development", "build cache"]
    if tail == ".terraform":
        return "Terraform provider/module cache", True, ["Terraform", "infrastructure as code", "development"]
    if tail in {".dart_tool", ".pub-cache"}:
        return "Dart/Flutter generated cache", True, ["Dart", "Flutter", "development"]
    if tail == "vendor":
        composer_root, composer_markers = _nearest_project_root(path, inventory)
        if composer_root and any(m.lower() == "composer.json" for m in composer_markers):
            return "PHP Composer dependencies", True, ["PHP", "development"]

    project_root, markers = _nearest_project_root(path, inventory)
    if project_root and tail in {"dist", "build", "out", "coverage", ".coverage", ".gradle"}:
        return "Project build/test output", True, ["development", "build output"]
    if project_root and tail == "target" and any(m.lower() in {"cargo.toml", "pom.xml"} for m in markers):
        return "Compiled project output", True, ["Rust/Java", "development"]
    if project_root and tail in {"bin", "obj"} and any(Path(m).suffix.lower() in {".sln", ".csproj", ".fsproj", ".vbproj"} for m in markers):
        return ".NET build output", True, [".NET", "development"]

    # Shared package/tool caches.
    if last2.endswith(".gradle/caches") or last2 == ".gradle/caches":
        return "Gradle cache", True, ["Java", "Android", "development"]
    if last2.endswith(".m2/repository") or last2 == ".m2/repository":
        return "Maven local repository", False, ["Java", "development"]
    if last2.endswith(".nuget/packages") or last2 == ".nuget/packages":
        return "NuGet global packages", True, [".NET", "development"]
    if last2.endswith(".cargo/registry") or last2.endswith(".cargo/git"):
        return "Cargo package cache", True, ["Rust", "development"]
    if last2.endswith(".rustup/toolchains"):
        return "Rust toolchains", False, ["Rust", "SDK", "development"]
    if last3.endswith("go/pkg/mod"):
        return "Go module cache", True, ["Go", "development"]
    if tail == "npm-cache" or last2.endswith("npm/cache"):
        return "npm cache", True, ["Node.js", "development"]
    if last2.endswith("yarn/cache"):
        return "Yarn cache", True, ["Node.js", "development"]
    if tail == "store" and "pnpm" in seg[-3:]:
        return "pnpm shared store", False, ["Node.js", "development"]
    if last2.endswith("pip/cache"):
        return "pip cache", True, ["Python", "development"]
    if tail == "pkgs" and any(x in seg for x in {"anaconda3", "miniconda3", "miniforge3", "conda"}):
        return "Conda package cache", True, ["Python", "Conda", "development"]
    if tail == "envs" and any(x in seg for x in {"anaconda3", "miniconda3", "miniforge3", "conda"}):
        return "Conda environments", False, ["Python", "Conda", "development"]
    if last2.endswith(".vscode/extensions"):
        return "VS Code extensions", False, ["VS Code", "development"]
    if tail == "caches" and "jetbrains" in seg:
        return "JetBrains IDE caches", True, ["JetBrains", "IDE", "development"]
    if tail == "deriveddatacache" and any("unreal" in x for x in seg):
        return "Unreal Derived Data Cache", True, ["Unreal Engine", "development", "game development"]

    project_root, markers = _nearest_project_root(path, inventory)
    if project_root and tail == "library" and any(m.lower() == "projectsettings/" for m in markers):
        return "Unity project Library", True, ["Unity", "development", "game development"]

    # Virtualization/emulation and cybersecurity data.
    if last2.endswith(".android/avd") or tail.endswith(".avd"):
        return "Android emulator data", False, ["Android", "emulator", "development"]
    if "system-images" in seg and "android" in seg:
        return "Android SDK system images", False, ["Android", "SDK", "emulator"]
    if tail in {"virtualbox vms", "virtual machines"}:
        return "Virtual machine library", False, ["VM", "virtualization", "cybersecurity"]
    if tail in {"wordlists", "seclists"} and any(x in seg for x in {"kali", "security", "pentest", "burp", "ctf", "seclists"}):
        return "Cybersecurity wordlist corpus", False, ["cybersecurity", "wordlists", "CTF"]
    if tail in {"pcaps", "captures", "packet-captures"} and any(x in seg for x in {"security", "pentest", "wireshark", "ctf", "forensics", "malware"}):
        return "Packet capture collection", False, ["cybersecurity", "packet capture", "forensics"]

    # Browser/cache hotspots. Entire profile directories are not rebuildable.
    if tail in {"cache", "code cache", "gpucache"} and any(x in seg for x in {"chrome", "edge", "brave-browser", "firefox", "discord", "slack"}):
        return "Application/browser cache", True, ["browser/application cache"]

    return None


def discover_project_artifacts(
    inventory: ScanInventory,
    min_size_bytes: int = 40 * MB,
    max_items: int = 700,
) -> list[ProjectArtifactRecord]:
    """Discover large semantic storage artifacts from directory context.

    This is deliberately evidence-based: it only emits directories whose path
    shape and/or nearby project manifests provide a useful ownership signal.
    """
    artifacts: list[ProjectArtifactRecord] = []
    for path, size in inventory.directory_sizes.items():
        if size < min_size_bytes:
            continue
        kind = _artifact_type(path, inventory)
        if not kind:
            continue
        artifact_type, rebuildable, related = kind
        project_root, markers = _nearest_project_root(path, inventory)
        artifacts.append(ProjectArtifactRecord(
            path=path,
            size_bytes=size,
            artifact_type=artifact_type,
            project_root=project_root,
            project_markers=markers,
            rebuildable=rebuildable,
            age_days=_age_days(inventory.directory_mtimes.get(path)),
            related_to=related,
        ))

    # Avoid noisy nested duplicates: if a parent semantic artifact already
    # represents the same type, keep the larger parent and suppress descendants.
    artifacts.sort(key=lambda x: x.size_bytes, reverse=True)
    kept: list[ProjectArtifactRecord] = []
    for item in artifacts:
        nested_duplicate = False
        for parent in kept:
            if parent.artifact_type != item.artifact_type:
                continue
            try:
                if os.path.commonpath([_norm(item.path), _norm(parent.path)]) == _norm(parent.path):
                    nested_duplicate = True
                    break
            except ValueError:
                pass
        if not nested_duplicate:
            kept.append(item)
        if len(kept) >= max_items:
            break
    return kept
