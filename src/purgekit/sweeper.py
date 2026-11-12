from __future__ import annotations

import os
from collections import deque
from pathlib import Path
from typing import Deque, List, Optional, Sequence, Set, Tuple

from purgekit.models import RiskLevel, SpaceLensEntry, SweepItem
from purgekit.safety import is_sip_protected_path, requires_admin_privileges
from purgekit.utils import get_path_size

INSTALLER_EXTENSIONS = frozenset({".dmg", ".pkg", ".mpkg", ".iso"})
LARGE_SCAN_USER_DIRS = ("Downloads", "Desktop", "Documents", "Movies", "Music", "Pictures")
PROJECT_CACHE_NAMES = frozenset({"node_modules", ".venv", "venv", "target"})
PROJECT_PARENT_DIRS = ("Projects", "Developer", "Dev", "Work", "Code", "Sites", "repos")


def _dev_cache_candidates(user_home: Path) -> List[Tuple[Path, str]]:
    """Collect known macOS developer & package cache targets safely."""
    targets: List[Tuple[Path, str]] = []

    # Expand per-subdirectory caches so individual projects/packages can be toggled
    expand_parents: Sequence[Tuple[Path, str]] = (
        (user_home / "Library" / "Developer" / "Xcode" / "DerivedData", "Xcode DerivedData"),
        (user_home / "Library" / "Developer" / "Xcode" / "Archives", "Xcode Archives"),
        (user_home / ".cache", "User CLI / ML cache"),
    )
    for parent, note in expand_parents:
        if parent.is_dir():
            try:
                with os.scandir(parent) as it:
                    for entry in it:
                        targets.append((Path(entry.path), note))
            except OSError:
                continue

    direct_caches: Sequence[Tuple[Path, str]] = (
        (user_home / "Library" / "Caches" / "Homebrew", "Homebrew download cache"),
        (user_home / "Library" / "Caches" / "pip", "Python pip cache"),
        (user_home / "Library" / "Developer" / "CoreSimulator" / "Caches", "iOS Simulator cache"),
        (user_home / ".npm" / "_cacache", "npm package cache"),
        (user_home / "Library" / "Application Support" / "Code" / "CachedExtensionVSIXs", "VS Code extension cache"),
        (user_home / "Library" / "Application Support" / "Cursor" / "CachedExtensionVSIXs", "Cursor extension cache"),
    )
    for p, note in direct_caches:
        if p.exists():
            targets.append((p, note))

    return targets


def _scan_project_build_caches(user_home: Path, min_bytes: int, limit: int = 40) -> List[Tuple[Path, str, int]]:
    """Find heavy `node_modules` / `.venv` / `target` folders inside common dev directories."""
    hits: List[Tuple[Path, str, int]] = []
    queue: Deque[Tuple[Path, int]] = deque()
    for name in PROJECT_PARENT_DIRS:
        p = user_home / name
        if p.is_dir():
            queue.append((p, 0))

    visited = 0
    while queue and visited < 8000 and len(hits) < limit:
        cur, depth = queue.popleft()
        try:
            with os.scandir(cur) as entries:
                for entry in entries:
                    visited += 1
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    ename = entry.name
                    ep = Path(entry.path)
                    if ename in PROJECT_CACHE_NAMES:
                        size = get_path_size(ep)
                        if size >= min_bytes:
                            hits.append((ep, f"Project {ename} folder", size))
                        continue
                    if depth + 1 < 4 and not ename.startswith(".") and not ename.endswith(".app"):
                        queue.append((ep, depth + 1))
        except OSError:
            continue
    return hits


def scan_sweep_targets(
    min_mb: int = 50,
    home: Optional[Path] = None,
    include_dev: bool = True,
    include_installers: bool = True,
    include_large_files: bool = True,
    limit: int = 120,
) -> List[SweepItem]:
    """Scan macOS installers, developer caches, and large user files for safe cleanup."""
    user_home = (home or Path.home()).resolve()
    min_bytes = max(1, min_mb) * 1024 * 1024
    cache_floor_bytes = min(min_bytes, 10 * 1024 * 1024)
    installer_floor_bytes = 5 * 1024 * 1024

    items: List[SweepItem] = []
    seen: Set[str] = set()

    def add_item(
        path: Path,
        category: str,
        size_bytes: int,
        risk: RiskLevel,
        note: str,
        is_dir: bool,
    ) -> None:
        abs_p = os.path.abspath(str(path))
        if abs_p in seen:
            return
        if is_sip_protected_path(path, home=user_home):
            return
        seen.add(abs_p)
        items.append(
            SweepItem(
                path=path,
                category=category,
                size_bytes=size_bytes,
                risk=risk,
                note=note,
                is_dir=is_dir,
                requires_admin=requires_admin_privileges(path, home=user_home),
            )
        )

    if include_dev:
        for path, note in _dev_cache_candidates(user_home):
            size = get_path_size(path)
            if size >= cache_floor_bytes:
                add_item(path, "Dev Cache", size, RiskLevel.LOW, note, path.is_dir())

        for path, note, size in _scan_project_build_caches(user_home, min_bytes=min_bytes):
            add_item(path, "Project Cache", size, RiskLevel.MEDIUM, note, True)

    if include_installers:
        for folder_name in ("Downloads", "Desktop"):
            root = user_home / folder_name
            if not root.is_dir():
                continue
            queue: Deque[Tuple[Path, int]] = deque([(root, 0)])
            while queue:
                cur, depth = queue.popleft()
                try:
                    with os.scandir(cur) as entries:
                        for entry in entries:
                            ep = Path(entry.path)
                            if entry.is_file(follow_symlinks=False):
                                if ep.suffix.lower() in INSTALLER_EXTENSIONS:
                                    size = entry.stat(follow_symlinks=False).st_size
                                    if size >= installer_floor_bytes:
                                        add_item(
                                            ep,
                                            "Installer",
                                            size,
                                            RiskLevel.LOW,
                                            f"macOS installer ({ep.suffix.lower()})",
                                            False,
                                        )
                            elif depth + 1 < 3 and entry.is_dir(follow_symlinks=False):
                                if not entry.name.endswith(".app") and not entry.name.startswith("."):
                                    queue.append((ep, depth + 1))
                except OSError:
                    continue

    if include_large_files:
        for folder_name in LARGE_SCAN_USER_DIRS:
            root = user_home / folder_name
            if not root.is_dir():
                continue
            queue = deque([(root, 0)])
            visited = 0
            while queue and visited < 20000:
                cur, depth = queue.popleft()
                try:
                    with os.scandir(cur) as entries:
                        for entry in entries:
                            visited += 1
                            ep = Path(entry.path)
                            if entry.is_file(follow_symlinks=False):
                                try:
                                    size = entry.stat(follow_symlinks=False).st_size
                                except OSError:
                                    continue
                                if size >= min_bytes:
                                    add_item(
                                        ep,
                                        "Large File",
                                        size,
                                        RiskLevel.MEDIUM,
                                        f"File >= {min_mb} MB in ~/{folder_name}",
                                        False,
                                    )
                            elif depth + 1 < 6 and entry.is_dir(follow_symlinks=False):
                                if not entry.name.endswith(".app") and not entry.name.startswith("."):
                                    queue.append((ep, depth + 1))
                except OSError:
                    continue

    items.sort(key=lambda item: (-item.size_bytes, str(item.path)))
    return items[:limit]


def scan_space_lens(
    target_dir: Optional[Path] = None,
    home: Optional[Path] = None,
    limit: int = 30,
) -> Tuple[Path, int, List[SpaceLensEntry]]:
    """Measure immediate child footprints under `target_dir` (default: home) for Space Lens."""
    user_home = (home or Path.home()).resolve()
    root = (target_dir or user_home).resolve()
    if not root.is_dir():
        return root, 0, []

    raw: List[Tuple[Path, str, int, bool, bool]] = []
    total_bytes = 0
    try:
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name == ".Trash":
                    continue
                ep = Path(entry.path)
                is_dir = entry.is_dir(follow_symlinks=False)
                size = get_path_size(ep)
                total_bytes += size
                raw.append((ep, entry.name, size, is_dir, is_sip_protected_path(ep, home=user_home)))
    except OSError:
        return root, 0, []

    raw.sort(key=lambda row: (-row[2], row[1].lower()))
    denom = max(total_bytes, 1)
    entries_out = [
        SpaceLensEntry(
            path=p,
            name=name,
            size_bytes=size,
            share_pct=(size / denom) * 100.0,
            is_dir=is_dir,
            is_protected=protected,
        )
        for p, name, size, is_dir, protected in raw[:limit]
    ]
    return root, total_bytes, entries_out
