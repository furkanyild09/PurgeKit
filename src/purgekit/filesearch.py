from __future__ import annotations

import os
import shutil
import subprocess
from collections import deque
from pathlib import Path
from typing import Deque, List, Optional, Sequence, Set, Tuple

from purgekit.models import FileSearchItem, RiskLevel
from purgekit.safety import is_sip_protected_path, requires_admin_privileges
from purgekit.utils import get_path_size

SKIP_DESCEND_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "node_modules",
    "__pycache__",
})


def _should_skip_noise(path: Path, query_lower: str) -> bool:
    """Filter out deep browser IndexedDB/cache internals unless specifically queried."""
    raw_lower = str(path).lower()
    if ".indexeddb." in raw_lower and "indexeddb" not in query_lower:
        return True
    if "/cache/cache_data/" in raw_lower and "cache_data" not in query_lower:
        return True
    return False


def _run_mdfind(query: str, roots: Sequence[Path], limit: int) -> List[Path]:
    """Query macOS Spotlight (`mdfind`) safely without shell interpolation."""
    if not shutil.which("mdfind"):
        return []

    results: List[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        try:
            proc = subprocess.run(
                ["mdfind", "-onlyin", str(root), "-name", query],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            if proc.returncode != 0:
                continue
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                results.append(Path(line))
                if len(results) >= limit * 2:
                    return results
        except (OSError, subprocess.SubprocessError):
            continue
    return results


def _direct_walk_search(
    query_lower: str,
    roots: Sequence[Path],
    max_depth: int = 3,
    limit: int = 120,
) -> List[Path]:
    """Fast breadth-first scan for unindexed folders (e.g. ~/Library, Downloads, Desktop)."""
    matches: List[Path] = []
    queue: Deque[Tuple[Path, int]] = deque((r, 0) for r in roots if r.is_dir())

    while queue and len(matches) < limit:
        current, depth = queue.popleft()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    name = entry.name
                    entry_path = Path(entry.path)
                    if query_lower in name.lower():
                        matches.append(entry_path)
                        if len(matches) >= limit:
                            break
                    if depth + 1 < max_depth and entry.is_dir(follow_symlinks=False):
                        if name.endswith(".app") or name in SKIP_DESCEND_DIRS:
                            continue
                        queue.append((entry_path, depth + 1))
        except OSError:
            continue
    return matches


def _classify_risk(path: Path, requires_admin: bool, user_home: Path) -> RiskLevel:
    if requires_admin:
        return RiskLevel.HIGH
    raw = os.path.abspath(str(path))
    downloads = str((user_home / "Downloads").resolve())
    caches = str((user_home / "Library" / "Caches").resolve())
    logs = str((user_home / "Library" / "Logs").resolve())
    if raw.startswith((downloads + "/", caches + "/", logs + "/")):
        return RiskLevel.LOW
    return RiskLevel.MEDIUM


def search_files(
    query: str,
    scope: str = "user",
    item_type: str = "all",
    home: Optional[Path] = None,
    system_root: Optional[Path] = None,
    use_spotlight: bool = True,
    limit: int = 120,
) -> List[FileSearchItem]:
    """Search for files and folders across macOS user directories, Library, or system."""
    q = query.strip()
    if not q:
        return []

    q_lower = q.lower()
    user_home = (home or Path.home()).resolve()
    sys_root = (system_root or Path("/")).resolve()

    if scope == "library":
        spotlight_roots: List[Path] = []
        walk_roots = [user_home / "Library", sys_root / "Library"]
        walk_depth = 3
    elif scope == "all":
        spotlight_roots = [user_home, sys_root / "Applications", sys_root / "Library"]
        walk_roots = [
            user_home / "Downloads",
            user_home / "Desktop",
            user_home / "Documents",
            user_home / "Library",
            sys_root / "Library",
            sys_root / "Applications",
        ]
        walk_depth = 3
    else:  # "user"
        spotlight_roots = [user_home]
        walk_roots = [
            user_home,
            user_home / "Downloads",
            user_home / "Desktop",
            user_home / "Documents",
            user_home / "Applications",
            user_home / "Library",
        ]
        walk_depth = 3

    candidates: List[Tuple[Path, str]] = []
    if use_spotlight and spotlight_roots:
        for p in _run_mdfind(q, spotlight_roots, limit=limit):
            candidates.append((p, "spotlight"))

    # Direct scan covers ~/Library (skipped by Spotlight) and unindexed/new files
    for p in _direct_walk_search(q_lower, walk_roots, max_depth=walk_depth, limit=limit):
        src = "library" if "/Library/" in str(p) else "scan"
        candidates.append((p, src))

    seen: Set[str] = set()
    results: List[FileSearchItem] = []

    for p, src in candidates:
        abs_p = os.path.abspath(str(p))
        if abs_p in seen:
            continue
        seen.add(abs_p)

        if is_sip_protected_path(p, home=user_home):
            continue
        if _should_skip_noise(p, q_lower):
            continue

        try:
            exists = p.exists() or p.is_symlink()
        except OSError:
            continue
        if not exists:
            continue

        is_dir = p.is_dir() and not p.is_symlink()
        if item_type == "file" and is_dir:
            continue
        if item_type == "dir" and not is_dir:
            continue

        needs_admin = requires_admin_privileges(p, home=user_home)
        risk = _classify_risk(p, needs_admin, user_home)
        size = get_path_size(p)
        results.append(
            FileSearchItem(
                path=p,
                name=p.name,
                is_dir=is_dir,
                size_bytes=size,
                source=src,
                risk=risk,
                requires_admin=needs_admin,
            )
        )
        if len(results) >= limit * 2:
            break

    def rank(item: FileSearchItem) -> Tuple[int, int, int, int, str]:
        name_lower = item.name.lower()
        stem_lower = item.path.stem.lower()
        exact = 0 if (name_lower == q_lower or stem_lower == q_lower) else 1
        prefix = 0 if name_lower.startswith(q_lower) else 1
        return (exact, prefix, len(item.path.parts), -item.size_bytes, name_lower)

    results.sort(key=rank)
    return results[:limit]
