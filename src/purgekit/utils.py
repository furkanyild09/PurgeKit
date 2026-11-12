from __future__ import annotations

import os
import re
from pathlib import Path


def format_bytes(num_bytes: int) -> str:
    """Format byte counts into human-readable units."""
    if num_bytes < 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(num_bytes)
    for unit in units:
        if size < 1024.0 or unit == units[-1]:
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{int(num_bytes)} B"


def get_path_size(path: Path) -> int:
    """Safely calculate disk size of a file or directory without following symlinks."""
    try:
        if path.is_symlink():
            return path.lstat().st_size
        if path.is_file():
            return path.stat().st_size
        if not path.is_dir():
            return 0
    except OSError:
        return 0

    total = 0
    stack = [path]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            total += entry.stat(follow_symlinks=False).st_size
                        elif entry.is_file(follow_symlinks=False):
                            total += entry.stat(follow_symlinks=False).st_size
                        elif entry.is_dir(follow_symlinks=False):
                            stack.append(Path(entry.path))
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def normalize_token(value: str) -> str:
    """Normalize an application or bundle token for fuzzy matching."""
    return re.sub(r"[^a-z0-9]+", "", value.lower())
