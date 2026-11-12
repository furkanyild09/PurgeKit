from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Set, Tuple

# macOS UF_NODUMP / SF_DATALESS cloud placeholder flag
_SF_DATALESS = 0x40000000


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


def _effective_file_bytes(st: os.stat_result) -> int:
    """Return physical disk footprint, avoiding inflation from cloud placeholders or sparse files."""
    if getattr(st, "st_flags", 0) & _SF_DATALESS:
        return 0
    blocks = getattr(st, "st_blocks", 0)
    if blocks > 0:
        return min(st.st_size, blocks * 512)
    if st.st_size >= 1024 * 1024:
        return 0
    return st.st_size


def get_path_size(path: Path) -> int:
    """Safely calculate physical disk size of a file or directory without following symlinks."""
    try:
        if path.is_symlink():
            return 0
        st_root = path.lstat()
        if os.path.isfile(path):
            return _effective_file_bytes(st_root)
        if not path.is_dir():
            return 0
    except OSError:
        return 0

    total = 0
    seen_hardlinks: Set[Tuple[int, int]] = set()
    stack = [os.fspath(path)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            stack.append(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            st = entry.stat(follow_symlinks=False)
                            if st.st_nlink > 1:
                                key = (st.st_dev, st.st_ino)
                                if key in seen_hardlinks:
                                    continue
                                seen_hardlinks.add(key)
                            total += _effective_file_bytes(st)
                    except OSError:
                        continue
        except OSError:
            continue
    return total


def normalize_token(value: str) -> str:
    """Normalize an application or bundle token for fuzzy matching."""
    return re.sub(r"[^a-z0-9]+", "", value.lower())
