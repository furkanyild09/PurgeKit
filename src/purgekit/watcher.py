from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence, Set

from purgekit.discovery import find_installed_apps, parse_app_bundle
from purgekit.models import AppInfo, ScanMode, ScanResult
from purgekit.scanner import scan_app_leftovers


def default_trash_dir(home: Optional[Path] = None) -> Path:
    return (home or Path.home()).resolve() / ".Trash"


def list_trashed_apps(trash_dir: Path) -> List[Path]:
    """List immediate `.app` bundles currently present inside Trash."""
    if not trash_dir.is_dir():
        return []
    found: List[Path] = []
    try:
        with os.scandir(trash_dir) as entries:
            for entry in entries:
                if entry.name.endswith(".app") and entry.is_dir(follow_symlinks=False):
                    found.append(Path(entry.path))
    except OSError:
        return []
    found.sort(key=lambda p: p.name.lower())
    return found


def find_newly_trashed_apps(trash_dir: Path, seen_paths: Set[str]) -> List[Path]:
    """Return `.app` bundles in `trash_dir` not yet recorded in `seen_paths`, updating `seen_paths`."""
    current = list_trashed_apps(trash_dir)
    new_apps: List[Path] = []
    for p in current:
        abs_p = os.path.abspath(str(p))
        if abs_p not in seen_paths:
            seen_paths.add(abs_p)
            new_apps.append(p)
    return new_apps


def scan_trashed_app_leftovers(
    trashed_app_path: Path,
    installed_apps: Optional[Sequence[AppInfo]] = None,
    mode: ScanMode = ScanMode.MODERATE,
    home: Optional[Path] = None,
    system_root: Optional[Path] = None,
) -> Optional[ScanResult]:
    """Parse a `.app` bundle moved to Trash and scan for remaining Library leftovers."""
    app_info = parse_app_bundle(
        trashed_app_path,
        compute_size=True,
        read_entitlements=True,
    )
    if not app_info:
        return None

    apps = (
        list(installed_apps)
        if installed_apps is not None
        else find_installed_apps(compute_sizes=False, read_entitlements=True, home=home)
    )
    return scan_app_leftovers(
        app_info,
        apps,
        mode=mode,
        home=home,
        system_root=system_root,
        check_processes=(system_root is None),
        check_fda=False,
        include_pkgutil=False,
    )
