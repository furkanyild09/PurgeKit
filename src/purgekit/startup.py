from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

from purgekit.models import RiskLevel, StartupItem
from purgekit.process import bootout_launch_plist, read_launch_label
from purgekit.safety import is_sip_protected_path, requires_admin_privileges
from purgekit.utils import get_path_size


def _loaded_launchctl_labels() -> Set[str]:
    """Query active service labels from `launchctl list`."""
    if not shutil.which("launchctl"):
        return set()
    try:
        proc = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode != 0:
            return set()
        labels: Set[str] = set()
        for line in proc.stdout.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) == 3 and parts[2] != "-":
                labels.add(parts[2].strip())
        return labels
    except (OSError, subprocess.SubprocessError):
        return set()


def _parse_launch_plist(plist_path: Path) -> Tuple[Optional[str], Optional[str], bool, bool]:
    try:
        with plist_path.open("rb") as fh:
            data = plistlib.load(fh)
        if not isinstance(data, dict):
            return None, None, False, False
        label = data.get("Label") if isinstance(data.get("Label"), str) else plist_path.stem
        exe: Optional[str] = None
        if isinstance(data.get("Program"), str):
            exe = data["Program"]
        elif isinstance(data.get("ProgramArguments"), list) and data["ProgramArguments"]:
            first = data["ProgramArguments"][0]
            if isinstance(first, str):
                exe = first
        run_at_load = bool(data.get("RunAtLoad", False))
        keep_alive = bool(data.get("KeepAlive", False))
        return label, exe, run_at_load, keep_alive
    except Exception:
        return plist_path.stem, None, False, False


def scan_startup_items(
    home: Optional[Path] = None,
    system_root: Optional[Path] = None,
    include_apple: bool = False,
) -> List[StartupItem]:
    """Scan macOS LaunchAgents and LaunchDaemons for user/third-party startup services."""
    user_home = (home or Path.home()).resolve()
    sys_root = (system_root or Path("/")).resolve()
    active_labels = _loaded_launchctl_labels() if system_root is None else set()

    locations: Sequence[Tuple[Path, str, RiskLevel]] = (
        (user_home / "Library" / "LaunchAgents", "User Agent", RiskLevel.LOW),
        (sys_root / "Library" / "LaunchAgents", "System Agent", RiskLevel.HIGH),
        (sys_root / "Library" / "LaunchDaemons", "System Daemon", RiskLevel.HIGH),
    )

    items: List[StartupItem] = []
    for folder, scope, risk in locations:
        if not folder.is_dir():
            continue
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    if not entry.name.endswith(".plist"):
                        continue
                    p = Path(entry.path)
                    if is_sip_protected_path(p, home=user_home):
                        continue
                    label, exe, run_at_load, keep_alive = _parse_launch_plist(p)
                    svc_label = label or p.stem
                    if not include_apple and svc_label.startswith("com.apple."):
                        continue
                    items.append(
                        StartupItem(
                            path=p,
                            label=svc_label,
                            scope=scope,
                            executable=exe,
                            size_bytes=get_path_size(p),
                            risk=risk,
                            is_running=(svc_label in active_labels),
                            run_at_load=run_at_load,
                            keep_alive=keep_alive,
                            requires_admin=requires_admin_privileges(p, home=user_home),
                        )
                    )
        except OSError:
            continue

    items.sort(key=lambda item: (0 if item.is_running else 1, item.scope, item.label.lower()))
    return items


def unload_startup_items(
    paths: Sequence[Path],
    home: Optional[Path] = None,
    dry_run: bool = True,
) -> Dict[Path, Tuple[bool, str]]:
    """Stop/unload LaunchAgent or LaunchDaemon plists via `launchctl bootout`."""
    results: Dict[Path, Tuple[bool, str]] = {}
    for p in paths:
        label = read_launch_label(p) or p.stem
        if dry_run:
            results[p] = (True, f"DRY-RUN: launchctl bootout {label}")
            continue
        if requires_admin_privileges(p, home=home):
            results[p] = (False, "System daemon/agent unload requires sudo/admin privileges.")
            continue
        ok, msg = bootout_launch_plist(p)
        results[p] = (ok, msg or f"Unloaded {label}")
    return results
