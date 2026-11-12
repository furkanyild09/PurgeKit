from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from purgekit.homebrew import DEFAULT_CASKROOM_ROOTS
from purgekit.models import AppInfo, InstallSource
from purgekit.safety import is_protected_app
from purgekit.utils import get_path_size, normalize_token


def default_app_dirs(home: Optional[Path] = None, include_system: bool = False) -> List[Path]:
    user_home = home or Path.home()
    dirs = [Path("/Applications"), user_home / "Applications"]
    if include_system:
        dirs.append(Path("/System/Applications"))
    return dirs


def _read_homebrew_cask_map(
    caskroom_roots: Optional[Sequence[Path]] = None,
) -> Dict[str, str]:
    """Map installed .app bundle names (lowercase) to Homebrew cask names."""
    cask_map: Dict[str, str] = {}
    for root in (caskroom_roots or DEFAULT_CASKROOM_ROOTS):
        if not root.is_dir():
            continue
        try:
            with os.scandir(root) as casks:
                for cask_entry in casks:
                    if not cask_entry.is_dir(follow_symlinks=False):
                        continue
                    cask_name = cask_entry.name
                    try:
                        with os.scandir(cask_entry.path) as versions:
                            for ver_entry in versions:
                                if not ver_entry.is_dir(follow_symlinks=False) or ver_entry.name.startswith("."):
                                    continue
                                try:
                                    with os.scandir(ver_entry.path) as items:
                                        for item in items:
                                            if item.name.endswith(".app"):
                                                cask_map[item.name.lower()] = cask_name
                                except OSError:
                                    continue
                    except OSError:
                        continue
        except OSError:
            continue
    return cask_map


def read_app_groups(app_path: Path) -> Tuple[str, ...]:
    """Extract com.apple.security.application-groups from code signature entitlements."""
    try:
        proc = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(app_path)],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ()

    raw = proc.stdout or proc.stderr
    if not raw:
        return ()

    start = raw.find(b"<?xml")
    end = raw.rfind(b"</plist>")
    if start == -1 or end == -1:
        return ()

    xml_bytes = raw[start : end + len(b"</plist>")]
    try:
        data = plistlib.loads(xml_bytes)
    except Exception:
        return ()

    if not isinstance(data, dict):
        return ()
    groups = data.get("com.apple.security.application-groups")
    if isinstance(groups, list):
        return tuple(str(g) for g in groups if isinstance(g, str))
    return ()


def parse_app_bundle(
    app_path: Path,
    cask_map: Optional[Dict[str, str]] = None,
    compute_size: bool = True,
    read_entitlements: bool = False,
) -> Optional[AppInfo]:
    """Parse a .app bundle's Info.plist and metadata into an AppInfo instance."""
    if not app_path.is_dir() or app_path.suffix != ".app":
        return None

    plist_path = app_path / "Contents" / "Info.plist"
    plist_data: dict = {}
    if plist_path.is_file():
        try:
            with plist_path.open("rb") as fh:
                loaded = plistlib.load(fh)
                if isinstance(loaded, dict):
                    plist_data = loaded
        except Exception:
            plist_data = {}

    name = (
        plist_data.get("CFBundleDisplayName")
        or plist_data.get("CFBundleName")
        or app_path.stem
    )
    bundle_id = plist_data.get("CFBundleIdentifier")
    version = plist_data.get("CFBundleShortVersionString") or plist_data.get("CFBundleVersion")

    protected = is_protected_app(app_path, bundle_id)
    cask_name = (cask_map or {}).get(app_path.name.lower())

    if protected or str(app_path).startswith("/System"):
        source = InstallSource.SYSTEM
    elif (app_path / "Contents" / "_MASReceipt" / "receipt").exists():
        source = InstallSource.APP_STORE
    elif cask_name:
        source = InstallSource.HOMEBREW
    else:
        source = InstallSource.STANDARD

    size_bytes = get_path_size(app_path) if compute_size else 0
    app_groups = read_app_groups(app_path) if read_entitlements else ()

    return AppInfo(
        name=str(name),
        path=app_path,
        bundle_id=str(bundle_id) if bundle_id else None,
        version=str(version) if version else None,
        source=source,
        size_bytes=size_bytes,
        is_protected=protected,
        app_groups=app_groups,
        cask_name=cask_name,
    )


def _iter_app_bundles(root: Path, max_depth: int = 2) -> List[Path]:
    """Find .app bundles up to `max_depth` without descending inside .app bundles."""
    bundles: List[Path] = []
    if not root.is_dir():
        return bundles

    queue: List[Tuple[Path, int]] = [(root, 0)]
    while queue:
        current, depth = queue.pop(0)
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    entry_path = Path(entry.path)
                    if entry.name.endswith(".app"):
                        bundles.append(entry_path)
                    elif depth + 1 < max_depth and not entry.name.startswith("."):
                        queue.append((entry_path, depth + 1))
        except OSError:
            continue
    return bundles


def find_installed_apps(
    app_dirs: Optional[Sequence[Path]] = None,
    include_system: bool = False,
    compute_sizes: bool = True,
    read_entitlements: bool = False,
    home: Optional[Path] = None,
    caskroom_roots: Optional[Sequence[Path]] = None,
) -> List[AppInfo]:
    """Discover installed macOS applications across standard Application directories."""
    roots = list(app_dirs) if app_dirs is not None else default_app_dirs(home=home, include_system=include_system)
    cask_map = _read_homebrew_cask_map(caskroom_roots=caskroom_roots)
    seen_paths = set()
    apps: List[AppInfo] = []

    for root in roots:
        for bundle_path in _iter_app_bundles(root):
            key = os.path.abspath(str(bundle_path))
            if key in seen_paths:
                continue
            seen_paths.add(key)
            info = parse_app_bundle(
                bundle_path,
                cask_map=cask_map,
                compute_size=compute_sizes,
                read_entitlements=read_entitlements,
            )
            if info:
                apps.append(info)

    apps.sort(key=lambda a: a.name.lower())
    return apps


def resolve_app(query: str, apps: Sequence[AppInfo]) -> List[AppInfo]:
    """Match an application by exact path, bundle ID, exact name, or substring."""
    q = query.strip()
    if not q:
        return []

    q_path = Path(q).expanduser()
    if q_path.suffix == ".app" and q_path.exists():
        abs_q = os.path.abspath(str(q_path))
        for app in apps:
            if os.path.abspath(str(app.path)) == abs_q:
                return [app]
        parsed = parse_app_bundle(q_path, read_entitlements=True)
        return [parsed] if parsed else []

    q_lower = q.lower()
    # 1. Exact bundle_id
    exact_bundle = [a for a in apps if a.bundle_id and a.bundle_id.lower() == q_lower]
    if exact_bundle:
        return exact_bundle

    # 2. Exact name or .app stem
    exact_name = [
        a for a in apps if a.name.lower() == q_lower or a.path.stem.lower() == q_lower
    ]
    if exact_name:
        return exact_name

    # 3. Substring / normalized token match
    q_norm = normalize_token(q)
    matches = [
        a
        for a in apps
        if q_lower in a.name.lower()
        or q_lower in a.path.stem.lower()
        or (a.bundle_id and q_lower in a.bundle_id.lower())
        or (q_norm and q_norm in normalize_token(a.name))
    ]
    return matches
