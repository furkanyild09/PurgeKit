from __future__ import annotations

import os
from pathlib import Path
from typing import List, Optional, Sequence, Set, Tuple

from purgekit.models import AppInfo

SIP_PROTECTED_PREFIXES = (
    "/System",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/libexec",
    "/Library/Apple",
)

GENERIC_VENDOR_TOKENS = frozenset({
    "com",
    "org",
    "net",
    "io",
    "co",
    "me",
    "dev",
    "app",
    "mac",
    "osx",
    "macos",
    "client",
    "desktop",
    "helper",
    "software",
    "studio",
    "labs",
    "inc",
    "llc",
})


def _critical_roots(home: Optional[Path] = None) -> Set[str]:
    user_home = (home or Path.home()).resolve()
    roots = {
        "/",
        "/Applications",
        "/Library",
        "/Library/Application Support",
        "/Library/Caches",
        "/Library/Preferences",
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        "/Library/PrivilegedHelperTools",
        "/Library/Logs",
        str(user_home),
        str(user_home / "Applications"),
        str(user_home / "Library"),
    }
    for sub in (
        "Application Support",
        "Caches",
        "Preferences",
        "Preferences/ByHost",
        "Logs",
        "Saved Application State",
        "Containers",
        "Group Containers",
        "HTTPStorages",
        "WebKit",
        "Application Scripts",
        "LaunchAgents",
        "Cookies",
    ):
        roots.add(str(user_home / "Library" / sub))
    return roots


def is_sip_protected_path(path: Path, home: Optional[Path] = None) -> bool:
    """Return True if path is SIP-protected or a critical system/library root."""
    candidates = [os.path.abspath(str(path))]
    try:
        candidates.append(str(path.resolve()))
    except OSError:
        pass

    critical = _critical_roots(home)
    for candidate in candidates:
        if candidate in critical:
            return True
        for prefix in SIP_PROTECTED_PREFIXES:
            if candidate == prefix or candidate.startswith(prefix + "/"):
                return True
    return False


def is_protected_app(app_path: Path, bundle_id: Optional[str]) -> bool:
    """Return True if an app is an Apple/SIP-protected system bundle."""
    if is_sip_protected_path(app_path):
        return True
    if bundle_id and bundle_id.startswith("com.apple."):
        # Allow inspecting but protect built-in Apple apps in /Applications or /System
        abs_path = os.path.abspath(str(app_path))
        if abs_path.startswith("/System") or abs_path.startswith("/Applications/Utilities"):
            return True
        if abs_path in ("/Applications/Safari.app",):
            return True
    return False


def requires_admin_privileges(path: Path, home: Optional[Path] = None) -> bool:
    """Determine whether modifying or removing `path` likely requires admin elevation."""
    user_home = os.path.abspath(str(home or Path.home()))
    abs_path = os.path.abspath(str(path))
    if abs_path.startswith(user_home + "/"):
        return False

    target = path if path.exists() else path.parent
    if target.exists():
        if os.access(target, os.W_OK) and os.access(target.parent, os.W_OK):
            return False
        return True

    return abs_path.startswith("/Library/")


def check_full_disk_access(home: Optional[Path] = None) -> Tuple[bool, List[Path]]:
    """Probe TCC-protected Library folders to detect missing Full Disk Access."""
    user_home = home or Path.home()
    probes = [
        user_home / "Library" / "Containers",
        user_home / "Library" / "Cookies",
        user_home / "Library" / "Safari",
        user_home / "Library" / "Mail",
    ]
    blocked: List[Path] = []
    for probe in probes:
        if not probe.exists():
            continue
        try:
            with os.scandir(probe) as it:
                next(it, None)
        except PermissionError:
            blocked.append(probe)
        except OSError:
            continue
    return (len(blocked) == 0, blocked)


def extract_vendor_token(bundle_id: Optional[str]) -> Optional[str]:
    """Extract a meaningful vendor identifier from a reverse-DNS bundle ID."""
    if not bundle_id:
        return None
    parts = [part.lower() for part in bundle_id.split(".") if part]
    if len(parts) < 2:
        return None
    candidate = parts[1]
    if len(candidate) < 3 or candidate in GENERIC_VENDOR_TOKENS:
        return None
    return candidate


def get_shared_vendor_tokens(apps: Sequence[AppInfo], target_app: AppInfo) -> Set[str]:
    """Find vendor tokens shared with other installed applications (sibling app check)."""
    target_vendor = extract_vendor_token(target_app.bundle_id)
    if not target_vendor:
        return set()

    shared: Set[str] = set()
    target_resolved = os.path.abspath(str(target_app.path))
    for other in apps:
        if os.path.abspath(str(other.path)) == target_resolved:
            continue
        if other.bundle_id == target_app.bundle_id:
            continue
        other_vendor = extract_vendor_token(other.bundle_id)
        if other_vendor and other_vendor == target_vendor:
            shared.add(other_vendor)
    return shared
