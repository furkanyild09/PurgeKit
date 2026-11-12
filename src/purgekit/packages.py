from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence

from purgekit.models import AppInfo, PkgReceiptInfo
from purgekit.safety import is_sip_protected_path
from purgekit.utils import get_path_size, normalize_token


def list_all_pkg_ids() -> List[str]:
    """Return all installed package receipt IDs via `pkgutil --pkgs`."""
    try:
        proc = subprocess.run(
            ["pkgutil", "--pkgs"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []

    if proc.returncode != 0:
        return []
    return [line.strip() for line in proc.stdout.splitlines() if line.strip()]


def find_matching_pkg_ids(
    app: AppInfo,
    all_pkg_ids: Optional[Sequence[str]] = None,
) -> List[str]:
    """Find non-Apple `.pkg` receipt IDs belonging to `app`."""
    pkg_ids = list(all_pkg_ids) if all_pkg_ids is not None else list_all_pkg_ids()
    if not app.bundle_id:
        return []

    bundle_lower = app.bundle_id.lower()
    bundle_parts = [p for p in bundle_lower.split(".") if p]
    vendor_prefix = ".".join(bundle_parts[:2]) if len(bundle_parts) >= 2 else ""
    sub_prefix = ".".join(bundle_parts[:3]) if len(bundle_parts) >= 4 else ""
    app_tokens = {
        tok
        for tok in (normalize_token(app.name), normalize_token(app.path.stem))
        if len(tok) >= 4
    }
    if len(bundle_parts) >= 3 and len(normalize_token(bundle_parts[-1])) >= 4:
        app_tokens.add(normalize_token(bundle_parts[-1]))

    matched: List[str] = []
    for pkg_id in pkg_ids:
        pkg_lower = pkg_id.lower()
        if pkg_lower.startswith("com.apple."):
            continue

        if pkg_lower == bundle_lower or pkg_lower.startswith(bundle_lower + "."):
            matched.append(pkg_id)
            continue

        if sub_prefix and pkg_lower.startswith(sub_prefix + "."):
            matched.append(pkg_id)
            continue

        if vendor_prefix and pkg_lower.startswith(vendor_prefix + "."):
            pkg_norm = normalize_token(pkg_lower)
            if any(tok in pkg_norm for tok in app_tokens):
                matched.append(pkg_id)

    return sorted(set(matched))


def inspect_pkg_receipt(
    pkg_id: str,
    app_path: Optional[Path] = None,
    home: Optional[Path] = None,
) -> Optional[PkgReceiptInfo]:
    """Read metadata and existing non-bundle files for a `.pkg` receipt."""
    try:
        info_proc = subprocess.run(
            ["pkgutil", "--pkg-info", pkg_id],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if info_proc.returncode != 0:
            return None

        files_proc = subprocess.run(
            ["pkgutil", "--files", pkg_id],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None

    version: Optional[str] = None
    volume = "/"
    location = ""
    install_time: Optional[str] = None

    for line in info_proc.stdout.splitlines():
        if line.startswith("version:"):
            version = line.split(":", 1)[1].strip() or None
        elif line.startswith("volume:"):
            volume = line.split(":", 1)[1].strip() or "/"
        elif line.startswith("location:"):
            location = line.split(":", 1)[1].strip()
        elif line.startswith("install-time:"):
            install_time = line.split(":", 1)[1].strip() or None

    base = Path(volume) / location.lstrip("/")
    app_resolved = os.path.abspath(str(app_path)) if app_path else None
    external_files: List[Path] = []
    total_bytes = 0

    if files_proc.returncode == 0:
        for rel in files_proc.stdout.splitlines():
            rel = rel.strip()
            if not rel:
                continue
            candidate = base / rel
            cand_abs = os.path.abspath(str(candidate))
            if app_resolved and (cand_abs == app_resolved or cand_abs.startswith(app_resolved + "/")):
                continue
            if is_sip_protected_path(candidate, home=home):
                continue
            if candidate.is_file() or candidate.is_symlink():
                external_files.append(candidate)
                total_bytes += get_path_size(candidate)

    return PkgReceiptInfo(
        pkg_id=pkg_id,
        version=version,
        volume=volume,
        location=location,
        install_time=install_time,
        external_files=external_files,
        total_bytes=total_bytes,
    )
