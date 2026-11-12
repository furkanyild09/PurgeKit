from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

from purgekit.safety import is_sip_protected_path

DEFAULT_CASKROOM_ROOTS = (
    Path("/opt/homebrew/Caskroom"),
    Path("/usr/local/Caskroom"),
)


def find_brew_binary() -> Optional[str]:
    """Locate the Homebrew CLI binary if installed."""
    found = shutil.which("brew")
    if found:
        return found
    for candidate in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _expand_cask_path(raw: str, home: Optional[Path] = None) -> Optional[Path]:
    """Expand `~` safely and ignore wildcard/templated Ruby expressions."""
    cleaned = raw.strip().strip('"').strip("'")
    if not cleaned or any(ch in cleaned for ch in ("*", "?", "#{", "[")):
        return None
    if cleaned.startswith("~/"):
        return (home or Path.home()) / cleaned[2:]
    if cleaned.startswith("/"):
        return Path(cleaned)
    return None


def _extract_zap_from_json(json_path: Path, home: Optional[Path] = None) -> List[Path]:
    paths: List[Path] = []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return paths

    casks = data.get("casks") if isinstance(data, dict) else ([data] if isinstance(data, dict) else [])
    if not isinstance(casks, list):
        casks = [data] if isinstance(data, dict) else []

    for cask in casks:
        if not isinstance(cask, dict):
            continue
        artifacts = cask.get("artifacts") or []
        if not isinstance(artifacts, list):
            continue
        for artifact in artifacts:
            if not isinstance(artifact, dict) or "zap" not in artifact:
                continue
            zap_entries = artifact["zap"]
            if not isinstance(zap_entries, list):
                continue
            for entry in zap_entries:
                if not isinstance(entry, dict):
                    continue
                for key in ("trash", "delete"):
                    items = entry.get(key)
                    if isinstance(items, str):
                        items = [items]
                    if isinstance(items, list):
                        for raw in items:
                            if isinstance(raw, str):
                                expanded = _expand_cask_path(raw, home=home)
                                if expanded:
                                    paths.append(expanded)
    return paths


def _extract_zap_from_rb(rb_path: Path, home: Optional[Path] = None) -> List[Path]:
    paths: List[Path] = []
    try:
        text = rb_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return paths

    zap_idx = text.find("zap ")
    if zap_idx == -1:
        return paths

    zap_section = text[zap_idx:]
    for match in re.findall(r"""["']((?:~/|/)[^"'\n]+)["']""", zap_section):
        expanded = _expand_cask_path(match, home=home)
        if expanded:
            paths.append(expanded)
    return paths


def get_cask_zap_paths(
    cask_name: str,
    caskroom_roots: Optional[Sequence[Path]] = None,
    home: Optional[Path] = None,
) -> List[Path]:
    """Read local Caskroom `.metadata` zap paths without needing network access."""
    roots = caskroom_roots or DEFAULT_CASKROOM_ROOTS
    candidates: List[Path] = []
    seen = set()

    for root in roots:
        meta_dir = root / cask_name / ".metadata"
        if not meta_dir.is_dir():
            continue
        for json_file in meta_dir.rglob(f"{cask_name}.json"):
            candidates.extend(_extract_zap_from_json(json_file, home=home))
        for rb_file in meta_dir.rglob(f"{cask_name}.rb"):
            candidates.extend(_extract_zap_from_rb(rb_file, home=home))

    existing: List[Path] = []
    for p in candidates:
        abs_p = os.path.abspath(str(p))
        if abs_p in seen or is_sip_protected_path(p, home=home):
            continue
        seen.add(abs_p)
        if p.exists() or p.is_symlink():
            existing.append(p)
    return existing


def run_brew_uninstall_cask(
    cask_name: str,
    zap: bool = False,
    dry_run: bool = True,
) -> Tuple[bool, str]:
    """Invoke `brew uninstall --cask` when Homebrew is installed."""
    brew_bin = find_brew_binary()
    if not brew_bin:
        return False, "Homebrew (`brew`) was not found on this system."

    cmd = [brew_bin, "uninstall", "--cask"]
    if zap:
        cmd.append("--zap")
    cmd.append(cask_name)

    if dry_run:
        return True, f"DRY-RUN: {' '.join(cmd)}"

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode == 0:
            return True, (proc.stdout or "brew uninstall completed").strip()
        return False, (proc.stderr or proc.stdout or f"brew exit {proc.returncode}").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
