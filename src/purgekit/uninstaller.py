from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from send2trash import send2trash

from purgekit.models import RemovalOutcome, ScanResult
from purgekit.process import bootout_launch_plist, terminate_processes
from purgekit.safety import is_sip_protected_path, requires_admin_privileges
from purgekit.utils import get_path_size


def default_history_dir(home: Optional[Path] = None) -> Path:
    return (home or Path.home()) / ".purgekit" / "history"


def _delete_permanently(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _run_privileged_removal(
    paths: Sequence[Path],
    permanent: bool,
    home: Optional[Path] = None,
    forget_pkgs: Sequence[str] = (),
) -> Tuple[bool, str]:
    """Invoke macOS administrator prompt via osascript for protected /Library paths & pkgutil --forget."""
    if not paths and not forget_pkgs:
        return True, ""

    trash_dir = (home or Path.home()) / ".Trash"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    commands: List[str] = []

    for idx, p in enumerate(paths):
        quoted = shlex.quote(str(p))
        if p.suffix == ".plist" and "LaunchDaemons" in p.parts:
            commands.append(f"(launchctl bootout system {quoted} 2>/dev/null || true)")
        if permanent:
            commands.append(f"rm -rf {quoted}")
        else:
            # Move to user's Trash with a unique collision-safe suffix
            dest = trash_dir / f"{p.name}.{stamp}_{idx}"
            commands.append(f"mv {quoted} {shlex.quote(str(dest))}")

    for pkg_id in forget_pkgs:
        commands.append(f"pkgutil --forget {shlex.quote(pkg_id)}")

    shell_cmd = " && ".join(commands)
    escaped_cmd = shell_cmd.replace("\\", "\\\\").replace('"', '\\"')
    applescript = f'do shell script "{escaped_cmd}" with administrator privileges'

    try:
        proc = subprocess.run(
            ["osascript", "-e", applescript],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode == 0:
            return True, ""
        return False, (proc.stderr or proc.stdout or "Administrator authorization failed").strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)


def _write_manifest(outcome: RemovalOutcome, history_dir: Path) -> Path:
    history_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", outcome.app_name).strip("_") or "app"
    manifest_path = history_dir / f"{ts}_{safe_name}.json"
    payload = {
        "timestamp_utc": ts,
        "app_name": outcome.app_name,
        "bundle_id": outcome.bundle_id,
        "reclaimed_bytes": outcome.reclaimed_bytes,
        "trashed": [str(p) for p in outcome.trashed],
        "deleted_permanently": [str(p) for p in outcome.deleted_permanently],
        "forgotten_pkgs": list(outcome.forgotten_pkgs),
        "failed": [{"path": str(p), "error": err} for p, err in outcome.failed],
    }
    manifest_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest_path


def _validate_targets(
    targets: Sequence[Path],
    outcome: RemovalOutcome,
    home: Optional[Path] = None,
) -> List[Path]:
    """Deduplicate targets, skip missing items, and enforce SIP/root safety."""
    seen = set()
    validated: List[Path] = []
    for p in targets:
        abs_p = os.path.abspath(str(p))
        if abs_p in seen:
            continue
        seen.add(abs_p)
        if is_sip_protected_path(p, home=home):
            outcome.failed.append((p, "SIP/kritik sistem yolu koruması nedeniyle atlandı."))
            continue
        if not p.exists() and not p.is_symlink():
            continue
        validated.append(p)
    return validated


def _populate_dry_run(
    validated_targets: Sequence[Path],
    outcome: RemovalOutcome,
    permanent: bool,
) -> RemovalOutcome:
    for p in validated_targets:
        outcome.reclaimed_bytes += get_path_size(p)
        if permanent:
            outcome.deleted_permanently.append(p)
        else:
            outcome.trashed.append(p)
    return outcome


def _remove_standard_targets(
    targets: Sequence[Path],
    outcome: RemovalOutcome,
    permanent: bool,
) -> None:
    for p in targets:
        size = get_path_size(p)
        try:
            if permanent:
                _delete_permanently(p)
                outcome.deleted_permanently.append(p)
            else:
                send2trash(str(p))
                outcome.trashed.append(p)
            outcome.reclaimed_bytes += size
        except Exception as exc:
            outcome.failed.append((p, str(exc)))


def execute_removal(
    scan_result: ScanResult,
    selected_paths: Optional[Sequence[Path]] = None,
    include_app: bool = True,
    permanent: bool = False,
    dry_run: bool = True,
    stop_processes: bool = True,
    allow_admin: bool = False,
    forget_pkgs: bool = False,
    history_dir: Optional[Path] = None,
    home: Optional[Path] = None,
) -> RemovalOutcome:
    """Safely remove an application bundle and selected leftover items."""
    app = scan_result.app
    outcome = RemovalOutcome(
        app_name=app.name,
        bundle_id=app.bundle_id,
        dry_run=dry_run,
    )

    if app.is_protected and include_app:
        outcome.failed.append((app.path, "SIP/Apple korumalı sistem uygulaması kaldırılamaz."))
        return outcome

    if selected_paths is None:
        leftover_targets = [
            item.path for item in scan_result.leftovers if item.selected_by_default
        ]
    else:
        leftover_targets = list(selected_paths)

    targets: List[Path] = []
    if include_app:
        targets.append(app.path)
    targets.extend(leftover_targets)

    pkg_ids_to_forget = [r.pkg_id for r in scan_result.pkg_receipts] if forget_pkgs else []

    validated_targets = _validate_targets(targets, outcome, home=home)
    if dry_run:
        outcome.forgotten_pkgs.extend(pkg_ids_to_forget)
        return _populate_dry_run(validated_targets, outcome, permanent=permanent)

    if stop_processes and scan_result.running_processes:
        terminate_processes(scan_result.running_processes)

    for p in validated_targets:
        if p.suffix == ".plist" and "LaunchAgents" in p.parts:
            bootout_launch_plist(p)

    standard_targets: List[Path] = []
    admin_targets: List[Path] = []
    for p in validated_targets:
        if requires_admin_privileges(p, home=home):
            admin_targets.append(p)
        else:
            standard_targets.append(p)

    _remove_standard_targets(standard_targets, outcome, permanent=permanent)

    if admin_targets or pkg_ids_to_forget:
        if not allow_admin:
            for p in admin_targets:
                outcome.failed.append((p, "Yönetici izni gerektirir (--admin ile çalıştırın)."))
            for pkg_id in pkg_ids_to_forget:
                outcome.failed.append((Path(pkg_id), "pkgutil --forget için --admin izni gerekir."))
        else:
            sizes = {p: get_path_size(p) for p in admin_targets}
            ok, err_msg = _run_privileged_removal(
                admin_targets,
                permanent=permanent,
                home=home,
                forget_pkgs=pkg_ids_to_forget,
            )
            if ok:
                for p in admin_targets:
                    if permanent:
                        outcome.deleted_permanently.append(p)
                    else:
                        outcome.trashed.append(p)
                    outcome.reclaimed_bytes += sizes[p]
                outcome.forgotten_pkgs.extend(pkg_ids_to_forget)
            else:
                for p in admin_targets:
                    outcome.failed.append((p, err_msg))
                for pkg_id in pkg_ids_to_forget:
                    outcome.failed.append((Path(pkg_id), err_msg))

    target_history = history_dir or default_history_dir(home=home)
    outcome.manifest_path = _write_manifest(outcome, target_history)
    return outcome


def execute_path_removal(
    paths: Sequence[Path],
    label: str = "FileCleanup",
    permanent: bool = False,
    dry_run: bool = True,
    allow_admin: bool = False,
    history_dir: Optional[Path] = None,
    home: Optional[Path] = None,
) -> RemovalOutcome:
    """Safely remove arbitrary selected files/folders via the shared safety pipeline."""
    outcome = RemovalOutcome(
        app_name=label,
        bundle_id=None,
        dry_run=dry_run,
    )
    validated = _validate_targets(paths, outcome, home=home)
    if dry_run:
        return _populate_dry_run(validated, outcome, permanent=permanent)

    standard_targets: List[Path] = []
    admin_targets: List[Path] = []
    for p in validated:
        if requires_admin_privileges(p, home=home):
            admin_targets.append(p)
        else:
            standard_targets.append(p)

    _remove_standard_targets(standard_targets, outcome, permanent=permanent)

    if admin_targets:
        if not allow_admin:
            for p in admin_targets:
                outcome.failed.append((p, "Yönetici izni gerektirir (--admin ile çalıştırın)."))
        else:
            sizes = {p: get_path_size(p) for p in admin_targets}
            ok, err_msg = _run_privileged_removal(admin_targets, permanent=permanent, home=home)
            if ok:
                for p in admin_targets:
                    if permanent:
                        outcome.deleted_permanently.append(p)
                    else:
                        outcome.trashed.append(p)
                    outcome.reclaimed_bytes += sizes[p]
            else:
                for p in admin_targets:
                    outcome.failed.append((p, err_msg))

    target_history = history_dir or default_history_dir(home=home)
    outcome.manifest_path = _write_manifest(outcome, target_history)
    return outcome


def execute_orphan_removal(
    paths: Sequence[Path],
    permanent: bool = False,
    dry_run: bool = True,
    history_dir: Optional[Path] = None,
    home: Optional[Path] = None,
) -> RemovalOutcome:
    """Safely remove selected orphan leftover items via the shared safety pipeline."""
    return execute_path_removal(
        paths=paths,
        label="OrphanCleanup",
        permanent=permanent,
        dry_run=dry_run,
        allow_admin=False,
        history_dir=history_dir,
        home=home,
    )


def load_history(history_dir: Optional[Path] = None, limit: int = 20) -> List[Dict]:
    """Load recent uninstall audit manifests from disk."""
    target_dir = history_dir or default_history_dir()
    if not target_dir.is_dir():
        return []

    files = sorted(target_dir.glob("*.json"), reverse=True)[:limit]
    records: List[Dict] = []
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                data["_file"] = str(f)
                records.append(data)
        except Exception:
            continue
    return records
