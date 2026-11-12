from __future__ import annotations

import os
import plistlib
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

import psutil

from purgekit.models import AppInfo, RunningProcessInfo


def find_running_processes(app: AppInfo) -> List[RunningProcessInfo]:
    """Find running processes belonging to the given .app bundle."""
    app_prefix = os.path.abspath(str(app.path)).rstrip("/") + "/"
    bundle_lower = app.bundle_id.lower() if app.bundle_id else None
    results: List[RunningProcessInfo] = []
    seen_pids = set()

    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            info = proc.info
            pid = int(info["pid"])
            if pid == os.getpid() or pid in seen_pids:
                continue

            exe = info.get("exe") or ""
            cmdline = info.get("cmdline") or []
            cmd_joined = " ".join(cmdline) if isinstance(cmdline, list) else ""

            matched = False
            if exe and (exe.startswith(app_prefix) or exe == str(app.path)):
                matched = True
            elif cmdline and any(isinstance(arg, str) and arg.startswith(app_prefix) for arg in cmdline):
                matched = True
            elif bundle_lower and bundle_lower in cmd_joined.lower():
                matched = True

            if matched:
                seen_pids.add(pid)
                results.append(
                    RunningProcessInfo(
                        pid=pid,
                        name=str(info.get("name") or Path(exe).name or pid),
                        exe=exe or None,
                    )
                )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return results


def terminate_processes(
    processes: List[RunningProcessInfo],
    timeout_seconds: float = 3.0,
) -> List[Tuple[int, bool]]:
    """Gracefully terminate processes, escalating to SIGKILL if needed."""
    outcomes: List[Tuple[int, bool]] = []
    ps_procs: List[psutil.Process] = []

    for item in processes:
        try:
            proc = psutil.Process(item.pid)
            proc.terminate()
            ps_procs.append(proc)
        except psutil.NoSuchProcess:
            outcomes.append((item.pid, True))
        except psutil.AccessDenied:
            outcomes.append((item.pid, False))

    _, alive = psutil.wait_procs(ps_procs, timeout=timeout_seconds)
    alive_pids = {p.pid for p in alive}

    for proc in ps_procs:
        if proc.pid not in alive_pids:
            outcomes.append((proc.pid, True))

    for proc in alive:
        try:
            proc.kill()
            proc.wait(timeout=1.5)
            outcomes.append((proc.pid, True))
        except (psutil.NoSuchProcess, psutil.TimeoutExpired, psutil.AccessDenied):
            outcomes.append((proc.pid, False))

    return outcomes


def read_launch_label(plist_path: Path) -> Optional[str]:
    """Read the `Label` key from a LaunchAgent or LaunchDaemon plist."""
    try:
        with plist_path.open("rb") as fh:
            data = plistlib.load(fh)
        if isinstance(data, dict) and isinstance(data.get("Label"), str):
            return data["Label"]
    except Exception:
        return None
    return None


def bootout_launch_plist(plist_path: Path) -> Tuple[bool, str]:
    """Unload a LaunchAgent/LaunchDaemon via `launchctl bootout`."""
    uid = os.getuid()
    is_system = str(plist_path).startswith("/Library/LaunchDaemons")
    domain = "system" if is_system else f"gui/{uid}"
    try:
        proc = subprocess.run(
            ["launchctl", "bootout", domain, str(plist_path)],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0:
            return True, "unloaded"
        msg = (proc.stderr or proc.stdout or "").strip()
        # Return code 5 / "No such process" means it wasn't loaded
        if "No such process" in msg or "Could not find service" in msg:
            return True, "not loaded"
        return False, msg or f"exit {proc.returncode}"
    except (OSError, subprocess.SubprocessError) as exc:
        return False, str(exc)
