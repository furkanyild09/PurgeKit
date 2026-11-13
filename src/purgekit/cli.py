from __future__ import annotations

import json
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional, Sequence

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from purgekit import __version__
from purgekit.discovery import find_installed_apps, parse_app_bundle, resolve_app
from purgekit.filesearch import search_files
from purgekit.homebrew import find_brew_binary, run_brew_uninstall_cask
from purgekit.models import AppInfo, RiskLevel, ScanMode
from purgekit.packages import find_matching_pkg_ids, inspect_pkg_receipt
from purgekit.safety import check_full_disk_access
from purgekit.scanner import scan_app_leftovers, scan_orphans
from purgekit.startup import scan_startup_items, unload_startup_items
from purgekit.sweeper import scan_space_lens, scan_sweep_targets
from purgekit.uninstaller import default_history_dir, execute_path_removal, execute_removal, load_history
from purgekit.utils import format_bytes
from purgekit.watcher import (
    default_trash_dir,
    find_newly_trashed_apps,
    list_trashed_apps,
    scan_trashed_app_leftovers,
)

REPO_GIT_URL = "git+https://github.com/jebidayyah/PurgeKit.git"

app = typer.Typer(
    name="purgekit",
    help="Smart macOS application uninstaller, file finder, and leftover scanner (CLI & TUI).",
)
console = Console()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    include_system: bool = typer.Option(False, "--system", help="Also list Apple system apps in read-only mode."),
    resize: bool = typer.Option(True, "--resize/--no-resize", help="Automatically enlarge the terminal window for the TUI on launch."),
) -> None:
    """Launch the interactive TUI directly when invoked without a subcommand."""
    if ctx.invoked_subcommand is None:
        from purgekit.ui.tui import run_tui

        run_tui(include_system=include_system, resize=resize)


RISK_STYLE = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
}


def _pick_app_interactively(matches: List[AppInfo], query: str) -> Optional[AppInfo]:
    if not matches:
        console.print(f"[red]No installed application matched '{query}'.[/red]")
        return None
    if len(matches) == 1:
        return matches[0]

    table = Table(title="Multiple matches found", box=box.ROUNDED)
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Application", style="bold")
    table.add_column("Bundle ID")
    table.add_column("Path")
    for idx, item in enumerate(matches, start=1):
        table.add_row(str(idx), item.name, item.bundle_id or "-", str(item.path))
    console.print(table)

    choice = Prompt.ask(
        "Select number (0 to cancel)",
        default="1",
    )
    if not choice.isdigit():
        return None
    idx = int(choice)
    if idx <= 0 or idx > len(matches):
        return None
    return matches[idx - 1]


@app.command()
def version() -> None:
    """Show the current PurgeKit version."""
    console.print(f"purgekit v{__version__}")


@app.command("list")
def list_apps(
    include_system: bool = typer.Option(False, "--system", help="Include built-in system apps under /System/Applications."),
    sort_by: str = typer.Option("name", "--sort", help="Sort order: name | size"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="Filter by app name or Bundle ID."),
    no_size: bool = typer.Option(False, "--no-size", help="Skip bundle size calculation for faster listing."),
) -> None:
    """List installed macOS applications."""
    with console.status("Scanning installed applications..."):
        apps = find_installed_apps(
            include_system=include_system,
            compute_sizes=not no_size,
        )

    if search:
        q = search.lower()
        apps = [
            a
            for a in apps
            if q in a.name.lower() or (a.bundle_id and q in a.bundle_id.lower())
        ]

    if sort_by == "size":
        apps.sort(key=lambda a: -a.size_bytes)
    else:
        apps.sort(key=lambda a: a.name.lower())

    table = Table(title=f"Installed Applications ({len(apps)})", box=box.ROUNDED)
    table.add_column("Name", style="bold cyan")
    table.add_column("Version", justify="right")
    table.add_column("Source")
    table.add_column("Size", justify="right")
    table.add_column("Bundle ID", style="dim")

    total_bytes = 0
    for item in apps:
        total_bytes += item.size_bytes
        source_label = item.source.value
        if item.cask_name:
            source_label = f"homebrew ({item.cask_name})"
        if item.is_protected:
            source_label += " [protected]"
        size_text = "-" if no_size else format_bytes(item.size_bytes)
        table.add_row(
            item.name,
            item.version or "-",
            source_label,
            size_text,
            item.bundle_id or "-",
        )

    console.print(table)
    if not no_size:
        console.print(f"Total application footprint: [bold]{format_bytes(total_bytes)}[/bold]")


@app.command()
def scan(
    query: str = typer.Argument(..., help="Application name, Bundle ID, or .app path."),
    mode: ScanMode = typer.Option(ScanMode.MODERATE, "--mode", "-m", help="Scan mode: safe | moderate | advanced"),
    as_json: bool = typer.Option(False, "--json", help="Print output as JSON."),
) -> None:
    """Scan all leftover files and receipts for an application without removing anything."""
    apps = find_installed_apps(compute_sizes=False)
    matches = resolve_app(query, apps)
    target = _pick_app_interactively(matches, query)
    if not target:
        raise typer.Exit(code=1)

    with console.status(f"Scanning leftovers for {target.name} ({mode.value})..."):
        cask_map = {target.path.name.lower(): target.cask_name} if target.cask_name else None
        detailed = (
            parse_app_bundle(target.path, cask_map=cask_map, compute_size=True, read_entitlements=True)
            or target
        )
        result = scan_app_leftovers(detailed, apps, mode=mode)

    if as_json:
        payload = {
            "app": {
                "name": result.app.name,
                "bundle_id": result.app.bundle_id,
                "version": result.app.version,
                "path": str(result.app.path),
                "size_bytes": result.app.size_bytes,
                "source": result.app.source.value,
                "cask_name": result.app.cask_name,
                "protected": result.app.is_protected,
            },
            "mode": result.mode.value,
            "running_processes": [
                {"pid": p.pid, "name": p.name, "exe": p.exe} for p in result.running_processes
            ],
            "pkg_receipts": [
                {
                    "pkg_id": r.pkg_id,
                    "version": r.version,
                    "external_file_count": len(r.external_files),
                    "total_bytes": r.total_bytes,
                }
                for r in result.pkg_receipts
            ],
            "leftovers": [
                {
                    "path": str(item.path),
                    "category": item.category,
                    "size_bytes": item.size_bytes,
                    "risk": item.risk.value,
                    "confidence": item.confidence.value,
                    "reason": item.reason,
                    "requires_admin": item.requires_admin,
                    "selected_by_default": item.selected_by_default,
                }
                for item in result.leftovers
            ],
            "warnings": result.warnings,
            "total_size_bytes": result.total_size_bytes,
        }
        typer.echo(json.dumps(payload, indent=2, ensure_ascii=False))
        return

    _render_scan_result(result)


def _render_scan_result(result) -> None:
    app_info = result.app
    extra_meta = ""
    if app_info.cask_name:
        extra_meta += f" | Homebrew Cask: [magenta]{app_info.cask_name}[/magenta]"
    if result.pkg_receipts:
        extra_meta += f" | .pkg Receipts: [cyan]{len(result.pkg_receipts)}[/cyan]"

    summary = (
        f"[bold]{app_info.name}[/bold] ({app_info.version or '?'})\n"
        f"Path: {app_info.path}\n"
        f"Bundle ID: {app_info.bundle_id or '-'}{extra_meta}\n"
        f"App Size: [cyan]{format_bytes(app_info.size_bytes)}[/cyan] | "
        f"Leftovers ({len(result.leftovers)}): [yellow]{format_bytes(result.leftover_size_bytes)}[/yellow] | "
        f"Total: [bold green]{format_bytes(result.total_size_bytes)}[/bold green]"
    )
    console.print(Panel(summary, title=f"Scan Result ({result.mode.value})", expand=False))

    for warn in result.warnings:
        console.print(f"[yellow]Warning:[/yellow] {warn}")

    if result.running_processes:
        proc_table = Table(title="Running Processes", box=box.SIMPLE)
        proc_table.add_column("PID", justify="right")
        proc_table.add_column("Process")
        proc_table.add_column("Executable", style="dim")
        for proc in result.running_processes:
            proc_table.add_row(str(proc.pid), proc.name, proc.exe or "-")
        console.print(proc_table)

    if not result.leftovers:
        console.print("[green]No matching leftover files found.[/green]")
        return

    table = Table(title="Detected Leftover Files", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Selected", justify="center")
    table.add_column("Risk")
    table.add_column("Category")
    table.add_column("Size", justify="right")
    table.add_column("Path")
    table.add_column("Match Reason", style="dim")

    for idx, item in enumerate(result.leftovers, start=1):
        style = RISK_STYLE[item.risk]
        mark = "✓" if item.selected_by_default else " "
        admin_tag = " [admin]" if item.requires_admin else ""
        table.add_row(
            str(idx),
            mark,
            f"[{style}]{item.risk.value}{admin_tag}[/{style}]",
            item.category,
            format_bytes(item.size_bytes),
            str(item.path),
            item.reason,
        )
    console.print(table)


@app.command()
def uninstall(
    query: str = typer.Argument(..., help="Application name, Bundle ID, or .app path to uninstall."),
    mode: ScanMode = typer.Option(ScanMode.MODERATE, "--mode", "-m", help="Scan mode: safe | moderate | advanced"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview changes without deleting any files."),
    permanent: bool = typer.Option(False, "--permanent", help="Delete permanently instead of moving to Trash."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Uninstall default selected items without confirmation."),
    admin: bool = typer.Option(False, "--admin", help="Prompt for administrator privileges for system paths under /Library."),
    forget_pkgs: bool = typer.Option(False, "--forget-pkgs", help="Run `pkgutil --forget` on matching .pkg receipts (requires --admin)."),
    use_brew: bool = typer.Option(False, "--brew", help="Run `brew uninstall --cask` first if managed by Homebrew."),
    app_only: bool = typer.Option(False, "--app-only", help="Remove only the .app bundle and leave leftovers untouched."),
) -> None:
    """Safely uninstall an application and its selected leftover items."""
    apps = find_installed_apps(compute_sizes=False)
    matches = resolve_app(query, apps)
    target = _pick_app_interactively(matches, query)
    if not target:
        raise typer.Exit(code=1)

    if target.is_protected:
        console.print(f"[red]{target.name} is system-protected and cannot be removed.[/red]")
        raise typer.Exit(code=1)

    with console.status(f"Analyzing {target.name}..."):
        cask_map = {target.path.name.lower(): target.cask_name} if target.cask_name else None
        detailed = (
            parse_app_bundle(target.path, cask_map=cask_map, compute_size=True, read_entitlements=True)
            or target
        )
        result = scan_app_leftovers(detailed, apps, mode=mode)

    _render_scan_result(result)

    selected_paths: List[Path] = []
    if not app_only:
        selected_paths = [
            item.path
            for item in result.leftovers
            if item.selected_by_default and (not item.requires_admin or admin)
        ]

        if not yes and not dry_run and result.leftovers:
            custom = Prompt.ask(
                "Override selection by index? (Enter = default ✓ items, 'all' = everything, or comma-separated e.g. 1,2)",
                default="",
            ).strip()
            if custom.lower() == "all":
                selected_paths = [item.path for item in result.leftovers]
            elif custom:
                chosen: List[Path] = []
                for token in custom.split(","):
                    token = token.strip()
                    if token.isdigit():
                        idx = int(token)
                        if 1 <= idx <= len(result.leftovers):
                            chosen.append(result.leftovers[idx - 1].path)
                if chosen:
                    selected_paths = chosen

    if dry_run:
        if use_brew and result.app.cask_name:
            _, brew_msg = run_brew_uninstall_cask(result.app.cask_name, dry_run=True)
            console.print(f"[magenta]{brew_msg}[/magenta]")
        outcome = execute_removal(
            result,
            selected_paths=selected_paths,
            include_app=True,
            permanent=permanent,
            dry_run=True,
            allow_admin=admin,
            forget_pkgs=forget_pkgs,
        )
        pkg_note = f" | .pkg receipts to forget: {len(outcome.forgotten_pkgs)}" if outcome.forgotten_pkgs else ""
        console.print(
            Panel(
                f"[cyan]DRY-RUN PREVIEW[/cyan]: {len(outcome.trashed) + len(outcome.deleted_permanently)} item(s) "
                f"would be removed ({format_bytes(outcome.reclaimed_bytes)} reclaimed){pkg_note}.",
                expand=False,
            )
        )
        return

    action_label = "PERMANENTLY DELETED" if permanent else "moved to Trash"
    if not yes:
        confirmed = Confirm.ask(
            f"[bold]{result.app.name}[/bold] and {len(selected_paths)} leftover item(s) will be {action_label}. Continue?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]Operation cancelled.[/yellow]")
            raise typer.Exit(code=0)

    include_app_bundle = True
    if use_brew and result.app.cask_name:
        brew_ok, brew_msg = run_brew_uninstall_cask(result.app.cask_name, dry_run=False)
        if brew_ok:
            console.print(f"[magenta]Homebrew:[/magenta] {brew_msg}")
            include_app_bundle = not result.app.path.exists()
        else:
            console.print(f"[yellow]Homebrew warning:[/yellow] {brew_msg}")

    outcome = execute_removal(
        result,
        selected_paths=selected_paths,
        include_app=include_app_bundle,
        permanent=permanent,
        dry_run=False,
        allow_admin=admin,
        forget_pkgs=forget_pkgs,
    )

    removed_count = len(outcome.trashed) + len(outcome.deleted_permanently)
    console.print(
        f"[green]Completed:[/green] {removed_count} item(s) removed, "
        f"[bold]{format_bytes(outcome.reclaimed_bytes)}[/bold] freed."
    )
    if outcome.forgotten_pkgs:
        console.print(f"Forgotten .pkg receipts: {', '.join(outcome.forgotten_pkgs)}")
    if outcome.manifest_path:
        console.print(f"Audit log: [dim]{outcome.manifest_path}[/dim]")
    if outcome.failed:
        console.print("[red]Failed items:[/red]")
        for path, err in outcome.failed:
            console.print(f"  - {path}: {err}")


@app.command()
def orphans(
    min_kb: int = typer.Option(0, "--min-kb", help="Only show orphans at least this many KB."),
) -> None:
    """List orphaned Library leftovers from previously removed applications."""
    with console.status("Scanning for orphaned leftovers..."):
        apps = find_installed_apps(compute_sizes=False, read_entitlements=True)
        items = scan_orphans(apps)

    if min_kb > 0:
        items = [i for i in items if i.size_bytes >= min_kb * 1024]

    if not items:
        console.print("[green]No notable orphaned leftovers found.[/green]")
        return

    table = Table(title=f"Orphaned Leftovers ({len(items)})", box=box.ROUNDED)
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Size", justify="right")
    table.add_column("Identifier", style="cyan")
    table.add_column("Note", style="yellow")
    table.add_column("Path", style="dim")

    total = 0
    for item in items:
        total += item.size_bytes
        style = RISK_STYLE[item.risk]
        note = f"shared vendor: {item.shared_vendor}" if item.shared_vendor else "-"
        table.add_row(
            item.category,
            f"[{style}]{item.risk.value}[/{style}]",
            format_bytes(item.size_bytes),
            item.identifier_hint,
            note,
            str(item.path),
        )
    console.print(table)
    console.print(f"Total orphan footprint: [bold]{format_bytes(total)}[/bold]")


def _prompt_select_paths(paths: Sequence[Path], prompt_label: str) -> List[Path]:
    raw = Prompt.ask(prompt_label, default="").strip()
    if not raw:
        return []
    if raw.lower() == "all":
        return list(paths)
    selected: List[Path] = []
    for token in raw.split(","):
        token = token.strip()
        if token.isdigit():
            idx = int(token)
            if 1 <= idx <= len(paths):
                selected.append(paths[idx - 1])
    return selected


def _interactive_trash_paths(
    candidate_paths: Sequence[Path],
    label: str,
    dry_run: bool,
    admin: bool,
    prompt_label: str = "Enter item numbers to move to Trash (e.g. 1,3 or 'all', Enter to cancel)",
) -> None:
    selected_paths = _prompt_select_paths(candidate_paths, prompt_label)
    if not selected_paths:
        console.print("[yellow]No items selected.[/yellow]")
        return

    if dry_run:
        outcome = execute_path_removal(selected_paths, label=label, dry_run=True, allow_admin=admin)
        console.print(
            Panel(
                f"[cyan]DRY-RUN:[/cyan] {len(outcome.trashed)} item(s) would be moved to Trash ({format_bytes(outcome.reclaimed_bytes)}).",
                expand=False,
            )
        )
        return

    if not Confirm.ask(f"Move {len(selected_paths)} selected item(s) to Trash?", default=False):
        console.print("[yellow]Operation cancelled.[/yellow]")
        return

    outcome = execute_path_removal(selected_paths, label=label, dry_run=False, allow_admin=admin)
    console.print(
        f"[green]Completed:[/green] {len(outcome.trashed)} item(s) moved to Trash ({format_bytes(outcome.reclaimed_bytes)})."
    )
    if outcome.failed:
        for p, err in outcome.failed:
            console.print(f"  [red]- {p}:[/red] {err}")


@app.command()
def find(
    query: str = typer.Argument(..., help="File or folder name to search for."),
    scope: str = typer.Option("user", "--scope", "-s", help="Search scope: user | library | all"),
    item_type: str = typer.Option("all", "--type", "-t", help="Item type filter: all | file | dir"),
    limit: int = typer.Option(60, "--limit", "-n", help="Maximum number of results."),
    trash: bool = typer.Option(False, "--trash", help="Interactively move selected results to Trash."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview removal without deleting when used with --trash."),
    admin: bool = typer.Option(False, "--admin", help="Allow admin prompt for protected /Library paths."),
) -> None:
    """Search for files and folders across macOS (Spotlight + ~/Library + User dirs) and optionally trash them."""
    with console.status(f"Searching Mac for '{query}' ({scope})..."):
        items = search_files(query=query, scope=scope, item_type=item_type, limit=limit)

    if not items:
        console.print(f"[yellow]No files or folders matched '{query}'.[/yellow]")
        return

    table = Table(title=f"Found Files & Folders ({len(items)})", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Type", justify="center")
    table.add_column("Risk")
    table.add_column("Size", justify="right")
    table.add_column("Source", style="dim")
    table.add_column("Path")

    total = 0
    for idx, item in enumerate(items, start=1):
        total += item.size_bytes
        style = RISK_STYLE[item.risk]
        admin_tag = " [admin]" if item.requires_admin else ""
        table.add_row(
            str(idx),
            "Folder" if item.is_dir else "File",
            f"[{style}]{item.risk.value}{admin_tag}[/{style}]",
            format_bytes(item.size_bytes),
            item.source,
            str(item.path),
        )
    console.print(table)
    console.print(f"Total matched size: [bold]{format_bytes(total)}[/bold]")

    if trash:
        _interactive_trash_paths([i.path for i in items], label="FileCleanup", dry_run=dry_run, admin=admin)


@app.command()
def ui(
    include_system: bool = typer.Option(False, "--system", help="Also list Apple system apps in read-only mode."),
    resize: bool = typer.Option(True, "--resize/--no-resize", help="Automatically enlarge the terminal window for the TUI on launch."),
) -> None:
    """Launch the interactive Textual terminal UI (TUI)."""
    from purgekit.ui.tui import run_tui

    run_tui(include_system=include_system, resize=resize)


@app.command()
def doctor() -> None:
    """Check macOS permissions (Full Disk Access) and required system tools."""
    has_fda, blocked = check_full_disk_access()
    codesign_ok = shutil.which("codesign") is not None
    pkgutil_ok = shutil.which("pkgutil") is not None
    launchctl_ok = shutil.which("launchctl") is not None
    hist_dir = default_history_dir()

    table = Table(title="PurgeKit System & Permission Check", box=box.ROUNDED)
    table.add_column("Check", style="bold")
    table.add_column("Status")
    table.add_column("Details")

    table.add_row(
        "Full Disk Access",
        "[green]OK[/green]" if has_fda else "[yellow]MISSING[/yellow]",
        "All protected Library directories are readable."
        if has_fda
        else f"Restricted paths: {', '.join(str(p) for p in blocked)}",
    )
    table.add_row("codesign", "[green]OK[/green]" if codesign_ok else "[red]MISSING[/red]", "App Groups entitlement inspection")
    table.add_row("pkgutil", "[green]OK[/green]" if pkgutil_ok else "[red]MISSING[/red]", ".pkg installer receipt lookup")
    table.add_row("launchctl", "[green]OK[/green]" if launchctl_ok else "[red]MISSING[/red]", "LaunchAgent/Daemon unloading")
    brew_bin = find_brew_binary()
    table.add_row("brew", "[green]OK[/green]" if brew_bin else "[dim]N/A[/dim]", brew_bin or "Homebrew not installed (optional)")
    table.add_row("History Dir", "[green]READY[/green]", str(hist_dir))
    console.print(table)


@app.command()
def pkg(
    query: str = typer.Argument(..., help="Application name/Bundle ID or explicit .pkg receipt ID."),
    show_files: bool = typer.Option(False, "--files", "-f", help="List installed files outside the .app bundle."),
) -> None:
    """Inspect `.pkg` installer receipts (pkgutil) associated with an application."""
    apps = find_installed_apps(compute_sizes=False)
    matches = resolve_app(query, apps)
    app_path: Optional[Path] = None
    if matches:
        target = matches[0]
        app_path = target.path
        pkg_ids = find_matching_pkg_ids(target)
        header = f"{target.name} ({target.bundle_id or '-'})"
    else:
        pkg_ids = [query]
        header = query

    receipts = [r for pid in pkg_ids for r in (inspect_pkg_receipt(pid, app_path=app_path),) if r]
    if not receipts:
        console.print(f"[yellow]No matching .pkg receipts found for {header}.[/yellow]")
        return

    table = Table(title=f".pkg Installer Receipts — {header}", box=box.ROUNDED)
    table.add_column("Package ID", style="cyan")
    table.add_column("Version", justify="right")
    table.add_column("External Files", justify="right")
    table.add_column("Size", justify="right")

    for rec in receipts:
        table.add_row(
            rec.pkg_id,
            rec.version or "-",
            str(len(rec.external_files)),
            format_bytes(rec.total_bytes),
        )
    console.print(table)

    if show_files:
        for rec in receipts:
            if not rec.external_files:
                continue
            console.print(f"\n[bold cyan]{rec.pkg_id}[/bold cyan] (files outside .app):")
            for f in rec.external_files[:100]:
                console.print(f"  - {f}")
            if len(rec.external_files) > 100:
                console.print(f"  ... (+{len(rec.external_files) - 100} more files)")


@app.command()
def history(
    limit: int = typer.Option(15, "--limit", "-n", help="Number of recent operations to display."),
    detail: Optional[int] = typer.Option(None, "--detail", "-d", help="Show details for entry number (1 = most recent)."),
) -> None:
    """Show audit history of past uninstall and cleanup actions."""
    records = load_history(limit=limit)
    if not records:
        console.print("[dim]No recorded removal operations yet.[/dim]")
        return

    if detail is not None:
        if detail < 1 or detail > len(records):
            console.print(f"[red]Invalid entry number: {detail} (1..{len(records)})[/red]")
            raise typer.Exit(code=1)
        rec = records[detail - 1]
        console.print(
            Panel(
                f"[bold]{rec.get('app_name')}[/bold] ({rec.get('bundle_id') or '-'})\n"
                f"Timestamp (UTC): {rec.get('timestamp_utc')}\n"
                f"Reclaimed Space: {format_bytes(int(rec.get('reclaimed_bytes', 0)))}\n"
                f"Manifest: {rec.get('_file')}",
                title="Operation Details",
                expand=False,
            )
        )
        for p in rec.get("trashed", []):
            console.print(f"  [yellow][Trashed][/yellow] {p}")
        for p in rec.get("deleted_permanently", []):
            console.print(f"  [red][Deleted][/red] {p}")
        for pkg_id in rec.get("forgotten_pkgs", []):
            console.print(f"  [cyan][pkgutil --forget][/cyan] {pkg_id}")
        return

    table = Table(title="Removal History", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Timestamp (UTC)")
    table.add_column("Target", style="bold")
    table.add_column("Trashed", justify="right")
    table.add_column("Permanent", justify="right")
    table.add_column("Reclaimed", justify="right")

    for idx, rec in enumerate(records, start=1):
        table.add_row(
            str(idx),
            str(rec.get("timestamp_utc", "-")),
            str(rec.get("app_name", "-")),
            str(len(rec.get("trashed", []))),
            str(len(rec.get("deleted_permanently", []))),
            format_bytes(int(rec.get("reclaimed_bytes", 0))),
        )
    console.print(table)


@app.command()
def sweep(
    min_mb: int = typer.Option(50, "--min-mb", help="Minimum size in MB for large user files & project caches."),
    limit: int = typer.Option(80, "--limit", "-n", help="Maximum number of results."),
    trash: bool = typer.Option(False, "--trash", help="Interactively move selected sweep targets to Trash."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview removal without deleting when used with --trash."),
    admin: bool = typer.Option(False, "--admin", help="Allow admin prompt if needed."),
) -> None:
    """Scan installers (.dmg/.pkg), dev caches (Xcode/Homebrew/npm/pip), and large files."""
    with console.status(f"Scanning space sweep targets (>= {min_mb} MB)..."):
        items = scan_sweep_targets(min_mb=min_mb, limit=limit)

    if not items:
        console.print("[green]No installers, heavy dev caches, or large files matched.[/green]")
        return

    table = Table(title=f"Space Sweep Candidates ({len(items)})", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Category")
    table.add_column("Risk")
    table.add_column("Size", justify="right")
    table.add_column("Path")
    table.add_column("Details", style="dim")

    total = 0
    for idx, item in enumerate(items, start=1):
        total += item.size_bytes
        style = RISK_STYLE[item.risk]
        table.add_row(
            str(idx),
            item.category,
            f"[{style}]{item.risk.value}[/{style}]",
            format_bytes(item.size_bytes),
            str(item.path),
            item.note,
        )
    console.print(table)
    console.print(f"Total reclaimable sweep size: [bold]{format_bytes(total)}[/bold]")

    if trash:
        _interactive_trash_paths([i.path for i in items], label="SpaceSweep", dry_run=dry_run, admin=admin)


@app.command()
def startup(
    include_apple: bool = typer.Option(False, "--apple", help="Also include com.apple.* LaunchAgents/Daemons."),
    unload: bool = typer.Option(False, "--unload", help="Interactively unload selected running startup agents."),
    trash: bool = typer.Option(False, "--trash", help="Interactively move selected startup plists to Trash."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Preview actions without modifying services or files."),
    admin: bool = typer.Option(False, "--admin", help="Prompt for admin privileges when trashing /Library plists."),
) -> None:
    """List, unload, or remove macOS LaunchAgents and LaunchDaemons."""
    with console.status("Scanning macOS LaunchAgents & LaunchDaemons..."):
        items = scan_startup_items(include_apple=include_apple)

    if not items:
        console.print("[green]No third-party startup services found.[/green]")
        return

    table = Table(title=f"Startup & Background Services ({len(items)})", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("State")
    table.add_column("Scope")
    table.add_column("Risk")
    table.add_column("Label", style="bold")
    table.add_column("Path", style="dim")

    for idx, item in enumerate(items, start=1):
        style = RISK_STYLE[item.risk]
        state = "[green]Running[/green]" if item.is_running else "[dim]Loaded/Idle[/dim]"
        table.add_row(
            str(idx),
            state,
            item.scope,
            f"[{style}]{item.risk.value}[/{style}]",
            item.label,
            str(item.path),
        )
    console.print(table)

    paths = [i.path for i in items]
    if unload:
        chosen = _prompt_select_paths(paths, "Enter service numbers to unload via launchctl (e.g. 1,2, Enter to cancel)")
        if chosen:
            outcomes = unload_startup_items(chosen, dry_run=dry_run)
            for p, (ok, msg) in outcomes.items():
                tag = "[green]OK[/green]" if ok else "[red]FAILED[/red]"
                console.print(f"  {tag} {p.name}: {msg}")

    if trash:
        _interactive_trash_paths(paths, label="StartupCleanup", dry_run=dry_run, admin=admin)


@app.command()
def lens(
    target: Optional[Path] = typer.Argument(None, help="Directory to inspect (defaults to your home folder ~)."),
    limit: int = typer.Option(25, "--limit", "-n", help="Number of top entries to show."),
) -> None:
    """Disk Space Lens: inspect top disk usage inside a folder with visual bars."""
    with console.status("Measuring directory sizes..."):
        root, total, entries = scan_space_lens(target_dir=target, limit=limit)

    if not entries:
        console.print(f"[yellow]No readable entries found under {root}.[/yellow]")
        return

    table = Table(title=f"Disk Space Lens — {root}", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Name", style="bold")
    table.add_column("Size", justify="right")
    table.add_column("Share", justify="right")
    table.add_column("Usage")
    table.add_column("Flag", style="dim")

    for idx, entry in enumerate(entries, start=1):
        blocks = max(1, int(round((entry.share_pct / 100.0) * 16))) if entry.size_bytes > 0 else 0
        bar = "█" * blocks + "░" * (16 - blocks)
        kind = f"{entry.name}/" if entry.is_dir else entry.name
        flag = "Protected root" if entry.is_protected else ("Folder" if entry.is_dir else "File")
        table.add_row(
            str(idx),
            kind,
            format_bytes(entry.size_bytes),
            f"{entry.share_pct:5.1f}%",
            f"[cyan]{bar}[/cyan]",
            flag,
        )
    console.print(table)
    console.print(f"Measured total in {root}: [bold]{format_bytes(total)}[/bold]")


@app.command()
def watch(
    mode: ScanMode = typer.Option(ScanMode.MODERATE, "--mode", "-m", help="Leftover scan mode: safe | moderate | advanced"),
    interval: float = typer.Option(2.0, "--interval", help="Polling interval in seconds."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Automatically trash detected leftovers without prompting."),
    dry_run: bool = typer.Option(False, "--dry-run", help="Simulate leftover cleanup without modifying files."),
    once: bool = typer.Option(False, "--once", help="Check Trash once for unexamined apps and exit."),
) -> None:
    """Watch ~/.Trash for newly trashed `.app` bundles and offer leftover cleanup."""
    trash_dir = default_trash_dir()
    seen = {str(p.resolve()) for p in list_trashed_apps(trash_dir)} if not once else set()
    console.print(
        f"[cyan]PurgeKit Trash Watcher active[/cyan] on [bold]{trash_dir}[/bold] "
        f"(already in Trash: {len(seen)} app(s)). Press Ctrl+C to stop."
    )

    try:
        while True:
            new_apps = find_newly_trashed_apps(trash_dir, seen)
            for app_path in new_apps:
                console.print(f"\n[yellow]Detected newly trashed app:[/yellow] [bold]{app_path.name}[/bold]")
                scan_res = scan_trashed_app_leftovers(app_path, mode=mode)
                if not scan_res or not scan_res.leftovers:
                    console.print("[dim]No leftover Library items found for this app.[/dim]")
                    continue
                _render_scan_result(scan_res)
                selected = [item.path for item in scan_res.leftovers if item.selected_by_default and not item.requires_admin]
                if not selected:
                    continue
                if dry_run:
                    outcome = execute_removal(scan_res, selected_paths=selected, include_app=False, dry_run=True)
                    console.print(
                        f"[cyan]DRY-RUN:[/cyan] Would trash {len(outcome.trashed)} leftover(s) ({format_bytes(outcome.reclaimed_bytes)})."
                    )
                    continue
                if yes or Confirm.ask(f"Move {len(selected)} leftover item(s) to Trash?", default=True):
                    outcome = execute_removal(scan_res, selected_paths=selected, include_app=False, dry_run=False)
                    console.print(
                        f"[green]Cleaned:[/green] {len(outcome.trashed)} leftover(s) moved to Trash ({format_bytes(outcome.reclaimed_bytes)})."
                    )
            if once:
                break
            time.sleep(max(0.5, interval))
    except KeyboardInterrupt:
        console.print("\n[dim]Trash Watcher stopped.[/dim]")


@app.command()
def update(
    source: str = typer.Option(REPO_GIT_URL, "--source", help="Git URL or local path to upgrade PurgeKit from."),
) -> None:
    """Update PurgeKit in the active environment with one command."""
    cmd = [sys.executable, "-m", "pip", "install", "--quiet", "--upgrade", source]
    with console.status("Updating PurgeKit..."):
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or f"pip exited with code {proc.returncode}").strip()
        console.print(f"[red]Update failed:[/red] {err}")
        raise typer.Exit(code=1)
    console.print("[green]PurgeKit updated successfully![/green] Run `purgekit` to launch the latest version.")


if __name__ == "__main__":
    app()
