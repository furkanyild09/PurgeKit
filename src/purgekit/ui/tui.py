from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    SelectionList,
    Static,
    TabbedContent,
    TabPane,
)
from textual.widgets.selection_list import Selection

from purgekit.discovery import find_installed_apps, parse_app_bundle
from purgekit.filesearch import search_files
from purgekit.models import (
    AppInfo,
    FileSearchItem,
    InstallSource,
    OrphanItem,
    RiskLevel,
    ScanMode,
    ScanResult,
    SpaceLensEntry,
    StartupItem,
    SweepItem,
)
from purgekit.safety import requires_admin_privileges
from purgekit.scanner import scan_app_leftovers, scan_orphans
from purgekit.startup import scan_startup_items, unload_startup_items
from purgekit.sweeper import scan_space_lens, scan_sweep_targets
from purgekit.uninstaller import execute_path_removal, execute_removal
from purgekit.utils import format_bytes

RISK_BADGE = {
    RiskLevel.LOW: "[green]● LOW[/green]",
    RiskLevel.MEDIUM: "[yellow]● MED[/yellow]",
    RiskLevel.HIGH: "[red]● HIGH[/red]",
}

THEME_CHOICES: Tuple[Tuple[str, str], ...] = (
    ("tokyo-night", "Tokyo Night"),
    ("textual-dark", "Dark"),
    ("nord", "Nord"),
    ("catppuccin-mocha", "Catppuccin"),
    ("dracula", "Dracula"),
    ("textual-light", "Light"),
)
THEME_LABELS: Dict[str, str] = dict(THEME_CHOICES)


def _reveal_path_in_finder(path: Path) -> None:
    """Reveal a file or directory in macOS Finder (`open -R`)."""
    subprocess.Popen(["open", "-R", str(path)])


def _short_path(path: Path, home: Optional[Path] = None) -> str:
    """Format paths under user home with `~/` for clean TUI display."""
    user_home = str((home or Path.home()).resolve())
    raw = str(path)
    if raw == user_home:
        return "~"
    if raw.startswith(user_home + "/"):
        return "~" + raw[len(user_home) :]
    return raw


def _source_label(app_info: AppInfo) -> str:
    if app_info.cask_name:
        return f"brew:{app_info.cask_name}"
    if app_info.source == InstallSource.APP_STORE:
        return "App Store"
    if app_info.source == InstallSource.SYSTEM:
        return "System"
    return "Standard"


def prepare_terminal_window(min_cols: int = 148, min_rows: int = 42) -> bool:
    """Enlarge interactive macOS terminal window to fit the dual-pane TUI comfortably."""
    if not sys.stdout.isatty():
        return False

    size = shutil.get_terminal_size(fallback=(80, 24))
    target_cols = max(size.columns, min_cols)
    target_rows = max(size.lines, min_rows)
    if target_cols == size.columns and target_rows == size.lines:
        return False

    resized = False
    try:
        sys.stdout.write(f"\x1b[8;{target_rows};{target_cols}t")
        sys.stdout.flush()
        time.sleep(0.06)
        after = shutil.get_terminal_size(fallback=(size.columns, size.lines))
        resized = after.columns >= target_cols and after.lines >= target_rows
    except OSError:
        resized = False

    if not resized and os.environ.get("TERM_PROGRAM") == "Apple_Terminal":
        try:
            script = (
                f'tell application "Terminal" to tell front window '
                f"to set {{number of columns, number of rows}} to {{{target_cols}, {target_rows}}}"
            )
            proc = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                timeout=1.5,
                check=False,
            )
            if proc.returncode == 0:
                time.sleep(0.06)
                resized = True
        except (OSError, subprocess.SubprocessError):
            pass

    return resized


class ConfirmRemovalModal(ModalScreen[bool]):
    """Modal confirmation dialog before moving files to Trash."""

    CSS = """
    ConfirmRemovalModal {
        align: center middle;
        background: $background 70%;
    }
    #confirm-dialog {
        width: 74;
        height: auto;
        border: heavy $error;
        background: $surface;
        padding: 1 2;
    }
    #confirm-title {
        text-style: bold;
        color: $error;
        margin-bottom: 1;
    }
    #confirm-body {
        margin-bottom: 1;
        padding: 1;
        background: $panel;
    }
    #confirm-actions {
        height: 3;
        align: right middle;
    }
    #confirm-actions Button {
        margin-left: 1;
    }
    """

    def __init__(self, title: str, body: str) -> None:
        super().__init__()
        self._title = title
        self._body = body

    def compose(self) -> ComposeResult:
        with Vertical(id="confirm-dialog"):
            yield Label(self._title, id="confirm-title")
            yield Static(self._body, id="confirm-body")
            with Horizontal(id="confirm-actions"):
                yield Button("Cancel", id="modal-cancel")
                yield Button("Move to Trash", variant="error", id="modal-confirm")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "modal-confirm")


class PurgeKitApp(App[None]):
    """Dual-pane Revo Uninstaller inspired Textual TUI for macOS."""

    TITLE = "PurgeKit"
    SUB_TITLE = "Smart macOS Application Uninstaller & File Cleaner"
    CSS = """
    Screen {
        background: $background;
    }
    HeaderIcon {
        width: auto;
        min-width: 12;
        padding: 0 1;
        background: $accent;
        color: $background;
        text-style: bold;
        content-align: center middle;
    }
    HeaderIcon:hover {
        background: $warning;
        color: $background;
    }
    #toolbar {
        height: 3;
        padding: 0 1;
        align: left middle;
        background: $panel;
        border-bottom: solid $primary-darken-2;
    }
    #search-input {
        width: 1fr;
        margin-right: 1;
    }
    #toolbar Button {
        margin-left: 1;
        min-width: 14;
    }
    #btn-theme {
        min-width: 22;
        text-style: bold;
    }
    #main-tabs {
        height: 1fr;
    }
    #apps-split {
        height: 1fr;
        padding: 0 1;
    }
    #left-pane {
        width: 43%;
        border: round $primary;
        border-title-color: $text;
        border-title-style: bold;
        border-subtitle-color: $text-muted;
        padding: 0 1;
        margin-right: 1;
    }
    #apps-table {
        height: 1fr;
    }
    #right-pane {
        width: 57%;
        border: round $accent;
        border-title-color: $text;
        border-title-style: bold;
        border-subtitle-color: $accent;
        padding: 0 1;
    }
    #metrics-row {
        height: 4;
        margin-bottom: 1;
    }
    .metric-card {
        width: 1fr;
        height: 4;
        background: $panel;
        border: round $primary-darken-2;
        content-align: center middle;
        text-align: center;
        margin-right: 1;
    }
    #metric-total {
        margin-right: 0;
        border: round $success-darken-1;
    }
    #app-summary {
        height: auto;
        padding: 0 1;
        background: $panel;
        border-left: tall $accent;
        margin-bottom: 1;
    }
    #leftovers-list, #orphans-list, #files-list, #sweep-list, #startup-list, #lens-list {
        height: 1fr;
        border: round $primary-darken-2;
        border-title-color: $text;
        border-subtitle-color: $text-muted;
    }
    #action-bar, #orphans-action-bar, #files-action-bar, #file-search-bar,
    #sweep-bar, #sweep-action-bar, #startup-action-bar, #lens-nav-bar, #lens-action-bar {
        height: 3;
        margin-top: 1;
        align: left middle;
    }
    #file-search-bar, #sweep-bar, #lens-nav-bar {
        margin-top: 0;
        margin-bottom: 1;
    }
    #file-search-input, #lens-path-input {
        width: 1fr;
        margin-right: 1;
    }
    #action-bar Button, #orphans-action-bar Button, #files-action-bar Button, #file-search-bar Button,
    #sweep-bar Button, #sweep-action-bar Button, #startup-action-bar Button, #lens-nav-bar Button, #lens-action-bar Button {
        margin-right: 1;
    }
    #orphans-container, #files-container, #sweep-container, #startup-container, #lens-container {
        padding: 0 1;
        height: 1fr;
    }
    #orphans-summary, #files-summary, #sweep-summary, #startup-summary, #lens-summary {
        height: auto;
        padding: 1;
        background: $panel;
        border-left: tall $warning;
        margin-bottom: 1;
    }
    #status-line {
        height: 1;
        padding: 0 2;
        background: $panel;
        color: $text-muted;
    }
    """

    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("t", "cycle_theme", "Theme"),
        Binding("f", "open_file_search", "Find Files"),
        Binding("o", "reveal_in_finder", "Finder"),
        Binding("m", "cycle_mode", "Mode"),
        Binding("s", "toggle_sort", "Sort"),
        Binding("r", "refresh_all", "Refresh"),
        Binding("a", "toggle_select_all", "All"),
        Binding("d", "dry_run_preview", "Dry-Run"),
        Binding("u", "request_uninstall", "Uninstall"),
        Binding("/", "focus_search", "Search"),
        Binding("escape", "focus_table", "Back to List", show=False),
    ]

    def __init__(
        self,
        app_dirs: Optional[Sequence[Path]] = None,
        home: Optional[Path] = None,
        system_root: Optional[Path] = None,
        history_dir: Optional[Path] = None,
        config_path: Optional[Path] = None,
        include_system: bool = False,
    ) -> None:
        super().__init__()
        self._app_dirs = app_dirs
        self._home = home
        self._system_root = system_root
        self._history_dir = history_dir
        self._config_path = config_path or ((home or Path.home()) / ".purgekit" / "config.json")
        self._include_system = include_system

        self._mode = ScanMode.MODERATE
        self._sort_by = "name"  # "name" | "size"
        self._file_scope = "user"  # "user" | "library" | "all"
        self._file_type = "all"  # "all" | "file" | "dir"
        self._sweep_min_mb = 50
        self._lens_dir: Path = (home or Path.home()).resolve()
        self._theme_name = self._load_saved_theme()
        self.theme = self._theme_name
        self._all_apps: List[AppInfo] = []
        self._filtered_apps: List[AppInfo] = []
        self._apps_by_key: Dict[str, AppInfo] = {}
        self._current_app: Optional[AppInfo] = None
        self._current_scan: Optional[ScanResult] = None
        self._orphans: List[OrphanItem] = []
        self._file_results: List[FileSearchItem] = []
        self._sweep_items: List[SweepItem] = []
        self._startup_items: List[StartupItem] = []
        self._lens_entries: List[SpaceLensEntry] = []
        self._scan_seq = 0
        self._file_search_seq = 0
        self._startup_seq = 0
        self._startup_scanning = False
        self._startup_loaded_once = False
        self._lens_seq = 0
        self._lens_scanning = False
        self._lens_loaded_once = False
        self._orphans_seq = 0
        self._orphans_scanning = False
        self._sweep_seq = 0
        self._sweep_scanning = False
        self._sweep_loaded_once = False

    def _load_saved_theme(self) -> str:
        try:
            if self._config_path.is_file():
                data = json.loads(self._config_path.read_text(encoding="utf-8"))
                saved = data.get("theme")
                if isinstance(saved, str) and saved in self.available_themes:
                    return saved
        except Exception:
            pass
        return "tokyo-night"

    def _save_theme(self, theme_name: str) -> None:
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            data: Dict[str, str] = {}
            if self._config_path.is_file():
                loaded = json.loads(self._config_path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    data = loaded
            data["theme"] = theme_name
            self._config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _theme_button_label(self) -> str:
        display = THEME_LABELS.get(self._theme_name, self._theme_name)
        return f"🎨 Theme: {display}"

    def compose(self) -> ComposeResult:
        yield Header(icon="☰ Commands")
        with Horizontal(id="toolbar"):
            yield Input(placeholder="Search apps (or press Enter to search Mac files)...", id="search-input")
            yield Button("🔍 Find Files", id="btn-search-files")
            yield Button(self._theme_button_label(), id="btn-theme", variant="warning")
            yield Button("Sort: Name ↑", id="btn-sort")
            yield Button(f"Mode: {self._mode.value.upper()}", id="btn-mode", variant="primary")
            yield Button("Refresh", id="btn-refresh")

        with TabbedContent(id="main-tabs"):
            with TabPane("Applications", id="tab-apps"):
                with Horizontal(id="apps-split"):
                    with Vertical(id="left-pane"):
                        yield DataTable(id="apps-table", cursor_type="row", zebra_stripes=True)
                    with Vertical(id="right-pane"):
                        with Horizontal(id="metrics-row"):
                            yield Static("App Size\n[bold cyan]-[/bold cyan]", id="metric-app", classes="metric-card")
                            yield Static("Leftovers\n[bold yellow]-[/bold yellow]", id="metric-leftovers", classes="metric-card")
                            yield Static("Total Freed\n[bold green]-[/bold green]", id="metric-total", classes="metric-card")
                        yield Static("Select an application...", id="app-summary")
                        yield SelectionList(id="leftovers-list")
                        with Horizontal(id="action-bar"):
                            yield Button("Select All / None", id="btn-toggle-all")
                            yield Button("Reveal in Finder", id="btn-reveal-leftover")
                            yield Button("Dry-Run", id="btn-dry-run")
                            yield Button("Uninstall to Trash", id="btn-uninstall", variant="error")
            with TabPane("File Search", id="tab-files"):
                with Vertical(id="files-container"):
                    with Horizontal(id="file-search-bar"):
                        yield Input(
                            placeholder="Search files or folders on Mac (e.g. .dmg, invoice, spotify)...",
                            id="file-search-input",
                        )
                        yield Button("Search", id="btn-run-file-search", variant="primary")
                        yield Button("Scope: User (~)", id="btn-file-scope")
                        yield Button("Type: All", id="btn-file-type")
                    yield Static(
                        "Type a filename, extension, or keywords and press Enter to scan Spotlight, ~/Library, and user folders.",
                        id="files-summary",
                    )
                    yield SelectionList(id="files-list")
                    with Horizontal(id="files-action-bar"):
                        yield Button("Select All / None", id="btn-files-toggle-all")
                        yield Button("Reveal in Finder", id="btn-files-reveal")
                        yield Button("Dry-Run", id="btn-files-dry-run")
                        yield Button("Move Selected to Trash", id="btn-files-clean", variant="error")
            with TabPane("Space Sweep", id="tab-sweep"):
                with Vertical(id="sweep-container"):
                    with Horizontal(id="sweep-bar"):
                        yield Button("Refresh Sweep", id="btn-scan-sweep", variant="primary")
                        yield Button(f"Min Size: {self._sweep_min_mb} MB", id="btn-sweep-min")
                    yield Static(
                        "Automatically finds old .dmg/.pkg installers, Xcode/Homebrew/npm/pip caches, and large files when opened.",
                        id="sweep-summary",
                    )
                    yield SelectionList(id="sweep-list")
                    with Horizontal(id="sweep-action-bar"):
                        yield Button("Select All / None", id="btn-sweep-toggle-all")
                        yield Button("Reveal in Finder", id="btn-sweep-reveal")
                        yield Button("Dry-Run", id="btn-sweep-dry-run")
                        yield Button("Trash Selected Items", id="btn-sweep-clean", variant="error")
            with TabPane("Startup Services", id="tab-startup"):
                with Vertical(id="startup-container"):
                    yield Static(
                        "Third-party LaunchAgents & LaunchDaemons scan automatically when this tab opens.",
                        id="startup-summary",
                    )
                    yield SelectionList(id="startup-list")
                    with Horizontal(id="startup-action-bar"):
                        yield Button("Refresh Services", id="btn-scan-startup", variant="primary")
                        yield Button("Select All / None", id="btn-startup-toggle-all")
                        yield Button("Unload Selected", id="btn-startup-unload", variant="warning")
                        yield Button("Reveal in Finder", id="btn-startup-reveal")
                        yield Button("Dry-Run", id="btn-startup-dry-run")
                        yield Button("Trash Selected Plists", id="btn-startup-clean", variant="error")
            with TabPane("Disk Lens", id="tab-lens"):
                with Vertical(id="lens-container"):
                    with Horizontal(id="lens-nav-bar"):
                        yield Input(value=_short_path(self._lens_dir, home=self._home), id="lens-path-input")
                        yield Button("Inspect", id="btn-run-lens", variant="primary")
                        yield Button("Up", id="btn-lens-up")
                        yield Button("Drill Selected", id="btn-lens-drill")
                    yield Static(
                        "Measures physical SSD space per subfolder (excluding cloud-only placeholders). Highlight a folder and click 'Drill Selected' to inspect inside.",
                        id="lens-summary",
                    )
                    yield SelectionList(id="lens-list")
                    with Horizontal(id="lens-action-bar"):
                        yield Button("Reveal in Finder", id="btn-lens-reveal")
                        yield Button("Dry-Run", id="btn-lens-dry-run")
                        yield Button("Trash Selected", id="btn-lens-clean", variant="error")
            with TabPane("Orphans", id="tab-orphans"):
                with Vertical(id="orphans-container"):
                    yield Static("Orphaned leftovers from removed apps scan automatically when this tab opens.", id="orphans-summary")
                    yield SelectionList(id="orphans-list")
                    with Horizontal(id="orphans-action-bar"):
                        yield Button("Refresh Orphans", id="btn-scan-orphans", variant="primary")
                        yield Button("Reveal in Finder", id="btn-orphans-reveal")
                        yield Button("Dry-Run", id="btn-orphans-dry-run")
                        yield Button("Trash Selected Orphans", id="btn-orphans-clean", variant="error")

        yield Static("● Ready", id="status-line")
        yield Footer()

    def on_mount(self) -> None:
        left_pane = self.query_one("#left-pane", Vertical)
        left_pane.border_title = "Installed Applications"
        left_pane.border_subtitle = "↑↓ Select  •  / Search"

        right_pane = self.query_one("#right-pane", Vertical)
        right_pane.border_title = "Application Analysis"
        right_pane.border_subtitle = f"Mode: {self._mode.value.upper()}"

        leftovers_list = self.query_one("#leftovers-list", SelectionList)
        leftovers_list.border_title = "Detected Leftovers"
        leftovers_list.border_subtitle = "Space: Toggle"

        files_list = self.query_one("#files-list", SelectionList)
        files_list.border_title = "Matched Files & Folders"
        files_list.border_subtitle = "Space: Toggle"

        orphans_list = self.query_one("#orphans-list", SelectionList)
        orphans_list.border_title = "Orphaned Library Items"
        orphans_list.border_subtitle = "Space: Toggle"

        sweep_list = self.query_one("#sweep-list", SelectionList)
        sweep_list.border_title = "Installers, Dev Caches & Large Files"
        sweep_list.border_subtitle = "Space: Toggle"

        startup_list = self.query_one("#startup-list", SelectionList)
        startup_list.border_title = "LaunchAgents & LaunchDaemons"
        startup_list.border_subtitle = "Space: Toggle"

        lens_list = self.query_one("#lens-list", SelectionList)
        lens_list.border_title = "Folder Footprint Breakdown"
        lens_list.border_subtitle = "Space: Toggle  •  o: Reveal"

        table = self.query_one("#apps-table", DataTable)
        table.add_columns("Application", "Version", "Source", "Size")
        table.focus()
        self._load_apps_worker()

    def _set_status(self, message: str) -> None:
        self.query_one("#status-line", Static).update(message)

    @work(thread=True)
    def _load_apps_worker(self) -> None:
        self.call_from_thread(self._set_status, "[yellow]⟳[/yellow] Scanning installed applications...")
        apps = find_installed_apps(
            app_dirs=self._app_dirs,
            include_system=self._include_system,
            compute_sizes=False,
            home=self._home,
        )
        self.call_from_thread(self._on_apps_loaded, apps)

        sized: List[AppInfo] = []
        for item in apps:
            cask_map = {item.path.name.lower(): item.cask_name} if item.cask_name else None
            updated = parse_app_bundle(item.path, cask_map=cask_map, compute_size=True, read_entitlements=False)
            sized.append(updated or item)
        self.call_from_thread(self._on_apps_sized, sized)

    def _on_apps_loaded(self, apps: List[AppInfo]) -> None:
        self._all_apps = apps
        self._apps_by_key = {os.path.abspath(str(a.path)): a for a in apps}
        self._populate_apps_table(self.query_one("#search-input", Input).value)
        self._set_status(f"[yellow]⟳[/yellow] Found {len(apps)} apps. Calculating sizes...")

    def _on_apps_sized(self, apps: List[AppInfo]) -> None:
        self._all_apps = apps
        self._apps_by_key = {os.path.abspath(str(a.path)): a for a in apps}
        self._populate_apps_table(self.query_one("#search-input", Input).value, preserve_selection=True)
        self._set_status(f"[green]●[/green] {len(apps)} apps ready.")

    def _populate_apps_table(self, search_query: str = "", preserve_selection: bool = False) -> None:
        q = search_query.strip().lower()
        if q:
            filtered = [
                a
                for a in self._all_apps
                if q in a.name.lower() or (a.bundle_id and q in a.bundle_id.lower())
            ]
        else:
            filtered = list(self._all_apps)

        if self._sort_by == "size":
            filtered.sort(key=lambda a: (-a.size_bytes, a.name.lower()))
        else:
            filtered.sort(key=lambda a: a.name.lower())

        self._filtered_apps = filtered
        self.query_one("#left-pane", Vertical).border_title = f"Installed Applications ({len(filtered)})"

        table = self.query_one("#apps-table", DataTable)
        prev_key = os.path.abspath(str(self._current_app.path)) if (preserve_selection and self._current_app) else None
        table.clear()

        target_row_index: Optional[int] = None
        for idx, item in enumerate(filtered):
            row_key = os.path.abspath(str(item.path))
            size_text = format_bytes(item.size_bytes) if item.size_bytes > 0 else "..."
            table.add_row(item.name, item.version or "-", _source_label(item), size_text, key=row_key)
            if prev_key and row_key == prev_key:
                target_row_index = idx

        if filtered and not preserve_selection:
            self._start_app_scan(filtered[0])
        elif target_row_index is not None:
            table.move_cursor(row=target_row_index)
        elif not filtered:
            self._current_app = None
            self._current_scan = None
            self.query_one("#metric-app", Static).update("App Size\n[bold cyan]-[/bold cyan]")
            self.query_one("#metric-leftovers", Static).update("Leftovers\n[bold yellow]-[/bold yellow]")
            self.query_one("#metric-total", Static).update("Total Freed\n[bold green]-[/bold green]")
            self.query_one("#app-summary", Static).update(
                "No matching applications.\n[cyan]Tip:[/cyan] Press [bold]Enter[/bold] or click [bold]🔍 Find Files[/bold] to search all files & folders on your Mac."
            )
            self.query_one("#leftovers-list", SelectionList).clear_options()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "search-input":
            self._populate_apps_table(event.value)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "search-input":
            self.action_open_file_search()
        elif event.input.id == "file-search-input":
            self._start_file_search(event.value)
        elif event.input.id == "lens-path-input":
            self._start_lens_scan(event.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "apps-table" or event.row_key.value is None:
            return
        app_info = self._apps_by_key.get(str(event.row_key.value))
        if app_info:
            self._start_app_scan(app_info)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "apps-table" or event.row_key.value is None:
            return
        app_info = self._apps_by_key.get(str(event.row_key.value))
        if app_info and (
            self._current_app is None
            or os.path.abspath(str(self._current_app.path)) != os.path.abspath(str(app_info.path))
        ):
            self._start_app_scan(app_info)

    def _start_app_scan(self, app_info: AppInfo) -> None:
        self._current_app = app_info
        self._scan_seq += 1
        seq = self._scan_seq
        right_pane = self.query_one("#right-pane", Vertical)
        right_pane.border_title = f"Application Analysis — {app_info.name}"
        right_pane.border_subtitle = f"Mode: {self._mode.value.upper()}"
        self.query_one("#app-summary", Static).update(
            f"Scanning [bold]{app_info.name}[/bold] ({self._mode.value})..."
        )
        self.query_one("#leftovers-list", SelectionList).clear_options()
        self._scan_app_worker(app_info, self._mode, seq)

    @work(thread=True)
    def _scan_app_worker(self, app_info: AppInfo, mode: ScanMode, seq: int) -> None:
        cask_map = {app_info.path.name.lower(): app_info.cask_name} if app_info.cask_name else None
        detailed = (
            parse_app_bundle(app_info.path, cask_map=cask_map, compute_size=True, read_entitlements=True)
            or app_info
        )
        result = scan_app_leftovers(
            detailed,
            self._all_apps,
            mode=mode,
            home=self._home,
            system_root=self._system_root,
            check_processes=(self._system_root is None),
            check_fda=(self._home is None),
            include_pkgutil=(self._system_root is None),
        )
        self.call_from_thread(self._on_app_scanned, result, seq)

    def _on_app_scanned(self, result: ScanResult, seq: int) -> None:
        if seq != self._scan_seq:
            return
        self._current_scan = result
        app_info = result.app

        self.query_one("#metric-app", Static).update(
            f"App Size\n[bold cyan]{format_bytes(app_info.size_bytes)}[/bold cyan]"
        )
        self.query_one("#metric-leftovers", Static).update(
            f"Leftovers ({len(result.leftovers)})\n[bold yellow]{format_bytes(result.leftover_size_bytes)}[/bold yellow]"
        )
        self.query_one("#metric-total", Static).update(
            f"Total Freed\n[bold green]{format_bytes(result.total_size_bytes)}[/bold green]"
        )

        meta_extra = ""
        if app_info.cask_name:
            meta_extra += f"  •  Homebrew: [magenta]{app_info.cask_name}[/magenta]"
        if result.pkg_receipts:
            meta_extra += f"  •  .pkg: [cyan]{len(result.pkg_receipts)}[/cyan]"

        warnings_text = ""
        if result.warnings:
            warnings_text = "\n[yellow]⚠ " + " | ".join(result.warnings) + "[/yellow]"

        summary = (
            f"[bold cyan]{app_info.name}[/bold cyan] ({app_info.version or '?'})  "
            f"[dim]{app_info.bundle_id or '-'}[/dim]{meta_extra}\n"
            f"[dim]Path:[/dim] {_short_path(app_info.path, home=self._home)}"
            f"{warnings_text}"
        )
        self.query_one("#app-summary", Static).update(summary)

        sel_list = self.query_one("#leftovers-list", SelectionList)
        sel_list.clear_options()
        sel_list.border_title = f"Detected Leftovers ({len(result.leftovers)})"
        options: List[Selection[str]] = []
        for item in result.leftovers:
            badge = RISK_BADGE[item.risk]
            admin_tag = " [red][ADMIN][/red]" if item.requires_admin else ""
            short_p = _short_path(item.path, home=self._home)
            label = (
                f"{badge}{admin_tag}  [bold]{format_bytes(item.size_bytes):>8}[/bold]  "
                f"[cyan]{item.category}[/cyan]  {short_p}"
            )
            options.append(Selection(label, str(item.path), initial_state=item.selected_by_default))
        sel_list.add_options(options)
        self._set_status(f"[green]●[/green] {app_info.name}: {len(result.leftovers)} leftover(s) listed.")

    def _start_orphans_scan(self) -> None:
        self._orphans_seq += 1
        self._orphans_scanning = True
        seq = self._orphans_seq
        self.query_one("#orphans-summary", Static).update(
            "[yellow]⟳[/yellow] Scanning ~/Library for orphaned leftovers..."
        )
        self._scan_orphans_worker(seq)

    @work(thread=True)
    def _scan_orphans_worker(self, seq: Optional[int] = None) -> None:
        active_seq = self._orphans_seq if seq is None else seq
        self.call_from_thread(self._set_status, "[yellow]⟳[/yellow] Scanning orphaned leftovers...")
        apps = self._all_apps or find_installed_apps(
            app_dirs=self._app_dirs,
            include_system=self._include_system,
            compute_sizes=False,
            read_entitlements=True,
            home=self._home,
        )
        items = scan_orphans(apps, home=self._home)
        self.call_from_thread(self._on_orphans_loaded, items, active_seq)

    def _on_orphans_loaded(self, items: List[OrphanItem], seq: int) -> None:
        if seq != self._orphans_seq:
            return
        self._orphans_scanning = False
        self._orphans = items
        total = sum(i.size_bytes for i in items)
        self.query_one("#orphans-summary", Static).update(
            f"Orphaned leftovers found: [bold]{len(items)}[/bold]  •  "
            f"Total Size: [bold yellow]{format_bytes(total)}[/bold yellow]"
        )
        sel_list = self.query_one("#orphans-list", SelectionList)
        sel_list.clear_options()
        sel_list.border_title = f"Orphaned Library Items ({len(items)})"
        options: List[Selection[str]] = []
        for item in items:
            badge = RISK_BADGE[item.risk]
            vendor_note = f" [yellow](shared vendor: {item.shared_vendor})[/yellow]" if item.shared_vendor else ""
            label = (
                f"{badge}  [bold]{format_bytes(item.size_bytes):>8}[/bold]  "
                f"[cyan]{item.category}[/cyan]  {item.identifier_hint}{vendor_note}"
            )
            options.append(Selection(label, str(item.path), initial_state=False))
        sel_list.add_options(options)
        self._set_status(f"[green]●[/green] Found {len(items)} orphaned leftover(s).")

    def _start_file_search(self, query: str) -> None:
        q = query.strip()
        if not q:
            self._set_status("Enter a filename, extension, or folder name to search.")
            return
        self._file_search_seq += 1
        seq = self._file_search_seq
        self.query_one("#files-summary", Static).update(
            f"Searching Mac for [bold]{q}[/bold] (scope={self._file_scope}, type={self._file_type})..."
        )
        self.query_one("#files-list", SelectionList).clear_options()
        self._search_files_worker(q, self._file_scope, self._file_type, seq)

    @work(thread=True)
    def _search_files_worker(self, query: str, scope: str, item_type: str, seq: int) -> None:
        self.call_from_thread(self._set_status, f"[yellow]⟳[/yellow] Searching Mac files for '{query}'...")
        items = search_files(
            query=query,
            scope=scope,
            item_type=item_type,
            home=self._home,
            system_root=self._system_root,
            use_spotlight=(self._home is None),
        )
        self.call_from_thread(self._on_files_loaded, items, query, seq)

    def _on_files_loaded(self, items: List[FileSearchItem], query: str, seq: int) -> None:
        if seq != self._file_search_seq:
            return
        self._file_results = items
        total = sum(i.size_bytes for i in items)
        hint = (
            "  •  Try switching Scope to 'All Mac'"
            if not items and self._file_scope != "all"
            else ""
        )
        self.query_one("#files-summary", Static).update(
            f"Query: [bold cyan]{query}[/bold cyan]  •  "
            f"Found: [bold]{len(items)}[/bold] item(s)  •  "
            f"Total Size: [bold yellow]{format_bytes(total)}[/bold yellow]{hint}"
        )
        sel_list = self.query_one("#files-list", SelectionList)
        sel_list.clear_options()
        sel_list.border_title = f"Matched Files & Folders ({len(items)})"
        options: List[Selection[str]] = []
        for item in items:
            badge = RISK_BADGE[item.risk]
            kind_icon = "📁" if item.is_dir else "📄"
            admin_tag = " [red][ADMIN][/red]" if item.requires_admin else ""
            short_p = _short_path(item.path, home=self._home)
            label = (
                f"{badge}{admin_tag}  {kind_icon}  [bold]{format_bytes(item.size_bytes):>8}[/bold]  "
                f"[dim][{item.source}][/dim]  {short_p}"
            )
            options.append(Selection(label, str(item.path), initial_state=False))
        sel_list.add_options(options)
        self._set_status(f"[green]●[/green] Found {len(items)} file/folder match(es) for '{query}'.")

    def _cycle_file_scope(self) -> None:
        order = ("user", "library", "all")
        labels = {"user": "User (~)", "library": "Library", "all": "All Mac"}
        self._file_scope = order[(order.index(self._file_scope) + 1) % len(order)]
        self.query_one("#btn-file-scope", Button).label = f"Scope: {labels[self._file_scope]}"
        current_q = self.query_one("#file-search-input", Input).value
        if current_q.strip():
            self._start_file_search(current_q)

    def _cycle_file_type(self) -> None:
        order = ("all", "file", "dir")
        labels = {"all": "All", "file": "Files", "dir": "Folders"}
        self._file_type = order[(order.index(self._file_type) + 1) % len(order)]
        self.query_one("#btn-file-type", Button).label = f"Type: {labels[self._file_type]}"
        current_q = self.query_one("#file-search-input", Input).value
        if current_q.strip():
            self._start_file_search(current_q)

    def action_open_file_search(self) -> None:
        app_q = self.query_one("#search-input", Input).value.strip()
        tabs = self.query_one("#main-tabs", TabbedContent)
        tabs.active = "tab-files"
        file_input = self.query_one("#file-search-input", Input)
        if app_q:
            file_input.value = app_q
            self._start_file_search(app_q)
        file_input.focus()

    def _active_tab_id(self) -> str:
        return self.query_one("#main-tabs", TabbedContent).active

    def action_focus_search(self) -> None:
        self.query_one("#search-input", Input).focus()

    def action_focus_table(self) -> None:
        self.query_one("#apps-table", DataTable).focus()

    def action_toggle_sort(self) -> None:
        self._sort_by = "size" if self._sort_by == "name" else "name"
        btn_label = "Sort: Size ↓" if self._sort_by == "size" else "Sort: Name ↑"
        self.query_one("#btn-sort", Button).label = btn_label
        self._populate_apps_table(self.query_one("#search-input", Input).value, preserve_selection=True)
        self._set_status(f"[green]●[/green] {btn_label}")

    def action_cycle_theme(self) -> None:
        theme_ids = [t[0] for t in THEME_CHOICES if t[0] in self.available_themes]
        if not theme_ids:
            return
        if self._theme_name in theme_ids:
            next_idx = (theme_ids.index(self._theme_name) + 1) % len(theme_ids)
        else:
            next_idx = 0
        self._theme_name = theme_ids[next_idx]
        self.theme = self._theme_name
        self._save_theme(self._theme_name)
        self.query_one("#btn-theme", Button).label = self._theme_button_label()
        self._set_status(f"[green]●[/green] Theme changed to: {THEME_LABELS.get(self._theme_name, self._theme_name)}")

    def action_cycle_mode(self) -> None:
        order = (ScanMode.SAFE, ScanMode.MODERATE, ScanMode.ADVANCED)
        next_idx = (order.index(self._mode) + 1) % len(order)
        self._mode = order[next_idx]
        self.query_one("#btn-mode", Button).label = f"Mode: {self._mode.value.upper()}"
        if self._current_app:
            self._start_app_scan(self._current_app)

    def _start_sweep_scan(self) -> None:
        self._sweep_seq += 1
        self._sweep_scanning = True
        seq = self._sweep_seq
        self.query_one("#sweep-summary", Static).update(
            f"[yellow]⟳[/yellow] Scanning installers, dev caches, and large files (>= {self._sweep_min_mb} MB)..."
        )
        self._scan_sweep_worker(seq)

    @work(thread=True)
    def _scan_sweep_worker(self, seq: Optional[int] = None) -> None:
        active_seq = self._sweep_seq if seq is None else seq
        self.call_from_thread(
            self._set_status,
            f"[yellow]⟳[/yellow] Scanning installers, dev caches, and large files (>= {self._sweep_min_mb} MB)...",
        )
        items = scan_sweep_targets(min_mb=self._sweep_min_mb, home=self._home)
        self.call_from_thread(self._on_sweep_loaded, items, active_seq)

    def _on_sweep_loaded(self, items: List[SweepItem], seq: int) -> None:
        if seq != self._sweep_seq:
            return
        self._sweep_scanning = False
        self._sweep_loaded_once = True
        self._sweep_items = items
        total = sum(i.size_bytes for i in items)
        self.query_one("#sweep-summary", Static).update(
            f"Sweep targets found: [bold]{len(items)}[/bold]  •  "
            f"Threshold: [cyan]{self._sweep_min_mb} MB[/cyan]  •  "
            f"Reclaimable: [bold yellow]{format_bytes(total)}[/bold yellow]"
        )
        sel_list = self.query_one("#sweep-list", SelectionList)
        sel_list.clear_options()
        sel_list.border_title = f"Installers, Dev Caches & Large Files ({len(items)})"
        options: List[Selection[str]] = []
        for item in items:
            badge = RISK_BADGE[item.risk]
            kind_icon = "📁" if item.is_dir else "📄"
            short_p = _short_path(item.path, home=self._home)
            label = (
                f"{badge}  {kind_icon}  [bold]{format_bytes(item.size_bytes):>8}[/bold]  "
                f"[cyan]{item.category}[/cyan]  {short_p}  [dim]({item.note})[/dim]"
            )
            options.append(Selection(label, str(item.path), initial_state=False))
        sel_list.add_options(options)
        self._set_status(f"[green]●[/green] Space Sweep found {len(items)} item(s) ({format_bytes(total)}).")

    def _cycle_sweep_min(self) -> None:
        order = (50, 250, 1024)
        idx = (order.index(self._sweep_min_mb) + 1) % len(order) if self._sweep_min_mb in order else 0
        self._sweep_min_mb = order[idx]
        lbl = "1 GB" if self._sweep_min_mb == 1024 else f"{self._sweep_min_mb} MB"
        self.query_one("#btn-sweep-min", Button).label = f"Min Size: {lbl}"
        if self._sweep_items:
            self._start_sweep_scan()

    def _start_startup_scan(self) -> None:
        self._startup_seq += 1
        self._startup_scanning = True
        seq = self._startup_seq
        self.query_one("#startup-summary", Static).update(
            "[yellow]⟳[/yellow] Scanning third-party LaunchAgents & LaunchDaemons..."
        )
        self._scan_startup_worker(seq)

    @work(thread=True)
    def _scan_startup_worker(self, seq: Optional[int] = None) -> None:
        active_seq = self._startup_seq if seq is None else seq
        self.call_from_thread(self._set_status, "[yellow]⟳[/yellow] Scanning LaunchAgents & LaunchDaemons...")
        items = scan_startup_items(home=self._home, system_root=self._system_root)
        self.call_from_thread(self._on_startup_loaded, items, active_seq)

    def _on_startup_loaded(self, items: List[StartupItem], seq: int) -> None:
        if seq != self._startup_seq:
            return
        self._startup_scanning = False
        self._startup_loaded_once = True
        self._startup_items = items
        running_count = sum(1 for i in items if i.is_running)
        self.query_one("#startup-summary", Static).update(
            f"Startup services found: [bold]{len(items)}[/bold]  •  "
            f"Active in launchctl: [bold green]{running_count}[/bold green]"
        )
        sel_list = self.query_one("#startup-list", SelectionList)
        sel_list.clear_options()
        sel_list.border_title = f"LaunchAgents & LaunchDaemons ({len(items)})"
        options: List[Selection[str]] = []
        for item in items:
            badge = RISK_BADGE[item.risk]
            state_tag = "[green][RUNNING][/green]" if item.is_running else "[dim][IDLE][/dim]"
            short_p = _short_path(item.path, home=self._home)
            label = f"{badge}  {state_tag}  [cyan]{item.scope}[/cyan]  [bold]{item.label}[/bold]  [dim]{short_p}[/dim]"
            options.append(Selection(label, str(item.path), initial_state=False))
        sel_list.add_options(options)
        self._set_status(f"[green]●[/green] Found {len(items)} startup service(s).")

    def _unload_selected_startup(self) -> None:
        paths = self._selected_paths_for("#startup-list")
        if not paths:
            self._set_status("Select at least one startup service first.")
            return
        outcomes = unload_startup_items(paths, home=self._home, dry_run=False)
        ok_count = sum(1 for ok, _ in outcomes.values() if ok)
        fail_msgs = [msg for ok, msg in outcomes.values() if not ok]
        if fail_msgs:
            self._set_status(f"[yellow]Unloaded {ok_count}/{len(paths)}:[/yellow] {fail_msgs[0]}")
        else:
            self._set_status(f"[green]✓ Unloaded {ok_count} service(s) via launchctl.[/green]")
        self._start_startup_scan()

    def _resolve_lens_input(self, raw_path: str) -> Path:
        text = raw_path.strip() or "~"
        base_home = (self._home or Path.home()).resolve()
        if text == "~":
            return base_home
        if text.startswith("~/"):
            return (base_home / text[2:]).resolve()
        return Path(text).expanduser().resolve()

    def _render_lens_options(self, entries: List[SpaceLensEntry]) -> None:
        sel_list = self.query_one("#lens-list", SelectionList)
        sel_list.clear_options()
        options: List[Selection[str]] = []
        for entry in entries:
            blocks = max(1, int(round((entry.share_pct / 100.0) * 14))) if entry.size_bytes > 0 else 0
            bar = "█" * blocks + "░" * (14 - blocks)
            icon = "📁" if entry.is_dir else "📄"
            prot = " [red][PROTECTED][/red]" if entry.is_protected else ""
            label = (
                f"[cyan]{bar}[/cyan]  {entry.share_pct:5.1f}%  [bold]{format_bytes(entry.size_bytes):>8}[/bold]  "
                f"{icon} {entry.name}{'/' if entry.is_dir else ''}{prot}"
            )
            options.append(Selection(label, str(entry.path), initial_state=False))
        sel_list.add_options(options)

    def _start_lens_scan(self, raw_path: Optional[str] = None) -> None:
        if raw_path is not None:
            self._lens_dir = self._resolve_lens_input(raw_path)
        self._lens_seq += 1
        self._lens_scanning = True
        seq = self._lens_seq
        short_dir = _short_path(self._lens_dir, home=self._home)
        self.query_one("#lens-path-input", Input).value = short_dir
        self.query_one("#lens-list", SelectionList).border_title = f"Disk Lens — {short_dir}"
        self.query_one("#lens-summary", Static).update(
            f"[yellow]⟳[/yellow] Scanning physical SSD footprint under [bold cyan]{short_dir}[/bold cyan]... "
            f"[dim](excluding cloud-only placeholders)[/dim]"
        )
        self._scan_lens_worker(self._lens_dir, seq)

    @work(thread=True)
    def _scan_lens_worker(self, target_dir: Path, seq: int) -> None:
        short_dir = _short_path(target_dir, home=self._home)
        self.call_from_thread(self._set_status, f"[yellow]⟳[/yellow] Measuring physical SSD footprint under {short_dir}...")

        def on_progress(
            done_count: int,
            total_count: int,
            current_name: str,
            total_bytes: int,
            partial_entries: List[SpaceLensEntry],
        ) -> None:
            self.call_from_thread(
                self._on_lens_progress,
                target_dir,
                done_count,
                total_count,
                current_name,
                total_bytes,
                partial_entries,
                seq,
            )

        root, total, entries = scan_space_lens(
            target_dir=target_dir,
            home=self._home,
            progress_cb=on_progress,
            should_cancel=lambda: seq != self._lens_seq,
        )
        self.call_from_thread(self._on_lens_loaded, root, total, entries, seq)

    def _on_lens_progress(
        self,
        root: Path,
        done_count: int,
        total_count: int,
        current_name: str,
        total_bytes: int,
        partial_entries: List[SpaceLensEntry],
        seq: int,
    ) -> None:
        if seq != self._lens_seq:
            return
        short_dir = _short_path(root, home=self._home)
        scanning_part = f" • measuring [bold]{current_name}[/bold]" if current_name else ""
        self.query_one("#lens-summary", Static).update(
            f"[yellow]⟳[/yellow] Directory: [bold cyan]{short_dir}[/bold cyan]  •  "
            f"Scanned: [bold]{done_count}/{total_count}[/bold]{scanning_part}  •  "
            f"Measured so far: [bold green]{format_bytes(total_bytes)}[/bold green]"
        )
        self._set_status(
            f"[yellow]⟳[/yellow] Disk Lens ({done_count}/{total_count}): measuring {current_name or short_dir}..."
        )
        if partial_entries:
            self._lens_entries = partial_entries
            self._render_lens_options(partial_entries)

    def _on_lens_loaded(self, root: Path, total: int, entries: List[SpaceLensEntry], seq: int) -> None:
        if seq != self._lens_seq:
            return
        self._lens_scanning = False
        self._lens_loaded_once = True
        self._lens_dir = root
        self._lens_entries = entries
        short_dir = _short_path(root, home=self._home)
        self.query_one("#lens-summary", Static).update(
            f"Directory: [bold cyan]{short_dir}[/bold cyan]  •  "
            f"Top Entries: [bold]{len(entries)}[/bold]  •  "
            f"Physical SSD Used: [bold green]{format_bytes(total)}[/bold green]  "
            f"[dim](cloud-only placeholders excluded • 'Drill Selected' opens subfolder)[/dim]"
        )
        self.query_one("#lens-list", SelectionList).border_title = f"Disk Lens — {short_dir}"
        self._render_lens_options(entries)
        self._set_status(f"[green]●[/green] Disk Lens measured {format_bytes(total)} in {short_dir}.")

    def _lens_drill_selected(self) -> None:
        target = self._highlighted_path_for("#lens-list")
        if target and target.is_dir():
            self._start_lens_scan(str(target))
        else:
            self._set_status("Highlight a folder in Disk Lens to drill into it.")

    def on_tabbed_content_tab_activated(self, event: TabbedContent.TabActivated) -> None:
        pane_id = event.pane.id if event.pane else ""
        if pane_id == "tab-sweep":
            if not self._sweep_loaded_once and not self._sweep_scanning:
                self._start_sweep_scan()
        elif pane_id == "tab-startup":
            if not self._startup_scanning:
                self._start_startup_scan()
        elif pane_id == "tab-lens":
            if not self._lens_loaded_once and not self._lens_scanning:
                self._start_lens_scan()
        elif pane_id == "tab-orphans":
            if not self._orphans_scanning:
                self._start_orphans_scan()

    def _lens_go_up(self) -> None:
        parent = self._lens_dir.parent
        self._start_lens_scan(str(parent))

    def _highlighted_path_for(self, list_id: str) -> Optional[Path]:
        sel_list = self.query_one(list_id, SelectionList)
        idx = sel_list.highlighted
        if idx is not None and 0 <= idx < sel_list.option_count:
            return Path(str(sel_list.get_option_at_index(idx).value))
        if sel_list.selected:
            return Path(str(sel_list.selected[0]))
        if sel_list.option_count > 0:
            return Path(str(sel_list.get_option_at_index(0).value))
        return None

    def action_reveal_in_finder(self) -> None:
        list_map = {
            "tab-apps": "#leftovers-list",
            "tab-files": "#files-list",
            "tab-sweep": "#sweep-list",
            "tab-startup": "#startup-list",
            "tab-lens": "#lens-list",
            "tab-orphans": "#orphans-list",
        }
        active = self._active_tab_id()
        list_id = list_map.get(active)
        target = self._highlighted_path_for(list_id) if list_id else None
        if target is None and active == "tab-apps" and self._current_app:
            target = self._current_app.path
        if target is None or not target.exists():
            self._set_status("No existing file or folder highlighted to reveal in Finder.")
            return
        try:
            _reveal_path_in_finder(target)
            self._set_status(f"[green]●[/green] Revealed in Finder: {_short_path(target, home=self._home)}")
        except OSError as exc:
            self._set_status(f"[red]Finder error:[/red] {exc}")

    def action_refresh_all(self) -> None:
        active = self._active_tab_id()
        if active == "tab-orphans":
            self._start_orphans_scan()
        elif active == "tab-files":
            self._start_file_search(self.query_one("#file-search-input", Input).value)
        elif active == "tab-sweep":
            self._start_sweep_scan()
        elif active == "tab-startup":
            self._start_startup_scan()
        elif active == "tab-lens":
            self._start_lens_scan(self.query_one("#lens-path-input", Input).value)
        else:
            self._load_apps_worker()

    def action_toggle_select_all(self) -> None:
        list_map = {
            "tab-apps": "#leftovers-list",
            "tab-files": "#files-list",
            "tab-sweep": "#sweep-list",
            "tab-startup": "#startup-list",
            "tab-lens": "#lens-list",
            "tab-orphans": "#orphans-list",
        }
        sel_list = self.query_one(list_map.get(self._active_tab_id(), "#leftovers-list"), SelectionList)
        if len(sel_list.selected) == sel_list.option_count:
            sel_list.deselect_all()
        else:
            sel_list.select_all()

    def _selected_paths_for(self, list_id: str) -> List[Path]:
        sel_list = self.query_one(list_id, SelectionList)
        return [Path(val) for val in sel_list.selected]

    _PATH_TAB_CONFIG: Dict[str, Tuple[str, str, str, str]] = {
        "tab-orphans": ("#orphans-list", "OrphanCleanup", "Orphans", "Trash Orphaned Leftovers"),
        "tab-files": ("#files-list", "FileCleanup", "Files", "Move Selected Files to Trash"),
        "tab-sweep": ("#sweep-list", "SpaceSweep", "Space Sweep", "Trash Selected Sweep Items"),
        "tab-startup": ("#startup-list", "StartupCleanup", "Startup", "Trash Selected Startup Plists"),
        "tab-lens": ("#lens-list", "DiskLensCleanup", "Disk Lens", "Trash Selected Items"),
    }

    def action_dry_run_preview(self) -> None:
        active = self._active_tab_id()
        if active in self._PATH_TAB_CONFIG:
            list_id, label, tag, _ = self._PATH_TAB_CONFIG[active]
            paths = self._selected_paths_for(list_id)
            outcome = execute_path_removal(paths, label=label, dry_run=True, home=self._home)
            self._set_status(
                f"[cyan]DRY-RUN ({tag}):[/cyan] {len(outcome.trashed)} item(s) would be moved to Trash ({format_bytes(outcome.reclaimed_bytes)})."
            )
            return

        if not self._current_scan:
            self._set_status("Select an application first.")
            return
        selected = self._selected_paths_for("#leftovers-list")
        outcome = execute_removal(
            self._current_scan,
            selected_paths=selected,
            include_app=True,
            dry_run=True,
            home=self._home,
        )
        self._set_status(
            f"[cyan]DRY-RUN ({self._current_scan.app.name}):[/cyan] {len(outcome.trashed)} item(s) would be removed ({format_bytes(outcome.reclaimed_bytes)})."
        )

    def _confirm_and_remove_paths(
        self,
        paths: List[Path],
        label: str,
        modal_title: str,
        on_done,
    ) -> None:
        if not paths:
            self._set_status("Select at least one item first.")
            return
        dry = execute_path_removal(paths, label=label, dry_run=True, home=self._home)
        admin_items = [p for p in dry.trashed if requires_admin_privileges(p, home=self._home)]
        admin_note = (
            f"\n• Administrator privileges will be requested for {len(admin_items)} system path(s)."
            if admin_items
            else ""
        )
        body = (
            f"Selected [bold]{len(dry.trashed)}[/bold] item(s) will be moved to Trash.\n"
            f"Reclaimed space: [bold green]{format_bytes(dry.reclaimed_bytes)}[/bold green]{admin_note}"
        )

        def on_confirm(confirmed: Optional[bool]) -> None:
            if not confirmed:
                self._set_status("Operation cancelled.")
                return
            res = execute_path_removal(
                paths,
                label=label,
                dry_run=False,
                allow_admin=bool(admin_items),
                history_dir=self._history_dir,
                home=self._home,
            )
            msg = (
                f"[green]✓ Completed:[/green] {len(res.trashed)} item(s) moved to Trash "
                f"({format_bytes(res.reclaimed_bytes)})."
            )
            if res.failed:
                msg += f" | [red]{len(res.failed)} error(s)![/red]"
            self._set_status(msg)
            on_done()

        self.push_screen(ConfirmRemovalModal(modal_title, body), on_confirm)

    def action_request_uninstall(self) -> None:
        active = self._active_tab_id()
        if active in self._PATH_TAB_CONFIG:
            list_id, label, _, modal_title = self._PATH_TAB_CONFIG[active]
            refresh_callbacks = {
                "tab-orphans": self._start_orphans_scan,
                "tab-files": lambda: self._start_file_search(self.query_one("#file-search-input", Input).value),
                "tab-sweep": self._start_sweep_scan,
                "tab-startup": self._start_startup_scan,
                "tab-lens": lambda: self._start_lens_scan(self.query_one("#lens-path-input", Input).value),
            }
            self._confirm_and_remove_paths(
                self._selected_paths_for(list_id),
                label=label,
                modal_title=modal_title,
                on_done=refresh_callbacks[active],
            )
            return

        if not self._current_scan:
            self._set_status("Select an application first.")
            return
        if self._current_scan.app.is_protected:
            self._set_status(f"[red]{self._current_scan.app.name} is system-protected and cannot be removed.[/red]")
            return

        selected = self._selected_paths_for("#leftovers-list")
        dry = execute_removal(
            self._current_scan,
            selected_paths=selected,
            include_app=True,
            dry_run=True,
            home=self._home,
        )
        admin_items = [
            item
            for item in self._current_scan.leftovers
            if item.path in set(selected) and item.requires_admin
        ]
        extra = ""
        if self._current_scan.running_processes:
            extra += f"\n• {len(self._current_scan.running_processes)} running process(es) will be stopped."
        if admin_items:
            extra += f"\n• Administrator privileges will be requested for {len(admin_items)} system item(s)."

        body = (
            f"[bold]{self._current_scan.app.name}[/bold] and [bold]{len(selected)}[/bold] selected leftover(s) "
            f"will be moved to Trash.\n"
            f"Reclaimed space: [bold green]{format_bytes(dry.reclaimed_bytes)}[/bold green]{extra}"
        )

        def on_confirm(confirmed: Optional[bool]) -> None:
            if not confirmed or not self._current_scan:
                self._set_status("Uninstall cancelled.")
                return
            res = execute_removal(
                self._current_scan,
                selected_paths=selected,
                include_app=True,
                dry_run=False,
                allow_admin=bool(admin_items),
                history_dir=self._history_dir,
                home=self._home,
            )
            msg = (
                f"[green]✓ Completed:[/green] {len(res.trashed)} item(s) moved to Trash "
                f"({format_bytes(res.reclaimed_bytes)})."
            )
            if res.failed:
                msg += f" | [red]{len(res.failed)} error(s)![/red]"
            self._set_status(msg)
            self._load_apps_worker()

        self.push_screen(ConfirmRemovalModal("Uninstall Application", body), on_confirm)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-search-files":
            self.action_open_file_search()
        elif btn_id == "btn-run-file-search":
            self._start_file_search(self.query_one("#file-search-input", Input).value)
        elif btn_id == "btn-file-scope":
            self._cycle_file_scope()
        elif btn_id == "btn-file-type":
            self._cycle_file_type()
        elif btn_id == "btn-theme":
            self.action_cycle_theme()
        elif btn_id == "btn-sort":
            self.action_toggle_sort()
        elif btn_id == "btn-mode":
            self.action_cycle_mode()
        elif btn_id == "btn-refresh":
            self.action_refresh_all()
        elif btn_id in ("btn-toggle-all", "btn-files-toggle-all", "btn-sweep-toggle-all", "btn-startup-toggle-all"):
            self.action_toggle_select_all()
        elif btn_id in (
            "btn-reveal-leftover",
            "btn-files-reveal",
            "btn-sweep-reveal",
            "btn-startup-reveal",
            "btn-lens-reveal",
            "btn-orphans-reveal",
        ):
            self.action_reveal_in_finder()
        elif btn_id in ("btn-dry-run", "btn-orphans-dry-run", "btn-files-dry-run", "btn-sweep-dry-run", "btn-startup-dry-run", "btn-lens-dry-run"):
            self.action_dry_run_preview()
        elif btn_id in ("btn-uninstall", "btn-orphans-clean", "btn-files-clean", "btn-sweep-clean", "btn-startup-clean", "btn-lens-clean"):
            self.action_request_uninstall()
        elif btn_id == "btn-scan-orphans":
            self._start_orphans_scan()
        elif btn_id == "btn-scan-sweep":
            self._start_sweep_scan()
        elif btn_id == "btn-sweep-min":
            self._cycle_sweep_min()
        elif btn_id == "btn-scan-startup":
            self._start_startup_scan()
        elif btn_id == "btn-startup-unload":
            self._unload_selected_startup()
        elif btn_id == "btn-run-lens":
            self._start_lens_scan(self.query_one("#lens-path-input", Input).value)
        elif btn_id == "btn-lens-up":
            self._lens_go_up()
        elif btn_id == "btn-lens-drill":
            self._lens_drill_selected()


def run_tui(include_system: bool = False, resize: bool = True) -> None:
    """Optionally resize terminal window and launch the interactive Textual TUI."""
    if resize:
        prepare_terminal_window()
    PurgeKitApp(include_system=include_system).run()
