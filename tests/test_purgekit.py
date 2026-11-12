from __future__ import annotations

import json
import plistlib
from pathlib import Path

from typer.testing import CliRunner

from purgekit.cli import app as cli_app
from purgekit.discovery import find_installed_apps, resolve_app
from purgekit.models import AppInfo, InstallSource, RiskLevel, ScanMode
from purgekit.safety import get_shared_vendor_tokens, is_sip_protected_path
from purgekit.scanner import scan_app_leftovers, scan_orphans
from purgekit.uninstaller import execute_orphan_removal, execute_removal


def _create_fake_app(
    root: Path,
    name: str,
    bundle_id: str,
    version: str = "1.0.0",
    mas: bool = False,
) -> Path:
    app_dir = root / f"{name}.app"
    contents = app_dir / "Contents"
    macos = contents / "MacOS"
    macos.mkdir(parents=True)
    (macos / name).write_bytes(b"binary-data" * 100)

    plist_data = {
        "CFBundleName": name,
        "CFBundleDisplayName": name,
        "CFBundleIdentifier": bundle_id,
        "CFBundleShortVersionString": version,
    }
    with (contents / "Info.plist").open("wb") as fh:
        plistlib.dump(plist_data, fh)

    if mas:
        receipt = contents / "_MASReceipt" / "receipt"
        receipt.parent.mkdir(parents=True)
        receipt.write_bytes(b"receipt")

    return app_dir


def test_discovery_and_resolve(tmp_path: Path) -> None:
    apps_dir = tmp_path / "Applications"
    apps_dir.mkdir()
    _create_fake_app(apps_dir, "AcmePlayer", "com.acme.player", version="2.4.1")
    _create_fake_app(apps_dir, "StoreNote", "com.store.note", mas=True)

    apps = find_installed_apps(app_dirs=[apps_dir], compute_sizes=True)
    assert len(apps) == 2

    acme = resolve_app("com.acme.player", apps)[0]
    assert acme.name == "AcmePlayer"
    assert acme.version == "2.4.1"
    assert acme.source == InstallSource.STANDARD
    assert acme.size_bytes > 0

    note = resolve_app("StoreNote", apps)[0]
    assert note.source == InstallSource.APP_STORE


def test_sip_and_critical_root_protection(tmp_path: Path) -> None:
    assert is_sip_protected_path(Path("/System/Applications/Safari.app"), home=tmp_path)
    assert is_sip_protected_path(Path("/usr/bin/python3"), home=tmp_path)
    assert is_sip_protected_path(tmp_path / "Library" / "Application Support", home=tmp_path)
    assert not is_sip_protected_path(
        tmp_path / "Library" / "Application Support" / "AcmePlayer", home=tmp_path
    )


def test_scanner_modes_and_sibling_vendor_protection(tmp_path: Path) -> None:
    home = tmp_path / "home"
    sys_root = tmp_path / "sys"
    apps_dir = sys_root / "Applications"
    apps_dir.mkdir(parents=True)

    chrome_path = _create_fake_app(apps_dir, "Chrome", "com.google.Chrome")
    _create_fake_app(apps_dir, "Drive", "com.google.drivefs")

    # User Library files
    user_lib = home / "Library"
    (user_lib / "Caches" / "com.google.Chrome").mkdir(parents=True)
    (user_lib / "Caches" / "com.google.Chrome" / "cache.bin").write_bytes(b"x" * 50)

    (user_lib / "Preferences").mkdir(parents=True)
    (user_lib / "Preferences" / "com.google.Chrome.plist").write_bytes(b"plist")

    # Shared vendor folder containing both Chrome and Drive
    (user_lib / "Application Support" / "Google" / "Chrome").mkdir(parents=True)
    (user_lib / "Application Support" / "Google" / "Chrome" / "Default").write_text("profile")
    (user_lib / "Application Support" / "Google" / "Drive").mkdir(parents=True)
    (user_lib / "Application Support" / "Google" / "Drive" / "sync.db").write_text("drive")

    # System LaunchDaemon (only in ADVANCED mode)
    (sys_root / "Library" / "LaunchDaemons").mkdir(parents=True)
    (sys_root / "Library" / "LaunchDaemons" / "com.google.Chrome.daemon.plist").write_text("daemon")

    apps = find_installed_apps(app_dirs=[apps_dir], compute_sizes=True)
    chrome_app = resolve_app("com.google.Chrome", apps)[0]
    assert "google" in get_shared_vendor_tokens(apps, chrome_app)

    # Safe mode: exact bundle_id user items
    safe_scan = scan_app_leftovers(
        chrome_app,
        apps,
        mode=ScanMode.SAFE,
        home=home,
        system_root=sys_root,
        check_processes=False,
        check_fda=False,
        include_pkgutil=False,
    )
    safe_paths = {p.path for p in safe_scan.leftovers}
    assert user_lib / "Caches" / "com.google.Chrome" in safe_paths
    assert user_lib / "Preferences" / "com.google.Chrome.plist" in safe_paths
    assert user_lib / "Application Support" / "Google" not in safe_paths

    # Moderate mode: protects parent Google folder, targets nested Chrome folder instead
    mod_scan = scan_app_leftovers(
        chrome_app,
        apps,
        mode=ScanMode.MODERATE,
        home=home,
        system_root=sys_root,
        check_processes=False,
        check_fda=False,
        include_pkgutil=False,
    )
    mod_paths = {p.path for p in mod_scan.leftovers}
    assert user_lib / "Application Support" / "Google" not in mod_paths
    assert user_lib / "Application Support" / "Google" / "Chrome" in mod_paths
    assert user_lib / "Application Support" / "Google" / "Drive" not in mod_paths
    assert sys_root / "Library" / "LaunchDaemons" / "com.google.Chrome.daemon.plist" not in mod_paths

    # Advanced mode: picks up LaunchDaemons as HIGH risk
    adv_scan = scan_app_leftovers(
        chrome_app,
        apps,
        mode=ScanMode.ADVANCED,
        home=home,
        system_root=sys_root,
        check_processes=False,
        check_fda=False,
        include_pkgutil=False,
    )
    daemon_items = [i for i in adv_scan.leftovers if i.category == "System LaunchDaemons"]
    assert len(daemon_items) == 1
    assert daemon_items[0].risk == RiskLevel.HIGH
    assert daemon_items[0].selected_by_default is False


def test_execute_removal_dry_run_and_permanent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    apps_dir = home / "Applications"
    apps_dir.mkdir(parents=True)
    app_path = _create_fake_app(apps_dir, "TempTool", "com.example.temptool")

    cache_dir = home / "Library" / "Caches" / "com.example.temptool"
    cache_dir.mkdir(parents=True)
    (cache_dir / "data.bin").write_bytes(b"abc" * 100)

    apps = find_installed_apps(app_dirs=[apps_dir], compute_sizes=True)
    target = apps[0]
    scan_res = scan_app_leftovers(
        target,
        apps,
        mode=ScanMode.MODERATE,
        home=home,
        system_root=tmp_path / "sys",
        check_processes=False,
        check_fda=False,
        include_pkgutil=False,
    )

    # Dry run keeps files intact
    dry = execute_removal(scan_res, dry_run=True, permanent=True, home=home)
    assert app_path.exists()
    assert cache_dir.exists()
    assert dry.reclaimed_bytes > 0

    # Permanent removal in isolated tmp_path deletes files and writes audit manifest
    history_dir = home / ".purgekit" / "history"
    real = execute_removal(
        scan_res,
        dry_run=False,
        permanent=True,
        stop_processes=False,
        history_dir=history_dir,
        home=home,
    )
    assert not app_path.exists()
    assert not cache_dir.exists()
    assert real.manifest_path is not None
    assert real.manifest_path.is_file()
    manifest = json.loads(real.manifest_path.read_text(encoding="utf-8"))
    assert manifest["app_name"] == "TempTool"
    assert len(manifest["deleted_permanently"]) == 2


def test_orphan_scanner_and_cleanup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    apps_dir = home / "Applications"
    apps_dir.mkdir(parents=True)
    _create_fake_app(apps_dir, "AliveApp", "com.alive.app")

    (home / "Library" / "Caches" / "com.alive.app").mkdir(parents=True)
    ghost = home / "Library" / "Caches" / "com.deleted.ghost"
    ghost.mkdir(parents=True)
    (ghost / "blob").write_bytes(b"12345")
    (home / "Library" / "Caches" / "com.alive.updater").mkdir(parents=True)
    (home / "Library" / "Caches" / "com.apple.Safari").mkdir(parents=True)

    apps = find_installed_apps(app_dirs=[apps_dir], compute_sizes=False)
    orphans = scan_orphans(apps, home=home)
    by_hint = {o.identifier_hint: o for o in orphans}
    assert "com.deleted.ghost" in by_hint
    assert by_hint["com.deleted.ghost"].shared_vendor is None
    assert "com.alive.updater" in by_hint
    assert by_hint["com.alive.updater"].shared_vendor == "alive"
    assert "com.alive.app" not in by_hint
    assert "com.apple.Safari" not in by_hint

    dry = execute_orphan_removal([ghost], dry_run=True, permanent=True, home=home)
    assert ghost.exists()
    assert dry.reclaimed_bytes == 5

    real = execute_orphan_removal(
        [ghost],
        dry_run=False,
        permanent=True,
        history_dir=home / ".purgekit" / "history",
        home=home,
    )
    assert not ghost.exists()
    assert real.manifest_path is not None and real.manifest_path.is_file()


def test_cli_version_and_doctor() -> None:
    runner = CliRunner()
    res_ver = runner.invoke(cli_app, ["version"])
    assert res_ver.exit_code == 0
    assert "purgekit v" in res_ver.stdout

    res_doc = runner.invoke(cli_app, ["doctor"])
    assert res_doc.exit_code == 0
    assert "Full Disk Access" in res_doc.stdout


def test_cli_bare_command_launches_tui(monkeypatch) -> None:
    import purgekit.ui.tui as tui_mod

    called = {}

    def fake_run_tui(include_system: bool = False, resize: bool = True) -> None:
        called["include_system"] = include_system
        called["resize"] = resize

    monkeypatch.setattr(tui_mod, "run_tui", fake_run_tui)
    runner = CliRunner()
    res = runner.invoke(cli_app, [])
    assert res.exit_code == 0
    assert called == {"include_system": False, "resize": True}


def test_tui_smoke_flow(tmp_path: Path) -> None:
    import asyncio
    from textual.widgets import DataTable, SelectionList, Static
    from purgekit.ui.tui import PurgeKitApp

    home = tmp_path / "home"
    sys_root = tmp_path / "sys"
    apps_dir = sys_root / "Applications"
    apps_dir.mkdir(parents=True)
    _create_fake_app(apps_dir, "BetaNote", "com.beta.note", version="3.1.0")
    _create_fake_app(apps_dir, "AlphaPlayer", "com.alpha.player", version="1.2.0")

    cache_dir = home / "Library" / "Caches" / "com.alpha.player"
    cache_dir.mkdir(parents=True)
    (cache_dir / "blob.dat").write_bytes(b"z" * 200)

    async def _run() -> None:
        from textual.widgets import Button

        cfg_path = home / ".purgekit" / "config.json"
        tui = PurgeKitApp(
            app_dirs=[apps_dir],
            home=home,
            system_root=sys_root,
            history_dir=home / ".purgekit" / "history",
            config_path=cfg_path,
        )
        async with tui.run_test() as pilot:
            # Wait for background workers to populate table and initial scan
            for _ in range(25):
                await pilot.pause(0.05)
                if tui.query_one("#apps-table", DataTable).row_count == 2 and tui._current_scan is not None:
                    break

            table = tui.query_one("#apps-table", DataTable)
            assert table.row_count == 2
            assert tui._current_scan is not None
            assert tui._current_scan.app.name == "AlphaPlayer"

            # Prominent top-left HeaderIcon button & theme button
            from textual.widgets._header import HeaderIcon

            header_icon = tui.query_one(HeaderIcon)
            assert "Commands" in str(header_icon.render())
            theme_btn = tui.query_one("#btn-theme", Button)
            assert "Theme:" in str(theme_btn.label)
            initial_theme = tui.theme
            await pilot.press("t")
            await pilot.pause(0.05)
            assert tui.theme != initial_theme
            assert cfg_path.is_file()
            assert json.loads(cfg_path.read_text(encoding="utf-8"))["theme"] == tui.theme

            sel = tui.query_one("#leftovers-list", SelectionList)
            assert sel.option_count == 1
            assert len(sel.selected) == 1

            # Trigger dry-run preview via keybinding 'd'
            await pilot.press("d")
            await pilot.pause(0.05)
            status_text = str(tui.query_one("#status-line", Static).render())
            assert "DRY-RUN" in status_text

            # Cycle scan mode via 'm'
            await pilot.press("m")
            await pilot.pause(0.1)
            assert tui._mode == ScanMode.ADVANCED

            # Check metric cards and toggle sort via 's'
            metric_text = str(tui.query_one("#metric-total", Static).render())
            assert "Total Freed" in metric_text
            await pilot.press("s")
            await pilot.pause(0.05)
            assert tui._sort_by == "size"

            # Filter search input
            await pilot.press("/")
            await pilot.press("b", "e", "t", "a")
            await pilot.pause(0.1)
            assert table.row_count == 1

    asyncio.run(_run())


def test_pkg_matching_heuristics(tmp_path: Path) -> None:
    from purgekit.packages import find_matching_pkg_ids

    sample_pkgs = [
        "com.apple.pkg.CLTools_Executables",
        "org.openvpn.client.pkg",
        "org.openvpn.helper_framework.pkg",
        "com.fortinet.forticlient.vpnservice",
        "com.fortinet.forticlient.preinstall",
        "com.google.Drive",
    ]

    openvpn = AppInfo(
        name="OpenVPN Connect",
        path=tmp_path / "OpenVPN Connect.app",
        bundle_id="org.openvpn.client.app",
    )
    assert find_matching_pkg_ids(openvpn, all_pkg_ids=sample_pkgs) == [
        "org.openvpn.client.pkg",
    ]

    forti = AppInfo(
        name="FortiClient",
        path=tmp_path / "FortiClient.app",
        bundle_id="com.fortinet.FortiClient",
    )
    assert find_matching_pkg_ids(forti, all_pkg_ids=sample_pkgs) == [
        "com.fortinet.forticlient.preinstall",
        "com.fortinet.forticlient.vpnservice",
    ]

    chrome = AppInfo(
        name="Google Chrome",
        path=tmp_path / "Google Chrome.app",
        bundle_id="com.google.Chrome",
    )
    assert find_matching_pkg_ids(chrome, all_pkg_ids=sample_pkgs) == []


def test_homebrew_cask_detection_and_zap_scan(tmp_path: Path) -> None:
    home = tmp_path / "home"
    apps_dir = tmp_path / "Applications"
    apps_dir.mkdir(parents=True)
    _create_fake_app(apps_dir, "BrewTool", "com.brew.tool")

    caskroom = tmp_path / "Caskroom"
    cask_ver = caskroom / "brew-tool" / "1.0.0"
    cask_ver.mkdir(parents=True)
    (cask_ver / "BrewTool.app").mkdir()

    meta_casks = caskroom / "brew-tool" / ".metadata" / "1.0.0" / "20260101" / "Casks"
    meta_casks.mkdir(parents=True)
    custom_zap_dir = home / "Library" / "CustomBrewState"
    custom_zap_dir.mkdir(parents=True)
    (custom_zap_dir / "state.db").write_text("state")

    cask_json = {
        "casks": [
            {
                "token": "brew-tool",
                "artifacts": [
                    {
                        "zap": [
                            {
                                "trash": [
                                    "~/Library/CustomBrewState",
                                    "/System/ProtectedShouldBeIgnored",
                                ]
                            }
                        ]
                    }
                ],
            }
        ]
    }
    (meta_casks / "brew-tool.json").write_text(json.dumps(cask_json), encoding="utf-8")

    apps = find_installed_apps(
        app_dirs=[apps_dir],
        compute_sizes=True,
        caskroom_roots=[caskroom],
    )
    assert len(apps) == 1
    assert apps[0].source == InstallSource.HOMEBREW
    assert apps[0].cask_name == "brew-tool"

    scan_res = scan_app_leftovers(
        apps[0],
        apps,
        mode=ScanMode.MODERATE,
        home=home,
        system_root=tmp_path / "sys",
        check_processes=False,
        check_fda=False,
        include_pkgutil=False,
        caskroom_roots=[caskroom],
    )
    zap_items = [i for i in scan_res.leftovers if i.category == "HomebrewZap"]
    assert len(zap_items) == 1
    assert zap_items[0].path == custom_zap_dir


def test_privileged_removal_command_and_forget_pkgs(tmp_path: Path, monkeypatch) -> None:
    from purgekit.models import PkgReceiptInfo, ScanResult
    import purgekit.uninstaller as uninstaller_mod

    home = tmp_path / "home"
    home.mkdir()
    daemon_plist = tmp_path / "Library" / "LaunchDaemons" / "com.acme.daemon.plist"
    daemon_plist.parent.mkdir(parents=True)
    daemon_plist.write_text("daemon")

    fake_app = AppInfo(
        name="Acme",
        path=tmp_path / "Acme.app",
        bundle_id="com.acme.app",
    )
    scan_res = ScanResult(
        app=fake_app,
        mode=ScanMode.ADVANCED,
        pkg_receipts=[PkgReceiptInfo(pkg_id="com.acme.pkg")],
    )

    captured_scripts = []

    def fake_subprocess_run(cmd, **kwargs):
        captured_scripts.append(cmd)

        class FakeProc:
            returncode = 0
            stdout = ""
            stderr = ""

        return FakeProc()

    monkeypatch.setattr(uninstaller_mod.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(uninstaller_mod, "requires_admin_privileges", lambda p, home=None: True)

    outcome = execute_removal(
        scan_res,
        selected_paths=[daemon_plist],
        include_app=False,
        permanent=False,
        dry_run=False,
        stop_processes=False,
        allow_admin=True,
        forget_pkgs=True,
        history_dir=home / ".purgekit" / "history",
        home=home,
    )

    assert len(captured_scripts) == 1
    script_arg = captured_scripts[0][2]
    assert "launchctl bootout system" in script_arg
    assert "pkgutil --forget com.acme.pkg" in script_arg
    assert outcome.forgotten_pkgs == ["com.acme.pkg"]
    assert daemon_plist in outcome.trashed


def test_short_path_and_terminal_resize(tmp_path: Path, monkeypatch) -> None:
    import io
    import os
    from purgekit.ui.tui import _short_path, prepare_terminal_window

    home = tmp_path / "home"
    home.mkdir()
    assert _short_path(home / "Library" / "Caches", home=home) == "~/Library/Caches"

    # Non-TTY stdout should safely no-op
    fake_non_tty = io.StringIO()
    monkeypatch.setattr("sys.stdout", fake_non_tty)
    assert prepare_terminal_window() is False

    # Small TTY stdout should emit xterm resize escape sequence
    class FakeTTY(io.StringIO):
        def isatty(self) -> bool:
            return True

    fake_tty = FakeTTY()
    monkeypatch.setattr("sys.stdout", fake_tty)
    sizes = iter([os.terminal_size((80, 24)), os.terminal_size((148, 42))])
    monkeypatch.setattr(
        "purgekit.ui.tui.shutil.get_terminal_size",
        lambda fallback=(80, 24): next(sizes, os.terminal_size((148, 42))),
    )
    assert prepare_terminal_window(min_cols=148, min_rows=42) is True
    assert "\x1b[8;42;148t" in fake_tty.getvalue()


def test_file_search_and_critical_folder_protection(tmp_path: Path) -> None:
    from purgekit.filesearch import search_files
    from purgekit.safety import is_sip_protected_path
    from purgekit.uninstaller import execute_path_removal

    home = tmp_path / "home"
    downloads = home / "Downloads"
    documents = home / "Documents"
    lib_caches = home / "Library" / "Caches"
    sys_root = tmp_path / "sys_root"
    downloads.mkdir(parents=True)
    documents.mkdir(parents=True)
    lib_caches.mkdir(parents=True)
    sys_root.mkdir(parents=True)

    # Critical standard folders themselves must remain protected
    assert is_sip_protected_path(downloads, home=home) is True
    assert is_sip_protected_path(documents, home=home) is True

    target_file = downloads / "SpotifyInstaller.dmg"
    target_file.write_bytes(b"dmgdata" * 100)
    target_dir = lib_caches / "SpotifyCache"
    target_dir.mkdir()
    (target_dir / "chunk.bin").write_bytes(b"12345")

    # Search all in user scope
    results = search_files(
        "Spotify",
        scope="user",
        item_type="all",
        home=home,
        system_root=sys_root,
        use_spotlight=False,
    )
    matched_paths = {item.path for item in results}
    assert target_file in matched_paths
    assert target_dir in matched_paths

    # Critical folder search by name must NOT return ~/Downloads itself
    dl_results = search_files(
        "Downloads",
        scope="user",
        item_type="dir",
        home=home,
        system_root=sys_root,
        use_spotlight=False,
    )
    assert downloads not in {item.path for item in dl_results}

    # Filter by item_type and scope
    file_only = search_files(
        "Spotify",
        scope="user",
        item_type="file",
        home=home,
        system_root=sys_root,
        use_spotlight=False,
    )
    assert {item.path for item in file_only} == {target_file}

    lib_only = search_files(
        "Spotify",
        scope="library",
        item_type="all",
        home=home,
        system_root=sys_root,
        use_spotlight=False,
    )
    assert {item.path for item in lib_only} == {target_dir}

    # Dry-run & real permanent path removal
    history_dir = home / ".purgekit_history"
    dry_outcome = execute_path_removal(
        [target_file, target_dir],
        label="TestCleanup",
        permanent=True,
        dry_run=True,
        history_dir=history_dir,
        home=home,
    )
    assert dry_outcome.dry_run is True
    assert target_file.exists() and target_dir.exists()

    real_outcome = execute_path_removal(
        [target_file, target_dir],
        label="TestCleanup",
        permanent=True,
        dry_run=False,
        history_dir=history_dir,
        home=home,
    )
    assert real_outcome.failed == []
    assert not target_file.exists()
    assert not target_dir.exists()
    assert real_outcome.manifest_path is not None and real_outcome.manifest_path.exists()


def test_tui_file_search_from_app_search(tmp_path: Path) -> None:
    import asyncio
    from textual.widgets import Input, SelectionList, TabbedContent
    from purgekit.ui.tui import PurgeKitApp

    apps_dir = tmp_path / "Applications"
    apps_dir.mkdir()
    home = tmp_path / "home"
    downloads = home / "Downloads"
    downloads.mkdir(parents=True)
    target = downloads / "Fatura2026.pdf"
    target.write_text("pdf", encoding="utf-8")
    sys_root = tmp_path / "sys_root"
    sys_root.mkdir()

    app = PurgeKitApp(
        app_dirs=[apps_dir],
        home=home,
        system_root=sys_root,
        history_dir=home / ".purgekit_history",
        config_path=home / ".purgekit_config.json",
    )

    async def scenario() -> None:
        async with app.run_test(size=(140, 40)) as pilot:
            await pilot.pause(0.2)
            search_input = app.query_one("#search-input", Input)
            search_input.focus()
            search_input.value = "Fatura2026"
            await pilot.press("enter")
            for _ in range(25):
                await pilot.pause(0.1)
                files_list = app.query_one("#files-list", SelectionList)
                if len(files_list.options) > 0:
                    break
            tabs = app.query_one("#main-tabs", TabbedContent)
            assert tabs.active == "tab-files"
            files_list = app.query_one("#files-list", SelectionList)
            assert len(files_list.options) >= 1
            assert any(str(target) == str(opt.value) for opt in files_list.options)

    asyncio.run(scenario())


def test_file_search_deep_unicode_and_multi_token(tmp_path: Path) -> None:
    import unicodedata
    from purgekit.filesearch import search_files

    home = tmp_path / "home"
    sys_root = tmp_path / "sys_root"
    deep_dir = home / "Documents" / "Work" / "2026" / "Q4" / "Invoices"
    custom_dir = home / "Projects" / "ClientPortal"
    deep_dir.mkdir(parents=True)
    custom_dir.mkdir(parents=True)
    sys_root.mkdir(parents=True)

    # Finder-style NFD decomposed filename with Turkish characters
    nfd_name = unicodedata.normalize("NFD", "Müşteri_Ödeme_2026.pdf")
    nfd_file = deep_dir / nfd_name
    nfd_file.write_bytes(b"pdf-bytes")

    project_file = custom_dir / "İstanbul_Notlar.txt"
    project_file.write_text("notes", encoding="utf-8")

    # 1. NFC Turkish query should match NFD deep file (depth 5 inside Documents)
    hit_turkish = search_files(
        "müşteri",
        scope="user",
        home=home,
        system_root=sys_root,
        use_spotlight=False,
    )
    assert any(item.path.name == nfd_name for item in hit_turkish)

    # 2. ASCII-folded + multi-token query should also match decomposed Turkish filename
    hit_multi = search_files(
        "musteri odeme",
        scope="user",
        home=home,
        system_root=sys_root,
        use_spotlight=False,
    )
    assert any(item.path.name == nfd_name for item in hit_multi)

    # 3. Custom top-level folder (~/Projects/...) & uppercase Turkish İ -> i folding
    hit_istanbul = search_files(
        "istanbul",
        scope="user",
        home=home,
        system_root=sys_root,
        use_spotlight=False,
    )
    assert any(item.path == project_file for item in hit_istanbul)


def test_space_sweep_and_disk_lens(tmp_path: Path) -> None:
    from purgekit.sweeper import scan_space_lens, scan_sweep_targets

    home = tmp_path / "home"
    downloads = home / "Downloads"
    derived = home / "Library" / "Developer" / "Xcode" / "DerivedData" / "DemoApp-abc"
    node_mods = home / "Projects" / "WebApp" / "node_modules"
    movies = home / "Movies"
    downloads.mkdir(parents=True)
    derived.mkdir(parents=True)
    node_mods.mkdir(parents=True)
    movies.mkdir(parents=True)

    dmg = downloads / "OldInstaller.dmg"
    dmg.write_bytes(b"0" * (6 * 1024 * 1024))
    (derived / "build.bin").write_bytes(b"1" * (11 * 1024 * 1024))
    (node_mods / "bundle.js").write_bytes(b"2" * (11 * 1024 * 1024))
    big_video = movies / "Recording.mov"
    big_video.write_bytes(b"3" * (12 * 1024 * 1024))

    sweep_items = scan_sweep_targets(min_mb=10, home=home)
    by_path = {i.path: i for i in sweep_items}
    assert dmg in by_path and by_path[dmg].category == "Installer"
    assert derived in by_path and by_path[derived].category == "Dev Cache"
    assert node_mods in by_path and by_path[node_mods].category == "Project Cache"
    assert big_video in by_path and by_path[big_video].category == "Large File"

    root, total, lens_entries = scan_space_lens(target_dir=home, home=home)
    assert root == home.resolve()
    assert total >= 39 * 1024 * 1024
    names = {e.name: e for e in lens_entries}
    assert "Movies" in names and names["Movies"].is_protected is True
    assert "Projects" in names and names["Projects"].is_protected is False
    assert abs(sum(e.share_pct for e in lens_entries) - 100.0) < 0.5


def test_startup_services_and_trash_watcher(tmp_path: Path) -> None:
    import plistlib
    from purgekit.startup import scan_startup_items, unload_startup_items
    from purgekit.watcher import find_newly_trashed_apps, scan_trashed_app_leftovers

    home = tmp_path / "home"
    sys_root = tmp_path / "sys"
    user_agents = home / "Library" / "LaunchAgents"
    sys_daemons = sys_root / "Library" / "LaunchDaemons"
    trash_dir = home / ".Trash"
    user_agents.mkdir(parents=True)
    sys_daemons.mkdir(parents=True)
    trash_dir.mkdir(parents=True)

    user_plist = user_agents / "com.example.updater.plist"
    with user_plist.open("wb") as fh:
        plistlib.dump(
            {"Label": "com.example.updater", "Program": "/usr/local/bin/updater", "RunAtLoad": True},
            fh,
        )

    apple_plist = sys_daemons / "com.apple.example.plist"
    with apple_plist.open("wb") as fh:
        plistlib.dump({"Label": "com.apple.example"}, fh)

    services = scan_startup_items(home=home, system_root=sys_root, include_apple=False)
    assert len(services) == 1
    assert services[0].label == "com.example.updater"
    assert services[0].run_at_load is True

    dry_unload = unload_startup_items([user_plist], home=home, dry_run=True)
    assert dry_unload[user_plist][0] is True
    assert "DRY-RUN" in dry_unload[user_plist][1]

    # Trash Watcher: simulate an app dragged into ~/.Trash with a Library cache leftover
    trashed_app = _create_fake_app(trash_dir, "TrashMe", "com.test.trashme")
    cache = home / "Library" / "Caches" / "com.test.trashme"
    cache.mkdir(parents=True)
    (cache / "cache.dat").write_bytes(b"abc")

    seen = set()
    new_apps = find_newly_trashed_apps(trash_dir, seen)
    assert new_apps == [trashed_app]
    assert find_newly_trashed_apps(trash_dir, seen) == []

    scan_res = scan_trashed_app_leftovers(
        trashed_app,
        installed_apps=[],
        home=home,
        system_root=sys_root,
    )
    assert scan_res is not None
    assert any(item.path == cache for item in scan_res.leftovers)


def test_tui_new_tabs_and_reveal_in_finder(tmp_path: Path, monkeypatch) -> None:
    import asyncio
    import plistlib
    from textual.widgets import SelectionList, TabbedContent
    import purgekit.ui.tui as tui_mod
    from purgekit.ui.tui import PurgeKitApp

    apps_dir = tmp_path / "Applications"
    home = tmp_path / "home"
    sys_root = tmp_path / "sys"
    apps_dir.mkdir()
    (home / "Downloads").mkdir(parents=True)
    (home / "Library" / "LaunchAgents").mkdir(parents=True)
    sys_root.mkdir()

    _create_fake_app(apps_dir, "DemoTool", "com.demo.tool")
    dmg = home / "Downloads" / "SetupTool.dmg"
    dmg.write_bytes(b"x" * (6 * 1024 * 1024))
    with (home / "Library" / "LaunchAgents" / "com.demo.agent.plist").open("wb") as fh:
        plistlib.dump({"Label": "com.demo.agent"}, fh)

    revealed_paths = []
    monkeypatch.setattr(tui_mod, "_reveal_path_in_finder", lambda p: revealed_paths.append(p))

    app = PurgeKitApp(
        app_dirs=[apps_dir],
        home=home,
        system_root=sys_root,
        history_dir=home / ".purgekit_history",
        config_path=home / ".purgekit_config.json",
    )

    async def scenario() -> None:
        async def switch_tab(tab_id: str, button_id: str) -> None:
            await pilot.click(f"#--content-tab-{tab_id}")
            for _ in range(25):
                await pilot.pause(0.05)
                if app.query_one(button_id).region.width > 0:
                    break

        async with app.run_test(size=(150, 42)) as pilot:
            await pilot.pause(0.2)
            # Test Space Sweep tab
            await switch_tab("tab-sweep", "#btn-scan-sweep")
            await pilot.click("#btn-scan-sweep")
            for _ in range(25):
                await pilot.pause(0.05)
                if app.query_one("#sweep-list", SelectionList).option_count > 0:
                    break
            assert app.query_one("#sweep-list", SelectionList).option_count >= 1

            # Test Startup Services tab & Reveal in Finder ('o')
            await switch_tab("tab-startup", "#btn-scan-startup")
            await pilot.click("#btn-scan-startup")
            for _ in range(25):
                await pilot.pause(0.05)
                if app.query_one("#startup-list", SelectionList).option_count > 0:
                    break
            startup_list = app.query_one("#startup-list", SelectionList)
            assert startup_list.option_count == 1
            startup_list.focus()
            await pilot.pause(0.05)
            await pilot.press("o")
            await pilot.pause(0.05)
            assert any(p.name == "com.demo.agent.plist" for p in revealed_paths)

            # Test Disk Lens tab
            await switch_tab("tab-lens", "#btn-run-lens")
            await pilot.click("#btn-run-lens")
            for _ in range(25):
                await pilot.pause(0.05)
                if app.query_one("#lens-list", SelectionList).option_count > 0:
                    break
            assert app.query_one("#lens-list", SelectionList).option_count >= 2

    asyncio.run(scenario())
