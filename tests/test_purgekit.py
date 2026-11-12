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

            # Prominent theme button & cycling via 't'
            theme_btn = tui.query_one("#btn-theme", Button)
            assert "Tema:" in str(theme_btn.label)
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
            assert "Toplam Alan" in metric_text
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
