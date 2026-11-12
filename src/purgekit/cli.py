from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import List, Optional

import typer
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from purgekit import __version__
from purgekit.discovery import find_installed_apps, parse_app_bundle, resolve_app
from purgekit.homebrew import find_brew_binary, run_brew_uninstall_cask
from purgekit.models import AppInfo, RiskLevel, ScanMode
from purgekit.packages import find_matching_pkg_ids, inspect_pkg_receipt
from purgekit.safety import check_full_disk_access
from purgekit.scanner import scan_app_leftovers, scan_orphans
from purgekit.uninstaller import default_history_dir, execute_removal, load_history
from purgekit.utils import format_bytes

app = typer.Typer(
    name="purgekit",
    help="Revo Uninstaller yaklaşımından esinlenen macOS akıllı uygulama kaldırıcı ve artık tarayıcı.",
    no_args_is_help=True,
)
console = Console()

RISK_STYLE = {
    RiskLevel.LOW: "green",
    RiskLevel.MEDIUM: "yellow",
    RiskLevel.HIGH: "red",
}


def _pick_app_interactively(matches: List[AppInfo], query: str) -> Optional[AppInfo]:
    if not matches:
        console.print(f"[red]'{query}' ile eşleşen uygulama bulunamadı.[/red]")
        return None
    if len(matches) == 1:
        return matches[0]

    table = Table(title="Birden fazla eşleşme bulundu", box=box.ROUNDED)
    table.add_column("#", style="cyan", justify="right")
    table.add_column("Uygulama", style="bold")
    table.add_column("Bundle ID")
    table.add_column("Yol")
    for idx, item in enumerate(matches, start=1):
        table.add_row(str(idx), item.name, item.bundle_id or "-", str(item.path))
    console.print(table)

    choice = Prompt.ask(
        "Seçiminiz (iptal için 0)",
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
    """Sürüm bilgisini gösterir."""
    console.print(f"purgekit v{__version__}")


@app.command("list")
def list_apps(
    include_system: bool = typer.Option(False, "--system", help="/System/Applications altındaki sistem uygulamalarını da göster."),
    sort_by: str = typer.Option("name", "--sort", help="Sıralama: name | size"),
    search: Optional[str] = typer.Option(None, "--search", "-s", help="İsim veya Bundle ID filtrele."),
    no_size: bool = typer.Option(False, "--no-size", help="Hızlı listeleme için boyut hesaplamasını atla."),
) -> None:
    """Kurulu macOS uygulamalarını listeler."""
    with console.status("Uygulamalar taranıyor..."):
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

    table = Table(title=f"Kurulu Uygulamalar ({len(apps)})", box=box.ROUNDED)
    table.add_column("Ad", style="bold cyan")
    table.add_column("Sürüm", justify="right")
    table.add_column("Kaynak")
    table.add_column("Boyut", justify="right")
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
        console.print(f"Toplam uygulama boyutu: [bold]{format_bytes(total_bytes)}[/bold]")


@app.command()
def scan(
    query: str = typer.Argument(..., help="Uygulama adı, Bundle ID veya .app yolu."),
    mode: ScanMode = typer.Option(ScanMode.MODERATE, "--mode", "-m", help="Tarama modu: safe | moderate | advanced"),
    as_json: bool = typer.Option(False, "--json", help="Çıktıyı JSON olarak yazdır."),
) -> None:
    """Bir uygulamayı kaldırmadan tüm artık dosyalarını tarar."""
    apps = find_installed_apps(compute_sizes=False)
    matches = resolve_app(query, apps)
    target = _pick_app_interactively(matches, query)
    if not target:
        raise typer.Exit(code=1)

    with console.status(f"{target.name} için artık dosyalar taranıyor ({mode.value})..."):
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
        extra_meta += f" | .pkg Kayıtları: [cyan]{len(result.pkg_receipts)}[/cyan]"

    summary = (
        f"[bold]{app_info.name}[/bold] ({app_info.version or '?'})\n"
        f"Yol: {app_info.path}\n"
        f"Bundle ID: {app_info.bundle_id or '-'}{extra_meta}\n"
        f"Uygulama Boyutu: [cyan]{format_bytes(app_info.size_bytes)}[/cyan] | "
        f"Artık Dosyalar ({len(result.leftovers)}): [yellow]{format_bytes(result.leftover_size_bytes)}[/yellow] | "
        f"Toplam: [bold green]{format_bytes(result.total_size_bytes)}[/bold green]"
    )
    console.print(Panel(summary, title=f"Tarama Sonucu ({result.mode.value})", expand=False))

    for warn in result.warnings:
        console.print(f"[yellow]Uyarı:[/yellow] {warn}")

    if result.running_processes:
        proc_table = Table(title="Çalışan Süreçler", box=box.SIMPLE)
        proc_table.add_column("PID", justify="right")
        proc_table.add_column("Süreç")
        proc_table.add_column("Yürütülebilir Dosya", style="dim")
        for proc in result.running_processes:
            proc_table.add_row(str(proc.pid), proc.name, proc.exe or "-")
        console.print(proc_table)

    if not result.leftovers:
        console.print("[green]Eşleşen artık dosya bulunamadı.[/green]")
        return

    table = Table(title="Tespit Edilen Artık Dosyalar", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Seçili", justify="center")
    table.add_column("Risk")
    table.add_column("Kategori")
    table.add_column("Boyut", justify="right")
    table.add_column("Yol")
    table.add_column("Eşleşme Nedeni", style="dim")

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
    query: str = typer.Argument(..., help="Kaldırılacak uygulama adı, Bundle ID veya .app yolu."),
    mode: ScanMode = typer.Option(ScanMode.MODERATE, "--mode", "-m", help="Tarama modu: safe | moderate | advanced"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Hiçbir dosyayı silmeden yalnızca simülasyon yapar."),
    permanent: bool = typer.Option(False, "--permanent", help="Çöp Kutusu yerine kalıcı olarak siler."),
    yes: bool = typer.Option(False, "--yes", "-y", help="Onay istemeden varsayılan seçili öğeleri kaldırır."),
    admin: bool = typer.Option(False, "--admin", help="/Library gibi sistem yolları için yönetici izni ister."),
    forget_pkgs: bool = typer.Option(False, "--forget-pkgs", help="Eşleşen .pkg receipt kayıtlarını `pkgutil --forget` ile temizler (--admin gerektirir)."),
    use_brew: bool = typer.Option(False, "--brew", help="Homebrew Cask ise önce `brew uninstall --cask` çalıştırır."),
    app_only: bool = typer.Option(False, "--app-only", help="Artık dosyaları bırakıp yalnızca .app paketini kaldırır."),
) -> None:
    """Uygulamayı ve seçilen artık dosyalarını güvenli şekilde kaldırır."""
    apps = find_installed_apps(compute_sizes=False)
    matches = resolve_app(query, apps)
    target = _pick_app_interactively(matches, query)
    if not target:
        raise typer.Exit(code=1)

    if target.is_protected:
        console.print(f"[red]{target.name} sistem korumalı bir uygulamadır ve kaldırılamaz.[/red]")
        raise typer.Exit(code=1)

    with console.status(f"{target.name} analiz ediliyor..."):
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
                "Hariç tutmak veya eklemek istediğiniz numara var mı? (Boş bırakın = varsayılan ✓ seçililer, 'all' = tümü)",
                default="",
            ).strip()
            if custom.lower() == "all":
                selected_paths = [item.path for item in result.leftovers]
            elif custom:
                # Allow comma-separated explicit index selection
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
        pkg_note = f" | Unutulacak .pkg: {len(outcome.forgotten_pkgs)}" if outcome.forgotten_pkgs else ""
        console.print(
            Panel(
                f"[cyan]DRY-RUN SİMÜLASYONU[/cyan]: {len(outcome.trashed) + len(outcome.deleted_permanently)} öğe "
                f"kaldırılacaktı ({format_bytes(outcome.reclaimed_bytes)} alan kazanılacaktı){pkg_note}.",
                expand=False,
            )
        )
        return

    action_label = "KALICI OLARAK SİLİNECEK" if permanent else "Çöp Kutusu'na taşınacak"
    if not yes:
        confirmed = Confirm.ask(
            f"[bold]{result.app.name}[/bold] ve {len(selected_paths)} artık öğe {action_label}. Devam edilsin mi?",
            default=False,
        )
        if not confirmed:
            console.print("[yellow]İşlem iptal edildi.[/yellow]")
            raise typer.Exit(code=0)

    include_app_bundle = True
    if use_brew and result.app.cask_name:
        brew_ok, brew_msg = run_brew_uninstall_cask(result.app.cask_name, dry_run=False)
        if brew_ok:
            console.print(f"[magenta]Homebrew:[/magenta] {brew_msg}")
            include_app_bundle = not result.app.path.exists()
        else:
            console.print(f"[yellow]Homebrew uyarısı:[/yellow] {brew_msg}")

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
        f"[green]Tamamlandı:[/green] {removed_count} öğe kaldırıldı, "
        f"[bold]{format_bytes(outcome.reclaimed_bytes)}[/bold] alan açıldı."
    )
    if outcome.forgotten_pkgs:
        console.print(f"Unutulan .pkg kayıtları: {', '.join(outcome.forgotten_pkgs)}")
    if outcome.manifest_path:
        console.print(f"İşlem kaydı: [dim]{outcome.manifest_path}[/dim]")
    if outcome.failed:
        console.print("[red]Başarısız öğeler:[/red]")
        for path, err in outcome.failed:
            console.print(f"  - {path}: {err}")


@app.command()
def orphans(
    min_kb: int = typer.Option(0, "--min-kb", help="En az bu KB boyutundaki yetim artıkları listele."),
) -> None:
    """Önceden normal yolla silinmiş uygulamalardan kalan yetim Library artıklarını listeler."""
    with console.status("Yetim artıklar taranıyor..."):
        apps = find_installed_apps(compute_sizes=False, read_entitlements=True)
        items = scan_orphans(apps)

    if min_kb > 0:
        items = [i for i in items if i.size_bytes >= min_kb * 1024]

    if not items:
        console.print("[green]Dikkat çekici bir yetim artık bulunamadı.[/green]")
        return

    table = Table(title=f"Yetim Artık Dosyalar ({len(items)})", box=box.ROUNDED)
    table.add_column("Kategori")
    table.add_column("Risk")
    table.add_column("Boyut", justify="right")
    table.add_column("Tanımlayıcı", style="cyan")
    table.add_column("Not", style="yellow")
    table.add_column("Yol", style="dim")

    total = 0
    for item in items:
        total += item.size_bytes
        style = RISK_STYLE[item.risk]
        note = f"ortak geliştirici: {item.shared_vendor}" if item.shared_vendor else "-"
        table.add_row(
            item.category,
            f"[{style}]{item.risk.value}[/{style}]",
            format_bytes(item.size_bytes),
            item.identifier_hint,
            note,
            str(item.path),
        )
    console.print(table)
    console.print(f"Toplam yetim artık boyutu: [bold]{format_bytes(total)}[/bold]")


@app.command()
def ui(
    include_system: bool = typer.Option(False, "--system", help="Sistem uygulamalarını da salt-okunur olarak listele."),
    resize: bool = typer.Option(True, "--resize/--no-resize", help="Başlangıçta terminal penceresini otomatik olarak TUI'a göre genişlet."),
) -> None:
    """Etkileşimli Textual terminal arayüzünü (TUI) başlatır."""
    from purgekit.ui.tui import run_tui

    run_tui(include_system=include_system, resize=resize)


@app.command()
def doctor() -> None:
    """macOS izinlerini (Full Disk Access) ve sistem araçlarını kontrol eder."""
    has_fda, blocked = check_full_disk_access()
    codesign_ok = shutil.which("codesign") is not None
    pkgutil_ok = shutil.which("pkgutil") is not None
    launchctl_ok = shutil.which("launchctl") is not None
    hist_dir = default_history_dir()

    table = Table(title="PurgeKit Sistem & İzin Kontrolü", box=box.ROUNDED)
    table.add_column("Kontrol", style="bold")
    table.add_column("Durum")
    table.add_column("Detay")

    table.add_row(
        "Full Disk Access",
        "[green]TAMAM[/green]" if has_fda else "[yellow]EKSİK[/yellow]",
        "Tüm korumalı dizinler okunabiliyor."
        if has_fda
        else f"Erişilemeyen yollar: {', '.join(str(p) for p in blocked)}",
    )
    table.add_row("codesign", "[green]VAR[/green]" if codesign_ok else "[red]YOK[/red]", "App Groups entitlements okuma")
    table.add_row("pkgutil", "[green]VAR[/green]" if pkgutil_ok else "[red]YOK[/red]", ".pkg kurulum kayıtları tarama")
    table.add_row("launchctl", "[green]VAR[/green]" if launchctl_ok else "[red]YOK[/red]", "LaunchAgent/Daemon durdurma")
    brew_bin = find_brew_binary()
    table.add_row("brew", "[green]VAR[/green]" if brew_bin else "[dim]YOK[/dim]", brew_bin or "Homebrew kurulu değil (opsiyonel)")
    table.add_row("Kayıt Dizini", "[green]HAZIR[/green]", str(hist_dir))
    console.print(table)


@app.command()
def pkg(
    query: str = typer.Argument(..., help="Uygulama adı/Bundle ID veya doğrudan .pkg kimliği."),
    show_files: bool = typer.Option(False, "--files", "-f", help=".app dışındaki kurulu dosyaları da listele."),
) -> None:
    """Bir uygulamaya ait .pkg kurulum kayıtlarını (pkgutil receipts) inceler."""
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
        console.print(f"[yellow]{header} için eşleşen .pkg kaydı bulunamadı.[/yellow]")
        return

    table = Table(title=f".pkg Kurulum Kayıtları — {header}", box=box.ROUNDED)
    table.add_column("Paket Kimliği", style="cyan")
    table.add_column("Sürüm", justify="right")
    table.add_column("Harici Dosya", justify="right")
    table.add_column("Boyut", justify="right")

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
            console.print(f"\n[bold cyan]{rec.pkg_id}[/bold cyan] (.app dışı dosyalar):")
            for f in rec.external_files[:100]:
                console.print(f"  - {f}")
            if len(rec.external_files) > 100:
                console.print(f"  ... (+{len(rec.external_files) - 100} dosya daha)")


@app.command()
def history(
    limit: int = typer.Option(15, "--limit", "-n", help="Gösterilecek son işlem sayısı."),
    detail: Optional[int] = typer.Option(None, "--detail", "-d", help="Detayı görüntülenecek satır numarası (1 = en son)."),
) -> None:
    """Geçmiş kaldırma işlemlerinin dökümünü gösterir."""
    records = load_history(limit=limit)
    if not records:
        console.print("[dim]Henüz kayıtlı kaldırma işlemi yok.[/dim]")
        return

    if detail is not None:
        if detail < 1 or detail > len(records):
            console.print(f"[red]Geçersiz kayıt numarası: {detail} (1..{len(records)})[/red]")
            raise typer.Exit(code=1)
        rec = records[detail - 1]
        console.print(
            Panel(
                f"[bold]{rec.get('app_name')}[/bold] ({rec.get('bundle_id') or '-'})\n"
                f"Tarih (UTC): {rec.get('timestamp_utc')}\n"
                f"Açılan Alan: {format_bytes(int(rec.get('reclaimed_bytes', 0)))}\n"
                f"Dosya: {rec.get('_file')}",
                title="İşlem Detayı",
                expand=False,
            )
        )
        for p in rec.get("trashed", []):
            console.print(f"  [yellow][Çöp][/yellow] {p}")
        for p in rec.get("deleted_permanently", []):
            console.print(f"  [red][Silindi][/red] {p}")
        for pkg_id in rec.get("forgotten_pkgs", []):
            console.print(f"  [cyan][pkgutil --forget][/cyan] {pkg_id}")
        return

    table = Table(title="Kaldırma Geçmişi", box=box.ROUNDED)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Tarih (UTC)")
    table.add_column("Uygulama", style="bold")
    table.add_column("Çöp Kutusu", justify="right")
    table.add_column("Kalıcı", justify="right")
    table.add_column("Açılan Alan", justify="right")

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


if __name__ == "__main__":
    app()
