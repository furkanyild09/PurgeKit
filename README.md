# PurgeKit

macOS için **Revo Uninstaller** yaklaşımından esinlenen akıllı uygulama kaldırıcı ve artık dosya tarayıcı.

## Özellikler

- **Çift Panelli Textual TUI (`purgekit ui`):** Tema seçimi (`Tokyo Night`, `Dark`, `Nord`, `Catppuccin`, `Dracula`, `Light`), metrik kartları, arama/sıralama, checkbox ile artık seçimi ve otomatik pencere boyutlandırma.
- **Uygulama Keşfi:** `/Applications`, `~/Applications` (alt klasörler dahil) taraması; `Info.plist`, Mac App Store ve Homebrew Cask (`zap` dahil) tespiti.
- **3 Kademeli Artık Tarama:** `safe`, `moderate`, `advanced` modları ile `~/Library`, `/Library`, `LaunchAgents`, `LaunchDaemons`, `Group Containers` (`codesign` entitlements üzerinden) ve `.pkg` receipt analizi.
- **Güvenlik Katmanı:** SIP koruması, kardeş uygulama kontrolü (ortak geliştirici klasörlerini koruma), risk sınıflandırması (`low` / `medium` / `high`) ve Full Disk Access kontrolü.
- **Güvenli Kaldırma:** Varsayılan olarak Çöp Kutusu'na taşıma, `dry-run` önizleme, çalışan süreç sonlandırma, LaunchAgent/Daemon durdurma, `--admin --forget-pkgs` ve `~/.purgekit/history/` altında JSON işlem kaydı.
- **Yetim Artık Tarayıcı (`orphans`):** Önceden normal yolla silinmiş uygulamaların `~/Library` içinde bıraktığı artıkları tespit edip temizler.

## Kurulum & Çalıştırma

```bash
git clone https://github.com/furkanyild09/PurgeKit.git
cd PurgeKit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Temel Komutlar

```bash
purgekit ui                  # Çift panelli etkileşimli Textual TUI
purgekit doctor              # Full Disk Access, codesign, pkgutil, brew kontrolü
purgekit list --sort size
purgekit scan "Spotify" --mode moderate
purgekit pkg "FortiClient" --files       # .pkg kurulum kayıtlarını incele
purgekit uninstall "Spotify" --dry-run
purgekit uninstall "App" --mode advanced --admin --forget-pkgs
purgekit orphans
purgekit history --detail 1
```

### TUI Kısayolları (`purgekit ui`)

- `/`: Uygulama ara (`Escape` ile listeye dönüş)
- `t`: Temayı değiştir (`Tokyo Night`, `Dark`, `Nord`, `Catppuccin`, `Dracula`, `Light` — tercih kaydedilir)
- `s`: Sıralamayı değiştir (`Ad ↑` / `Boyut ↓`)
- `m`: Tarama modunu değiştir (`safe` / `moderate` / `advanced`)
- `a`: Artık dosyaların tümünü seç / seçimi temizle
- `d`: Dry-run önizleme
- `u`: Seçili uygulama veya yetim artıkları Çöp Kutusu'na kaldır (onay penceresiyle)
- `r`: Listeyi / taramayı yenile
- `q`: Çıkış

> Not: `purgekit ui` başlatıldığında terminal penceresini otomatik olarak en az `148x42` boyutuna genişletir (devre dışı bırakmak için `--no-resize`).

## Lisans

[MIT](LICENSE)
