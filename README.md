# PurgeKit

[![CI](https://github.com/furkanyild09/PurgeKit/actions/workflows/ci.yml/badge.svg)](https://github.com/furkanyild09/PurgeKit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A smart application uninstaller and deep leftover scanner for **macOS** (CLI & interactive TUI), inspired by **Revo Uninstaller**.

## Features

- **Multi-Tab Textual TUI (`purgekit`):** Built-in theme switcher (`Tokyo Night`, `Dark`, `Nord`, `Catppuccin`, `Dracula`, `Light`), top-left `☰ Commands` palette button, disk-usage metric cards, live search/sorting, and automatic terminal window sizing across **6 interactive views**:
  - **Applications:** Revo-style leftover inspector and safe uninstaller.
  - **File Search (`f`):** Hybrid macOS search across Spotlight (`mdfind`), `~/Library`, and deep user directories with Unicode NFD/NFC & multi-word matching.
  - **Space Sweep:** Finds old `.dmg`/`.pkg`/`.iso` installers, Xcode/Homebrew/npm/pip/project caches, and large files (`>= 50 MB`).
  - **Startup Services:** Inspects, unloads (`launchctl bootout`), or trashes third-party `LaunchAgents` and `LaunchDaemons`.
  - **Disk Lens:** Hierarchical folder footprint breakdown with visual usage bars and safe drill-down.
  - **Orphans:** Detects leftover `~/Library` directories and plists left behind by previously removed apps.
- **Trash Watcher (`purgekit watch`):** Monitors `~/.Trash` in real time and offers instant leftover cleanup whenever an `.app` is dragged to Trash via Finder.
- **Application Discovery:** Scans `/Applications` and `~/Applications` (including subdirectories), reads `Info.plist` metadata, and detects Mac App Store receipts and Homebrew Cask installations (`zap` stanzas included).
- **3-Tier Leftover Scanner:** Supports `safe`, `moderate`, and `advanced` modes across `~/Library`, `/Library`, `LaunchAgents`, `LaunchDaemons`, `Group Containers` (via `codesign` entitlements), and `.pkg` receipts.
- **Safety Guardrails:**
  - Enforces System Integrity Protection (SIP) and critical user/Library root exclusions (`~/Desktop`, `~/Documents`, `~/Downloads`, etc.).
  - **Sibling App Check:** Protects shared vendor folders (e.g., `~/Library/Application Support/Google`) when other apps from the same developer remain installed.
  - **Reveal in Finder (`o`):** Inspect any highlighted file, folder, or app directly in Finder before removal.
  - Risk classification (`low`, `medium`, `high`) and macOS Full Disk Access (FDA) diagnostics.
- **Safe Removal & Audit Trail:** Moves items to Trash by default (`send2trash`), supports `--dry-run` previews, terminates running app processes, unloads LaunchAgents/Daemons, supports `--admin --forget-pkgs`, and records JSON manifests under `~/.purgekit/history/`.

## Requirements

- macOS
- Python 3.9+

## Quick Start (One-Command Install)

Install directly from GitHub on macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/furkanyild09/PurgeKit/main/install.sh | bash
```

Then just run:

```bash
purgekit
```

### Alternatives (`uvx` / `pipx` / Source)

Run instantly without installing (requires `uv`):
```bash
uvx --from git+https://github.com/furkanyild09/PurgeKit purgekit
```

Or install globally with `pipx`:
```bash
pipx install git+https://github.com/furkanyild09/PurgeKit
purgekit
```

<details>
<summary>Manual install from source</summary>

```bash
git clone https://github.com/furkanyild09/PurgeKit.git
cd PurgeKit
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
purgekit
```

</details>

## Usage

### Interactive TUI

Running `purgekit` (or `PurgeKit` / `purgekit ui`) launches the interactive TUI directly:

```bash
purgekit
```

**Keyboard Shortcuts:**
- `/` — Search apps (press `Enter` or `f` to search matching files/folders across macOS)
- `f` — Jump to **File Search** (Spotlight + `~/Library` + user folders)
- `o` — **Reveal in Finder** (`open -R`) for the highlighted item
- `t` — Switch theme (persisted in `~/.purgekit/config.json`)
- `s` — Toggle sort order (`Name ↑` / `Size ↓`)
- `m` — Cycle scan mode (`safe` / `moderate` / `advanced`)
- `a` — Select / deselect all items in the active tab
- `d` — Run a `dry-run` preview
- `u` — Move selected app/leftovers, files, sweep targets, or plists to Trash (with confirmation modal)
- `r` — Refresh list / rescan active tab
- `q` — Quit

> Note: `purgekit ui` automatically enlarges interactive terminal windows to at least `148×42` on startup. Pass `--no-resize` to keep your current terminal dimensions.

### CLI Commands

```bash
purgekit doctor                            # Check Full Disk Access, codesign, pkgutil, launchctl, brew
purgekit list --sort size                  # List installed apps sorted by disk size
purgekit find "installer.dmg" --trash      # Find files/folders (Spotlight + Library) & optionally trash them
purgekit sweep --min-mb 100 --trash        # Find old installers, dev caches (Xcode/brew/npm/pip), & large files
purgekit startup --unload                  # List, launchctl bootout, or trash LaunchAgents & LaunchDaemons
purgekit lens ~/Library                    # Visual Disk Space Lens breakdown of folder sizes
purgekit watch                             # Watch ~/.Trash for newly trashed .app bundles & clean leftovers
purgekit scan "Spotify" --mode moderate    # Scan leftovers without deleting anything
purgekit pkg "FortiClient" --files         # Inspect matching .pkg receipts and external files
purgekit uninstall "Spotify" --dry-run     # Preview an uninstall safely
purgekit uninstall "App" --mode advanced --admin --forget-pkgs
purgekit orphans --min-kb 100              # Find orphaned leftovers from removed apps
purgekit history --detail 1                # Inspect the latest removal manifest
purgekit update                            # Upgrade PurgeKit to the latest GitHub release
```

## Full Disk Access (Recommended)

If `purgekit doctor` reports missing **Full Disk Access**, some TCC-protected paths (such as `~/Library/Cookies`, `~/Library/Safari`, or `~/Library/Mail`) cannot be scanned. Grant Full Disk Access to your terminal app under **System Settings → Privacy & Security → Full Disk Access** for complete scans.

## Development

```bash
pip install -e ".[dev]"
pytest -v
```

## License

[MIT](LICENSE)
