from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

from purgekit.discovery import read_app_groups
from purgekit.homebrew import get_cask_zap_paths
from purgekit.models import (
    AppInfo,
    LeftoverItem,
    MatchConfidence,
    OrphanItem,
    RiskLevel,
    ScanMode,
    ScanResult,
)
from purgekit.packages import find_matching_pkg_ids, inspect_pkg_receipt
from purgekit.process import find_running_processes, read_launch_label
from purgekit.safety import (
    check_full_disk_access,
    extract_vendor_token,
    get_shared_vendor_tokens,
    is_sip_protected_path,
    requires_admin_privileges,
)
from purgekit.utils import get_path_size, normalize_token


@dataclass(frozen=True)
class ScanRule:
    scope: str  # "user" or "system"
    rel_dir: str
    category: str
    risk: RiskLevel
    min_mode: ScanMode
    allow_name_match: bool = False
    allow_prefix_match: bool = True
    is_plist_dir: bool = False


SCAN_RULES: Tuple[ScanRule, ...] = (
    # User Library (~/Library)
    ScanRule("user", "Library/Application Support", "Application Support", RiskLevel.MEDIUM, ScanMode.SAFE, allow_name_match=True),
    ScanRule("user", "Library/Caches", "Caches", RiskLevel.LOW, ScanMode.SAFE, allow_name_match=True),
    ScanRule("user", "Library/Preferences", "Preferences", RiskLevel.MEDIUM, ScanMode.SAFE, allow_name_match=False, is_plist_dir=True),
    ScanRule("user", "Library/Preferences/ByHost", "Preferences (ByHost)", RiskLevel.MEDIUM, ScanMode.SAFE, allow_name_match=False, is_plist_dir=True),
    ScanRule("user", "Library/Saved Application State", "Saved State", RiskLevel.LOW, ScanMode.SAFE, allow_name_match=False),
    ScanRule("user", "Library/Containers", "Containers", RiskLevel.MEDIUM, ScanMode.SAFE, allow_name_match=False),
    ScanRule("user", "Library/Group Containers", "Group Containers", RiskLevel.MEDIUM, ScanMode.SAFE, allow_name_match=False),
    ScanRule("user", "Library/HTTPStorages", "HTTPStorages", RiskLevel.LOW, ScanMode.SAFE, allow_name_match=False),
    ScanRule("user", "Library/WebKit", "WebKit", RiskLevel.LOW, ScanMode.SAFE, allow_name_match=False),
    ScanRule("user", "Library/Logs", "Logs", RiskLevel.LOW, ScanMode.SAFE, allow_name_match=True),
    ScanRule("user", "Library/Application Scripts", "Application Scripts", RiskLevel.LOW, ScanMode.SAFE, allow_name_match=False),
    ScanRule("user", "Library/Cookies", "Cookies", RiskLevel.LOW, ScanMode.SAFE, allow_name_match=False),
    ScanRule("user", "Library/LaunchAgents", "LaunchAgents", RiskLevel.MEDIUM, ScanMode.SAFE, allow_name_match=False, is_plist_dir=True),
    # System Library (/Library)
    ScanRule("system", "Library/Application Support", "System App Support", RiskLevel.HIGH, ScanMode.MODERATE, allow_name_match=True),
    ScanRule("system", "Library/Preferences", "System Preferences", RiskLevel.HIGH, ScanMode.MODERATE, allow_name_match=False, is_plist_dir=True),
    ScanRule("system", "Library/Caches", "System Caches", RiskLevel.LOW, ScanMode.MODERATE, allow_name_match=True),
    ScanRule("system", "Library/Logs", "System Logs", RiskLevel.LOW, ScanMode.MODERATE, allow_name_match=True),
    ScanRule("system", "Library/LaunchAgents", "System LaunchAgents", RiskLevel.HIGH, ScanMode.MODERATE, allow_name_match=False, is_plist_dir=True),
    ScanRule("system", "Library/LaunchDaemons", "System LaunchDaemons", RiskLevel.HIGH, ScanMode.ADVANCED, allow_name_match=False, is_plist_dir=True),
    ScanRule("system", "Library/PrivilegedHelperTools", "Privileged Helper Tools", RiskLevel.HIGH, ScanMode.ADVANCED, allow_name_match=False),
)

MODE_ORDER = {
    ScanMode.SAFE: 0,
    ScanMode.MODERATE: 1,
    ScanMode.ADVANCED: 2,
}

BUNDLE_LIKE_RE = re.compile(r"^(com|org|net|io|co|app|dev|me)\.[a-z0-9_-]+(\.[a-z0-9_-]+)+", re.IGNORECASE)


def _mode_enabled(current: ScanMode, minimum: ScanMode) -> bool:
    return MODE_ORDER[current] >= MODE_ORDER[minimum]


def _candidate_app_names(app: AppInfo) -> Set[str]:
    names = {app.name.strip(), app.path.stem.strip()}
    return {n for n in names if len(n) >= 3}


def _match_entry(
    entry_name: str,
    app: AppInfo,
    rule: ScanRule,
    mode: ScanMode,
    app_groups: Tuple[str, ...],
    shared_vendors: Set[str],
) -> Optional[Tuple[MatchConfidence, str]]:
    """Evaluate whether a directory/file entry belongs to `app` under `rule` & `mode`."""
    lower = entry_name.lower()
    bundle_lower = app.bundle_id.lower() if app.bundle_id else None

    # 1. Verified App Groups (for Group Containers)
    if rule.category == "Group Containers":
        for grp in app_groups:
            if lower == grp.lower():
                return MatchConfidence.EXACT, f"Entitlements App Group eşleşmesi ({grp})"
        if bundle_lower and (lower == bundle_lower or lower.endswith("." + bundle_lower)):
            return MatchConfidence.HIGH, "Group Container bundle ID eşleşmesi"
        if _mode_enabled(mode, ScanMode.MODERATE) and bundle_lower:
            # e.g. TEAMID.com.vendor.app*
            if f".{bundle_lower}" in lower:
                return MatchConfidence.HEURISTIC, "Group Container önek eşleşmesi"
        return None

    # 2. Exact Bundle ID match
    if bundle_lower:
        if lower == bundle_lower:
            return MatchConfidence.EXACT, f"Tam Bundle ID eşleşmesi ({app.bundle_id})"
        if lower.startswith(bundle_lower + "."):
            # e.g. com.foo.bar.plist, com.foo.bar.savedState, com.foo.bar.helper.plist
            if rule.is_plist_dir or lower.endswith((".savedstate", ".binarycookies")):
                return MatchConfidence.EXACT, f"Bundle ID dosya eşleşmesi ({app.bundle_id})"
            if _mode_enabled(mode, ScanMode.MODERATE) and rule.allow_prefix_match:
                return MatchConfidence.HIGH, f"Bundle ID alt bileşen öneki ({app.bundle_id}.*)"

    # 3. Safe / Moderate Name Match (guarding against shared vendor folders)
    if rule.allow_name_match and _mode_enabled(mode, ScanMode.MODERATE):
        for candidate in _candidate_app_names(app):
            cand_lower = candidate.lower()
            if lower == cand_lower:
                # If entry name is also a shared vendor name (rare, e.g. "Adobe"), guard it
                if cand_lower in shared_vendors:
                    return None
                return MatchConfidence.HIGH, f"Uygulama adı eşleşmesi ({candidate})"
            if _mode_enabled(mode, ScanMode.ADVANCED) and len(candidate) >= 5:
                if normalize_token(entry_name) == normalize_token(candidate):
                    return MatchConfidence.HEURISTIC, f"Normalize ad eşleşmesi ({candidate})"

    return None


def scan_app_leftovers(
    app: AppInfo,
    installed_apps: Sequence[AppInfo],
    mode: ScanMode = ScanMode.MODERATE,
    home: Optional[Path] = None,
    system_root: Optional[Path] = None,
    check_processes: bool = True,
    check_fda: bool = True,
    include_pkgutil: bool = True,
    caskroom_roots: Optional[Sequence[Path]] = None,
) -> ScanResult:
    """Scan all macOS Library locations for leftovers belonging to `app`."""
    user_home = home or Path.home()
    sys_root = system_root or Path("/")
    result = ScanResult(app=app, mode=mode)

    if app.is_protected:
        result.warnings.append(
            f"{app.name} sistem korumalı (SIP/Apple) bir uygulamadır; kaldırılması engellenmiştir."
        )

    if check_fda:
        has_fda, blocked = check_full_disk_access(home=user_home)
        if not has_fda:
            result.blocked_paths.extend(blocked)
            result.warnings.append(
                "Full Disk Access (Tam Disk Erişimi) eksik: Bazı korumalı Library dizinleri taranamadı."
            )

    app_groups = app.app_groups or read_app_groups(app.path)
    shared_vendors = get_shared_vendor_tokens(installed_apps, app)
    seen_paths: Set[str] = set()

    def add_leftover(
        path: Path,
        category: str,
        risk: RiskLevel,
        confidence: MatchConfidence,
        reason: str,
    ) -> None:
        if is_sip_protected_path(path, home=user_home):
            return
        abs_p = os.path.abspath(str(path))
        if abs_p in seen_paths:
            return
        seen_paths.add(abs_p)

        needs_admin = requires_admin_privileges(path, home=user_home)
        selected = risk != RiskLevel.HIGH and confidence in (MatchConfidence.EXACT, MatchConfidence.HIGH)
        result.leftovers.append(
            LeftoverItem(
                path=path,
                category=category,
                size_bytes=get_path_size(path),
                risk=risk,
                confidence=confidence,
                reason=reason,
                requires_admin=needs_admin,
                selected_by_default=selected,
            )
        )

    for rule in SCAN_RULES:
        if not _mode_enabled(mode, rule.min_mode):
            continue
        base_root = user_home if rule.scope == "user" else sys_root
        target_dir = base_root / rule.rel_dir
        if not target_dir.is_dir():
            continue

        try:
            with os.scandir(target_dir) as entries:
                for entry in entries:
                    entry_path = Path(entry.path)
                    entry_name = entry.name

                    # Sibling check: if folder name is a shared vendor (e.g. "Google"), look inside for <AppName>
                    if (
                        rule.allow_name_match
                        and entry.is_dir(follow_symlinks=False)
                        and entry_name.lower() in shared_vendors
                    ):
                        for candidate in _candidate_app_names(app):
                            nested = entry_path / candidate
                            if nested.exists():
                                add_leftover(
                                    nested,
                                    rule.category,
                                    rule.risk,
                                    MatchConfidence.HIGH,
                                    f"Paylaşılan geliştirici klasörü içinde uygulama alt dizini ({entry_name}/{candidate})",
                                )
                        continue

                    matched = _match_entry(entry_name, app, rule, mode, app_groups, shared_vendors)
                    if matched:
                        confidence, reason = matched
                        add_leftover(entry_path, rule.category, rule.risk, confidence, reason)
                        if rule.category in ("LaunchAgents", "System LaunchAgents", "System LaunchDaemons"):
                            label = read_launch_label(entry_path)
                            if label:
                                result.launch_labels.append(label)
        except PermissionError:
            result.blocked_paths.append(target_dir)
        except OSError:
            continue

    # Homebrew Cask zap metadata paths (Moderate/Advanced)
    if _mode_enabled(mode, ScanMode.MODERATE) and app.cask_name:
        for zap_path in get_cask_zap_paths(
            app.cask_name,
            caskroom_roots=caskroom_roots,
            home=user_home,
        ):
            add_leftover(
                zap_path,
                "HomebrewZap",
                RiskLevel.MEDIUM,
                MatchConfidence.EXACT,
                f"Homebrew Cask zap tanımı ({app.cask_name})",
            )

    # Advanced mode: .pkg receipt analysis & external files
    if mode == ScanMode.ADVANCED and include_pkgutil and system_root is None:
        for pkg_id in find_matching_pkg_ids(app):
            receipt = inspect_pkg_receipt(pkg_id, app_path=app.path, home=user_home)
            if not receipt:
                continue
            result.pkg_receipts.append(receipt)
            for pkg_file in receipt.external_files:
                add_leftover(
                    pkg_file,
                    "PkgReceipt",
                    RiskLevel.HIGH,
                    MatchConfidence.HIGH,
                    f".pkg kurulum kaydı ({pkg_id})",
                )

    if check_processes:
        result.running_processes = find_running_processes(app)
        if result.running_processes:
            result.warnings.append(
                f"Uygulamaya ait {len(result.running_processes)} çalışan süreç tespit edildi."
            )

    risk_rank = {RiskLevel.LOW: 0, RiskLevel.MEDIUM: 1, RiskLevel.HIGH: 2}
    result.leftovers.sort(key=lambda item: (risk_rank[item.risk], -item.size_bytes, str(item.path)))
    return result


def scan_orphans(
    installed_apps: Sequence[AppInfo],
    home: Optional[Path] = None,
) -> List[OrphanItem]:
    """Detect leftover bundle-ID directories/plists from previously removed applications."""
    user_home = home or Path.home()
    known_bundles = {a.bundle_id.lower() for a in installed_apps if a.bundle_id}
    known_groups = {g.lower() for a in installed_apps for g in a.app_groups}
    known_vendors = {
        v for a in installed_apps for v in (extract_vendor_token(a.bundle_id),) if v
    }

    categories: Tuple[Tuple[str, str, RiskLevel], ...] = (
        ("Library/Application Support", "Application Support", RiskLevel.MEDIUM),
        ("Library/Caches", "Caches", RiskLevel.LOW),
        ("Library/Containers", "Containers", RiskLevel.MEDIUM),
        ("Library/Saved Application State", "Saved State", RiskLevel.LOW),
        ("Library/HTTPStorages", "HTTPStorages", RiskLevel.LOW),
        ("Library/Preferences", "Preferences", RiskLevel.MEDIUM),
        ("Library/LaunchAgents", "LaunchAgents", RiskLevel.MEDIUM),
    )

    orphans: List[OrphanItem] = []
    for rel_dir, cat_name, risk in categories:
        folder = user_home / rel_dir
        if not folder.is_dir():
            continue
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    name = entry.name
                    lower = name.lower()
                    if not BUNDLE_LIKE_RE.match(lower):
                        continue
                    if lower.startswith("com.apple.") or lower.startswith("org.python."):
                        continue

                    stem = lower
                    for suffix in (".plist", ".savedstate", ".binarycookies"):
                        if stem.endswith(suffix):
                            stem = stem[: -len(suffix)]

                    if stem in known_bundles or stem in known_groups:
                        continue
                    if any(stem.startswith(b + ".") for b in known_bundles):
                        continue

                    # Conservative: skip if vendor still has another app installed in LaunchAgents/Preferences
                    vendor = extract_vendor_token(stem)
                    active_shared_vendor = vendor if (vendor and vendor in known_vendors) else None
                    if active_shared_vendor and cat_name in ("Preferences", "LaunchAgents"):
                        continue

                    p = Path(entry.path)
                    if is_sip_protected_path(p, home=user_home):
                        continue
                    orphans.append(
                        OrphanItem(
                            path=p,
                            category=cat_name,
                            identifier_hint=stem,
                            size_bytes=get_path_size(p),
                            risk=risk,
                            shared_vendor=active_shared_vendor,
                        )
                    )
        except OSError:
            continue

    orphans.sort(key=lambda o: -o.size_bytes)
    return orphans
