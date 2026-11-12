from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional, Tuple


class InstallSource(str, Enum):
    STANDARD = "standard"
    APP_STORE = "app_store"
    HOMEBREW = "homebrew"
    SYSTEM = "system"


class ScanMode(str, Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    ADVANCED = "advanced"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class MatchConfidence(str, Enum):
    EXACT = "exact"
    HIGH = "high"
    HEURISTIC = "heuristic"


@dataclass(frozen=True)
class AppInfo:
    name: str
    path: Path
    bundle_id: Optional[str] = None
    version: Optional[str] = None
    source: InstallSource = InstallSource.STANDARD
    size_bytes: int = 0
    is_protected: bool = False
    app_groups: Tuple[str, ...] = ()
    cask_name: Optional[str] = None


@dataclass(frozen=True)
class LeftoverItem:
    path: Path
    category: str
    size_bytes: int
    risk: RiskLevel
    confidence: MatchConfidence
    reason: str
    requires_admin: bool = False
    selected_by_default: bool = True


@dataclass(frozen=True)
class RunningProcessInfo:
    pid: int
    name: str
    exe: Optional[str] = None


@dataclass(frozen=True)
class PkgReceiptInfo:
    pkg_id: str
    version: Optional[str] = None
    volume: str = "/"
    location: str = ""
    install_time: Optional[str] = None
    external_files: List[Path] = field(default_factory=list)
    total_bytes: int = 0


@dataclass
class ScanResult:
    app: AppInfo
    mode: ScanMode
    leftovers: List[LeftoverItem] = field(default_factory=list)
    running_processes: List[RunningProcessInfo] = field(default_factory=list)
    launch_labels: List[str] = field(default_factory=list)
    pkg_receipts: List[PkgReceiptInfo] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    blocked_paths: List[Path] = field(default_factory=list)

    @property
    def leftover_size_bytes(self) -> int:
        return sum(item.size_bytes for item in self.leftovers)

    @property
    def total_size_bytes(self) -> int:
        return self.app.size_bytes + self.leftover_size_bytes


@dataclass(frozen=True)
class OrphanItem:
    path: Path
    category: str
    identifier_hint: str
    size_bytes: int
    risk: RiskLevel
    shared_vendor: Optional[str] = None


@dataclass(frozen=True)
class FileSearchItem:
    path: Path
    name: str
    is_dir: bool
    size_bytes: int
    source: str
    risk: RiskLevel
    requires_admin: bool = False


@dataclass(frozen=True)
class SweepItem:
    path: Path
    category: str
    size_bytes: int
    risk: RiskLevel
    note: str
    is_dir: bool = False
    requires_admin: bool = False


@dataclass(frozen=True)
class StartupItem:
    path: Path
    label: str
    scope: str
    executable: Optional[str]
    size_bytes: int
    risk: RiskLevel
    is_running: bool = False
    run_at_load: bool = False
    keep_alive: bool = False
    requires_admin: bool = False


@dataclass(frozen=True)
class SpaceLensEntry:
    path: Path
    name: str
    size_bytes: int
    share_pct: float
    is_dir: bool
    is_protected: bool = False


@dataclass
class RemovalOutcome:
    app_name: str
    bundle_id: Optional[str]
    trashed: List[Path] = field(default_factory=list)
    deleted_permanently: List[Path] = field(default_factory=list)
    forgotten_pkgs: List[str] = field(default_factory=list)
    failed: List[Tuple[Path, str]] = field(default_factory=list)
    reclaimed_bytes: int = 0
    manifest_path: Optional[Path] = None
    dry_run: bool = True
