from __future__ import annotations

import os
import shutil
import subprocess
import unicodedata
from collections import deque
from pathlib import Path
from typing import Deque, List, Optional, Sequence, Set, Tuple

from purgekit.models import FileSearchItem, RiskLevel
from purgekit.safety import is_sip_protected_path, requires_admin_privileges
from purgekit.utils import get_path_size

SKIP_DESCEND_DIRS = frozenset({
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
})

NOISY_HOME_DOTDIRS = frozenset({
    ".Trash",
    ".npm",
    ".pyenv",
    ".rustup",
    ".cargo",
    ".gradle",
    ".m2",
    ".cache",
    ".ollama",
    ".docker",
    ".vscode",
    ".cursor",
    ".gemini",
})

NOISY_LIBRARY_DIRS = frozenset({
    "Developer",
    "CoreSimulator",
    "Biome",
    "Metadata",
    "Suggestions",
    "Assistant",
})


def _fold_text(text: str, ascii_fold: bool = False) -> str:
    """Normalize macOS NFD/NFC text and Turkish characters for reliable matching."""
    nfc = unicodedata.normalize("NFC", text)
    # Prevent Python's `İ -> i\u0307` and normalize dotted/dotless I consistently
    folded = nfc.replace("\u0130", "i").replace("I", "i")
    if ascii_fold:
        folded = folded.replace("\u0131", "i")
        nfd = unicodedata.normalize("NFD", folded)
        folded = "".join(ch for ch in nfd if unicodedata.category(ch) != "Mn")
    return folded.casefold()


def _prepare_tokens(query: str) -> Tuple[List[str], List[str]]:
    raw_tokens = [tok for tok in query.strip().split() if tok]
    strict_tokens = [_fold_text(tok, ascii_fold=False) for tok in raw_tokens]
    ascii_tokens = [_fold_text(tok, ascii_fold=True) for tok in raw_tokens]
    return strict_tokens, ascii_tokens


def _matches_tokens(
    name: str,
    rel_path: str,
    strict_tokens: Sequence[str],
    ascii_tokens: Sequence[str],
) -> Tuple[bool, bool]:
    """Return `(matched, matched_in_name)` with NFC/NFD + diacritic-insensitive fallback.

    Single-token queries match against the entry filename (`name`) so a folder match
    does not flood results with thousands of unrelated nested files. Multi-token or
    slash (`a/b`) queries can span parent folders + filename as long as at least one
    token matches the filename (unless `/` is explicitly used).
    """
    if not strict_tokens:
        return False, False

    has_slash = any("/" in tok for tok in strict_tokens)
    name_strict = _fold_text(name, ascii_fold=False)
    name_ascii = _fold_text(name, ascii_fold=True)

    if len(strict_tokens) == 1 and not has_slash:
        if strict_tokens[0] in name_strict:
            return True, True
        if ascii_tokens[0] in name_ascii:
            return True, True
        return False, False

    if all(tok in name_strict for tok in strict_tokens):
        return True, True

    path_strict = _fold_text(rel_path, ascii_fold=False)
    if all(tok in path_strict for tok in strict_tokens):
        if has_slash or any(tok in name_strict for tok in strict_tokens):
            return True, False

    if all(tok in name_ascii for tok in ascii_tokens):
        return True, True

    path_ascii = _fold_text(rel_path, ascii_fold=True)
    if all(tok in path_ascii for tok in ascii_tokens):
        if has_slash or any(tok in name_ascii for tok in ascii_tokens):
            return True, False

    return False, False


def _should_skip_noise(path: Path, query_lower: str) -> bool:
    """Filter out deep browser/Trash internals unless specifically queried."""
    raw_lower = _fold_text(str(path), ascii_fold=True)
    if "/.trash/" in raw_lower and "trash" not in query_lower:
        return True
    if ".indexeddb." in raw_lower and "indexeddb" not in query_lower:
        return True
    if "/cache/cache_data/" in raw_lower and "cache_data" not in query_lower:
        return True
    if "/codex/" in raw_lower and "codex" not in query_lower and "/service worker/" in raw_lower:
        return True
    return False


def _run_mdfind(query: str, roots: Sequence[Path], per_root_cap: int) -> List[Path]:
    """Query macOS Spotlight (`mdfind`) safely without shell interpolation."""
    if not shutil.which("mdfind"):
        return []

    tokens = [tok for tok in query.strip().split() if tok]
    if not tokens:
        return []
    # Query Spotlight with the longest token so multi-word queries match filenames with `_`/`-`
    spotlight_term = max(tokens, key=len) if len(tokens) > 1 else query.strip()

    results: List[Path] = []
    for root in roots:
        if not root.is_dir():
            continue
        root_hits = 0
        try:
            proc = subprocess.run(
                ["mdfind", "-onlyin", str(root), "-name", spotlight_term],
                capture_output=True,
                text=True,
                timeout=6,
                check=False,
            )
            if proc.returncode != 0:
                continue
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                results.append(Path(line))
                root_hits += 1
                if root_hits >= per_root_cap:
                    break
        except (OSError, subprocess.SubprocessError):
            continue
    return results


def _walk_job(
    root: Path,
    max_depth: int,
    max_entries: int,
    strict_tokens: Sequence[str],
    ascii_tokens: Sequence[str],
    query_ascii: str,
    user_home: Path,
    match_cap: int,
    skip_dirs: frozenset[str] = SKIP_DESCEND_DIRS,
) -> List[Path]:
    """Bounded breadth-first filesystem walk resilient to macOS NFD & unindexed dirs."""
    if not root.is_dir():
        return []

    matches: List[Path] = []
    queue: Deque[Tuple[Path, int]] = deque([(root, 0)])
    visited_entries = 0
    home_prefix = str(user_home) + "/"

    while queue and visited_entries < max_entries and len(matches) < match_cap:
        current, depth = queue.popleft()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    visited_entries += 1
                    name = entry.name
                    raw_path = entry.path
                    rel_path = raw_path[len(home_prefix) :] if raw_path.startswith(home_prefix) else raw_path

                    matched, _ = _matches_tokens(name, rel_path, strict_tokens, ascii_tokens)
                    if matched:
                        matches.append(Path(raw_path))
                        if len(matches) >= match_cap:
                            break

                    if depth + 1 < max_depth and entry.is_dir(follow_symlinks=False):
                        if name.endswith(".app"):
                            continue
                        folded_name = _fold_text(name, ascii_fold=True)
                        if name in skip_dirs and folded_name not in query_ascii:
                            continue
                        if name in NOISY_LIBRARY_DIRS and folded_name not in query_ascii and "/Library" in raw_path:
                            continue
                        queue.append((Path(raw_path), depth + 1))

                    if visited_entries >= max_entries:
                        break
        except OSError:
            continue

    return matches


def _build_scan_jobs(scope: str, user_home: Path, sys_root: Path, query_ascii: str) -> List[Tuple[Path, int, int]]:
    """Build prioritized `(root, max_depth, entry_budget)` jobs for fast deep scanning."""
    jobs: List[Tuple[Path, int, int]] = []

    if scope == "library":
        jobs.append((user_home / "Library", 5, 30000))
        jobs.append((sys_root / "Library", 4, 20000))
        return jobs

    # Prioritized high-signal user directories (deep scan, fast ~0.1-0.2s total)
    priority_user_dirs = [
        "Downloads",
        "Desktop",
        "Documents",
        "Applications",
        "Movies",
        "Music",
        "Pictures",
        "Public",
    ]
    seen_roots: Set[str] = set()
    for rel in priority_user_dirs:
        p = user_home / rel
        if p.is_dir():
            seen_roots.add(p.name)
            jobs.append((p, 7, 25000))

    # Immediate children of ~ plus custom non-dot folders (e.g. ~/Projects, ~/Work)
    try:
        with os.scandir(user_home) as entries:
            for entry in entries:
                if not entry.is_dir(follow_symlinks=False):
                    continue
                name = entry.name
                if name == "Library" or name in seen_roots:
                    continue
                if name.startswith("."):
                    if name in NOISY_HOME_DOTDIRS and _fold_text(name, ascii_fold=True) not in query_ascii:
                        continue
                    jobs.append((Path(entry.path), 3, 5000))
                else:
                    jobs.append((Path(entry.path), 6, 20000))
    except OSError:
        pass

    # Top level of user_home (files directly in ~/) + ~/Library scan
    jobs.append((user_home, 1, 2000))
    jobs.append((user_home / "Library", 4, 22000))

    if scope == "all":
        jobs.append((sys_root / "Applications", 3, 5000))
        jobs.append((sys_root / "Library", 4, 20000))
        jobs.append((sys_root / "Users" / "Shared", 5, 10000))
        jobs.append((sys_root / "opt" / "homebrew", 3, 10000))

    return jobs


def _classify_risk(path: Path, requires_admin: bool, user_home: Path) -> RiskLevel:
    if requires_admin:
        return RiskLevel.HIGH
    raw = os.path.abspath(str(path))
    downloads = str((user_home / "Downloads").resolve())
    caches = str((user_home / "Library" / "Caches").resolve())
    logs = str((user_home / "Library" / "Logs").resolve())
    if raw.startswith((downloads + "/", caches + "/", logs + "/")):
        return RiskLevel.LOW
    return RiskLevel.MEDIUM


def search_files(
    query: str,
    scope: str = "user",
    item_type: str = "all",
    home: Optional[Path] = None,
    system_root: Optional[Path] = None,
    use_spotlight: bool = True,
    limit: int = 120,
) -> List[FileSearchItem]:
    """Search for files and folders across macOS user directories, Library, or system."""
    q = query.strip()
    if not q:
        return []

    strict_tokens, ascii_tokens = _prepare_tokens(q)
    if not strict_tokens:
        return []
    query_ascii = _fold_text(q, ascii_fold=True)

    user_home = (home or Path.home()).resolve()
    sys_root = (system_root or Path("/")).resolve()
    home_prefix = str(user_home) + "/"

    if scope == "library":
        spotlight_roots: List[Path] = []
    elif scope == "all":
        spotlight_roots = [user_home, sys_root / "Applications", sys_root / "Library", sys_root / "Users" / "Shared"]
    else:  # "user"
        spotlight_roots = [user_home]

    candidates: List[Tuple[Path, str]] = []
    if use_spotlight and spotlight_roots:
        for p in _run_mdfind(q, spotlight_roots, per_root_cap=max(limit * 3, 300)):
            candidates.append((p, "spotlight"))

    scan_jobs = _build_scan_jobs(scope=scope, user_home=user_home, sys_root=sys_root, query_ascii=query_ascii)
    per_job_match_cap = max(limit * 2, 120)
    for root, max_depth, budget in scan_jobs:
        found = _walk_job(
            root=root,
            max_depth=max_depth,
            max_entries=budget,
            strict_tokens=strict_tokens,
            ascii_tokens=ascii_tokens,
            query_ascii=query_ascii,
            user_home=user_home,
            match_cap=per_job_match_cap,
        )
        for p in found:
            src = "library" if "/Library/" in str(p) else "scan"
            candidates.append((p, src))

    seen: Set[str] = set()
    filtered_entries: List[Tuple[Path, str, bool, bool]] = []

    for p, src in candidates:
        abs_p = os.path.abspath(str(p))
        if abs_p in seen:
            continue
        seen.add(abs_p)

        rel_p = abs_p[len(home_prefix) :] if abs_p.startswith(home_prefix) else abs_p
        matched, matched_in_name = _matches_tokens(p.name, rel_p, strict_tokens, ascii_tokens)
        if not matched:
            continue

        if is_sip_protected_path(p, home=user_home):
            continue
        if _should_skip_noise(p, query_ascii):
            continue

        try:
            exists = p.exists() or p.is_symlink()
        except OSError:
            continue
        if not exists:
            continue

        is_dir = p.is_dir() and not p.is_symlink()
        if item_type == "file" and is_dir:
            continue
        if item_type == "dir" and not is_dir:
            continue

        filtered_entries.append((p, src, is_dir, matched_in_name))

    # Rank lightweight path attributes first, then compute sizes on top candidates
    def pre_rank(entry: Tuple[Path, str, bool, bool]) -> Tuple[int, int, int, int, int, str]:
        p, _, _, matched_in_name = entry
        name_folded = _fold_text(p.name, ascii_fold=True)
        stem_folded = _fold_text(p.stem, ascii_fold=True)
        exact = 0 if (name_folded == query_ascii or stem_folded == query_ascii) else 1
        prefix = 0 if name_folded.startswith(query_ascii) else 1
        in_name = 0 if matched_in_name else 1
        lib_penalty = 1 if "/Library/" in str(p) else 0
        return (exact, in_name, prefix, lib_penalty, len(p.parts), name_folded)

    filtered_entries.sort(key=pre_rank)
    capped = filtered_entries[: max(limit * 2, 200)]

    results: List[FileSearchItem] = []
    for p, src, is_dir, _ in capped:
        needs_admin = requires_admin_privileges(p, home=user_home)
        risk = _classify_risk(p, needs_admin, user_home)
        size = get_path_size(p)
        results.append(
            FileSearchItem(
                path=p,
                name=p.name,
                is_dir=is_dir,
                size_bytes=size,
                source=src,
                risk=risk,
                requires_admin=needs_admin,
            )
        )

    def final_rank(item: FileSearchItem) -> Tuple[int, int, int, int, str]:
        name_folded = _fold_text(item.name, ascii_fold=True)
        stem_folded = _fold_text(item.path.stem, ascii_fold=True)
        exact = 0 if (name_folded == query_ascii or stem_folded == query_ascii) else 1
        prefix = 0 if name_folded.startswith(query_ascii) else 1
        return (exact, prefix, len(item.path.parts), -item.size_bytes, name_folded)

    results.sort(key=final_rank)
    return results[:limit]
